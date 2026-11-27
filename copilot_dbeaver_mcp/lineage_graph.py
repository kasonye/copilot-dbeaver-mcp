"""
1-Call Foreign-Key & Naming-Convention Record Lineage Graph (`trace_record_graph`).

Given a root table and primary key value (or WHERE condition), automatically:
  1. Fetches the root record(s) (PII-masked).
  2. Discovers parent (upstream) references via both explicit JDBC Foreign Keys and
     optional `_id` naming conventions, fetching parent rows and flagging ORPHAN_FOREIGN_KEY anomalies!
  3. Discovers child (downstream) referencing tables across the schema and fetches bounded child summaries!
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from copilot_dbeaver_mcp.sql_guard import (
    DynamicDataMasker,
    quote_ident,
    sql_literal,
    validate_identifier,
    validate_where_clause,
)


def _match_implicit_parent_table(fk_col: str, all_tables_lower: Dict[str, str], root_table_low: str) -> Optional[str]:
    low = fk_col.lower()
    if not low.endswith("_id") or low == "id":
        return None
    stem = low[:-3]  # e.g. "customer" from "customer_id" or "order" from "order_id"
    if not stem or len(stem) < 2:
        return None

    candidates = [
        stem,
        f"{stem}s",
        f"{stem}es",
        f"t_{stem}",
        f"t_{stem}s",
        f"tb_{stem}",
        f"sys_{stem}",
    ]
    if stem.endswith("y") and len(stem) > 2:
        candidates.append(f"{stem[:-1]}ies")

    for cand in candidates:
        if cand in all_tables_lower and cand != root_table_low:
            return all_tables_lower[cand]
    return None


def trace_related_record_graph(
    *,
    run_query_fn: Callable[[str, int], Dict[str, Any]],
    inspect_table_fn: Callable[[str], Dict[str, Any]],
    bulk_schema_fn: Callable[[], Dict[str, Any]],
    masker: DynamicDataMasker,
    dialect: str,
    table: str,
    pk_value: Any = None,
    where_clause: str = "",
    infer_implicit_fks: bool = True,
    max_child_tables: int = 8,
    max_rows_per_relation: int = 10,
) -> Dict[str, Any]:
    id_err = validate_identifier(table, "table")
    if id_err:
        raise ValueError(id_err)

    short_table = table.split(".")[-1]
    root_meta = inspect_table_fn(short_table)
    pks: List[str] = list(root_meta.get("primaryKeys") or [])
    root_cols_meta: List[Dict[str, Any]] = list(root_meta.get("columns") or [])
    if not root_cols_meta:
        raise ValueError(f"Table '{table}' not found or has no columns.")

    if where_clause and where_clause.strip():
        clean_where, w_err = validate_where_clause(where_clause)
        if w_err:
            raise ValueError(w_err)
    elif pk_value is not None:
        if not pks:
            raise ValueError(f"Table '{table}' has no primary key; pass 'where_clause' instead of 'primary_key_value'.")
        clean_where = f"{quote_ident(pks[0], dialect)} = {sql_literal(pk_value, dialect)}"
    else:
        raise ValueError("Provide either 'primary_key_value' or 'where_clause' to trace_record_graph.")

    q_root = quote_ident(short_table, dialect)
    root_res = run_query_fn(f"SELECT * FROM {q_root} WHERE {clean_where}", 5)
    root_columns = root_res.get("columns", [])
    root_rows_unmasked = root_res.get("rows", [])
    masked_root_rows, _ = masker.mask_rows(root_columns, root_rows_unmasked)

    if not root_rows_unmasked:
        return {
            "root_table": short_table,
            "where_clause": clean_where,
            "found": False,
            "root_rows": [],
            "parent_relations": [],
            "child_relations": [],
            "anomalies_detected": [f"ROOT_NOT_FOUND: 0 rows matched '{clean_where}' in {short_table}."],
        }

    root_col_names = [c["name"] for c in root_columns]
    first_root_map = dict(zip(root_col_names, root_rows_unmasked[0]))

    # Load bulk schema once to resolve both implicit parent tables and inbound child tables!
    bulk = bulk_schema_fn()
    all_tables: Dict[str, Dict[str, Any]] = bulk.get("tables") or {}
    all_tables_lower = {t.lower(): t for t in all_tables.keys()}
    root_low = short_table.lower()

    # 1. Resolve Parent Relations (explicit FKs + optional implicit *_id columns)
    parent_specs: List[Tuple[str, str, str, str]] = []  # (fk_col, parent_table, parent_pk_col, source_kind)
    seen_fk_cols = set()
    for fk in root_meta.get("foreignKeys") or []:
        fk_c = fk.get("fkColumn")
        pk_t = fk.get("pkTable")
        pk_c = fk.get("pkColumn")
        if fk_c and pk_t and pk_c:
            parent_specs.append((fk_c, pk_t, pk_c, "explicit_fk"))
            seen_fk_cols.add(fk_c.lower())

    if infer_implicit_fks:
        pk_set_low = {p.lower() for p in pks}
        for col_name in root_col_names:
            clow = col_name.lower()
            if clow in seen_fk_cols or clow in pk_set_low:
                continue
            matched_parent = _match_implicit_parent_table(col_name, all_tables_lower, root_low)
            if matched_parent:
                p_meta = all_tables.get(matched_parent) or {}
                p_pks = p_meta.get("primaryKeys") or []
                p_cols = {c["name"].lower(): c["name"] for c in (p_meta.get("columns") or [])}
                target_pk = p_pks[0] if p_pks else p_cols.get(clow) or p_cols.get("id")
                if target_pk:
                    parent_specs.append((col_name, matched_parent, target_pk, "implicit_naming"))
                    seen_fk_cols.add(clow)

    anomalies: List[str] = []
    parent_relations: List[Dict[str, Any]] = []

    for fk_col, p_table, p_pk, rel_kind in parent_specs:
        # Collect non-null FK values across matched root rows
        fk_idx = next((i for i, c in enumerate(root_col_names) if c.lower() == fk_col.lower()), -1)
        if fk_idx < 0:
            continue
        fk_vals = []
        for r in root_rows_unmasked:
            v = r[fk_idx]
            if v is not None and str(v) != "" and v not in fk_vals:
                fk_vals.append(v)
        if not fk_vals:
            continue

        in_sql = ", ".join(sql_literal(v, dialect) for v in fk_vals)
        p_sql = f"SELECT * FROM {quote_ident(p_table, dialect)} WHERE {quote_ident(p_pk, dialect)} IN ({in_sql})"
        try:
            pres = run_query_fn(p_sql, max_rows_per_relation)
            p_cols = pres.get("columns", [])
            p_rows_raw = pres.get("rows", [])
            p_rows_masked, _ = masker.mask_rows(p_cols, p_rows_raw)

            # Check for orphan foreign keys!
            p_pk_idx = next((i for i, c in enumerate(p_cols) if c["name"].lower() == p_pk.lower()), 0)
            found_p_vals = {str(pr[p_pk_idx]) for pr in p_rows_raw if pr}
            for expected_v in fk_vals:
                if str(expected_v) not in found_p_vals:
                    anomalies.append(
                        f"ORPHAN_FOREIGN_KEY ({rel_kind}): {short_table}.{fk_col}={expected_v!r} has NO matching parent record in {p_table}.{p_pk}!"
                    )

            parent_relations.append(
                {
                    "fk_column": fk_col,
                    "parent_table": p_table,
                    "parent_pk_column": p_pk,
                    "relation_source": rel_kind,
                    "referenced_values": fk_vals,
                    "found_count": len(p_rows_masked),
                    "columns": p_cols,
                    "rows": p_rows_masked,
                }
            )
        except Exception as exc:
            parent_relations.append({"fk_column": fk_col, "parent_table": p_table, "error": str(exc)})

    # 2. Resolve Child Relations (tables referencing root PK)
    child_relations: List[Dict[str, Any]] = []
    if pks:
        root_pk = pks[0]
        root_pk_val = first_root_map.get(root_pk)
        if root_pk_val is not None:
            # Candidate column names in child tables referencing root_pk
            root_stem = re.sub(r"^(t_|tb_|sys_)", "", root_low)
            if root_stem.endswith("s") and len(root_stem) > 3:
                root_stem_singular = root_stem[:-1]
            else:
                root_stem_singular = root_stem
            candidate_child_fk_names = {root_pk.lower(), f"{root_stem}_id", f"{root_stem_singular}_id"}
            candidate_child_fk_names.discard("id")

            for cand_table, c_meta in all_tables.items():
                if len(child_relations) >= max_child_tables:
                    break
                if cand_table.lower() == root_low:
                    continue
                c_pks_low = {p.lower() for p in (c_meta.get("primaryKeys") or [])}
                matched_child_col = None
                for c_col in c_meta.get("columns") or []:
                    cn_low = c_col["name"].lower()
                    if cn_low in candidate_child_fk_names and not (len(c_pks_low) == 1 and cn_low in c_pks_low):
                        matched_child_col = c_col["name"]
                        break
                if not matched_child_col:
                    continue

                c_sql = (
                    f"SELECT * FROM {quote_ident(cand_table, dialect)} "
                    f"WHERE {quote_ident(matched_child_col, dialect)} = {sql_literal(root_pk_val, dialect)}"
                )
                try:
                    cres = run_query_fn(c_sql, max_rows_per_relation)
                    c_cols = cres.get("columns", [])
                    c_rows_raw = cres.get("rows", [])
                    c_rows_masked, _ = masker.mask_rows(c_cols, c_rows_raw)
                    child_relations.append(
                        {
                            "child_table": cand_table,
                            "child_fk_column": matched_child_col,
                            "sample_row_count": len(c_rows_masked),
                            "truncated": bool(cres.get("truncated")),
                            "columns": c_cols,
                            "rows": c_rows_masked,
                        }
                    )
                except Exception:
                    continue

    return {
        "root_table": short_table,
        "where_clause": clean_where,
        "found": True,
        "root_columns": root_columns,
        "root_rows": masked_root_rows,
        "parent_relations": parent_relations,
        "child_relations": child_relations,
        "anomalies_detected": anomalies,
    }
