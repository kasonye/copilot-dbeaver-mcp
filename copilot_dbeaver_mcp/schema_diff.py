"""
Cross-Environment Database Schema Diff & Incremental DDL Patch Generator.
Compares source (e.g. local dev) vs target (e.g. SIT / staging / UAT) bulk metadata snapshots.
"""

from __future__ import annotations

from typing import Any, Dict, List

from copilot_dbeaver_mcp.sql_guard import quote_ident


def _format_col_type(col: Dict[str, Any]) -> str:
    raw_type = str(col.get("type") or "VARCHAR").upper()
    size = int(col.get("size") or 0)
    # Types that take an explicit length parameter in DDL
    if any(k in raw_type for k in ("CHAR", "VARCHAR", "BINARY", "VARBINARY")) and 0 < size <= 16383:
        if "(" not in raw_type:
            return f"{raw_type}({size})"
    return raw_type


def _format_col_definition(col: Dict[str, Any], dialect: str) -> str:
    qname = quote_ident(str(col["name"]), dialect)
    ctype = _format_col_type(col)
    null_sql = "NULL" if col.get("nullable", True) else "NOT NULL"
    default_val = col.get("defaultValue")
    def_sql = f" DEFAULT {default_val}" if default_val is not None and str(default_val) != "" else ""
    return f"{qname} {ctype} {null_sql}{def_sql}"


def compute_schema_diff(
    source_tables: Dict[str, Dict[str, Any]],
    target_tables: Dict[str, Dict[str, Any]],
    target_dialect: str = "mysql",
) -> Dict[str, Any]:
    """
    Compares source_tables (reference schema) against target_tables (schema to inspect/upgrade).
    Generates structured diffs and additive/safe ALTER/CREATE sync DDL suggestions for target.
    """
    src_map = {k.lower(): (k, v) for k, v in source_tables.items()}
    tgt_map = {k.lower(): (k, v) for k, v in target_tables.items()}

    missing_tables_in_target: List[str] = []
    extra_tables_in_target: List[str] = []
    table_diffs: List[Dict[str, Any]] = []
    suggested_ddl: List[str] = []
    reverse_rollback_ddl: List[str] = []

    for low_t, (src_tname, src_meta) in sorted(src_map.items()):
        if low_t not in tgt_map:
            missing_tables_in_target.append(src_tname)
            cols = src_meta.get("columns") or []
            pks = src_meta.get("primaryKeys") or []
            col_defs = [_format_col_definition(c, target_dialect) for c in cols]
            if pks:
                pk_quoted = ", ".join(quote_ident(p, target_dialect) for p in pks)
                col_defs.append(f"PRIMARY KEY ({pk_quoted})")
            qt = quote_ident(src_tname, target_dialect)
            body = ",\n  ".join(col_defs)
            suggested_ddl.append(f"CREATE TABLE {qt} (\n  {body}\n);")
            reverse_rollback_ddl.append(f"-- Reverse for new table {src_tname}: DROP TABLE {qt};")
            continue

        tgt_tname, tgt_meta = tgt_map[low_t]
        src_cols = {c["name"].lower(): c for c in (src_meta.get("columns") or [])}
        tgt_cols = {c["name"].lower(): c for c in (tgt_meta.get("columns") or [])}

        missing_cols: List[Dict[str, Any]] = []
        extra_cols: List[str] = []
        mismatched_cols: List[Dict[str, Any]] = []

        qt = quote_ident(tgt_tname, target_dialect)

        for low_c, scol in src_cols.items():
            if low_c not in tgt_cols:
                missing_cols.append(scol)
                col_def = _format_col_definition(scol, target_dialect)
                if target_dialect == "oracle":
                    suggested_ddl.append(f"ALTER TABLE {qt} ADD ({col_def});")
                elif target_dialect == "mssql":
                    suggested_ddl.append(f"ALTER TABLE {qt} ADD {col_def};")
                else:
                    suggested_ddl.append(f"ALTER TABLE {qt} ADD COLUMN {col_def};")
                qc = quote_ident(scol["name"], target_dialect)
                reverse_rollback_ddl.append(f"ALTER TABLE {qt} DROP COLUMN {qc};")
            else:
                tcol = tgt_cols[low_c]
                s_type = str(scol.get("type") or "").upper()
                t_type = str(tcol.get("type") or "").upper()
                s_size = int(scol.get("size") or 0)
                t_size = int(tcol.get("size") or 0)
                s_null = bool(scol.get("nullable", True))
                t_null = bool(tcol.get("nullable", True))

                if s_type != t_type or s_size != t_size or s_null != t_null:
                    mismatched_cols.append(
                        {
                            "column": scol["name"],
                            "source": {"type": s_type, "size": s_size, "nullable": s_null},
                            "target": {"type": t_type, "size": t_size, "nullable": t_null},
                        }
                    )

        for low_c, tcol in tgt_cols.items():
            if low_c not in src_cols:
                extra_cols.append(tcol["name"])

        src_pks = sorted(p.lower() for p in (src_meta.get("primaryKeys") or []))
        tgt_pks = sorted(p.lower() for p in (tgt_meta.get("primaryKeys") or []))
        pk_mismatch = (src_pks != tgt_pks)

        if missing_cols or extra_cols or mismatched_cols or pk_mismatch:
            table_diffs.append(
                {
                    "table": tgt_tname,
                    "missing_columns_in_target": missing_cols,
                    "extra_columns_in_target": extra_cols,
                    "column_definition_mismatches": mismatched_cols,
                    "primary_key_mismatch": (
                        {"source": src_meta.get("primaryKeys"), "target": tgt_meta.get("primaryKeys")}
                        if pk_mismatch
                        else None
                    ),
                }
            )

    for low_t, (tgt_tname, _) in sorted(tgt_map.items()):
        if low_t not in src_map:
            extra_tables_in_target.append(tgt_tname)

    identical = (
        not missing_tables_in_target
        and not extra_tables_in_target
        and not table_diffs
    )

    return {
        "identical": identical,
        "source_table_count": len(source_tables),
        "target_table_count": len(target_tables),
        "missing_tables_in_target": missing_tables_in_target,
        "extra_tables_in_target": extra_tables_in_target,
        "table_diffs": table_diffs,
        "suggested_sync_ddl": suggested_ddl,
        "reverse_rollback_ddl": reverse_rollback_ddl,
    }
