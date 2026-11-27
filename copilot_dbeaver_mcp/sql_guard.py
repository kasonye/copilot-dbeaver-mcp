"""
SQL AST/Lexer Guardrails & Structural PII Dynamic Masking for copilot-dbeaver-mcp.

Defense-in-depth layer complementing database account grants and JDBC wire-protocol
read-only / single-statement isolation.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

READONLY_START_KEYWORDS = {"SELECT", "WITH", "SHOW", "DESCRIBE", "DESC", "EXPLAIN"}

FORBIDDEN_IN_READONLY = {
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "TRUNCATE",
    "ALTER",
    "CREATE",
    "REPLACE",
    "MERGE",
    "GRANT",
    "REVOKE",
    "CALL",
    "EXEC",
    "EXECUTE",
    "RENAME",
    "LOAD",
    "HANDLER",
    "SET",
    "LOCK",
    "UNLOCK",
    "COMMIT",
    "ROLLBACK",
    "START",
    "BEGIN",
}

FORBIDDEN_READONLY_PATTERNS = [
    (re.compile(r"\bINTO\s+(OUTFILE|DUMPFILE)\b", re.IGNORECASE), "INTO OUTFILE/DUMPFILE file write is forbidden"),
    (re.compile(r"\bFOR\s+UPDATE\b", re.IGNORECASE), "Locking SELECT ... FOR UPDATE is forbidden in diagnostics"),
    (re.compile(r"\bLOCK\s+IN\s+SHARE\s+MODE\b", re.IGNORECASE), "Locking read is forbidden in diagnostics"),
    (re.compile(r"\b(LOAD_FILE|PG_READ_FILE|PG_READ_BINARY_FILE|LO_IMPORT|LO_EXPORT)\s*\(", re.IGNORECASE), "Filesystem SQL function is forbidden"),
    (re.compile(r"\b(SLEEP|BENCHMARK|PG_SLEEP|DBMS_LOCK\.SLEEP)\s*\(", re.IGNORECASE), "Delay/DoS function is forbidden"),
    (re.compile(r"\b(UTL_FILE|UTL_HTTP|UTL_TCP|DBMS_SCHEDULER|DBMS_SQL)\b", re.IGNORECASE), "Privileged Oracle package is forbidden"),
]

FORBIDDEN_IN_DML = {
    "DROP",
    "TRUNCATE",
    "ALTER",
    "CREATE",
    "RENAME",
    "GRANT",
    "REVOKE",
    "CALL",
    "EXEC",
    "EXECUTE",
    "LOAD",
    "REPLACE",
    "MERGE",
}

# Safe technical column names that end with _name or similar and should NOT be PII-masked
SAFE_TECHNICAL_COLUMNS = {
    "table_name",
    "column_name",
    "type_name",
    "status_name",
    "state_name",
    "role_name",
    "group_name",
    "dept_name",
    "department_name",
    "unit_name",
    "division_name",
    "file_name",
    "filename",
    "doc_type_name",
    "module_name",
    "class_name",
    "method_name",
    "service_name",
    "constraint_name",
    "index_name",
    "schema_name",
    "db_name",
    "database_name",
    "enum_name",
    "code_name",
    "category_name",
    "config_name",
    "param_name",
    "job_name",
    "queue_name",
    "event_name",
    "action_name",
    "menu_name",
    "permission_name",
    "template_name",
    "step_name",
    "stage_name",
    "node_name",
    "task_name",
}

DEFAULT_SENSITIVE_COLUMN_PATTERNS = [
    r"(^|_)(national_id|hkid|id_card|idcard|id_no|idno|nric|passport|ssn|tax_id|driver_license|cert_no|identity_no)($|_)",
    r"(^|_)(password|passwd|pwd|secret|token|access_token|refresh_token|api_key|apikey|private_key|salt|credential)($|_)",
    r"(^|_)(phone|mobile|tel|telephone|fax|contact_no)($|_)",
    r"(^|_)(email|e_mail|mail_addr)($|_)",
    r"(^|_)(address|home_addr|office_addr|residential_addr|street_addr)($|_)",
    r"(^|_)(bank_account|bank_acc|card_no|credit_card|iban|salary)($|_)",
    r"(^|_)(name|cname|ename|chinese_name|english_name|full_name|real_name|surname|given_name|first_name|last_name|person_name|customer_name|user_real_name|applicant_name)($|_)",
]

VALUE_PII_PATTERNS = [
    (re.compile(r"^[A-Z]{1,2}\d{6}\(?[0-9A]\)?$", re.IGNORECASE), "HKID_LIKE"),
    (re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$"), "EMAIL_LIKE"),
    (re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$"), "BCRYPT_HASH"),
]


def strip_comments_and_literals(sql: str) -> Tuple[str, List[str]]:
    """
    Lexes SQL and replaces comments with a single space and string literals with 'STR',
    while rejecting dangerous MySQL executable comments (/*! ... */).
    Returns (normalized_sql_without_literals, issues).
    """
    issues: List[str] = []
    out: List[str] = []
    i = 0
    n = len(sql)

    while i < n:
        ch = sql[i]

        # MySQL executable comments /*! ... */ or /*!50000 ... */
        if ch == "/" and i + 2 < n and sql[i + 1] == "*" and sql[i + 2] == "!":
            issues.append("Executable MySQL comments (/*! ... */) are prohibited.")
            end = sql.find("*/", i + 3)
            i = n if end == -1 else end + 2
            out.append(" ")
            continue

        # Block comment /* ... */
        if ch == "/" and i + 1 < n and sql[i + 1] == "*":
            end = sql.find("*/", i + 2)
            if end == -1:
                issues.append("Unclosed block comment /* in SQL.")
                break
            i = end + 2
            out.append(" ")
            continue

        # Line comment --
        if ch == "-" and i + 1 < n and sql[i + 1] == "-":
            end = sql.find("\n", i + 2)
            i = n if end == -1 else end + 1
            out.append(" ")
            continue

        # MySQL # line comment
        if ch == "#":
            end = sql.find("\n", i + 1)
            i = n if end == -1 else end + 1
            out.append(" ")
            continue

        # Single-quoted string literal
        if ch == "'":
            i += 1
            closed = False
            while i < n:
                c = sql[i]
                if c == "\\":
                    i += 2
                    continue
                if c == "'" and i + 1 < n and sql[i + 1] == "'":
                    i += 2
                    continue
                if c == "'":
                    i += 1
                    closed = True
                    break
                i += 1
            if not closed:
                issues.append("Unclosed single-quoted literal in SQL.")
            out.append("'S'")
            continue

        # Double-quoted identifier / literal
        if ch == '"':
            i += 1
            closed = False
            while i < n:
                c = sql[i]
                if c == "\\":
                    i += 2
                    continue
                if c == '"' and i + 1 < n and sql[i + 1] == '"':
                    i += 2
                    continue
                if c == '"':
                    i += 1
                    closed = True
                    break
                i += 1
            if not closed:
                issues.append("Unclosed double-quoted token in SQL.")
            out.append("IDENT")
            continue

        # Backtick quoted identifier
        if ch == "`":
            end = sql.find("`", i + 1)
            if end == -1:
                issues.append("Unclosed backtick identifier in SQL.")
                break
            # Keep identifier inner text if safe alphanumeric/underscore so column checks work
            ident = sql[i + 1 : end]
            out.append(ident if re.match(r"^[A-Za-z0-9_]+$", ident) else "IDENT")
            i = end + 1
            continue

        out.append(ch)
        i += 1

    return "".join(out), issues


def clean_single_statement(sql: str) -> Tuple[str, Optional[str]]:
    """Strips optional single trailing semicolon and rejects multi-statement SQL."""
    if not sql or not sql.strip():
        return "", "SQL statement cannot be empty."
    trimmed = sql.strip()
    while trimmed.endswith(";"):
        trimmed = trimmed[:-1].strip()
    norm, issues = strip_comments_and_literals(trimmed)
    if issues:
        return "", "; ".join(issues)
    if ";" in norm:
        return "", "Multi-statement SQL (semicolon-separated queries) is strictly prohibited."
    return trimmed, None


def validate_readonly_sql(sql: str) -> Tuple[str, Optional[str]]:
    """Validates that a query is strictly read-only and free of side-effect constructs."""
    cleaned, err = clean_single_statement(sql)
    if err:
        return "", err

    norm, issues = strip_comments_and_literals(cleaned)
    if issues:
        return "", "; ".join(issues)

    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_.]*", norm)
    if not tokens:
        return "", "No valid SQL keywords found."

    first = tokens[0].upper()
    if first not in READONLY_START_KEYWORDS:
        return "", f"Read-only channel only allows {sorted(READONLY_START_KEYWORDS)}, got '{first}'."

    # Allow read-only metadata commands like SHOW CREATE TABLE / VIEW / FUNCTION / GRANTS
    check_tokens = list(tokens)
    if (
        len(check_tokens) >= 2
        and check_tokens[0].upper() == "SHOW"
        and check_tokens[1].upper() in {"CREATE", "GRANTS"}
    ):
        check_tokens = [check_tokens[0], *check_tokens[2:]]

    upper_tokens = {t.upper() for t in check_tokens}
    bad_keywords = upper_tokens.intersection(FORBIDDEN_IN_READONLY)
    if bad_keywords:
        return "", f"Forbidden write/control keyword(s) in read-only query: {sorted(bad_keywords)}."

    for pattern, msg in FORBIDDEN_READONLY_PATTERNS:
        if pattern.search(norm):
            return "", msg

    return cleaned, None


def validate_identifier(name: str, kind: str = "identifier") -> Optional[str]:
    if not name or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$", name):
        return f"Invalid {kind} '{name}'. Use plain table/schema.table identifier."
    return None


def validate_where_clause(where_clause: str) -> Tuple[str, Optional[str]]:
    """Ensures a WHERE clause is present, single-statement, and NOT a trivial tautology like 1=1."""
    if not where_clause or not where_clause.strip():
        return "", "where_clause is mandatory for controlled remediation."
    cleaned = where_clause.strip()
    if re.match(r"^WHERE\b", cleaned, re.IGNORECASE):
        cleaned = cleaned[5:].strip()
    cleaned, err = clean_single_statement(cleaned)
    if err:
        return "", f"Invalid where_clause: {err}"

    norm, issues = strip_comments_and_literals(cleaned)
    if issues:
        return "", "; ".join(issues)

    # Block subquery mutations or comments tricks
    tokens = {t.upper() for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", norm)}
    if tokens.intersection(FORBIDDEN_IN_READONLY):
        return "", "where_clause contains forbidden keywords."

    # Reject trivial tautologies like 1=1, true, 'S'='S'
    compact = re.sub(r"\s+", "", norm).upper()
    if compact in {"1=1", "TRUE", "'S'='S'", "IDENT=IDENT", "(1=1)", "(TRUE)"}:
        return "", "Tautology where_clause (e.g., 1=1 or TRUE) is prohibited."
    if re.search(r"\bOR\s+(1\s*=\s*1|TRUE|'S'\s*=\s*'S')\b", norm, re.IGNORECASE):
        return "", "Tautology OR condition in where_clause is prohibited."

    # Require at least one column identifier + equality / IN comparison
    has_col_eq = bool(
        re.search(r"\b[A-Za-z_][A-Za-z0-9_.]*\s*(=|\bIN\s*\()", norm, re.IGNORECASE)
    )
    if not has_col_eq:
        return (
            "",
            "Remediation where_clause must filter on at least one explicit column equality (=) or IN (...) condition (preferably primary key).",
        )

    return cleaned, None


def validate_remediation_sql(table: str, where_clause: str, dml_sql: str) -> Tuple[str, str, Optional[str]]:
    """
    Validates a controlled remediation DML statement (UPDATE / DELETE / INSERT)
    and constructs the paired pre/post inspection SELECT statement.
    Returns (select_sql, cleaned_dml, error_msg).
    """
    id_err = validate_identifier(table, "table")
    if id_err:
        return "", "", id_err

    clean_where, w_err = validate_where_clause(where_clause)
    if w_err:
        return "", "", w_err

    clean_dml, d_err = clean_single_statement(dml_sql)
    if d_err:
        return "", "", d_err

    norm, issues = strip_comments_and_literals(clean_dml)
    if issues:
        return "", "", "; ".join(issues)

    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_.]*", norm)
    if not tokens:
        return "", "", "Invalid DML statement."

    verb = tokens[0].upper()
    if verb not in {"UPDATE", "DELETE", "INSERT"}:
        return "", "", f"Controlled remediation only permits UPDATE, DELETE, or INSERT (got '{verb}')."

    upper_tokens = {t.upper() for t in tokens}
    bad = upper_tokens.intersection(FORBIDDEN_IN_DML)
    if bad:
        return "", "", f"Forbidden destructive/DDL keyword(s) in remediation SQL: {sorted(bad)}."

    # Verify target table matches declared table
    short_table = table.split(".")[-1].lower()
    lower_tokens = [t.lower() for t in tokens]
    if short_table not in lower_tokens:
        return "", "", f"DML statement must explicitly target declared table '{table}'."

    if verb in {"UPDATE", "DELETE"}:
        if "WHERE" not in upper_tokens:
            return "", "", f"{verb} without an explicit WHERE clause is strictly prohibited."
        # Ensure the DML's WHERE condition matches the declared where_clause
        m = re.search(r"\bWHERE\b(.*)$", clean_dml, flags=re.IGNORECASE | re.DOTALL)
        if not m:
            return "", "", f"Could not parse WHERE clause in {verb} statement."
        dml_where = m.group(1).strip()
        _, dw_err = validate_where_clause(dml_where)
        if dw_err:
            return "", "", f"DML WHERE clause failed safety validation: {dw_err}"

    select_sql = f"SELECT * FROM {table} WHERE {clean_where}"
    return select_sql, clean_dml, None


class DynamicDataMasker:
    """
    Masks PII / sensitive values before returning query results to cloud LLMs,
    while preserving length, NULL vs empty string, and whitespace anomalies
    so bad-data diagnostics remain 100% effective.
    """

    def __init__(
        self,
        enabled: bool = True,
        extra_column_patterns: Optional[Sequence[str]] = None,
        exempt_columns: Optional[Sequence[str]] = None,
    ) -> None:
        self.enabled = enabled
        patterns = list(DEFAULT_SENSITIVE_COLUMN_PATTERNS)
        if extra_column_patterns:
            patterns.extend(extra_column_patterns)
        self.col_regexes = [re.compile(p, re.IGNORECASE) for p in patterns]
        self.exempt = set(SAFE_TECHNICAL_COLUMNS)
        if exempt_columns:
            self.exempt.update(c.lower() for c in exempt_columns)

    def is_sensitive_column(self, col_name: str) -> bool:
        if not self.enabled or not col_name:
            return False
        raw = col_name.strip()
        # Normalize camelCase / PascalCase (e.g. mobilePhone -> mobile_phone, idCardNo -> id_card_no)
        snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", raw).lower()
        low = raw.lower()
        if low in self.exempt or snake in self.exempt:
            return False
        return any(rx.search(low) or rx.search(snake) for rx in self.col_regexes)

    def _mask_json_node(self, node: Any, parent_sensitive: bool = False) -> Tuple[Any, bool]:
        changed = False
        if isinstance(node, dict):
            out_dict: Dict[str, Any] = {}
            for k, v in node.items():
                key_sens = parent_sensitive or self.is_sensitive_column(str(k))
                masked_v, sub_changed = self._mask_json_node(v, parent_sensitive=key_sens)
                out_dict[k] = masked_v
                changed = changed or sub_changed
            return out_dict, changed
        if isinstance(node, list):
            out_list: List[Any] = []
            for item in node:
                masked_item, sub_changed = self._mask_json_node(item, parent_sensitive=parent_sensitive)
                out_list.append(masked_item)
                changed = changed or sub_changed
            return out_list, changed
        if isinstance(node, str):
            masked_str = self._mask_scalar_string(node, force_sensitive=parent_sensitive, tag="JSON_PII")
            return masked_str, (masked_str != node)
        if parent_sensitive and isinstance(node, (int, float)) and not isinstance(node, bool):
            s = str(node)
            if len(s) >= 6:
                return f"[MASKED:JSON_PII len={len(s)}]", True
        return node, False

    def _mask_scalar_string(self, s: str, force_sensitive: bool, tag: str = "PII") -> str:
        if s == "":
            return ""
        matched_tag = tag if force_sensitive else None
        if not matched_tag and self.enabled and len(s) <= 128:
            stripped_check = s.strip()
            for rx, vtag in VALUE_PII_PATTERNS:
                if rx.match(stripped_check):
                    matched_tag = vtag
                    break
        if not matched_tag:
            return s
        if s.strip() == "":
            return f"[WHITESPACE_ONLY len={len(s)}]"
        lead_ws = len(s) - len(s.lstrip())
        trail_ws = len(s) - len(s.rstrip())
        core = s.strip()
        preview = f"{core[0]}***{core[-1]}" if len(core) >= 3 else "***"
        ws_note = f" lead_ws={lead_ws} trail_ws={trail_ws}" if (lead_ws or trail_ws) else ""
        return f"{preview} [MASKED:{matched_tag} len={len(s)}{ws_note}]"

    def mask_value(self, val: Any, force_sensitive: bool, tag: str = "PII") -> Any:
        if val is None or isinstance(val, (int, float, bool)):
            return val
        s = str(val)
        if s == "":
            return ""

        # Check nested JSON objects/arrays in non-sensitive payload/ext columns
        if self.enabled and not force_sensitive and len(s) <= 32768:
            trimmed = s.strip()
            if (trimmed.startswith("{") and trimmed.endswith("}")) or (
                trimmed.startswith("[") and trimmed.endswith("]")
            ):
                try:
                    parsed = json.loads(trimmed)
                    if isinstance(parsed, (dict, list)):
                        masked_node, changed = self._mask_json_node(parsed, parent_sensitive=False)
                        if changed:
                            return json.dumps(masked_node, ensure_ascii=False)
                        return val
                except Exception:
                    pass

        return self._mask_scalar_string(s, force_sensitive=force_sensitive, tag=tag)

    def mask_rows(
        self, columns: Sequence[Dict[str, str]], rows: Sequence[Sequence[Any]]
    ) -> Tuple[List[List[Any]], List[str]]:
        if not self.enabled:
            return [list(r) for r in rows], []

        col_flags = [self.is_sensitive_column(c.get("name", "")) for c in columns]
        masked_cols = [
            columns[i].get("name", "") for i, flag in enumerate(col_flags) if flag
        ]
        out_rows: List[List[Any]] = []
        for row in rows:
            new_row: List[Any] = []
            for idx, val in enumerate(row):
                is_sens = col_flags[idx] if idx < len(col_flags) else False
                new_row.append(self.mask_value(val, force_sensitive=is_sens))
            out_rows.append(new_row)
        return out_rows, masked_cols


def infer_sql_dialect(jdbc_url: str = "", driver: str = "") -> str:
    """Infers SQL dialect ('mysql', 'postgres', 'oracle', 'mssql', 'sqlite', 'ansi') from JDBC URL or driver."""
    low = f"{jdbc_url} {driver}".lower()
    if any(k in low for k in ("jdbc:mysql:", "jdbc:mariadb:", "jdbc:clickhouse:", "jdbc:oceanbase:", "mode=mariadb", "mode=mysql")):
        return "mysql"
    if any(k in low for k in ("jdbc:postgresql:", "jdbc:gaussdb:", "jdbc:kingbase", "postgres", "gauss")):
        return "postgres"
    if any(k in low for k in ("jdbc:oracle:", "jdbc:dm:", "oracle", "dameng")):
        return "oracle"
    if any(k in low for k in ("jdbc:sqlserver:", "mssql", "sqlserver")):
        return "mssql"
    if "jdbc:sqlite:" in low or "sqlite" in low:
        return "sqlite"
    return "ansi"


def quote_ident(name: str, dialect: str = "mysql") -> str:
    """Quotes a column or short identifier according to the target SQL dialect."""
    if dialect == "mysql":
        return f"`{name.replace('`', '``')}`"
    if dialect == "mssql":
        return f"[{name.replace(']', ']]')}]"
    escaped = name.replace('"', '""')
    return f'"{escaped}"'


def use_database_sql(database: str, dialect: str = "mysql") -> str:
    if not database or not re.match(r"^[A-Za-z0-9_$-]+$", database):
        return ""
    if dialect == "mysql":
        return f"USE `{database}`;\n"
    if dialect == "mssql":
        return f"USE [{database}];\n"
    if dialect == "postgres":
        return f'SET search_path TO "{database}";\n'
    if dialect == "oracle":
        return f'ALTER SESSION SET CURRENT_SCHEMA = "{database.upper()}";\n'
    return ""


def begin_transaction_header(dialect: str = "mysql") -> List[str]:
    if dialect == "mysql":
        return ["SET autocommit = 0;", "START TRANSACTION;"]
    if dialect == "postgres":
        return ["BEGIN;"]
    if dialect == "mssql":
        return ["BEGIN TRANSACTION;"]
    if dialect == "sqlite":
        return ["BEGIN TRANSACTION;"]
    if dialect == "oracle":
        return ["-- Oracle starts transaction implicitly on first DML (disable Auto-Commit in client)"]
    return ["START TRANSACTION;"]


def sql_literal(val: Any, dialect: str = "mysql") -> str:
    """Formats a value safely for generated reverse/rollback SQL scripts across SQL dialects."""
    if val is None:
        return "NULL"
    if isinstance(val, bool):
        if dialect in {"postgres", "ansi"}:
            return "TRUE" if val else "FALSE"
        return "1" if val else "0"
    if isinstance(val, (int, float)):
        return str(val)
    s = str(val).replace("'", "''")
    if dialect == "mysql":
        s = s.replace("\\", "\\\\")
    return f"'{s}'"


def build_insert_backup_sql(
    table: str,
    columns: Sequence[Dict[str, str]],
    rows: Sequence[Sequence[Any]],
    database: str = "",
    dialect: str = "mysql",
) -> str:
    """Generates standalone raw INSERT backup SQL for all pre-modification rows."""
    use_prefix = use_database_sql(database, dialect)
    if not rows or not columns:
        return f"{use_prefix}-- No pre-existing rows existed prior to modification (e.g. INSERT operation)."

    col_names = [c["name"] for c in columns]
    cols_quoted = ", ".join(quote_ident(c, dialect) for c in col_names)
    lines = [
        f"-- Pre-modification full row backup for {table} ({len(rows)} row(s), dialect={dialect})",
        use_prefix.rstrip("\n") if use_prefix else "-- (default database)",
    ]
    for row in rows:
        vals_sql = ", ".join(sql_literal(v, dialect) for v in row)
        lines.append(f"INSERT INTO {table} ({cols_quoted}) VALUES ({vals_sql});")
    return "\n".join(lines)


def build_rollback_sql(
    table: str,
    columns: Sequence[Dict[str, str]],
    before_rows: Sequence[Sequence[Any]],
    after_rows: Optional[Sequence[Sequence[Any]]] = None,
    primary_keys: Optional[Sequence[str]] = None,
    dml_verb: str = "UPDATE",
    where_clause: str = "",
    database: str = "",
    dialect: str = "mysql",
) -> str:
    """
    Generates a complete, dialect-aware, transaction-wrapped executable reverse/rollback SQL script
    for UPDATE, DELETE, or INSERT operations.
    """
    verb = (dml_verb or "UPDATE").upper()
    col_names = [c["name"] for c in columns] if columns else []
    pk_list = [pk for pk in (primary_keys or []) if pk in col_names]
    if not pk_list and col_names:
        for candidate in ("id", "ID", f"{table.split('.')[-1]}_id"):
            if candidate in col_names:
                pk_list = [candidate]
                break

    use_stmt = use_database_sql(database, dialect)
    stmts: List[str] = [f"-- Auto-generated executable rollback script for {verb} on {table} (dialect={dialect})"]
    if use_stmt:
        stmts.append(use_stmt.rstrip("\n"))
    stmts.extend(begin_transaction_header(dialect))

    if verb == "DELETE":
        if not before_rows or not col_names:
            stmts.append("-- No deleted rows captured.")
        else:
            cols_quoted = ", ".join(quote_ident(c, dialect) for c in col_names)
            for row in before_rows:
                vals_sql = ", ".join(sql_literal(v, dialect) for v in row)
                stmts.append(f"INSERT INTO {table} ({cols_quoted}) VALUES ({vals_sql});")

    elif verb == "INSERT":
        target_rows = after_rows or []
        if target_rows and col_names and pk_list:
            for row in target_rows:
                row_map = dict(zip(col_names, row))
                where_parts = [
                    f"{quote_ident(pk, dialect)} = {sql_literal(row_map[pk], dialect)}"
                    if row_map[pk] is not None
                    else f"{quote_ident(pk, dialect)} IS NULL"
                    for pk in pk_list
                ]
                stmts.append(f"DELETE FROM {table} WHERE {' AND '.join(where_parts)};")
        elif where_clause:
            stmts.append(f"DELETE FROM {table} WHERE {where_clause};")
        else:
            stmts.append("-- Identify inserted primary key(s) before running DELETE.")

    else:  # UPDATE
        if not before_rows or not col_names:
            stmts.append("-- No pre-existing rows captured.")
        else:
            for row in before_rows:
                row_map = dict(zip(col_names, row))
                if pk_list:
                    set_parts = [
                        f"{quote_ident(c, dialect)} = {sql_literal(row_map[c], dialect)}"
                        for c in col_names
                        if c not in pk_list
                    ]
                    where_parts = [
                        f"{quote_ident(pk, dialect)} = {sql_literal(row_map[pk], dialect)}"
                        for pk in pk_list
                    ]
                    if set_parts:
                        stmts.append(
                            f"UPDATE {table} SET {', '.join(set_parts)} WHERE {' AND '.join(where_parts)};"
                        )
                else:
                    set_parts = [
                        f"{quote_ident(c, dialect)} = {sql_literal(row_map[c], dialect)}"
                        for c in col_names
                    ]
                    cond = where_clause or "1=0"
                    stmts.append(f"UPDATE {table} SET {', '.join(set_parts)} WHERE {cond};")

    stmts.append("-- Verify restored rows before committing:")
    if where_clause:
        stmts.append(f"SELECT * FROM {table} WHERE {where_clause};")
    stmts.append("COMMIT;")
    return "\n".join(stmts)


ALLOWED_DDL_PATTERNS = [
    re.compile(r"^\s*CREATE\s+TABLE\b", re.IGNORECASE),
    re.compile(r"^\s*ALTER\s+TABLE\b", re.IGNORECASE),
    re.compile(r"^\s*CREATE\s+(UNIQUE\s+|FULLTEXT\s+|SPATIAL\s+)?INDEX\b", re.IGNORECASE),
    re.compile(r"^\s*DROP\s+INDEX\b", re.IGNORECASE),
    re.compile(r"^\s*CREATE\s+(OR\s+REPLACE\s+)?VIEW\b", re.IGNORECASE),
    re.compile(r"^\s*COMMENT\s+ON\s+(TABLE|COLUMN)\b", re.IGNORECASE),
]

FORBIDDEN_CATASTROPHIC_DDL = [
    (re.compile(r"\bDROP\s+(DATABASE|SCHEMA|TABLE|USER|ROLE)\b", re.IGNORECASE), "Catastrophic DROP (DATABASE/SCHEMA/TABLE/USER) is strictly prohibited."),
    (re.compile(r"\bTRUNCATE\b", re.IGNORECASE), "TRUNCATE is strictly prohibited in DDL migrations."),
    (re.compile(r"\b(GRANT|REVOKE)\b", re.IGNORECASE), "Privilege GRANT/REVOKE statements are prohibited."),
]


def split_sql_statements_safe(script: str) -> Tuple[List[str], Optional[str]]:
    """
    Splits a multi-statement DDL migration script on top-level semicolons outside
    quotes and comments, validating no unclosed comments or executable /*! ... */ comments exist.
    """
    if not script or not script.strip():
        return [], "DDL SQL script cannot be empty."

    _, issues = strip_comments_and_literals(script)
    if issues:
        return [], "; ".join(issues)

    statements: List[str] = []
    cur: List[str] = []
    i = 0
    n = len(script)

    while i < n:
        ch = script[i]
        if ch == "/" and i + 1 < n and script[i + 1] == "*":
            end = script.find("*/", i + 2)
            cur.append(script[i : (n if end == -1 else end + 2)])
            i = n if end == -1 else end + 2
            continue
        if ch == "-" and i + 1 < n and script[i + 1] == "-":
            end = script.find("\n", i + 2)
            cur.append(script[i : (n if end == -1 else end + 1)])
            i = n if end == -1 else end + 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            cur.append(ch)
            i += 1
            while i < n:
                c = script[i]
                cur.append(c)
                if c == "\\" and quote != "`" and i + 1 < n:
                    i += 1
                    cur.append(script[i])
                    i += 1
                    continue
                if c == quote and i + 1 < n and script[i + 1] == quote and quote != "`":
                    i += 1
                    cur.append(script[i])
                    i += 1
                    continue
                if c == quote:
                    i += 1
                    break
                i += 1
            continue
        if ch == ";":
            stmt = "".join(cur).strip()
            if stmt:
                # Ignore comment-only chunks
                norm_chunk, _ = strip_comments_and_literals(stmt)
                if norm_chunk.strip():
                    statements.append(stmt)
            cur = []
            i += 1
            continue

        cur.append(ch)
        i += 1

    tail = "".join(cur).strip()
    if tail:
        norm_tail, _ = strip_comments_and_literals(tail)
        if norm_tail.strip():
            statements.append(tail)

    if not statements:
        return [], "No executable DDL statements found."
    return statements, None


def validate_ddl_migration_sql(ddl_sql: str) -> Tuple[List[str], List[str], Optional[str]]:
    """
    Validates a forward DDL migration script for open_ddl_migration_in_dbeaver.
    Allows CREATE TABLE, ALTER TABLE, CREATE/DROP INDEX, CREATE VIEW, COMMENT ON.
    Blocks catastrophic DROP TABLE/DATABASE/SCHEMA, TRUNCATE, GRANT/REVOKE, and DML mutations.
    Returns (cleaned_statements, risk_warnings, error_msg).
    """
    stmts, err = split_sql_statements_safe(ddl_sql)
    if err:
        return [], [], err

    warnings: List[str] = []
    for st in stmts:
        norm, issues = strip_comments_and_literals(st)
        if issues:
            return [], [], "; ".join(issues)
        norm_stripped = norm.strip()

        for rx, msg in FORBIDDEN_CATASTROPHIC_DDL:
            if rx.search(norm_stripped):
                return [], [], msg

        if not any(rx.match(norm_stripped) for rx in ALLOWED_DDL_PATTERNS):
            return (
                [],
                [],
                f"DDL statement not in allowed list (CREATE TABLE / ALTER TABLE / CREATE|DROP INDEX / CREATE VIEW / COMMENT ON): '{st[:80]}'",
            )

        if re.search(r"\bDROP\s+COLUMN\b", norm_stripped, re.IGNORECASE):
            warnings.append("HIGH RISK: ALTER TABLE ... DROP COLUMN detected — verify column data is no longer needed before executing.")
        if re.search(r"\bMODIFY\s+(COLUMN\s+)?|\bALTER\s+COLUMN\b|\bCHANGE\s+(COLUMN\s+)?", norm_stripped, re.IGNORECASE):
            warnings.append("CAUTION: Column type/definition change detected — verify existing values will not truncate.")

    return stmts, warnings, None


def build_seed_batch_sql(
    table: str,
    rows: Sequence[Dict[str, Any]],
    primary_keys: Sequence[str],
    max_seed_rows: int = 50,
    database: str = "",
    dialect: str = "mysql",
) -> Tuple[List[str], str, str, Optional[str]]:
    """
    Constructs parameterized-style safe INSERT statements from structured row dicts,
    plus a collision/verification SELECT query and a consolidated 1-click cleanup rollback.sql.
    Returns (insert_statements, verify_select_sql, cleanup_rollback_sql, error_msg).
    """
    id_err = validate_identifier(table, "table")
    if id_err:
        return [], "", "", id_err

    if not rows:
        return [], "", "", "rows list cannot be empty."
    if len(rows) > max_seed_rows:
        return [], "", "", f"Seed batch size ({len(rows)}) exceeds max_seed_rows ({max_seed_rows})."

    if not primary_keys:
        return (
            [],
            "",
            "",
            f"Table '{table}' has no detected primary key; cannot guarantee deterministic 1-click seed cleanup.",
        )

    first_cols = list(rows[0].keys())
    if not first_cols:
        return [], "", "", "Row objects cannot be empty."

    for col in first_cols:
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", str(col)):
            return [], "", "", f"Invalid column name '{col}' in seed rows."

    col_map_lower = {c.lower(): c for c in first_cols}
    resolved_pks: List[str] = []
    for pk in primary_keys:
        actual = col_map_lower.get(pk.lower())
        if not actual:
            return (
                [],
                "",
                "",
                f"Every seed row must explicitly specify primary key column '{pk}' so seeded test data can be tracked and cleaned up safely.",
            )
        resolved_pks.append(actual)

    cols_quoted = ", ".join(quote_ident(c, dialect) for c in first_cols)
    insert_stmts: List[str] = []
    pk_conditions: List[str] = []
    single_pk_vals: List[str] = []

    for idx, r in enumerate(rows):
        if set(r.keys()) != set(first_cols):
            return [], "", "", f"Row at index {idx} has inconsistent columns compared to row 0."
        for pk in resolved_pks:
            if r[pk] is None or str(r[pk]).strip() == "":
                return [], "", "", f"Primary key '{pk}' at row index {idx} cannot be NULL or empty."

        vals_sql = ", ".join(sql_literal(r[c], dialect) for c in first_cols)
        insert_stmts.append(f"INSERT INTO {table} ({cols_quoted}) VALUES ({vals_sql})")

        if len(resolved_pks) == 1:
            single_pk_vals.append(sql_literal(r[resolved_pks[0]], dialect))
        else:
            and_parts = [f"{quote_ident(pk, dialect)} = {sql_literal(r[pk], dialect)}" for pk in resolved_pks]
            pk_conditions.append("(" + " AND ".join(and_parts) + ")")

    if len(resolved_pks) == 1:
        where_clause = f"{quote_ident(resolved_pks[0], dialect)} IN ({', '.join(single_pk_vals)})"
    else:
        where_clause = " OR ".join(pk_conditions)

    verify_select_sql = f"SELECT * FROM {table} WHERE {where_clause}"
    use_stmt = use_database_sql(database, dialect)
    header = [f"-- Auto-generated 1-click cleanup script for {len(rows)} seeded dev test row(s) in {table} (dialect={dialect})"]
    if use_stmt:
        header.append(use_stmt.rstrip("\n"))
    header.extend(begin_transaction_header(dialect))
    cleanup_sql = "\n".join(
        [
            *header,
            f"DELETE FROM {table} WHERE {where_clause};",
            "-- Verify 0 test rows remain before committing:",
            f"SELECT COUNT(*) AS remaining_seed_rows FROM {table} WHERE {where_clause};",
            "COMMIT;",
        ]
    )
    return insert_stmts, verify_select_sql, cleanup_sql, None
