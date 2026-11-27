# Security Architecture & Threat Model

`copilot-dbeaver-mcp` is designed for engineering teams that want AI coding agents (GitHub Copilot, Cursor, Claude Code, etc.) to diagnose bad database records and assist with safe data remediation **without risking accidental data destruction, production table locks, or PII leakage to cloud LLMs**.

---

## 1. Threat Model

| Threat | How Naive DB MCP Servers Fail | How `copilot-dbeaver-mcp` Mitigates It |
| :--- | :--- | :--- |
| **Plaintext Password Exposure** | Requiring plaintext DSNs in `.mcp.json` or repo config files, or exposing credentials to LLM tool outputs | Zero-password config: decrypts DBeaver's `credentials-config.json` **strictly inside local JVM heap memory** (`JdbcBridge`). Credentials are never written to disk, logs, Python dicts, or MCP responses. |
| **Read-Only Bypass / Stacked SQL Injection** | Relying solely on regex keyword checks while leaving `allowMultiQueries=true` or writable CTEs open | **Triple Lock**: ① Lexer strips comments/literals, blocks `;`, MySQL `/*!...*/`, writable `WITH` CTEs, `INTO OUTFILE`, `LOAD_FILE`, `FOR UPDATE`; ② JDBC URL forces `allowMultiQueries=false`; ③ Database session executes `Connection.setReadOnly(true)` + `SET SESSION TRANSACTION READ ONLY` (`SET TRANSACTION READ ONLY` on Oracle) and always calls `conn.rollback()` in `finally`. |
| **Runaway Unbounded Updates / Deletes** | Exposing a raw `execute_sql` write tool where an LLM hallucination runs `UPDATE t SET ...` without `WHERE` | **AST & Row-Count Circuit Breaker**: Blocks `DROP / TRUNCATE / ALTER`; requires explicit column equality/IN `WHERE` (blocks `1=1` tautologies); aborts & rolls back if matched rows exceed `max_write_rows` (default `20`) or differ from `expected_affected_rows`. |
| **Irreversible Data Loss** | Executing `UPDATE` / `DELETE` without capturing original row values first | **Fail-Closed "No Backup, No Modification"**: Both `apply_remediation` and `open_remediation_in_dbeaver` first capture unmasked original rows in a dry-run transaction, verify `backup_record.json` + `before_rows_insert.sql` + `rollback.sql` are persisted on disk, and record chronological entries in `change-logs/`. |
| **Cloud LLM PII Exfiltration** | Sending raw citizen IDs, names, phone numbers, emails, and password hashes into cloud LLM prompts | **Structural Dynamic PII Masking**: Automatically masks sensitive column names and regex patterns (`C***h [MASKED:PII len=12 trail_ws=2]`), hiding real PII while preserving `NULL` vs `""`, string length, and leading/trailing whitespace anomalies needed to debug bad data. |
| **DBeaver Auto-Commit Traps** | DBeaver's `dev` connection profile defaults to `auto-commit: true` | Generated DBeaver `.sql` scripts explicitly inject `SET autocommit = 0; START TRANSACTION;` and end with `ROLLBACK;` by default so human reviewers inspect post-DML rows before manually running `COMMIT;`. |

---

## 2. Defense-in-Depth Recommendation for Production Databases

While `copilot-dbeaver-mcp` enforces session-level `READ ONLY` transactions and blocks direct writes on non-allowlisted connections, database engine permissions remain the ultimate security boundary. For production environments, we strongly recommend configuring a dedicated read-only database user in DBeaver (`GRANT SELECT, SHOW VIEW`) and keeping production connection names out of `allow_direct_apply_connections`.
