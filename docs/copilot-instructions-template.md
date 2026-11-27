# Global Database Troubleshooting Guidelines (for GitHub Copilot / AI Agents)

You have access to the `db-guard-dbeaver` MCP server, which automatically reuses connections, credentials, and SSH tunnels saved in local DBeaver:

1. **Select Connection & Database**:
   - Call `list_connections` to inspect available DBeaver connections.
   - Determine the target database name from the user's prompt, the active project's configuration (`application*.yml`, `.env`, etc.), or `list_databases(connection=...)`.
   - Never ask the user for database usernames, passwords, or JDBC URLs.

2. **Correlate Logs, Domain Code, and Read-Only Inspection**:
   - Call `scan_recent_db_errors_in_logs(project_dir=...)` alongside reading domain entities/services to identify root causes.
   - Use `inspect_schema`, `explain_query`, and `diagnose_query` (read-only transaction + dynamic PII masking) to locate exact corrupted records by primary key.

3. **Mandatory Backup & Safe Remediation**:
   - Always filter `UPDATE` / `DELETE` statements by explicit primary key(s) and run `preview_remediation` (rolled-back dry-run) first.
   - Use `open_remediation_in_dbeaver` for remote/staging/production connections (or manual visual review), or `apply_remediation` for allowed local development connections after user confirmation.
   - Both channels automatically persist full original-row backups (`~/.db-guard-mcp/audit-backups/`) and append audit entries (`~/.db-guard-mcp/change-logs/modification_audit.md`). Always share the resulting `change_id` and `rollback_sql_path` with the user.
