"""
Read-Only Database Lock-Wait, Deadlock & Uncommitted Long-Transaction Inspector.

Supports MySQL / MariaDB, PostgreSQL / GaussDB / KingbaseES, Oracle / Dameng,
SQL Server, H2, and SQLite. Never executes KILL or state-mutating commands.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List

from copilot_dbeaver_mcp.sql_guard import DynamicDataMasker


def inspect_locks_and_transactions(
    *,
    run_query_fn: Callable[[str, int], Dict[str, Any]],
    masker: DynamicDataMasker,
    dialect: str,
    jdbc_url: str,
) -> Dict[str, Any]:
    low_url = (jdbc_url or "").lower()
    sections: List[Dict[str, Any]] = []
    notes: List[str] = []

    def _try_collect(title: str, sql: str, limit: int = 50) -> bool:
        try:
            res = run_query_fn(sql, limit)
            cols = res.get("columns", [])
            rows_masked, _ = masker.mask_rows(cols, res.get("rows", []))
            sections.append(
                {
                    "section": title,
                    "row_count": len(rows_masked),
                    "columns": cols,
                    "rows": rows_masked,
                }
            )
            return True
        except Exception as exc:
            notes.append(f"{title} skipped/unavailable: {exc}")
            return False

    if "jdbc:h2:" in low_url:
        _try_collect(
            "active_h2_sessions_and_locks",
            "SELECT * FROM INFORMATION_SCHEMA.SESSIONS",
        )
    elif dialect == "mysql":
        _try_collect(
            "active_innodb_transactions",
            "SELECT trx_id, trx_state, trx_started, "
            "TIMESTAMPDIFF(SECOND, trx_started, NOW()) AS duration_sec, "
            "trx_mysql_thread_id, trx_tables_in_use, trx_tables_locked, "
            "trx_rows_locked, trx_rows_modified, trx_query "
            "FROM information_schema.innodb_trx ORDER BY trx_started ASC",
        )
        # Try MySQL 8+ performance_schema.data_lock_waits, fallback to MariaDB/MySQL 5.7 innodb_lock_waits
        ok_wait = _try_collect(
            "blocking_lock_waits",
            "SELECT r.trx_id AS waiting_trx_id, r.trx_mysql_thread_id AS waiting_thread, r.trx_query AS waiting_query, "
            "b.trx_id AS blocking_trx_id, b.trx_mysql_thread_id AS blocking_thread, b.trx_query AS blocking_query, "
            "TIMESTAMPDIFF(SECOND, b.trx_started, NOW()) AS blocking_tx_age_sec "
            "FROM performance_schema.data_lock_waits w "
            "JOIN information_schema.innodb_trx b ON b.trx_id = w.BLOCKING_ENGINE_TRANSACTION_ID "
            "JOIN information_schema.innodb_trx r ON r.trx_id = w.REQUESTING_ENGINE_TRANSACTION_ID",
        )
        if not ok_wait:
            _try_collect(
                "blocking_lock_waits_legacy",
                "SELECT r.trx_id AS waiting_trx_id, r.trx_mysql_thread_id AS waiting_thread, r.trx_query AS waiting_query, "
                "b.trx_id AS blocking_trx_id, b.trx_mysql_thread_id AS blocking_thread, b.trx_query AS blocking_query "
                "FROM information_schema.innodb_lock_waits w "
                "JOIN information_schema.innodb_trx b ON b.trx_id = w.blocking_trx_id "
                "JOIN information_schema.innodb_trx r ON r.trx_id = w.requesting_trx_id",
            )
    elif dialect == "postgres":
        _try_collect(
            "pg_active_transactions_and_blockers",
            "SELECT pid, usename, application_name, client_addr::text AS client_addr, state, "
            "wait_event_type, wait_event, "
            "EXTRACT(EPOCH FROM (now() - xact_start))::int AS xact_duration_sec, "
            "pg_blocking_pids(pid)::text AS blocking_pids, "
            "LEFT(query, 500) AS current_or_last_query "
            "FROM pg_stat_activity "
            "WHERE pid <> pg_backend_pid() AND (xact_start IS NOT NULL OR cardinality(pg_blocking_pids(pid)) > 0) "
            "ORDER BY xact_start ASC NULLS LAST",
        )
    elif dialect == "oracle":
        _try_collect(
            "oracle_blocking_and_locked_objects",
            "SELECT s.sid, s.serial#, s.username, s.program, s.status, "
            "s.blocking_session, s.seconds_in_wait, o.object_name, l.locked_mode "
            "FROM v$locked_object l "
            "JOIN v$session s ON l.session_id = s.sid "
            "JOIN all_objects o ON l.object_id = o.object_id "
            "ORDER BY s.seconds_in_wait DESC",
        )
    elif dialect == "mssql":
        _try_collect(
            "mssql_blocking_requests",
            "SELECT session_id, blocking_session_id, status, wait_type, wait_time, total_elapsed_time, command "
            "FROM sys.dm_exec_requests WHERE blocking_session_id > 0 OR open_transaction_count > 0",
        )
    else:
        notes.append(f"Engine '{dialect}' does not expose system lock tables (e.g. embedded SQLite file lock).")

    total_active = sum(s["row_count"] for s in sections)
    return {
        "dialect": dialect,
        "total_flagged_entries": total_active,
        "sections": sections,
        "diagnostic_notes": notes,
        "remediation_advice": (
            "If an idle session (e.g. an uncommitted DBeaver SQL Editor tab in 'idle in transaction' / 'RUNNING' state) "
            "is blocking other queries, commit or roll back that DBeaver tab first rather than killing connections blindly."
        ),
    }
