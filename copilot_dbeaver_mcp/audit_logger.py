"""
Mandatory Pre-Modification Data Backup & Append-Only Audit Trail Manager.

Guarantees "No Backup, No Modification" (fail-closed):
Every modification (whether direct commit via apply_remediation or handoff via
open_remediation_in_dbeaver) MUST first persist:
  1. audit-backups/<YYYY-MM-DD>/<ts>_<conn>_<db>_<table>/
       - backup_record.json       (full metadata + unmasked before_rows & after_rows)
       - before_rows_insert.sql   (raw INSERT statements of original rows)
       - rollback.sql             (ready-to-execute transaction-safe reverse SQL)
  2. change-logs/modification_audit.jsonl (machine-readable chronological ledger)
  3. change-logs/modification_audit.md    (human-readable Markdown change log)
"""

from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

try:
    from .sql_guard import DynamicDataMasker, build_insert_backup_sql, build_rollback_sql
except ImportError:
    from sql_guard import DynamicDataMasker, build_insert_backup_sql, build_rollback_sql


def _safe_slug(text: str, max_len: int = 32) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "_", (text or "").strip()).strip("_")
    return (cleaned[:max_len] or "item")


def compute_field_diffs(
    columns: Sequence[Dict[str, str]],
    before_rows: Sequence[Sequence[Any]],
    after_rows: Sequence[Sequence[Any]],
    pk_cols: Sequence[str],
) -> List[Dict[str, Any]]:
    col_names = [c["name"] for c in columns]
    if not before_rows or not after_rows or len(before_rows) != len(after_rows):
        return []

    diffs: List[Dict[str, Any]] = []
    for b_row, a_row in zip(before_rows, after_rows):
        b_map = dict(zip(col_names, b_row))
        a_map = dict(zip(col_names, a_row))
        pk_id = {pk: b_map.get(pk) for pk in pk_cols if pk in b_map} or {"row_0": b_row[0] if b_row else None}
        changed_cols: Dict[str, Dict[str, Any]] = {}
        for col in col_names:
            if b_map.get(col) != a_map.get(col):
                changed_cols[col] = {"before": b_map.get(col), "after": a_map.get(col)}
        if changed_cols:
            diffs.append({"key": pk_id, "changes": changed_cols})
    return diffs


class ModificationAuditor:
    def __init__(self, base_dir: Path, masker: DynamicDataMasker) -> None:
        self.base_dir = base_dir
        self.backup_root = base_dir / "audit-backups"
        self.log_root = base_dir / "change-logs"
        self.jsonl_log_path = self.log_root / "modification_audit.jsonl"
        self.md_log_path = self.log_root / "modification_audit.md"
        self.masker = masker

    def create_pre_modification_backup(
        self,
        *,
        channel: str,  # "DIRECT_COMMIT" or "DBEAVER_HANDOFF"
        connection: str,
        database: str,
        table: str,
        dml_verb: str,
        where_clause: str,
        select_sql: str,
        dml_sql: str,
        issue_summary: str,
        columns: Sequence[Dict[str, str]],
        primary_keys: Sequence[str],
        before_rows_unmasked: Sequence[Sequence[Any]],
        after_rows_unmasked: Sequence[Sequence[Any]],
        expected_affected_rows: int,
        dialect: str = "mysql",
    ) -> Dict[str, str]:
        """
        Persists full unmasked data backup + executable rollback SQL to disk and verifies
        non-empty files BEFORE any database commit or DBeaver handoff is allowed to proceed.
        """
        now = dt.datetime.now()
        date_folder = now.strftime("%Y-%m-%d")
        change_id = now.strftime("%Y%m%d_%H%M%S_%f")[:19]
        folder_name = (
            f"{change_id}_{_safe_slug(connection, 20)}_"
            f"{_safe_slug(database or 'default', 20)}_{_safe_slug(table, 28)}"
        )
        bundle_dir = self.backup_root / date_folder / folder_name
        bundle_dir.mkdir(parents=True, exist_ok=True)

        backup_json_path = bundle_dir / "backup_record.json"
        insert_sql_path = bundle_dir / "before_rows_insert.sql"
        rollback_sql_path = bundle_dir / "rollback.sql"

        insert_backup_sql = build_insert_backup_sql(
            table=table,
            columns=columns,
            rows=before_rows_unmasked,
            database=database,
            dialect=dialect,
        )
        rollback_sql = build_rollback_sql(
            table=table,
            columns=columns,
            before_rows=before_rows_unmasked,
            after_rows=after_rows_unmasked,
            primary_keys=primary_keys,
            dml_verb=dml_verb,
            where_clause=where_clause,
            database=database,
            dialect=dialect,
        )

        record_payload = {
            "change_id": change_id,
            "created_at": now.isoformat(timespec="seconds"),
            "channel": channel,
            "status": "BACKUP_CREATED_PENDING_COMMIT",
            "connection": connection,
            "database": database,
            "table": table,
            "dml_verb": dml_verb,
            "issue_summary": issue_summary,
            "where_clause": where_clause,
            "select_sql": select_sql,
            "dml_sql": dml_sql,
            "expected_affected_rows": expected_affected_rows,
            "primary_keys": list(primary_keys),
            "columns": list(columns),
            "before_rows_unmasked": [list(r) for r in before_rows_unmasked],
            "after_rows_preview_unmasked": [list(r) for r in after_rows_unmasked],
        }

        backup_json_path.write_text(
            json.dumps(record_payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        insert_sql_path.write_text(insert_backup_sql + "\n", encoding="utf-8")
        rollback_sql_path.write_text(rollback_sql + "\n", encoding="utf-8")

        # Strict fail-closed verification
        for p in (backup_json_path, insert_sql_path, rollback_sql_path):
            if not p.is_file() or p.stat().st_size == 0:
                raise RuntimeError(f"Mandatory pre-modification backup verification failed for {p}")

        return {
            "change_id": change_id,
            "bundle_dir": str(bundle_dir),
            "backup_json_path": str(backup_json_path),
            "insert_sql_path": str(insert_sql_path),
            "rollback_sql_path": str(rollback_sql_path),
            "rollback_sql_content": rollback_sql,
        }

    def record_audit_log(
        self,
        *,
        change_id: str,
        channel: str,
        status: str,  # "COMMITTED", "DBEAVER_SCRIPT_OPENED", "ABORTED_ROLLED_BACK"
        connection: str,
        database: str,
        table: str,
        dml_verb: str,
        where_clause: str,
        dml_sql: str,
        issue_summary: str,
        affected_rows: int,
        columns: Sequence[Dict[str, str]],
        primary_keys: Sequence[str],
        before_rows_unmasked: Sequence[Sequence[Any]],
        after_rows_unmasked: Sequence[Sequence[Any]],
        backup_paths: Dict[str, str],
        dbeaver_script_path: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> Dict[str, str]:
        """Updates backup_record.json status and appends to modification_audit.jsonl and .md."""
        now_iso = dt.datetime.now().isoformat(timespec="seconds")
        self.log_root.mkdir(parents=True, exist_ok=True)

        # Update status in backup_record.json if present
        bjson = Path(backup_paths["backup_json_path"])
        if bjson.is_file():
            try:
                data = json.loads(bjson.read_text(encoding="utf-8"))
                data["status"] = status
                data["finalized_at"] = now_iso
                data["actual_affected_rows"] = affected_rows
                if after_rows_unmasked:
                    data["after_rows_unmasked"] = [list(r) for r in after_rows_unmasked]
                if dbeaver_script_path:
                    data["dbeaver_script_path"] = dbeaver_script_path
                if error_message:
                    data["error_message"] = error_message
                bjson.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass

        masked_before, _ = self.masker.mask_rows(columns, before_rows_unmasked)
        masked_after, _ = self.masker.mask_rows(columns, after_rows_unmasked)
        masked_diffs = compute_field_diffs(columns, masked_before, masked_after, primary_keys)

        log_entry = {
            "change_id": change_id,
            "timestamp": now_iso,
            "channel": channel,
            "status": status,
            "connection": connection,
            "database": database,
            "table": table,
            "dml_verb": dml_verb,
            "issue_summary": issue_summary,
            "where_clause": where_clause,
            "dml_sql": dml_sql,
            "affected_rows": affected_rows,
            "field_diffs_masked": masked_diffs,
            "backup_bundle_dir": backup_paths["bundle_dir"],
            "backup_json_path": backup_paths["backup_json_path"],
            "before_rows_insert_sql": backup_paths["insert_sql_path"],
            "rollback_sql_path": backup_paths["rollback_sql_path"],
            "dbeaver_script_path": dbeaver_script_path,
            "error": error_message,
        }

        with open(self.jsonl_log_path, "a", encoding="utf-8") as jf:
            jf.write(json.dumps(log_entry, ensure_ascii=False) + "\n")

        if not self.md_log_path.is_file():
            self.md_log_path.write_text(
                "# 数据库修改与备份审计台账 (Copilot-DBeaver-MCP Audit Log)\n\n"
                "> 每次修改操作均已在执行前自动生成完整未脱敏原始行冷备与可执行逆向回滚 SQL。\n\n",
                encoding="utf-8",
            )

        diff_summary = (
            json.dumps(masked_diffs, ensure_ascii=False)
            if masked_diffs
            else f"(共备份原始记录 {len(before_rows_unmasked)} 行，详见备份 JSON)"
        )
        extra_line = (
            f"- **DBeaver 审核脚本**: `{dbeaver_script_path}`\n" if dbeaver_script_path else ""
        )
        err_line = f"- **异常/回滚说明**: `{error_message}`\n" if error_message else ""

        md_block = (
            f"## [{now_iso}] `{status}` — `{connection}`.`{database or '(default)'}`.`{table}` (ID: `{change_id}`)\n"
            f"- **修改原因**: {issue_summary}\n"
            f"- **执行通道**: `{channel}` | **操作类型**: `{dml_verb}` | **影响行数**: `{affected_rows}`\n"
            f"- **执行 SQL**: `{dml_sql}`\n"
            f"- **字段变更摘要 (已脱敏)**: `{diff_summary}`\n"
            f"- **完整原始数据备份**: `{backup_paths['backup_json_path']}`\n"
            f"- **原始行 INSERT 冷备**: `{backup_paths['insert_sql_path']}`\n"
            f"- **一键逆向回滚脚本**: `{backup_paths['rollback_sql_path']}`\n"
            f"{extra_line}{err_line}\n---\n\n"
        )
        with open(self.md_log_path, "a", encoding="utf-8") as mf:
            mf.write(md_block)

        return {
            "audit_jsonl_path": str(self.jsonl_log_path),
            "audit_markdown_path": str(self.md_log_path),
        }

    def list_history(self, limit: int = 20, table_filter: Optional[str] = None) -> Dict[str, Any]:
        if not self.jsonl_log_path.is_file():
            return {
                "audit_jsonl_path": str(self.jsonl_log_path),
                "audit_markdown_path": str(self.md_log_path),
                "total_entries": 0,
                "entries": [],
            }
        lines = self.jsonl_log_path.read_text(encoding="utf-8").splitlines()
        parsed = [json.loads(line) for line in lines if line.strip()]
        if table_filter:
            low = table_filter.lower()
            parsed = [e for e in parsed if low in str(e.get("table", "")).lower()]
        recent = list(reversed(parsed))[: max(1, min(limit, 100))]
        return {
            "audit_jsonl_path": str(self.jsonl_log_path),
            "audit_markdown_path": str(self.md_log_path),
            "total_entries": len(parsed),
            "entries": recent,
        }

    def find_entry_by_change_id(self, change_id: str) -> Optional[Dict[str, Any]]:
        if not self.jsonl_log_path.is_file():
            return None
        target = (change_id or "").strip()
        lines = self.jsonl_log_path.read_text(encoding="utf-8").splitlines()
        for line in reversed(lines):
            if not line.strip():
                continue
            entry = json.loads(line)
            if str(entry.get("change_id")) == target:
                return entry
        return None

    def record_ddl_migration_backup_and_log(
        self,
        *,
        connection: str,
        database: str,
        table: str,
        migration_title: str,
        ddl_sql: str,
        rollback_ddl_sql: str,
        existing_schema_snapshot: Dict[str, Any],
        warnings: Sequence[str],
    ) -> Dict[str, str]:
        """Persists pre-migration table DDL/column snapshot + reverse rollback DDL before opening DBeaver."""
        now = dt.datetime.now()
        date_folder = now.strftime("%Y-%m-%d")
        change_id = now.strftime("%Y%m%d_%H%M%S_%f")[:19]
        folder_name = (
            f"{change_id}_DDL_{_safe_slug(connection, 18)}_"
            f"{_safe_slug(database or 'default', 18)}_{_safe_slug(table, 24)}"
        )
        bundle_dir = self.backup_root / date_folder / folder_name
        bundle_dir.mkdir(parents=True, exist_ok=True)

        snapshot_json_path = bundle_dir / "before_schema_snapshot.json"
        before_ddl_path = bundle_dir / "before_table_ddl.sql"
        rollback_sql_path = bundle_dir / "rollback.sql"

        existing_ddl = existing_schema_snapshot.get("ddl") or (
            "-- Table did not exist prior to migration (or engine does not expose SHOW CREATE TABLE)."
        )
        snapshot_payload = {
            "change_id": change_id,
            "created_at": now.isoformat(timespec="seconds"),
            "channel": "DBEAVER_DDL_HANDOFF",
            "status": "DDL_SCRIPT_OPENED",
            "connection": connection,
            "database": database,
            "table": table,
            "migration_title": migration_title,
            "forward_ddl_sql": ddl_sql,
            "rollback_ddl_sql": rollback_ddl_sql,
            "warnings": list(warnings),
            "existing_schema_snapshot": existing_schema_snapshot,
        }
        snapshot_json_path.write_text(
            json.dumps(snapshot_payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        before_ddl_path.write_text(str(existing_ddl) + "\n", encoding="utf-8")
        rollback_sql_path.write_text(rollback_ddl_sql.strip() + "\n", encoding="utf-8")

        for p in (snapshot_json_path, before_ddl_path, rollback_sql_path):
            if not p.is_file() or p.stat().st_size == 0:
                raise RuntimeError(f"Mandatory pre-DDL schema backup failed for {p}")

        return {
            "change_id": change_id,
            "bundle_dir": str(bundle_dir),
            "backup_json_path": str(snapshot_json_path),
            "insert_sql_path": str(before_ddl_path),
            "rollback_sql_path": str(rollback_sql_path),
        }

    def create_seed_cleanup_backup(
        self,
        *,
        connection: str,
        database: str,
        table: str,
        seed_summary: str,
        insert_statements: Sequence[str],
        cleanup_rollback_sql: str,
        columns: Sequence[Dict[str, str]],
        inserted_rows_unmasked: Sequence[Sequence[Any]],
    ) -> Dict[str, str]:
        """Persists seeded row manifest + 1-click DELETE cleanup rollback.sql."""
        now = dt.datetime.now()
        date_folder = now.strftime("%Y-%m-%d")
        change_id = now.strftime("%Y%m%d_%H%M%S_%f")[:19]
        folder_name = (
            f"{change_id}_SEED_{_safe_slug(connection, 18)}_"
            f"{_safe_slug(database or 'default', 18)}_{_safe_slug(table, 24)}"
        )
        bundle_dir = self.backup_root / date_folder / folder_name
        bundle_dir.mkdir(parents=True, exist_ok=True)

        backup_json_path = bundle_dir / "backup_record.json"
        seed_inserts_path = bundle_dir / "seeded_rows_insert.sql"
        rollback_sql_path = bundle_dir / "rollback.sql"

        payload = {
            "change_id": change_id,
            "created_at": now.isoformat(timespec="seconds"),
            "channel": "DEV_TEST_SEED",
            "status": "COMMITTED",
            "connection": connection,
            "database": database,
            "table": table,
            "seed_summary": seed_summary,
            "seeded_row_count": len(inserted_rows_unmasked),
            "columns": list(columns),
            "inserted_rows_unmasked": [list(r) for r in inserted_rows_unmasked],
        }
        backup_json_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        seed_inserts_path.write_text(
            ";\n".join(insert_statements) + ";\n", encoding="utf-8"
        )
        rollback_sql_path.write_text(cleanup_rollback_sql.strip() + "\n", encoding="utf-8")

        for p in (backup_json_path, seed_inserts_path, rollback_sql_path):
            if not p.is_file() or p.stat().st_size == 0:
                raise RuntimeError(f"Mandatory seed cleanup backup failed for {p}")

        return {
            "change_id": change_id,
            "bundle_dir": str(bundle_dir),
            "backup_json_path": str(backup_json_path),
            "insert_sql_path": str(seed_inserts_path),
            "rollback_sql_path": str(rollback_sql_path),
        }
