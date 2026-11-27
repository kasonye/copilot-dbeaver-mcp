"""
DB-Guard MCP Server Core Implementation.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from db_guard import __version__
from db_guard.audit_logger import ModificationAuditor
from db_guard.dbeaver_bridge import (
    find_dbeaver_driver_dirs,
    find_dbeaver_sshj_jars,
    launch_script_in_dbeaver,
    load_dbeaver_connections,
    scan_db_errors_in_logs,
    write_dbeaver_ddl_migration_script,
    write_dbeaver_remediation_script,
)
from db_guard.sql_guard import (
    DynamicDataMasker,
    build_rollback_sql,
    build_seed_batch_sql,
    validate_ddl_migration_sql,
    validate_identifier,
    validate_readonly_sql,
    validate_remediation_sql,
)

PACKAGE_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKAGE_DIR.parent
DEFAULT_USER_HOME_DIR = Path.home() / ".db-guard-mcp"
SUPPORTED_PROTOCOL_VERSIONS = {"2024-11-05", "2025-03-26", "2025-06-18"}


def _b64(text: Optional[str]) -> str:
    if not text:
        return ""
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _extract_dml_verb(dml_sql: str) -> str:
    m = re.match(r"^\s*([A-Za-z]+)", dml_sql or "")
    return m.group(1).upper() if m else "UPDATE"


def discover_default_driver_paths(
    dbeaver_exe: Optional[str] = None, extra_paths: Optional[List[str]] = None
) -> List[str]:
    m2_repo = Path.home() / ".m2" / "repository"
    candidates: List[str] = [
        *find_dbeaver_driver_dirs(),
        str(m2_repo / "org" / "mariadb" / "jdbc" / "mariadb-java-client"),
        str(m2_repo / "com" / "mysql" / "mysql-connector-j"),
        str(m2_repo / "org" / "postgresql" / "postgresql"),
        str(m2_repo / "com" / "h2database" / "h2"),
        *find_dbeaver_sshj_jars(dbeaver_exe),
    ]
    if extra_paths:
        candidates.extend(os.path.expanduser(os.path.expandvars(p)) for p in extra_paths)

    paths: List[str] = []
    for p in candidates:
        if p and os.path.exists(p) and p not in paths:
            paths.append(p)
    return paths


@dataclass
class ResolvedTarget:
    display_name: str
    dbeaver_conn_name: Optional[str]
    jdbc_url: str
    user_spec: str
    pass_spec: str
    target_db: str
    props_text: str
    allow_direct_apply: bool
    max_write_rows: int
    source: str


class JdbcBridgeProcess:
    """Manages persistent Java JDBC worker subprocess, compiling into writable cache."""

    def __init__(
        self,
        driver_paths: List[str],
        compile_dir: Path,
        java_bin: str = "java",
        javac_bin: str = "javac",
    ) -> None:
        self.driver_paths = driver_paths
        self.java_bin = java_bin
        self.javac_bin = javac_bin
        self.src_file = PACKAGE_DIR / "java" / "JdbcBridge.java"
        self.bin_dir = compile_dir
        self.class_file = self.bin_dir / "JdbcBridge.class"
        self._proc: Optional[subprocess.Popen[str]] = None
        self._lock = threading.Lock()

    def ensure_compiled(self) -> None:
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        if (
            not self.class_file.exists()
            or self.src_file.stat().st_mtime > self.class_file.stat().st_mtime
        ):
            res = subprocess.run(
                [
                    self.javac_bin,
                    "-encoding",
                    "UTF-8",
                    "-d",
                    str(self.bin_dir),
                    str(self.src_file),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if res.returncode != 0:
                raise RuntimeError(f"Failed to compile JdbcBridge.java: {res.stderr}")

    def _ensure_started(self) -> subprocess.Popen[str]:
        if self._proc is not None and self._proc.poll() is None:
            return self._proc
        self.ensure_compiled()
        cmd = [
            self.java_bin,
            "-Dfile.encoding=UTF-8",
            "-cp",
            str(self.bin_dir),
            "JdbcBridge",
            *self.driver_paths,
        ]
        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        return self._proc

    def request(
        self,
        mode: str,
        jdbc_url: str = "",
        user_spec: str = "",
        pass_spec: str = "",
        target_db: str = "",
        props_text: str = "",
        timeout_sec: int = 8,
        max_rows: int = 100,
        dry_run: bool = True,
        expected_rows: int = -1,
        arg1: str = "",
        arg2: str = "",
    ) -> Dict[str, Any]:
        with self._lock:
            proc = self._ensure_started()
            req_id = uuid.uuid4().hex[:12]
            frame = "|".join(
                [
                    "REQ",
                    req_id,
                    mode,
                    _b64(jdbc_url),
                    _b64(user_spec),
                    _b64(pass_spec),
                    str(int(timeout_sec)),
                    str(int(max_rows)),
                    "true" if dry_run else "false",
                    str(int(expected_rows)),
                    _b64(arg1),
                    _b64(arg2),
                    _b64(target_db),
                    _b64(props_text),
                ]
            )
            assert proc.stdin is not None and proc.stdout is not None
            proc.stdin.write(frame + "\n")
            proc.stdin.flush()
            resp_line = proc.stdout.readline()
            if not resp_line:
                stderr_tail = ""
                if proc.stderr is not None:
                    try:
                        stderr_tail = proc.stderr.read()[:500]
                    except Exception:
                        pass
                self._proc = None
                raise RuntimeError(f"JdbcBridge process terminated unexpectedly. {stderr_tail}")
            return json.loads(resp_line)

    def close(self) -> None:
        with self._lock:
            proc = self._proc
            self._proc = None
            if proc is not None:
                try:
                    if proc.poll() is None and proc.stdin:
                        proc.stdin.write("EXIT\n")
                        proc.stdin.flush()
                        proc.wait(timeout=2)
                except Exception:
                    proc.kill()
                finally:
                    for stream in (proc.stdin, proc.stdout, proc.stderr):
                        if stream is not None:
                            try:
                                stream.close()
                            except Exception:
                                pass


def resolve_default_config_path() -> Path:
    env_cfg = os.environ.get("DB_GUARD_CONFIG")
    if env_cfg:
        return Path(os.path.expanduser(os.path.expandvars(env_cfg)))
    for candidate in (
        REPO_ROOT / "config.local.yaml",
        DEFAULT_USER_HOME_DIR / "config.yaml",
        REPO_ROOT / "config.example.yaml",
    ):
        if candidate.is_file():
            return candidate
    return DEFAULT_USER_HOME_DIR / "config.yaml"


class DbGuardApp:
    def __init__(
        self, config_path: Optional[Path] = None, storage_dir: Optional[Path] = None
    ) -> None:
        self.config_path = config_path or resolve_default_config_path()
        env_storage = os.environ.get("DB_GUARD_STORAGE_DIR")
        if storage_dir:
            self.storage_root = storage_dir
        elif env_storage:
            self.storage_root = Path(os.path.expanduser(os.path.expandvars(env_storage)))
        else:
            self.storage_root = DEFAULT_USER_HOME_DIR

        self.remediation_dir = self.storage_root / "remediations"
        self._jdbc: Optional[JdbcBridgeProcess] = None
        self.reload_config()

    def reload_config(self) -> None:
        raw: Dict[str, Any] = {}
        if self.config_path and self.config_path.is_file():
            with open(self.config_path, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}

        self.config = raw
        if raw.get("storage_dir") and not os.environ.get("DB_GUARD_STORAGE_DIR"):
            self.storage_root = Path(os.path.expanduser(os.path.expandvars(str(raw["storage_dir"]))))
            self.remediation_dir = self.storage_root / "remediations"

        self.default_connection = str(raw.get("default_connection") or "localhost")
        self.default_database = str(raw.get("default_database") or "")

        sec = raw.get("security") or {}
        self.query_timeout_sec = int(sec.get("query_timeout_sec", 10))
        self.default_max_rows = int(sec.get("default_max_rows", 100))
        self.hard_max_rows = int(sec.get("hard_max_rows", 500))
        self.max_write_rows = int(sec.get("max_write_rows", 20))
        self.max_seed_rows = int(sec.get("max_seed_rows", 50))
        allow_list = sec.get("allow_direct_apply_connections")
        if allow_list is None:
            allow_list = ["localhost", "127.0.0.1"]
        self.allow_direct_apply_set = {str(x).lower() for x in allow_list}

        self.masker = DynamicDataMasker(
            enabled=bool(sec.get("mask_sensitive_data", True)),
            extra_column_patterns=sec.get("extra_sensitive_column_patterns"),
            exempt_columns=sec.get("exempt_columns"),
        )
        self.auditor = ModificationAuditor(base_dir=self.storage_root, masker=self.masker)

        dbeaver_cfg = raw.get("dbeaver") or {}
        self.dbeaver_exe = dbeaver_cfg.get("executable_path") or None
        self.dbeaver_datasources = dbeaver_cfg.get("datasources_json") or None

        if self._jdbc is None:
            driver_paths = discover_default_driver_paths(
                dbeaver_exe=self.dbeaver_exe,
                extra_paths=raw.get("extra_driver_jars"),
            )
            self._jdbc = JdbcBridgeProcess(
                driver_paths=driver_paths,
                compile_dir=self.storage_root / "bin",
            )

    @property
    def jdbc(self) -> JdbcBridgeProcess:
        assert self._jdbc is not None
        return self._jdbc

    def _resolve_target(
        self, connection: Optional[str] = None, database: Optional[str] = None, for_write: bool = False
    ) -> ResolvedTarget:
        req_conn = (connection or "").strip() or self.default_connection
        req_db = (database or "").strip()

        custom_profiles = self.config.get("profiles") or {}
        if req_conn in custom_profiles:
            prof = custom_profiles[req_conn]
            cred_block = (
                (prof.get("remediate") or prof.get("readonly") or {})
                if for_write
                else (prof.get("readonly") or {})
            )
            return ResolvedTarget(
                display_name=req_conn,
                dbeaver_conn_name=prof.get("dbeaver_connection_name"),
                jdbc_url=os.path.expandvars(str(prof.get("jdbc_url", ""))),
                user_spec=os.path.expandvars(str(cred_block.get("user") or prof.get("user") or "")),
                pass_spec=os.path.expandvars(str(cred_block.get("password") or prof.get("password") or "")),
                target_db=req_db or str(prof.get("default_schema") or ""),
                props_text="",
                allow_direct_apply=bool(prof.get("allow_controlled_write", False)),
                max_write_rows=int(prof.get("max_write_rows", self.max_write_rows)),
                source="custom_profile",
            )

        dbv = load_dbeaver_connections(self.dbeaver_datasources)
        conns: List[Dict[str, Any]] = dbv.get("connections") or []
        if not conns:
            raise ValueError(
                "No DBeaver connections found automatically. Configure connections in DBeaver first."
            )

        low = req_conn.lower()
        matched: Optional[Dict[str, Any]] = None

        for pred in (
            lambda c: str(c["name"]).lower() == low,
            lambda c: str(c["id"]).lower() == low,
            lambda c: f"{c['host']}:{c['port']}".lower() == low,
            lambda c: str(c["host"]).lower() == low,
        ):
            hits = [c for c in conns if pred(c)]
            if hits:
                matched = hits[0]
                break

        if matched is None:
            sub_hits = [
                c
                for c in conns
                if low in str(c["name"]).lower()
                or low in str(c["default_database"]).lower()
                or low in str(c["id"]).lower()
            ]
            if len(sub_hits) == 1:
                matched = sub_hits[0]
            elif len(sub_hits) > 1:
                names = [f"{c['name']} ({c['driver']} {c['host']}:{c['port']})" for c in sub_hits]
                raise ValueError(
                    f"Ambiguous connection '{req_conn}'. Matches multiple DBeaver connections: {names}."
                )

        if matched is None:
            available = [f"{c['name']} ({c['driver']} -> {c['host']}:{c['port']})" for c in conns]
            raise ValueError(
                f"Connection '{req_conn}' not found in DBeaver. Available connections: {available}"
            )

        if not matched.get("save_password") or not matched.get("credentials_file"):
            raise ValueError(
                f"DBeaver connection '{matched['name']}' has 'Save password' disabled in DBeaver."
            )

        user_spec = f"@DBEAVER:{matched['id']}|{matched['credentials_file']}"
        ssh = matched.get("ssh_tunnel") or {}
        if ssh.get("enabled"):
            pass_spec = (
                f"@SSH:{ssh['bastion_host']}|{ssh['bastion_port']}|"
                f"{matched['host']}|{matched['port']}|"
                f"{ssh.get('auth_type', 'PASSWORD')}|{ssh.get('private_key', '')}"
            )
        else:
            pass_spec = ""

        props_map: Dict[str, Any] = matched.get("driver_properties") or {}
        props_text = "\n".join(f"{k}={v}" for k, v in props_map.items())

        effective_db = req_db or str(matched.get("default_database") or "")
        if (
            not effective_db
            and str(matched["name"]).lower() == self.default_connection.lower()
            and self.default_database
        ):
            effective_db = self.default_database

        can_apply = (
            "*" in self.allow_direct_apply_set
            or str(matched["name"]).lower() in self.allow_direct_apply_set
            or str(matched["host"]).lower() in self.allow_direct_apply_set
            or str(matched["id"]).lower() in self.allow_direct_apply_set
        )

        return ResolvedTarget(
            display_name=str(matched["name"]),
            dbeaver_conn_name=str(matched["name"]),
            jdbc_url=str(matched["jdbc_url"]),
            user_spec=user_spec,
            pass_spec=pass_spec,
            target_db=effective_db,
            props_text=props_text,
            allow_direct_apply=can_apply,
            max_write_rows=self.max_write_rows,
            source="dbeaver",
        )

    def _fetch_primary_keys(self, tgt: ResolvedTarget, table: str) -> List[str]:
        short_table = table.split(".")[-1]
        try:
            res = self.jdbc.request(
                mode="SCHEMA",
                jdbc_url=tgt.jdbc_url,
                user_spec=tgt.user_spec,
                pass_spec=tgt.pass_spec,
                target_db=tgt.target_db,
                props_text=tgt.props_text,
                timeout_sec=self.query_timeout_sec,
                max_rows=50,
                arg1=tgt.target_db,
                arg2=short_table,
            )
            if res.get("ok"):
                return list(res.get("primaryKeys") or [])
        except Exception:
            pass
        return []

    # -------------------- MCP Tool Handlers --------------------

    def tool_list_connections(self, _args: Dict[str, Any]) -> Dict[str, Any]:
        self.reload_config()
        dbv = load_dbeaver_connections(self.dbeaver_datasources)
        dbeaver_items = []
        for c in dbv.get("connections") or []:
            can_apply = (
                "*" in self.allow_direct_apply_set
                or str(c["name"]).lower() in self.allow_direct_apply_set
                or str(c["host"]).lower() in self.allow_direct_apply_set
            )
            dbeaver_items.append(
                {
                    "name": c["name"],
                    "id": c["id"],
                    "workspace_project": c.get("workspace_project", "General"),
                    "driver": c["driver"],
                    "host": c["host"],
                    "port": c["port"],
                    "default_database": c["default_database"],
                    "ready_to_use": c["save_password"],
                    "ssh_tunnel_enabled": c["ssh_tunnel"]["enabled"],
                    "allow_direct_apply": can_apply,
                }
            )

        ping = self.jdbc.request(mode="PING")
        return {
            "default_connection": self.default_connection,
            "default_database": self.default_database,
            "loaded_jdbc_drivers": ping.get("drivers", []),
            "dbeaver_connections": dbeaver_items,
            "storage_root": str(self.storage_root),
            "backup_root_dir": str(self.auditor.backup_root),
            "audit_log_markdown": str(self.auditor.md_log_path),
        }

    def tool_list_databases(self, args: Dict[str, Any]) -> Dict[str, Any]:
        self.reload_config()
        tgt = self._resolve_target(args.get("connection") or args.get("profile"))
        res = self.jdbc.request(
            mode="LIST_DBS",
            jdbc_url=tgt.jdbc_url,
            user_spec=tgt.user_spec,
            pass_spec=tgt.pass_spec,
            target_db=tgt.target_db,
            props_text=tgt.props_text,
            timeout_sec=self.query_timeout_sec,
        )
        if not res.get("ok"):
            raise RuntimeError(f"Failed to list databases on '{tgt.display_name}': {res.get('error')}")
        return {
            "connection": tgt.display_name,
            "product_name": res.get("productName"),
            "current_database": res.get("currentDatabase"),
            "databases": res.get("databases", []),
        }

    def tool_inspect_schema(self, args: Dict[str, Any]) -> Dict[str, Any]:
        self.reload_config()
        db_arg = args.get("database") or args.get("schema")
        tgt = self._resolve_target(args.get("connection") or args.get("profile"), db_arg)
        table_target = (args.get("table") or args.get("table_pattern") or "%").strip()

        res = self.jdbc.request(
            mode="SCHEMA",
            jdbc_url=tgt.jdbc_url,
            user_spec=tgt.user_spec,
            pass_spec=tgt.pass_spec,
            target_db=tgt.target_db,
            props_text=tgt.props_text,
            timeout_sec=self.query_timeout_sec,
            max_rows=min(int(args.get("max_tables", 200)), 500),
            arg1=tgt.target_db,
            arg2=table_target,
        )
        if not res.get("ok"):
            raise RuntimeError(
                f"Schema inspection failed on '{tgt.display_name}' (db='{tgt.target_db}'): {res.get('error')}"
            )
        res["connection"] = tgt.display_name
        res.pop("id", None)
        return res

    def tool_diagnose_query(self, args: Dict[str, Any]) -> Dict[str, Any]:
        self.reload_config()
        tgt = self._resolve_target(
            args.get("connection") or args.get("profile"), args.get("database")
        )
        raw_sql = args.get("sql") or ""
        clean_sql, err = validate_readonly_sql(raw_sql)
        if err:
            raise ValueError(f"SQL Guardrail Blocked Query: {err}")

        req_limit = int(args.get("max_rows", self.default_max_rows))
        cap = max(1, min(req_limit, self.hard_max_rows))

        res = self.jdbc.request(
            mode="QUERY",
            jdbc_url=tgt.jdbc_url,
            user_spec=tgt.user_spec,
            pass_spec=tgt.pass_spec,
            target_db=tgt.target_db,
            props_text=tgt.props_text,
            timeout_sec=self.query_timeout_sec,
            max_rows=cap,
            arg1=clean_sql,
        )
        if not res.get("ok"):
            raise RuntimeError(
                f"Query failed on '{tgt.display_name}' [{res.get('sqlState') or 'ERR'}]: {res.get('error')}"
            )

        columns = res.get("columns", [])
        raw_rows = res.get("rows", [])
        masked_rows, masked_cols = self.masker.mask_rows(columns, raw_rows)

        return {
            "connection": tgt.display_name,
            "database": res.get("activeDatabase") or tgt.target_db,
            "executed_sql": clean_sql,
            "elapsed_ms": res.get("elapsedMs"),
            "row_count": res.get("rowCount"),
            "truncated": res.get("truncated"),
            "max_rows_cap": cap,
            "masked_sensitive_columns": masked_cols,
            "columns": columns,
            "rows": masked_rows,
        }

    def tool_explain_query(self, args: Dict[str, Any]) -> Dict[str, Any]:
        self.reload_config()
        tgt = self._resolve_target(
            args.get("connection") or args.get("profile"), args.get("database")
        )
        raw_sql = args.get("sql") or ""
        clean_sql, err = validate_readonly_sql(raw_sql)
        if err:
            raise ValueError(f"SQL Guardrail Blocked EXPLAIN target: {err}")
        if not clean_sql.upper().startswith("EXPLAIN"):
            clean_sql = f"EXPLAIN {clean_sql}"

        res = self.jdbc.request(
            mode="QUERY",
            jdbc_url=tgt.jdbc_url,
            user_spec=tgt.user_spec,
            pass_spec=tgt.pass_spec,
            target_db=tgt.target_db,
            props_text=tgt.props_text,
            timeout_sec=self.query_timeout_sec,
            max_rows=100,
            arg1=clean_sql,
        )
        if not res.get("ok"):
            raise RuntimeError(f"EXPLAIN failed: {res.get('error')}")
        return {
            "connection": tgt.display_name,
            "database": tgt.target_db,
            "explain_sql": clean_sql,
            "columns": res.get("columns", []),
            "plan_rows": res.get("rows", []),
        }

    def tool_preview_remediation(self, args: Dict[str, Any]) -> Dict[str, Any]:
        self.reload_config()
        tgt = self._resolve_target(
            args.get("connection") or args.get("profile"), args.get("database")
        )
        table = (args.get("table") or "").strip()
        where_clause = (args.get("where_clause") or "").strip()
        dml_sql = (args.get("dml_sql") or "").strip()
        issue_title = (args.get("issue_summary") or f"Fix {table}").strip()

        select_sql, clean_dml, err = validate_remediation_sql(table, where_clause, dml_sql)
        if err:
            raise ValueError(f"Remediation Guardrail Blocked SQL: {err}")

        dml_verb = _extract_dml_verb(clean_dml)
        clean_where = select_sql.split(" WHERE ", 1)[1]
        pks = self._fetch_primary_keys(tgt, table)

        res = self.jdbc.request(
            mode="REMEDIATE",
            jdbc_url=tgt.jdbc_url,
            user_spec=tgt.user_spec,
            pass_spec=tgt.pass_spec,
            target_db=tgt.target_db,
            props_text=tgt.props_text,
            timeout_sec=self.query_timeout_sec,
            max_rows=tgt.max_write_rows,
            dry_run=True,
            expected_rows=-1,
            arg1=select_sql,
            arg2=clean_dml,
        )
        if not res.get("ok"):
            raise RuntimeError(f"Dry-run remediation failed (rolled back): {res.get('error')}")

        columns = res.get("columns", [])
        before_raw = res.get("beforeRows", [])
        after_raw = res.get("afterRows", [])
        affected = res.get("affectedRows", 0)
        rollback_sql = build_rollback_sql(
            table=table,
            columns=columns,
            before_rows=before_raw,
            after_rows=after_raw,
            primary_keys=pks,
            dml_verb=dml_verb,
            where_clause=clean_where,
            database=tgt.target_db,
        )
        masked_before, masked_cols = self.masker.mask_rows(columns, before_raw)
        masked_after, _ = self.masker.mask_rows(columns, after_raw)

        script_path = write_dbeaver_remediation_script(
            output_dir=self.remediation_dir,
            issue_title=issue_title,
            table=table,
            where_clause=clean_where,
            dml_sql=clean_dml,
            rollback_sql=rollback_sql,
            dbeaver_conn_name=tgt.dbeaver_conn_name,
            database_name=tgt.target_db,
            expected_rows=affected,
        )

        sidecar = Path(str(script_path) + ".meta.json")
        sidecar.write_text(
            json.dumps(
                {
                    "connection": tgt.display_name,
                    "database": tgt.target_db,
                    "table": table,
                    "where_clause": clean_where,
                    "dml_sql": clean_dml,
                    "issue_summary": issue_title,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        return {
            "connection": tgt.display_name,
            "database": tgt.target_db,
            "preview_mode": "transactional_dry_run_rolled_back",
            "committed": False,
            "expected_affected_rows": affected,
            "primary_keys": pks,
            "allow_direct_apply": tgt.allow_direct_apply,
            "masked_sensitive_columns": masked_cols,
            "columns": columns,
            "before_rows": masked_before,
            "after_rows_preview": masked_after,
            "generated_dbeaver_script": str(script_path),
            "next_step_hint": (
                "Call 'open_remediation_in_dbeaver' (automatically backs up original rows & logs the change before opening DBeaver)"
                + (
                    ", or call 'apply_remediation' with expected_affected_rows after user approval."
                    if tgt.allow_direct_apply
                    else "."
                )
            ),
        }

    def tool_open_remediation_in_dbeaver(self, args: Dict[str, Any]) -> Dict[str, Any]:
        self.reload_config()
        script_path_arg = args.get("script_path")
        conn_arg = args.get("connection") or args.get("dbeaver_connection_name") or args.get("profile")
        db_arg = args.get("database")
        table = (args.get("table") or "").strip()
        where_clause = (args.get("where_clause") or "").strip()
        dml_sql = (args.get("dml_sql") or "").strip()
        issue_title = (args.get("issue_summary") or "").strip()

        if script_path_arg and (not table or not dml_sql):
            sidecar = Path(str(script_path_arg) + ".meta.json")
            if sidecar.is_file():
                meta = json.loads(sidecar.read_text(encoding="utf-8"))
                conn_arg = conn_arg or meta.get("connection")
                db_arg = db_arg or meta.get("database")
                table = table or meta.get("table", "")
                where_clause = where_clause or meta.get("where_clause", "")
                dml_sql = dml_sql or meta.get("dml_sql", "")
                issue_title = issue_title or meta.get("issue_summary", "")

        if script_path_arg and not dml_sql:
            existing_path = Path(script_path_arg)
            if not existing_path.is_file():
                raise FileNotFoundError(f"Script file not found: {existing_path}")
            if self.auditor.backup_root.resolve() not in existing_path.resolve().parents:
                raise ValueError(
                    "Mandatory Backup Policy: Cannot open an un-backed-up SQL file without table/where_clause/dml_sql metadata."
                )
            tgt = self._resolve_target(conn_arg, db_arg) if conn_arg else None
            dbeaver_conn = args.get("dbeaver_connection_name") or (tgt.dbeaver_conn_name if tgt else None)
            return launch_script_in_dbeaver(
                script_path=existing_path,
                dbeaver_conn_name=dbeaver_conn,
                dbeaver_exe=self.dbeaver_exe,
            )

        tgt = self._resolve_target(conn_arg, db_arg)
        issue_title = issue_title or f"Fix {table}"
        select_sql, clean_dml, err = validate_remediation_sql(table, where_clause, dml_sql)
        if err:
            raise ValueError(f"Remediation Guardrail Blocked SQL: {err}")

        dml_verb = _extract_dml_verb(clean_dml)
        clean_where = select_sql.split(" WHERE ", 1)[1]
        pks = self._fetch_primary_keys(tgt, table)

        dry = self.jdbc.request(
            mode="REMEDIATE",
            jdbc_url=tgt.jdbc_url,
            user_spec=tgt.user_spec,
            pass_spec=tgt.pass_spec,
            target_db=tgt.target_db,
            props_text=tgt.props_text,
            timeout_sec=self.query_timeout_sec,
            max_rows=tgt.max_write_rows,
            dry_run=True,
            expected_rows=-1,
            arg1=select_sql,
            arg2=clean_dml,
        )
        if not dry.get("ok"):
            raise RuntimeError(
                f"Mandatory pre-backup dry-run failed on '{tgt.display_name}': {dry.get('error')}"
            )

        columns = dry.get("columns", [])
        before_unmasked = dry.get("beforeRows", [])
        after_unmasked = dry.get("afterRows", [])
        affected = int(dry.get("affectedRows", 0))

        if dml_verb in {"UPDATE", "DELETE"} and len(before_unmasked) == 0:
            raise ValueError(
                f"Target WHERE clause matched 0 existing rows in '{table}'; aborted DBeaver handoff."
            )

        backup_paths = self.auditor.create_pre_modification_backup(
            channel="DBEAVER_HANDOFF",
            connection=tgt.display_name,
            database=tgt.target_db,
            table=table,
            dml_verb=dml_verb,
            where_clause=clean_where,
            select_sql=select_sql,
            dml_sql=clean_dml,
            issue_summary=issue_title,
            columns=columns,
            primary_keys=pks,
            before_rows_unmasked=before_unmasked,
            after_rows_unmasked=after_unmasked,
            expected_affected_rows=affected,
        )

        script_path = write_dbeaver_remediation_script(
            output_dir=self.remediation_dir,
            issue_title=issue_title,
            table=table,
            where_clause=clean_where,
            dml_sql=clean_dml,
            rollback_sql=backup_paths["rollback_sql_content"],
            dbeaver_conn_name=tgt.dbeaver_conn_name,
            database_name=tgt.target_db,
            expected_rows=affected,
            backup_bundle_dir=backup_paths["bundle_dir"],
            rollback_sql_path=backup_paths["rollback_sql_path"],
        )

        log_paths = self.auditor.record_audit_log(
            change_id=backup_paths["change_id"],
            channel="DBEAVER_HANDOFF",
            status="DBEAVER_SCRIPT_OPENED",
            connection=tgt.display_name,
            database=tgt.target_db,
            table=table,
            dml_verb=dml_verb,
            where_clause=clean_where,
            dml_sql=clean_dml,
            issue_summary=issue_title,
            affected_rows=affected,
            columns=columns,
            primary_keys=pks,
            before_rows_unmasked=before_unmasked,
            after_rows_unmasked=after_unmasked,
            backup_paths=backup_paths,
            dbeaver_script_path=str(script_path),
        )

        if bool(args.get("_skip_gui_for_test", False)):
            launch_info: Dict[str, Any] = {
                "launched": False,
                "note": "GUI launch skipped for automated test",
                "script_path": str(script_path),
            }
        else:
            launch_info = launch_script_in_dbeaver(
                script_path=script_path,
                dbeaver_conn_name=tgt.dbeaver_conn_name,
                dbeaver_exe=self.dbeaver_exe,
            )

        return {
            **launch_info,
            "change_id": backup_paths["change_id"],
            "connection": tgt.display_name,
            "database": tgt.target_db,
            "expected_affected_rows": affected,
            "backup_bundle_dir": backup_paths["bundle_dir"],
            "backup_json_path": backup_paths["backup_json_path"],
            "before_rows_insert_sql": backup_paths["insert_sql_path"],
            "rollback_sql_path": backup_paths["rollback_sql_path"],
            "audit_log_markdown": log_paths["audit_markdown_path"],
        }

    def tool_apply_remediation(self, args: Dict[str, Any]) -> Dict[str, Any]:
        self.reload_config()
        tgt = self._resolve_target(
            args.get("connection") or args.get("profile"),
            args.get("database"),
            for_write=True,
        )
        if not tgt.allow_direct_apply:
            raise PermissionError(
                f"Direct write remediation is disabled on connection '{tgt.display_name}' by safety policy "
                f"(allow_direct_apply_connections). Use 'open_remediation_in_dbeaver' instead."
            )

        table = (args.get("table") or "").strip()
        where_clause = (args.get("where_clause") or "").strip()
        dml_sql = (args.get("dml_sql") or "").strip()
        issue_title = (args.get("issue_summary") or f"Fix {table}").strip()

        if "expected_affected_rows" not in args or args.get("expected_affected_rows") is None:
            raise ValueError(
                "expected_affected_rows is mandatory for apply_remediation. Run preview_remediation first."
            )
        expected_rows = int(args["expected_affected_rows"])
        if expected_rows < 1 or expected_rows > tgt.max_write_rows:
            raise ValueError(
                f"expected_affected_rows must be between 1 and max_write_rows ({tgt.max_write_rows}), got {expected_rows}."
            )

        select_sql, clean_dml, err = validate_remediation_sql(table, where_clause, dml_sql)
        if err:
            raise ValueError(f"Remediation Guardrail Blocked SQL: {err}")

        dml_verb = _extract_dml_verb(clean_dml)
        clean_where = select_sql.split(" WHERE ", 1)[1]
        pks = self._fetch_primary_keys(tgt, table)

        dry = self.jdbc.request(
            mode="REMEDIATE",
            jdbc_url=tgt.jdbc_url,
            user_spec=tgt.user_spec,
            pass_spec=tgt.pass_spec,
            target_db=tgt.target_db,
            props_text=tgt.props_text,
            timeout_sec=self.query_timeout_sec,
            max_rows=tgt.max_write_rows,
            dry_run=True,
            expected_rows=expected_rows,
            arg1=select_sql,
            arg2=clean_dml,
        )
        if not dry.get("ok"):
            raise RuntimeError(f"Pre-commit verification failed (nothing changed): {dry.get('error')}")
        if dry.get("affectedRows") != expected_rows:
            raise RuntimeError(
                f"Pre-commit row count mismatch: expected {expected_rows}, dry-run affected {dry.get('affectedRows')}. Aborted."
            )

        columns = dry.get("columns", [])
        before_unmasked = dry.get("beforeRows", [])
        after_preview_unmasked = dry.get("afterRows", [])

        backup_paths = self.auditor.create_pre_modification_backup(
            channel="DIRECT_COMMIT",
            connection=tgt.display_name,
            database=tgt.target_db,
            table=table,
            dml_verb=dml_verb,
            where_clause=clean_where,
            select_sql=select_sql,
            dml_sql=clean_dml,
            issue_summary=issue_title,
            columns=columns,
            primary_keys=pks,
            before_rows_unmasked=before_unmasked,
            after_rows_unmasked=after_preview_unmasked,
            expected_affected_rows=expected_rows,
        )

        commit_res = self.jdbc.request(
            mode="REMEDIATE",
            jdbc_url=tgt.jdbc_url,
            user_spec=tgt.user_spec,
            pass_spec=tgt.pass_spec,
            target_db=tgt.target_db,
            props_text=tgt.props_text,
            timeout_sec=self.query_timeout_sec,
            max_rows=tgt.max_write_rows,
            dry_run=False,
            expected_rows=expected_rows,
            arg1=select_sql,
            arg2=clean_dml,
        )
        if not commit_res.get("ok"):
            err_msg = str(commit_res.get("error"))
            self.auditor.record_audit_log(
                change_id=backup_paths["change_id"],
                channel="DIRECT_COMMIT",
                status="ABORTED_ROLLED_BACK",
                connection=tgt.display_name,
                database=tgt.target_db,
                table=table,
                dml_verb=dml_verb,
                where_clause=clean_where,
                dml_sql=clean_dml,
                issue_summary=issue_title,
                affected_rows=0,
                columns=columns,
                primary_keys=pks,
                before_rows_unmasked=before_unmasked,
                after_rows_unmasked=[],
                backup_paths=backup_paths,
                error_message=err_msg,
            )
            raise RuntimeError(f"Atomic commit aborted and rolled back: {err_msg}")

        after_committed_unmasked = commit_res.get("afterRows", [])
        actual_affected = int(commit_res.get("affectedRows", expected_rows))

        log_paths = self.auditor.record_audit_log(
            change_id=backup_paths["change_id"],
            channel="DIRECT_COMMIT",
            status="COMMITTED",
            connection=tgt.display_name,
            database=tgt.target_db,
            table=table,
            dml_verb=dml_verb,
            where_clause=clean_where,
            dml_sql=clean_dml,
            issue_summary=issue_title,
            affected_rows=actual_affected,
            columns=columns,
            primary_keys=pks,
            before_rows_unmasked=before_unmasked,
            after_rows_unmasked=after_committed_unmasked,
            backup_paths=backup_paths,
        )

        masked_before, masked_cols = self.masker.mask_rows(columns, before_unmasked)
        masked_after, _ = self.masker.mask_rows(columns, after_committed_unmasked)

        return {
            "change_id": backup_paths["change_id"],
            "connection": tgt.display_name,
            "database": tgt.target_db,
            "committed": True,
            "affected_rows": actual_affected,
            "masked_sensitive_columns": masked_cols,
            "columns": columns,
            "before_rows": masked_before,
            "after_rows": masked_after,
            "backup_bundle_dir": backup_paths["bundle_dir"],
            "backup_json_path": backup_paths["backup_json_path"],
            "before_rows_insert_sql": backup_paths["insert_sql_path"],
            "rollback_sql_path": backup_paths["rollback_sql_path"],
            "audit_log_markdown": log_paths["audit_markdown_path"],
            "audit_log_jsonl": log_paths["audit_jsonl_path"],
        }

    def tool_list_modification_history(self, args: Dict[str, Any]) -> Dict[str, Any]:
        self.reload_config()
        return self.auditor.list_history(
            limit=int(args.get("limit", 20)),
            table_filter=args.get("table"),
        )

    def tool_open_ddl_migration_in_dbeaver(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Safe Schema Migration Assistant:
        Validates forward DDL (blocks catastrophic DROP TABLE/DATABASE/TRUNCATE), snapshots
        existing table schema/DDL, saves paired reverse rollback DDL, optionally writes a
        project Flyway/Liquibase file, logs to audit ledger, and opens in DBeaver for human review.
        """
        self.reload_config()
        tgt = self._resolve_target(
            args.get("connection") or args.get("profile"), args.get("database")
        )
        table = (args.get("table") or "").strip()
        id_err = validate_identifier(table, "table")
        if id_err:
            raise ValueError(id_err)

        ddl_sql = (args.get("ddl_sql") or "").strip()
        rollback_ddl_sql = (args.get("rollback_ddl_sql") or "").strip()
        if not rollback_ddl_sql:
            raise ValueError(
                "rollback_ddl_sql is mandatory for open_ddl_migration_in_dbeaver "
                "(e.g. 'DROP TABLE IF EXISTS new_table;' or 'ALTER TABLE t DROP COLUMN added_col;')."
            )

        migration_title = (args.get("migration_title") or f"Schema migration on {table}").strip()
        ddl_stmts, warnings, ddl_err = validate_ddl_migration_sql(ddl_sql)
        if ddl_err:
            raise ValueError(f"DDL Guardrail Blocked Migration: {ddl_err}")

        # Capture read-only snapshot of current table metadata/DDL before migration
        short_table = table.split(".")[-1]
        schema_snap: Dict[str, Any] = {}
        try:
            sres = self.jdbc.request(
                mode="SCHEMA",
                jdbc_url=tgt.jdbc_url,
                user_spec=tgt.user_spec,
                pass_spec=tgt.pass_spec,
                target_db=tgt.target_db,
                props_text=tgt.props_text,
                timeout_sec=self.query_timeout_sec,
                max_rows=100,
                arg1=tgt.target_db,
                arg2=short_table,
            )
            if sres.get("ok"):
                sres.pop("id", None)
                schema_snap = sres
        except Exception:
            schema_snap = {"note": "Could not inspect pre-existing table snapshot."}

        backup_paths = self.auditor.record_ddl_migration_backup_and_log(
            connection=tgt.display_name,
            database=tgt.target_db,
            table=table,
            migration_title=migration_title,
            ddl_sql=ddl_sql,
            rollback_ddl_sql=rollback_ddl_sql,
            existing_schema_snapshot=schema_snap,
            warnings=warnings,
        )

        # Optionally write clean forward migration SQL file into the user's project (e.g. Flyway V2__*.sql)
        written_migration_file: Optional[str] = None
        mig_path_arg = (args.get("migration_file_path") or "").strip()
        if mig_path_arg:
            mp = Path(os.path.expanduser(os.path.expandvars(mig_path_arg))).resolve()
            mp.parent.mkdir(parents=True, exist_ok=True)
            header = f"-- Migration: {migration_title}\n-- Rollback : see {backup_paths['rollback_sql_path']}\n\n"
            mp.write_text(
                header + "\n\n".join(s.rstrip(";") + ";" for s in ddl_stmts) + "\n",
                encoding="utf-8",
            )
            written_migration_file = str(mp)

        script_path = write_dbeaver_ddl_migration_script(
            output_dir=self.remediation_dir,
            migration_title=migration_title,
            table=table,
            ddl_statements=ddl_stmts,
            rollback_ddl_sql=rollback_ddl_sql,
            warnings=warnings,
            dbeaver_conn_name=tgt.dbeaver_conn_name,
            database_name=tgt.target_db,
            backup_bundle_dir=backup_paths["bundle_dir"],
            project_migration_file=written_migration_file,
        )

        log_paths = self.auditor.record_audit_log(
            change_id=backup_paths["change_id"],
            channel="DBEAVER_DDL_HANDOFF",
            status="DDL_SCRIPT_OPENED",
            connection=tgt.display_name,
            database=tgt.target_db,
            table=table,
            dml_verb="DDL",
            where_clause="(schema migration)",
            dml_sql="; ".join(s.strip() for s in ddl_stmts),
            issue_summary=migration_title,
            affected_rows=0,
            columns=[],
            primary_keys=[],
            before_rows_unmasked=[],
            after_rows_unmasked=[],
            backup_paths=backup_paths,
            dbeaver_script_path=str(script_path),
        )

        if bool(args.get("_skip_gui_for_test", False)):
            launch_info: Dict[str, Any] = {
                "launched": False,
                "note": "GUI launch skipped for automated test",
                "script_path": str(script_path),
            }
        else:
            launch_info = launch_script_in_dbeaver(
                script_path=script_path,
                dbeaver_conn_name=tgt.dbeaver_conn_name,
                dbeaver_exe=self.dbeaver_exe,
            )

        return {
            **launch_info,
            "change_id": backup_paths["change_id"],
            "connection": tgt.display_name,
            "database": tgt.target_db,
            "warnings": warnings,
            "project_migration_file": written_migration_file,
            "schema_backup_dir": backup_paths["bundle_dir"],
            "before_table_ddl_file": backup_paths["insert_sql_path"],
            "rollback_ddl_file": backup_paths["rollback_sql_path"],
            "audit_log_markdown": log_paths["audit_markdown_path"],
        }

    def tool_seed_dev_test_data(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Local-Dev-Only Synthetic Test Data Seeder:
        Accepts structured row dicts (INSERT-only, immune to SQL injection), checks primary key
        collisions beforehand so existing rows are never overwritten, commits atomically, and
        generates a 1-click consolidated `DELETE ... WHERE pk IN (...)` cleanup backup & audit log.
        """
        self.reload_config()
        tgt = self._resolve_target(
            args.get("connection") or args.get("profile"),
            args.get("database"),
            for_write=True,
        )
        if not tgt.allow_direct_apply:
            raise PermissionError(
                f"seed_dev_test_data is strictly restricted to allowed development connections "
                f"(rejected '{tgt.display_name}')."
            )

        table = (args.get("table") or "").strip()
        rows = args.get("rows") or []
        if not isinstance(rows, list):
            raise ValueError("'rows' must be a JSON list of column->value objects.")
        seed_summary = (args.get("seed_summary") or f"Seed {len(rows)} dev test row(s) into {table}").strip()
        dry_run = bool(args.get("dry_run", False))

        pks = self._fetch_primary_keys(tgt, table)
        insert_stmts, verify_select_sql, cleanup_sql, build_err = build_seed_batch_sql(
            table=table,
            rows=rows,
            primary_keys=pks,
            max_seed_rows=self.max_seed_rows,
            database=tgt.target_db,
        )
        if build_err:
            raise ValueError(f"Seed Validation Error: {build_err}")

        seed_res = self.jdbc.request(
            mode="SEED",
            jdbc_url=tgt.jdbc_url,
            user_spec=tgt.user_spec,
            pass_spec=tgt.pass_spec,
            target_db=tgt.target_db,
            props_text=tgt.props_text,
            timeout_sec=self.query_timeout_sec,
            max_rows=self.max_seed_rows,
            dry_run=dry_run,
            arg1=verify_select_sql,
            arg2=json.dumps(insert_stmts, ensure_ascii=False),
        )
        if not seed_res.get("ok"):
            raise RuntimeError(f"Seed batch failed and rolled back: {seed_res.get('error')}")

        columns = seed_res.get("columns", [])
        inserted_unmasked = seed_res.get("afterRows", [])
        inserted_count = int(seed_res.get("insertedRows", len(inserted_unmasked)))
        masked_rows, masked_cols = self.masker.mask_rows(columns, inserted_unmasked)

        if dry_run:
            return {
                "connection": tgt.display_name,
                "database": tgt.target_db,
                "dry_run": True,
                "committed": False,
                "would_insert_rows": inserted_count,
                "primary_keys": pks,
                "masked_sensitive_columns": masked_cols,
                "columns": columns,
                "preview_rows": masked_rows,
                "cleanup_sql_preview": cleanup_sql,
            }

        clean_where = verify_select_sql.split(" WHERE ", 1)[1]
        backup_paths = self.auditor.create_seed_cleanup_backup(
            connection=tgt.display_name,
            database=tgt.target_db,
            table=table,
            seed_summary=seed_summary,
            insert_statements=insert_stmts,
            cleanup_rollback_sql=cleanup_sql,
            columns=columns,
            inserted_rows_unmasked=inserted_unmasked,
        )
        log_paths = self.auditor.record_audit_log(
            change_id=backup_paths["change_id"],
            channel="DEV_TEST_SEED",
            status="COMMITTED",
            connection=tgt.display_name,
            database=tgt.target_db,
            table=table,
            dml_verb="SEED_INSERT",
            where_clause=clean_where,
            dml_sql=f"INSERT INTO {table} ... ({inserted_count} rows)",
            issue_summary=seed_summary,
            affected_rows=inserted_count,
            columns=columns,
            primary_keys=pks,
            before_rows_unmasked=[],
            after_rows_unmasked=inserted_unmasked,
            backup_paths=backup_paths,
        )

        return {
            "change_id": backup_paths["change_id"],
            "connection": tgt.display_name,
            "database": tgt.target_db,
            "committed": True,
            "inserted_rows": inserted_count,
            "primary_keys": pks,
            "cleanup_where_clause": clean_where,
            "one_click_cleanup_dml": f"DELETE FROM {table} WHERE {clean_where}",
            "masked_sensitive_columns": masked_cols,
            "columns": columns,
            "seeded_rows": masked_rows,
            "backup_bundle_dir": backup_paths["bundle_dir"],
            "cleanup_rollback_sql_path": backup_paths["rollback_sql_path"],
            "audit_log_markdown": log_paths["audit_markdown_path"],
        }

    def tool_scan_recent_db_errors_in_logs(self, args: Dict[str, Any]) -> Dict[str, Any]:
        return scan_db_errors_in_logs(
            project_dir=args.get("project_dir"),
            log_path=args.get("log_path"),
            max_matches=min(int(args.get("max_matches", 15)), 50),
            tail_lines=min(int(args.get("tail_lines", 8000)), 50000),
        )


COMMON_TARGET_PROPS: Dict[str, Any] = {
    "connection": {
        "type": "string",
        "description": "DBeaver connection name or host (e.g. 'localhost', 'staging-db'). Defaults to default_connection.",
    },
    "database": {
        "type": "string",
        "description": "Target database/schema name on that connection.",
    },
}

TOOLS_MANIFEST: List[Dict[str, Any]] = [
    {
        "name": "scan_recent_db_errors_in_logs",
        "description": (
            "Scans application log files in the current workspace (pass project_dir or log_path) "
            "for recent SQL, JPA, Hibernate, constraint, and bad-data exceptions."
        ),
        "annotations": {
            "title": "Scan Logs for DB Errors",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_dir": {"type": "string"},
                "log_path": {"type": "string"},
                "max_matches": {"type": "integer", "default": 15},
                "tail_lines": {"type": "integer", "default": 8000},
            },
        },
    },
    {
        "name": "list_connections",
        "description": (
            "Lists all ready-to-use database connections automatically discovered from local DBeaver "
            "(names, hosts, ports, drivers, SSH tunnel flags) without exposing any credentials."
        ),
        "annotations": {
            "title": "List DBeaver Connections",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "list_databases",
        "description": "Lists all databases / schemas available on a specified DBeaver connection.",
        "annotations": {
            "title": "List Databases on Connection",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "inputSchema": {
            "type": "object",
            "properties": {"connection": COMMON_TARGET_PROPS["connection"]},
        },
    },
    {
        "name": "inspect_schema",
        "description": (
            "Inspects tables, columns, types, nullability, PKs, FKs, and DDL on a DBeaver connection + database. "
            "Pass table='exact_table' for full column/FK/DDL details, or table_pattern='%order%' to search tables."
        ),
        "annotations": {
            "title": "Inspect Database Schema",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_TARGET_PROPS,
                "table": {"type": "string"},
                "table_pattern": {"type": "string"},
                "max_tables": {"type": "integer", "default": 200},
            },
        },
    },
    {
        "name": "explain_query",
        "description": "Runs EXPLAIN on a SELECT query using the specified DBeaver connection + database.",
        "annotations": {
            "title": "Explain SQL Query Plan",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "inputSchema": {
            "type": "object",
            "required": ["sql"],
            "properties": {
                **COMMON_TARGET_PROPS,
                "sql": {"type": "string"},
            },
        },
    },
    {
        "name": "diagnose_query",
        "description": (
            "Executes a single strictly READ-ONLY diagnostic query (SELECT / SHOW / DESCRIBE) using DBeaver's "
            "saved connection inside an engine-enforced READ ONLY transaction with timeout & row caps. "
            "Automatically masks PII columns while preserving length, NULL vs empty, and whitespace anomalies."
        ),
        "annotations": {
            "title": "Run Read-Only Diagnostic SQL",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "inputSchema": {
            "type": "object",
            "required": ["sql"],
            "properties": {
                **COMMON_TARGET_PROPS,
                "sql": {"type": "string"},
                "max_rows": {"type": "integer", "default": 100},
            },
        },
    },
    {
        "name": "preview_remediation",
        "description": (
            "Runs a real transactional dry-run (START TRANSACTION -> pre-SELECT -> DML -> post-SELECT -> ROLLBACK) "
            "using DBeaver's connection WITHOUT committing any change. Returns before/after row diff and generates "
            "a transaction-safe .sql script."
        ),
        "annotations": {
            "title": "Preview Data Remediation (Rolled-Back Dry-Run)",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "inputSchema": {
            "type": "object",
            "required": ["table", "where_clause", "dml_sql"],
            "properties": {
                **COMMON_TARGET_PROPS,
                "issue_summary": {"type": "string"},
                "table": {"type": "string"},
                "where_clause": {"type": "string"},
                "dml_sql": {"type": "string"},
            },
        },
    },
    {
        "name": "open_remediation_in_dbeaver",
        "description": (
            "MANDATORY BACKUP + AUDIT HANDOFF: First backs up original rows (JSON + INSERT SQL + rollback.sql) "
            "to audit-backups/ and appends an audit entry to change-logs/, then opens the transaction-wrapped "
            ".sql script directly in DBeaver bound to that connection for human review and COMMIT."
        ),
        "annotations": {
            "title": "Backup, Log & Open Remediation in DBeaver",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
        "inputSchema": {
            "type": "object",
            "properties": {
                **COMMON_TARGET_PROPS,
                "script_path": {"type": "string"},
                "issue_summary": {"type": "string"},
                "table": {"type": "string"},
                "where_clause": {"type": "string"},
                "dml_sql": {"type": "string"},
            },
        },
    },
    {
        "name": "apply_remediation",
        "description": (
            "MANDATORY BACKUP + AUDIT COMMIT: Persists full original row backups (JSON + INSERT SQL + rollback.sql) "
            "to audit-backups/, executes atomic row-count-locked DML on allowed connections, and logs field-level "
            "changes to change-logs/modification_audit.md & .jsonl."
        ),
        "annotations": {
            "title": "Backup, Log & Apply DB Remediation",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": False,
        },
        "inputSchema": {
            "type": "object",
            "required": ["table", "where_clause", "dml_sql", "expected_affected_rows"],
            "properties": {
                **COMMON_TARGET_PROPS,
                "issue_summary": {"type": "string"},
                "table": {"type": "string"},
                "where_clause": {"type": "string"},
                "dml_sql": {"type": "string"},
                "expected_affected_rows": {"type": "integer"},
            },
        },
    },
    {
        "name": "open_ddl_migration_in_dbeaver",
        "description": (
            "Safe Schema Migration Assistant: Validates CREATE TABLE / ALTER TABLE / CREATE|DROP INDEX "
            "(blocks catastrophic DROP TABLE/DATABASE/TRUNCATE), snapshots existing table DDL to audit-backups/, "
            "optionally writes a project migration file (e.g. Flyway), logs the migration, and opens a review script "
            "with paired reverse rollback DDL in DBeaver for human execution."
        ),
        "annotations": {
            "title": "Snapshot & Open DDL Migration in DBeaver",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
        "inputSchema": {
            "type": "object",
            "required": ["table", "ddl_sql", "rollback_ddl_sql"],
            "properties": {
                **COMMON_TARGET_PROPS,
                "migration_title": {"type": "string", "description": "Short summary of the schema change."},
                "table": {"type": "string", "description": "Target table/view name."},
                "ddl_sql": {"type": "string", "description": "Forward DDL statement(s) (CREATE TABLE / ALTER TABLE / CREATE INDEX)."},
                "rollback_ddl_sql": {"type": "string", "description": "Reverse down-migration DDL to undo the schema change if needed."},
                "migration_file_path": {
                    "type": "string",
                    "description": "Optional path in project (e.g. src/main/resources/db/migration/V2__add_col.sql) to also save the forward DDL.",
                },
            },
        },
    },
    {
        "name": "seed_dev_test_data",
        "description": (
            "Local-Dev-Only Synthetic Test Data Seeder: Atomically inserts structured test row objects (explicit primary keys required, "
            "pre-checked against collisions so existing rows are never overwritten) on allowed local dev connections, and saves a "
            "consolidated 1-click `DELETE ... WHERE pk IN (...)` cleanup script in audit-backups/."
        ),
        "annotations": {
            "title": "Seed Dev Test Data (With 1-Click Cleanup)",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
        "inputSchema": {
            "type": "object",
            "required": ["table", "rows"],
            "properties": {
                **COMMON_TARGET_PROPS,
                "seed_summary": {"type": "string", "description": "Purpose of the seeded test dataset."},
                "table": {"type": "string", "description": "Target table name."},
                "rows": {
                    "type": "array",
                    "description": "List of column->value objects (must include primary key column(s)).",
                    "items": {"type": "object"},
                },
                "dry_run": {"type": "boolean", "default": False, "description": "If true, validates constraints and rolls back without committing."},
            },
        },
    },
    {
        "name": "list_modification_history",
        "description": (
            "Lists chronological database modification audit logs, field diffs, original data backup paths, "
            "and ready-to-run rollback.sql paths."
        ),
        "annotations": {
            "title": "List Modification Logs & Backups",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "default": 20},
                "table": {"type": "string"},
            },
        },
    },
]


class McpStdioServer:
    def __init__(self, app: DbGuardApp) -> None:
        self.app = app
        self.dispatch = {
            "scan_recent_db_errors_in_logs": self.app.tool_scan_recent_db_errors_in_logs,
            "list_connections": self.app.tool_list_connections,
            "list_databases": self.app.tool_list_databases,
            "inspect_schema": self.app.tool_inspect_schema,
            "explain_query": self.app.tool_explain_query,
            "diagnose_query": self.app.tool_diagnose_query,
            "preview_remediation": self.app.tool_preview_remediation,
            "open_remediation_in_dbeaver": self.app.tool_open_remediation_in_dbeaver,
            "apply_remediation": self.app.tool_apply_remediation,
            "open_ddl_migration_in_dbeaver": self.app.tool_open_ddl_migration_in_dbeaver,
            "seed_dev_test_data": self.app.tool_seed_dev_test_data,
            "list_modification_history": self.app.tool_list_modification_history,
        }

    def handle_message(self, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        method = msg.get("method")
        msg_id = msg.get("id")
        params = msg.get("params") or {}

        if msg_id is None:
            return None

        if method == "initialize":
            client_ver = str(params.get("protocolVersion", "2024-11-05"))
            negotiated = client_ver if client_ver in SUPPORTED_PROTOCOL_VERSIONS else "2024-11-05"
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": negotiated,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "db-guard-mcp", "version": __version__},
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS_MANIFEST}}

        if method == "tools/call":
            tool_name = params.get("name", "")
            tool_args = params.get("arguments") or {}
            fn = self.dispatch.get(tool_name)
            if not fn:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
                }
            try:
                result_obj = fn(tool_args)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(result_obj, ensure_ascii=False, indent=2),
                            }
                        ],
                        "isError": False,
                    },
                }
            except Exception as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(
                                    {"ok": False, "error": str(exc)}, ensure_ascii=False, indent=2
                                ),
                            }
                        ],
                        "isError": True,
                    },
                }

        if method in {"resources/list", "prompts/list"}:
            key = "resources" if method == "resources/list" else "prompts"
            return {"jsonrpc": "2.0", "id": msg_id, "result": {key: []}}

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    def serve_forever(self) -> None:
        stdin_bin = sys.stdin.buffer
        stdout_bin = sys.stdout.buffer

        try:
            while True:
                first_line = stdin_bin.readline()
                if not first_line:
                    break
                stripped = first_line.strip()
                if not stripped:
                    continue

                use_content_length = False
                if stripped.lower().startswith(b"content-length:"):
                    use_content_length = True
                    length = int(stripped.split(b":", 1)[1].strip())
                    while True:
                        hdr = stdin_bin.readline()
                        if not hdr or hdr in (b"\r\n", b"\n"):
                            break
                    body = stdin_bin.read(length)
                    msg = json.loads(body.decode("utf-8"))
                else:
                    msg = json.loads(stripped.decode("utf-8"))

                resp = self.handle_message(msg)
                if resp is not None:
                    payload = json.dumps(resp, ensure_ascii=False, separators=(",", ":")).encode(
                        "utf-8"
                    )
                    if use_content_length:
                        header = f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii")
                        stdout_bin.write(header + payload)
                    else:
                        stdout_bin.write(payload + b"\n")
                    stdout_bin.flush()
        finally:
            self.app.jdbc.close()
