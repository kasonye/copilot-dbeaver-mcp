"""
Pure-Python Fallback Database Engine (`PythonDbBridge`).

Provides a zero-JDK fallback when `java` / `javac` are not installed on the host machine:
  - SQLite (`jdbc:sqlite:...`): Built-in Python `sqlite3` (zero external dependencies!)
  - MySQL / MariaDB (`jdbc:mysql:...`, `jdbc:mariadb:...`): Uses `pymysql` if installed
  - PostgreSQL (`jdbc:postgresql:...`): Uses `psycopg` (v3) or `psycopg2` if installed

Implements the exact same `.request(mode=..., ...)` & `.close()` contract as `JdbcBridgeProcess`.
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from copilot_dbeaver_mcp.pure_aes import decrypt_dbeaver_credentials_in_memory


def _resolve_py_credentials(user_spec: str, pass_spec: str) -> Tuple[str, str]:
    if user_spec and user_spec.startswith("@DBEAVER:"):
        payload = user_spec[len("@DBEAVER:") :]
        conn_id, _, cred_file = payload.partition("|")
        if pass_spec and pass_spec.startswith("@SSH:"):
            raise RuntimeError(
                "SSH tunnel connections require either JDK 17+ (to use DBeaver's SSHJ tunnel) "
                "or a pre-established local SSH port-forward."
            )
        vault = decrypt_dbeaver_credentials_in_memory(cred_file)
        db_auth = (vault.get(conn_id) or {}).get("#connection") or {}
        return str(db_auth.get("user") or ""), str(db_auth.get("password") or "")
    return user_spec or "", pass_spec or ""


def _parse_host_port_db(jdbc_url: str, prefix: str, default_port: int) -> Tuple[str, int, str]:
    rest = jdbc_url[len(prefix) :]
    if rest.startswith("//"):
        rest = rest[2:]
    parsed = urllib.parse.urlsplit("http://" + rest)
    host = parsed.hostname or "localhost"
    port = parsed.port or default_port
    db = (parsed.path or "").lstrip("/")
    return host, port, db


class PythonDbBridge:
    """Drop-in pure-Python peer of JdbcBridgeProcess for machines without a JDK."""

    engine_name = "python-fallback"

    def __init__(self) -> None:
        self._drivers = ["sqlite3 (stdlib)"]
        try:
            import pymysql  # noqa: F401

            self._drivers.append("pymysql")
        except ImportError:
            pass
        for pg_mod in ("psycopg", "psycopg2"):
            try:
                __import__(pg_mod)
                self._drivers.append(pg_mod)
                break
            except ImportError:
                pass

    def close(self) -> None:
        pass

    def _open_conn(
        self, jdbc_url: str, user_spec: str, pass_spec: str, target_db: str, timeout_sec: int, readonly: bool
    ) -> Tuple[str, Any]:
        user, password = _resolve_py_credentials(user_spec, pass_spec)
        low = jdbc_url.lower()

        if low.startswith("jdbc:sqlite:"):
            raw_path = jdbc_url[len("jdbc:sqlite:") :].split("?")[0]
            conn = sqlite3.connect(raw_path, timeout=max(3, timeout_sec), isolation_level=None)
            if readonly:
                conn.execute("PRAGMA query_only = ON")
            conn.execute("BEGIN")
            return "sqlite", conn

        if low.startswith("jdbc:mysql:") or low.startswith("jdbc:mariadb:"):
            prefix = "jdbc:mysql:" if low.startswith("jdbc:mysql:") else "jdbc:mariadb:"
            try:
                import pymysql
            except ImportError as exc:
                raise RuntimeError(
                    "Neither JDK (java/javac) nor 'pymysql' is installed. "
                    "Install PyMySQL (`pip install pymysql`) or JDK 17+ to connect to MySQL/MariaDB."
                ) from exc
            host, port, url_db = _parse_host_port_db(jdbc_url, prefix, 3306)
            eff_db = target_db or url_db or None
            conn = pymysql.connect(
                host=host,
                port=port,
                user=user,
                password=password,
                database=eff_db,
                connect_timeout=max(3, timeout_sec),
                read_timeout=max(3, timeout_sec),
                write_timeout=max(3, timeout_sec),
                autocommit=False,
                charset="utf8mb4",
            )
            if readonly:
                with conn.cursor() as cur:
                    cur.execute("SET SESSION TRANSACTION READ ONLY")
            return "mysql", conn

        if low.startswith("jdbc:postgresql:"):
            host, port, url_db = _parse_host_port_db(jdbc_url, "jdbc:postgresql:", 5432)
            eff_db = target_db or url_db or "postgres"
            try:
                import psycopg  # type: ignore

                conn = psycopg.connect(
                    host=host,
                    port=port,
                    user=user,
                    password=password,
                    dbname=eff_db,
                    connect_timeout=max(3, timeout_sec),
                    autocommit=False,
                )
                if readonly:
                    conn.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
                return "postgres", conn
            except ImportError:
                try:
                    import psycopg2  # type: ignore

                    conn = psycopg2.connect(
                        host=host,
                        port=port,
                        user=user,
                        password=password,
                        dbname=eff_db,
                        connect_timeout=max(3, timeout_sec),
                    )
                    conn.autocommit = False
                    if readonly:
                        with conn.cursor() as cur:
                            cur.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
                    return "postgres", conn
                except ImportError as exc:
                    raise RuntimeError(
                        "Neither JDK (java/javac) nor 'psycopg' is installed. "
                        "Install psycopg (`pip install psycopg[binary]`) or JDK 17+ for PostgreSQL."
                    ) from exc

        raise RuntimeError(
            f"JDBC URL '{jdbc_url.split('?')[0]}' requires JDK 17+ (JdbcBridge) for vendor JDBC drivers."
        )

    @staticmethod
    def _read_cursor(cur: Any, cap: int) -> Tuple[List[Dict[str, str]], List[List[Any]], bool]:
        desc = cur.description or []
        cols = [{"name": str(d[0]), "type": str(getattr(d[1], "__name__", d[1] or "TEXT"))} for d in desc]
        fetched = cur.fetchmany(cap + 1)
        truncated = len(fetched) > cap
        rows_raw = fetched[:cap]
        rows_out: List[List[Any]] = []
        for r in rows_raw:
            row_vals: List[Any] = []
            for v in r:
                if v is None or isinstance(v, (int, float, bool)):
                    row_vals.append(v)
                elif isinstance(v, (bytes, bytearray, memoryview)):
                    row_vals.append(f"[BLOB {len(v)} bytes]")
                else:
                    s = str(v)
                    row_vals.append(s[:4000] + f"...[TRUNCATED len={len(s)}]" if len(s) > 4000 else s)
            rows_out.append(row_vals)
        return cols, rows_out, truncated

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
        if mode == "PING":
            return {"ok": True, "drivers": list(self._drivers)}

        try:
            if mode == "LIST_DBS":
                return self._handle_list_dbs(jdbc_url, user_spec, pass_spec, target_db, timeout_sec)
            if mode == "SCHEMA":
                return self._handle_schema(jdbc_url, user_spec, pass_spec, target_db, timeout_sec, max_rows, arg2)
            if mode == "BULK_SCHEMA":
                return self._handle_bulk_schema(jdbc_url, user_spec, pass_spec, target_db, timeout_sec, max_rows, arg2)
            if mode == "QUERY":
                return self._handle_query(jdbc_url, user_spec, pass_spec, target_db, timeout_sec, max_rows, arg1)
            if mode == "REMEDIATE":
                return self._handle_remediate(
                    jdbc_url, user_spec, pass_spec, target_db, timeout_sec, max_rows, dry_run, expected_rows, arg1, arg2
                )
            if mode == "SEED":
                return self._handle_seed(
                    jdbc_url, user_spec, pass_spec, target_db, timeout_sec, max_rows, dry_run, arg1, arg2
                )
            if mode == "EXEC_BATCH":
                return self._handle_exec_batch(jdbc_url, user_spec, pass_spec, target_db, timeout_sec, dry_run, arg1)
            return {"ok": False, "error": f"Unsupported mode in PythonDbBridge: {mode}"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def _handle_list_dbs(
        self, jdbc_url: str, user_spec: str, pass_spec: str, target_db: str, timeout_sec: int
    ) -> Dict[str, Any]:
        kind, conn = self._open_conn(jdbc_url, user_spec, pass_spec, target_db, timeout_sec, readonly=True)
        try:
            cur = conn.cursor()
            if kind == "sqlite":
                return {"ok": True, "productName": "SQLite", "currentDatabase": "main", "databases": ["main"]}
            if kind == "mysql":
                cur.execute("SHOW DATABASES")
                dbs = [r[0] for r in cur.fetchall()]
                return {"ok": True, "productName": "MySQL/MariaDB", "currentDatabase": target_db, "databases": dbs}
            cur.execute("SELECT datname FROM pg_database WHERE datistemplate = false")
            dbs = [r[0] for r in cur.fetchall()]
            return {"ok": True, "productName": "PostgreSQL", "currentDatabase": target_db, "databases": dbs}
        finally:
            try:
                conn.rollback()
            except Exception:
                pass
            conn.close()

    def _sqlite_table_details(self, cur: Any, table_name: str) -> Dict[str, Any]:
        cur.execute(f'PRAGMA table_info("{table_name}")')
        pks: List[str] = []
        cols: List[Dict[str, Any]] = []
        for cid, name, ctype, notnull, dflt, pk in cur.fetchall():
            is_pk = bool(pk)
            if is_pk:
                pks.append(name)
            cols.append(
                {
                    "name": name,
                    "type": ctype or "TEXT",
                    "size": 0,
                    "nullable": not bool(notnull),
                    "defaultValue": dflt,
                    "primaryKey": is_pk,
                    "remarks": None,
                }
            )
        fks: List[Dict[str, Any]] = []
        cur.execute(f'PRAGMA foreign_key_list("{table_name}")')
        for row in cur.fetchall():
            fks.append({"fkColumn": row[3], "pkTable": row[2], "pkColumn": row[4], "fkName": f"fk_{row[0]}"})

        indexes: List[Dict[str, Any]] = []
        cur.execute(f'PRAGMA index_list("{table_name}")')
        for idx_row in cur.fetchall():
            idx_name, is_unique, origin = idx_row[1], bool(idx_row[2]), idx_row[3]
            if origin == "pk" or str(idx_name).startswith("sqlite_autoindex_"):
                continue
            cur.execute(f'PRAGMA index_info("{idx_name}")')
            icols = [ir[2] for ir in cur.fetchall()]
            if icols:
                indexes.append({"name": idx_name, "unique": is_unique, "columns": icols})

        cur.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
        ddl_row = cur.fetchone()
        return {
            "primaryKeys": pks,
            "columns": cols,
            "foreignKeys": fks,
            "indexes": indexes,
            "ddl": ddl_row[0] if ddl_row else None,
        }

    def _handle_schema(
        self, jdbc_url: str, user_spec: str, pass_spec: str, target_db: str, timeout_sec: int, max_rows: int, table_target: str
    ) -> Dict[str, Any]:
        kind, conn = self._open_conn(jdbc_url, user_spec, pass_spec, target_db, timeout_sec, readonly=True)
        try:
            cur = conn.cursor()
            exact = bool(table_target and "%" not in table_target)
            if kind == "sqlite":
                if not exact:
                    pat = table_target or "%"
                    cur.execute(
                        "SELECT name, type FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' AND name LIKE ?",
                        (pat,),
                    )
                    tables = [{"catalog": None, "schema": "main", "name": r[0], "type": r[1].upper(), "remarks": None} for r in cur.fetchmany(max_rows)]
                    return {"ok": True, "productName": "SQLite", "productVersion": sqlite3.sqlite_version, "activeDatabase": "main", "tables": tables}
                det = self._sqlite_table_details(cur, table_target)
                return {"ok": True, "productName": "SQLite", "productVersion": sqlite3.sqlite_version, "activeDatabase": "main", "table": table_target, **det}

            # MySQL / PostgreSQL information_schema path
            schema_filter = target_db
            if kind == "postgres" and not schema_filter:
                schema_filter = "public"
            if not exact:
                pat = table_target or "%"
                if kind == "mysql":
                    cur.execute(
                        "SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE, TABLE_COMMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME LIKE %s LIMIT %s",
                        (pat, max_rows),
                    )
                else:
                    cur.execute(
                        "SELECT table_schema, table_name, table_type, '' FROM information_schema.tables WHERE table_schema = %s AND table_name LIKE %s LIMIT %s",
                        (schema_filter, pat, max_rows),
                    )
                tables = [{"catalog": r[0], "schema": r[0], "name": r[1], "type": r[2], "remarks": r[3]} for r in cur.fetchall()]
                return {"ok": True, "productName": kind, "productVersion": "", "activeDatabase": schema_filter, "tables": tables}

            if kind == "mysql":
                cur.execute(
                    "SELECT COLUMN_NAME, DATA_TYPE, COALESCE(CHARACTER_MAXIMUM_LENGTH, 0), IS_NULLABLE, COLUMN_DEFAULT, COLUMN_KEY, COLUMN_COMMENT "
                    "FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s ORDER BY ORDINAL_POSITION",
                    (table_target,),
                )
                pks = []
                cols = []
                for r in cur.fetchall():
                    is_pk = (r[5] == "PRI")
                    if is_pk:
                        pks.append(r[0])
                    cols.append({"name": r[0], "type": r[1].upper(), "size": int(r[2] or 0), "nullable": r[3] == "YES", "defaultValue": r[4], "primaryKey": is_pk, "remarks": r[6]})
                cur.execute(
                    "SELECT COLUMN_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME, CONSTRAINT_NAME "
                    "FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND REFERENCED_TABLE_NAME IS NOT NULL",
                    (table_target,),
                )
                fks = [{"fkColumn": r[0], "pkTable": r[1], "pkColumn": r[2], "fkName": r[3]} for r in cur.fetchall()]
                return {"ok": True, "productName": "MySQL", "productVersion": "", "activeDatabase": target_db, "table": table_target, "primaryKeys": pks, "columns": cols, "foreignKeys": fks, "indexes": [], "ddl": None}

            # Postgres exact table
            cur.execute(
                "SELECT column_name, data_type, COALESCE(character_maximum_length, 0), is_nullable, column_default "
                "FROM information_schema.columns WHERE table_schema = %s AND table_name = %s ORDER BY ordinal_position",
                (schema_filter, table_target),
            )
            cols = [{"name": r[0], "type": r[1].upper(), "size": int(r[2] or 0), "nullable": r[3] == "YES", "defaultValue": r[4], "primaryKey": False, "remarks": None} for r in cur.fetchall()]
            return {"ok": True, "productName": "PostgreSQL", "productVersion": "", "activeDatabase": schema_filter, "table": table_target, "primaryKeys": [], "columns": cols, "foreignKeys": [], "indexes": [], "ddl": None}
        finally:
            try:
                conn.rollback()
            except Exception:
                pass
            conn.close()

    def _handle_bulk_schema(
        self, jdbc_url: str, user_spec: str, pass_spec: str, target_db: str, timeout_sec: int, max_tables: int, table_pattern: str
    ) -> Dict[str, Any]:
        sres = self._handle_schema(jdbc_url, user_spec, pass_spec, target_db, timeout_sec, max_tables, table_pattern or "%")
        if not sres.get("ok"):
            return sres
        tables_out: Dict[str, Any] = {}
        for t in sres.get("tables") or []:
            tname = t["name"]
            det = self._handle_schema(jdbc_url, user_spec, pass_spec, target_db, timeout_sec, max_tables, tname)
            if det.get("ok"):
                tables_out[tname] = {
                    "primaryKeys": det.get("primaryKeys", []),
                    "indexes": det.get("indexes", []),
                    "columns": det.get("columns", []),
                }
        return {"ok": True, "productName": sres.get("productName"), "activeDatabase": sres.get("activeDatabase"), "tables": tables_out}

    def _handle_query(
        self, jdbc_url: str, user_spec: str, pass_spec: str, target_db: str, timeout_sec: int, max_rows: int, sql: str
    ) -> Dict[str, Any]:
        cap = max(1, min(max_rows, 500))
        _, conn = self._open_conn(jdbc_url, user_spec, pass_spec, target_db, timeout_sec, readonly=True)
        try:
            cur = conn.cursor()
            t0 = time.perf_counter()
            cur.execute(sql)
            elapsed_ms = int((time.perf_counter() - t0) * 1000)
            cols, rows, truncated = self._read_cursor(cur, cap)
            return {
                "ok": True,
                "elapsedMs": elapsed_ms,
                "activeDatabase": target_db,
                "truncated": truncated,
                "rowCount": len(rows),
                "columns": cols,
                "rows": rows,
            }
        finally:
            try:
                conn.rollback()
            except Exception:
                pass
            conn.close()

    def _handle_remediate(
        self,
        jdbc_url: str,
        user_spec: str,
        pass_spec: str,
        target_db: str,
        timeout_sec: int,
        max_write_rows: int,
        dry_run: bool,
        expected_rows: int,
        select_sql: str,
        dml_sql: str,
    ) -> Dict[str, Any]:
        cap = max(1, min(max_write_rows, 100))
        _, conn = self._open_conn(jdbc_url, user_spec, pass_spec, target_db, timeout_sec, readonly=False)
        committed = False
        try:
            cur = conn.cursor()
            cur.execute(select_sql)
            cols, before_rows, truncated = self._read_cursor(cur, cap)
            if truncated:
                conn.rollback()
                return {"ok": False, "error": f"WHERE matched more than max_write_rows ({cap}). Rolled back."}

            cur.execute(dml_sql)
            affected = int(cur.rowcount if cur.rowcount is not None and cur.rowcount >= 0 else 0)
            if affected > cap:
                conn.rollback()
                return {"ok": False, "error": f"DML affected {affected} > max_write_rows ({cap}). Rolled back."}
            if not dry_run and expected_rows >= 0 and affected != expected_rows:
                conn.rollback()
                return {"ok": False, "error": f"Row-count lock mismatch: expected {expected_rows}, affected {affected}. Rolled back."}

            cur.execute(select_sql)
            _, after_rows, _ = self._read_cursor(cur, cap)

            if dry_run:
                conn.rollback()
            else:
                conn.commit()
                committed = True

            return {
                "ok": True,
                "dryRun": dry_run,
                "committed": committed,
                "affectedRows": affected,
                "columns": cols,
                "beforeRows": before_rows,
                "afterRows": after_rows,
            }
        finally:
            if not committed:
                try:
                    conn.rollback()
                except Exception:
                    pass
            conn.close()

    def _handle_seed(
        self,
        jdbc_url: str,
        user_spec: str,
        pass_spec: str,
        target_db: str,
        timeout_sec: int,
        max_seed_rows: int,
        dry_run: bool,
        verify_select_sql: str,
        batch_inserts_json: str,
    ) -> Dict[str, Any]:
        cap = max(1, min(max_seed_rows, 200))
        insert_list = json.loads(batch_inserts_json)
        _, conn = self._open_conn(jdbc_url, user_spec, pass_spec, target_db, timeout_sec, readonly=False)
        committed = False
        try:
            cur = conn.cursor()
            cur.execute(verify_select_sql)
            _, existing, _ = self._read_cursor(cur, cap)
            if existing:
                conn.rollback()
                return {"ok": False, "error": f"Seed collision detected: {len(existing)} row(s) already exist."}

            total = 0
            for stmt in insert_list:
                cur.execute(stmt)
                total += int(cur.rowcount if cur.rowcount and cur.rowcount > 0 else 1)

            cur.execute(verify_select_sql)
            cols, after_rows, _ = self._read_cursor(cur, cap)
            if dry_run:
                conn.rollback()
            else:
                conn.commit()
                committed = True
            return {"ok": True, "dryRun": dry_run, "committed": committed, "insertedRows": total, "columns": cols, "afterRows": after_rows}
        finally:
            if not committed:
                try:
                    conn.rollback()
                except Exception:
                    pass
            conn.close()

    def _handle_exec_batch(
        self, jdbc_url: str, user_spec: str, pass_spec: str, target_db: str, timeout_sec: int, dry_run: bool, statements_json: str
    ) -> Dict[str, Any]:
        stmt_list = json.loads(statements_json)
        _, conn = self._open_conn(jdbc_url, user_spec, pass_spec, target_db, timeout_sec, readonly=False)
        committed = False
        try:
            cur = conn.cursor()
            total = 0
            for st in stmt_list:
                cur.execute(st)
                total += int(cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0)
            if dry_run:
                conn.rollback()
            else:
                conn.commit()
                committed = True
            return {"ok": True, "dryRun": dry_run, "committed": committed, "statementCount": len(stmt_list), "affectedRows": total}
        finally:
            if not committed:
                try:
                    conn.rollback()
                except Exception:
                    pass
            conn.close()
