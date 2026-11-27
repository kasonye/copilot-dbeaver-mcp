"""
Cross-Platform DBeaver Workspace, Driver, SSH Tunnel, and CLI Bridge
(Supports Windows, macOS, and Linux — including custom install directories, Snap, and Flatpak).
"""

from __future__ import annotations

import datetime as dt
import glob
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


def _discover_windows_dbeaver_from_registry() -> List[str]:
    if sys.platform != "win32":
        return []
    found: List[str] = []
    try:
        import winreg

        reg_roots = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        for hive, subkey in reg_roots:
            try:
                with winreg.OpenKey(hive, subkey) as root_key:
                    count = winreg.QueryInfoKey(root_key)[0]
                    for i in range(count):
                        try:
                            name = winreg.EnumKey(root_key, i)
                            with winreg.OpenKey(root_key, name) as item_key:
                                disp, _ = winreg.QueryValueEx(item_key, "DisplayName")
                                if "dbeaver" not in str(disp).lower():
                                    continue
                                for val_name in ("InstallLocation", "DisplayIcon"):
                                    try:
                                        raw_val, _ = winreg.QueryValueEx(item_key, val_name)
                                        cleaned = str(raw_val).split(",")[0].strip().strip('"')
                                        p = Path(cleaned)
                                        exe = p if p.suffix.lower() == ".exe" else p / "dbeaver.exe"
                                        if exe.is_file() and str(exe) not in found:
                                            found.append(str(exe))
                                    except OSError:
                                        pass
                        except OSError:
                            continue
            except OSError:
                continue
    except Exception:
        pass
    return found


def find_dbeaver_exe(configured_path: Optional[str] = None) -> Optional[str]:
    """Auto-detects DBeaver executable across Windows, macOS, and Linux."""
    if configured_path:
        expanded = os.path.expanduser(os.path.expandvars(configured_path))
        if os.path.isfile(expanded):
            return expanded

    for bin_name in ("dbeaver", "dbeaver-ce", "dbeaver.exe"):
        which_hit = shutil.which(bin_name)
        if which_hit and os.path.isfile(which_hit):
            return which_hit

    candidates: List[str] = []
    if sys.platform == "win32":
        candidates.extend(_discover_windows_dbeaver_from_registry())
        candidates.extend(
            [
                os.path.expandvars(r"%ProgramFiles%\DBeaver\dbeaver.exe"),
                os.path.expandvars(r"%LOCALAPPDATA%\DBeaver\dbeaver.exe"),
                os.path.expandvars(r"%LOCALAPPDATA%\Programs\DBeaver\dbeaver.exe"),
            ]
        )
    elif sys.platform == "darwin":
        candidates.extend(
            [
                "/Applications/DBeaver.app/Contents/MacOS/dbeaver",
                "/Applications/DBeaverEE.app/Contents/MacOS/dbeaver",
                str(Path.home() / "Applications/DBeaver.app/Contents/MacOS/dbeaver"),
            ]
        )
    else:
        candidates.extend(
            [
                "/usr/bin/dbeaver",
                "/usr/bin/dbeaver-ce",
                "/usr/local/bin/dbeaver",
                "/snap/bin/dbeaver-ce",
                "/var/lib/flatpak/exports/bin/io.dbeaver.DBeaverCommunity",
            ]
        )

    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return None


def find_dbeaver_data_roots() -> List[Path]:
    """Returns candidate DBeaverData directories for the current OS."""
    home = Path.home()
    roots: List[Path] = []
    env_override = os.environ.get("DBEAVER_DATA_DIR")
    if env_override:
        roots.append(Path(os.path.expanduser(os.path.expandvars(env_override))))

    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            roots.append(Path(appdata) / "DBeaverData")
    elif sys.platform == "darwin":
        roots.append(home / "Library" / "DBeaverData")
    else:
        xdg_data = Path(os.environ.get("XDG_DATA_HOME", str(home / ".local" / "share")))
        roots.extend(
            [
                xdg_data / "DBeaverData",
                home / "snap" / "dbeaver-ce" / "current" / ".local" / "share" / "DBeaverData",
                home / ".var" / "app" / "io.dbeaver.DBeaverCommunity" / "data" / "DBeaverData",
            ]
        )

    return [r for r in roots if r.is_dir()]


def find_dbeaver_driver_dirs() -> List[str]:
    dirs: List[str] = []
    for root in find_dbeaver_data_roots():
        drv = root / "drivers"
        if drv.is_dir() and str(drv) not in dirs:
            dirs.append(str(drv))
    return dirs


def find_dbeaver_sshj_jars(dbeaver_exe: Optional[str] = None) -> List[str]:
    exe = find_dbeaver_exe(dbeaver_exe)
    plugin_dirs: List[Path] = []
    if exe:
        exe_path = Path(exe).resolve()
        if sys.platform == "darwin":
            # /Applications/DBeaver.app/Contents/MacOS/dbeaver -> ../Eclipse/plugins
            plugin_dirs.append(exe_path.parent.parent / "Eclipse" / "plugins")
        else:
            plugin_dirs.append(exe_path.parent / "plugins")

    if sys.platform.startswith("linux"):
        plugin_dirs.extend(
            [
                Path("/usr/share/dbeaver-ce/plugins"),
                Path("/usr/share/dbeaver/plugins"),
                Path("/usr/lib/dbeaver/plugins"),
                Path("/snap/dbeaver-ce/current/usr/share/dbeaver-ce/plugins"),
            ]
        )

    jars: List[str] = []
    for pdir in plugin_dirs:
        if not pdir.is_dir():
            continue
        for pattern in (
            "org.jkiss.bundle.sshj*/lib/*.jar",
            "slf4j.api*.jar",
            "bcprov*.jar",
        ):
            for match in glob.glob(str(pdir / pattern)):
                if match not in jars:
                    jars.append(match)
    return jars


def discover_datasource_files(configured_path: Optional[str] = None) -> List[Path]:
    """Discovers data-sources.json across General and any custom DBeaver workspace projects."""
    if configured_path:
        expanded = Path(os.path.expanduser(os.path.expandvars(configured_path)))
        if expanded.is_file():
            return [expanded]
        if expanded.is_dir():
            return sorted(expanded.glob("*/.dbeaver/data-sources.json"))

    files: List[Path] = []
    for root in find_dbeaver_data_roots():
        ws = root / "workspace6"
        if not ws.is_dir():
            continue
        general = ws / "General" / ".dbeaver" / "data-sources.json"
        if general.is_file():
            files.append(general)
        for other in sorted(ws.glob("*/.dbeaver/data-sources.json")):
            if other not in files:
                files.append(other)
    return files


def load_dbeaver_connections(datasources_path: Optional[str] = None) -> Dict[str, Any]:
    ds_files = discover_datasource_files(datasources_path)
    if not ds_files:
        return {"found": False, "paths": [], "connections": []}

    conns_out: List[Dict[str, Any]] = []
    scanned_paths: List[str] = []
    any_cred_file = False

    for ds_file in ds_files:
        scanned_paths.append(str(ds_file))
        project_name = ds_file.parent.parent.name
        cred_path = ds_file.parent / "credentials-config.json"
        has_cred_file = cred_path.is_file()
        any_cred_file = any_cred_file or has_cred_file

        try:
            raw = json.loads(ds_file.read_text(encoding="utf-8"))
        except Exception:
            continue

        conn_types = raw.get("connection-types", {})
        for conn_id, info in (raw.get("connections") or {}).items():
            cfg = info.get("configuration") or {}
            ctype = cfg.get("type", "dev")
            ctype_meta = conn_types.get(ctype) or {}
            handlers = cfg.get("handlers") or {}
            ssh_info = handlers.get("ssh_tunnel") or {}
            ssh_enabled = bool(ssh_info.get("enabled"))
            ssh_props = ssh_info.get("properties") or {}
            raw_props = cfg.get("properties") or {}

            conns_out.append(
                {
                    "id": conn_id,
                    "name": info.get("name", conn_id),
                    "workspace_project": project_name,
                    "provider": info.get("provider"),
                    "driver": info.get("driver"),
                    "host": cfg.get("host", ""),
                    "port": str(cfg.get("port", "")),
                    "default_database": cfg.get("database") or "",
                    "jdbc_url": cfg.get("url") or "",
                    "save_password": bool(info.get("save-password", False)) and has_cred_file,
                    "credentials_file": str(cred_path) if has_cred_file else "",
                    "connection_type": ctype,
                    "dbeaver_auto_commit": ctype_meta.get("auto-commit", True),
                    "driver_properties": raw_props,
                    "ssh_tunnel": (
                        {
                            "enabled": True,
                            "bastion_host": str(ssh_props.get("host", "")),
                            "bastion_port": int(ssh_props.get("port", 22)),
                            "auth_type": str(ssh_props.get("authType", "PASSWORD")),
                            "private_key": str(ssh_props.get("keyPath", "")),
                        }
                        if ssh_enabled
                        else {"enabled": False}
                    ),
                }
            )

    return {
        "found": True,
        "paths": scanned_paths,
        "credentials_vault_found": any_cred_file,
        "connections": conns_out,
    }


def write_dbeaver_remediation_script(
    output_dir: Path,
    issue_title: str,
    table: str,
    where_clause: str,
    dml_sql: str,
    rollback_sql: str,
    dbeaver_conn_name: Optional[str] = None,
    database_name: Optional[str] = None,
    expected_rows: Optional[int] = None,
    backup_bundle_dir: Optional[str] = None,
    rollback_sql_path: Optional[str] = None,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    slug = re.sub(r"[^A-Za-z0-9_-]+", "_", issue_title.strip())[:40].strip("_") or "remediation"
    script_path = output_dir / f"{ts}_{slug}.sql"

    exp_note = f"{expected_rows} row(s)" if expected_rows is not None else "verify count before COMMIT"
    conn_note = dbeaver_conn_name or "(select target connection in DBeaver toolbar)"
    use_db_stmt = (
        f"USE `{database_name}`;\n"
        if database_name and re.match(r"^[A-Za-z0-9_$-]+$", database_name)
        else ""
    )
    bkp_note = backup_bundle_dir or "(persisted upon open_remediation_in_dbeaver / apply_remediation)"
    rb_note = rollback_sql_path or "(embedded at bottom of this file)"

    content = f"""-- ============================================================================
-- DB-Guard Safe Remediation Script (Pre-Backed-Up & Audited)
-- Generated At     : {dt.datetime.now().isoformat(timespec="seconds")}
-- Issue Summary    : {issue_title}
-- DBeaver Conn     : {conn_note}
-- Target Database  : {database_name or "(connection default)"}
-- Target Table     : {table}
-- Expected Impact  : {exp_note}
-- Data Backup Dir  : {bkp_note}
-- Rollback SQL File: {rb_note}
-- ============================================================================
-- SAFETY INSTRUCTIONS:
-- 1. Pre-modification original rows are backed up locally to Data Backup Dir.
-- 2. Disables DBeaver's default Auto-Commit and starts a manual transaction.
-- 3. Execute Step 1 -> Step 2 -> Step 3 and verify the modified row(s).
-- 4. Step 4 defaults to ROLLBACK. Highlight and run `COMMIT;` ONLY when satisfied!
-- ============================================================================

{use_db_stmt}SET autocommit = 0;
START TRANSACTION;

-- [Step 1] Inspect target row(s) BEFORE change
SELECT * FROM {table} WHERE {where_clause};

-- [Step 2] Apply targeted remediation DML (Expected: {exp_note})
{dml_sql.rstrip(';')};

-- [Step 3] Verify target row(s) AFTER change inside uncommitted transaction
SELECT * FROM {table} WHERE {where_clause};

-- [Step 4] SAFETY DEFAULT: Rollback unless explicitly committed by human reviewer
ROLLBACK;
-- Highlight and execute the line below ONLY after confirming Step 3:
-- COMMIT;

-- ============================================================================
-- [Emergency Restore / Reverse SQL] (if needed after COMMIT)
-- ============================================================================
{rollback_sql}
"""
    script_path.write_text(content, encoding="utf-8")
    return script_path


def launch_script_in_dbeaver(
    script_path: Path,
    dbeaver_conn_name: Optional[str] = None,
    dbeaver_exe: Optional[str] = None,
) -> Dict[str, Any]:
    exe = find_dbeaver_exe(dbeaver_exe)
    if not exe:
        return {
            "launched": False,
            "script_path": str(script_path),
            "message": "DBeaver executable not found automatically. Open script_path manually in DBeaver.",
        }

    cmd: List[str] = [exe]
    if dbeaver_conn_name:
        cmd.extend(["-con", f"name={dbeaver_conn_name}"])
    cmd.extend(["-f", str(script_path)])

    popen_kwargs: Dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
    }
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = (
            getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        )
    else:
        popen_kwargs["start_new_session"] = True

    try:
        subprocess.Popen(cmd, **popen_kwargs)
        return {
            "launched": True,
            "dbeaver_exe": exe,
            "connection_name": dbeaver_conn_name,
            "script_path": str(script_path),
            "command": cmd,
        }
    except Exception as exc:
        return {
            "launched": False,
            "dbeaver_exe": exe,
            "script_path": str(script_path),
            "error": str(exc),
        }


DB_EXCEPTION_KEYWORDS = re.compile(
    r"(SQLException|SQLSyntaxErrorException|SQLIntegrityConstraintViolationException|"
    r"DataIntegrityViolationException|ConstraintViolationException|DataAccessException|"
    r"BadSqlGrammarException|HibernateException|JdbcSQL|DeadlockLoserDataAccessException|"
    r"CannotAcquireLockException|Incorrect\s+\w+\s+value|Data\s+truncation|"
    r"Column\s+'[^']+'\s+cannot\s+be\s+null|Duplicate\s+entry|foreign\s+key\s+constraint\s+fails|"
    r"TransientPropertyValueException|EntityNotFoundException|OptimisticLockingFailureException|"
    r"ORA-\d{5}|PSQLException)",
    re.IGNORECASE,
)

FRAMEWORK_FRAME_PREFIXES = (
    "java.",
    "javax.",
    "jakarta.",
    "jdk.",
    "sun.",
    "org.springframework.",
    "org.hibernate.",
    "org.apache.",
    "com.zaxxer.",
    "io.netty.",
    "reactor.",
    "org.mariadb.jdbc.",
    "com.mysql.",
    "oracle.jdbc.",
    "org.postgresql.",
    "org.junit.",
)


def scan_db_errors_in_logs(
    project_dir: Optional[str] = None,
    log_path: Optional[str] = None,
    max_matches: int = 15,
    tail_lines: int = 8000,
) -> Dict[str, Any]:
    base_root = Path(project_dir).resolve() if project_dir else Path.cwd().resolve()
    candidate_files: List[Path] = []

    if log_path:
        p = Path(log_path)
        if not p.is_absolute():
            p = base_root / p
        if p.is_file():
            candidate_files.append(p)
        elif p.is_dir():
            candidate_files.extend(
                sorted(p.rglob("*.log"), key=lambda x: x.stat().st_mtime, reverse=True)[:5]
            )
    else:
        for sub in ("logs", "log"):
            ldir = base_root / sub
            if ldir.is_dir():
                candidate_files.extend(
                    sorted(ldir.rglob("*.log"), key=lambda x: x.stat().st_mtime, reverse=True)[:5]
                )
        candidate_files.extend(
            sorted(base_root.glob("*.log"), key=lambda x: x.stat().st_mtime, reverse=True)[:3]
        )

    if not candidate_files:
        return {
            "searched_root": str(base_root),
            "scanned_files": [],
            "matches": [],
            "note": "No .log files found. Pass 'project_dir' or 'log_path' explicitly.",
        }

    findings: List[Dict[str, Any]] = []
    scanned_paths: List[str] = []

    for lf in candidate_files:
        if len(findings) >= max_matches:
            break
        scanned_paths.append(str(lf))
        try:
            with open(lf, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()[-tail_lines:]
        except Exception:
            continue

        idx = 0
        while idx < len(lines) and len(findings) < max_matches:
            line = lines[idx]
            if DB_EXCEPTION_KEYWORDS.search(line):
                start = max(0, idx - 3)
                end = min(len(lines), idx + 22)
                snippet_block = "".join(lines[start:end]).strip()
                all_frames = re.findall(r"at\s+([A-Za-z0-9_.$]+\([^)]+\))", snippet_block)
                app_frames = [
                    fr for fr in all_frames if not fr.startswith(FRAMEWORK_FRAME_PREFIXES)
                ]
                findings.append(
                    {
                        "file": str(lf),
                        "approx_tail_line": idx + 1,
                        "headline": line.strip()[:300],
                        "application_frames": app_frames[:6],
                        "context": snippet_block[:2500],
                    }
                )
                idx = end
            else:
                idx += 1

    return {
        "searched_root": str(base_root),
        "scanned_files": scanned_paths,
        "match_count": len(findings),
        "matches": findings,
    }
