"""
CLI entrypoint for copilot-dbeaver-mcp (`copilot-dbeaver-mcp` or `python -m copilot_dbeaver_mcp`).
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Optional, Sequence

from copilot_dbeaver_mcp import __version__
from copilot_dbeaver_mcp.dbeaver_bridge import (
    find_dbeaver_driver_dirs,
    find_dbeaver_exe,
    find_dbeaver_sshj_jars,
    load_dbeaver_connections,
)
from copilot_dbeaver_mcp.server import DbGuardApp, McpStdioServer


def run_doctor(app: DbGuardApp) -> int:
    java_path = shutil.which("java")
    javac_path = shutil.which("javac")
    dbeaver_exe = find_dbeaver_exe(app.dbeaver_exe)
    dbv_meta = load_dbeaver_connections(app.dbeaver_datasources)
    conns = dbv_meta.get("connections") or []

    loaded_drivers = []
    java_bridge_ok = False
    java_err = None
    if java_path and javac_path:
        try:
            ping = app.jdbc.request(mode="PING")
            java_bridge_ok = bool(ping.get("ok"))
            loaded_drivers = ping.get("drivers", [])
        except Exception as exc:
            java_err = str(exc)
        finally:
            app.jdbc.close()

    report = {
        "version": __version__,
        "platform": sys.platform,
        "python": sys.version.split()[0],
        "java": {"java": java_path, "javac": javac_path, "bridge_ready": java_bridge_ok, "error": java_err},
        "loaded_jdbc_drivers": loaded_drivers,
        "dbeaver": {
            "executable": dbeaver_exe,
            "workspace_files": dbv_meta.get("paths", []),
            "credentials_vault_found": dbv_meta.get("credentials_vault_found", False),
            "discovered_connections_count": len(conns),
            "ready_connections_count": sum(1 for c in conns if c.get("save_password")),
            "ssh_tunnel_jars_found": len(find_dbeaver_sshj_jars(app.dbeaver_exe)),
            "driver_cache_dirs": find_dbeaver_driver_dirs(),
        },
        "paths": {
            "config_file": str(app.config_path),
            "storage_root": str(app.storage_root),
            "backup_dir": str(app.auditor.backup_root),
            "audit_log_md": str(app.auditor.md_log_path),
        },
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if java_bridge_ok else 1


def main(argv: Optional[Sequence[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        prog="copilot-dbeaver-mcp",
        description="Zero-password DBeaver MCP Server with read-only isolation, PII masking, mandatory backups, and audit trails.",
    )
    parser.add_argument("--version", action="version", version=f"copilot-dbeaver-mcp {__version__}")
    parser.add_argument("--config", type=str, default=None, help="Path to YAML configuration file.")
    parser.add_argument(
        "--storage-dir",
        type=str,
        default=None,
        help="Directory for backups, change logs, and compiled JDBC bridge (default: ~/.copilot-dbeaver-mcp).",
    )
    parser.add_argument(
        "--doctor",
        action="store_true",
        help="Run local environment, Java/JDBC driver, and DBeaver discovery diagnostics and exit.",
    )

    args = parser.parse_args(argv)
    cfg_path = Path(args.config).expanduser().resolve() if args.config else None
    storage_path = Path(args.storage_dir).expanduser().resolve() if args.storage_dir else None

    app = DbGuardApp(config_path=cfg_path, storage_dir=storage_path)
    if args.doctor:
        raise SystemExit(run_doctor(app))

    server = McpStdioServer(app)
    server.serve_forever()
