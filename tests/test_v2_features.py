from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from copilot_dbeaver_mcp.pure_aes import DBEAVER_LOCAL_KEY, aes_128_cbc_encrypt_pkcs7
from tests.test_mcp_e2e import call_tool, send_rpc

REPO_ROOT = Path(__file__).resolve().parent.parent


class V2DualEngineAndLineageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="copilot_dbeaver_v2_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_python_fallback_engine_aes_vault_and_trace_record_graph(self) -> None:
        """
        Simulates a host WITHOUT Java by forcing COPILOT_DBEAVER_ENGINE=python:
        1. Decrypts Java-encrypted DBeaver credentials-config.json via pure_aes.py (zero C-deps).
        2. Connects to SQLite via PythonDbBridge.
        3. Verifies trace_record_graph discovers implicit *_id parent/child tables, masks PII,
           and flags ORPHAN_FOREIGN_KEY anomalies in 1 call!
        4. Verifies apply_remediation & rollback_by_change_id work identically on PythonDbBridge.
        """
        sqlite_path = self.tmp_dir / "shop_dev.sqlite"
        conn = sqlite3.connect(str(sqlite_path))
        try:
            conn.executescript(
                """
                CREATE TABLE customers (
                    customer_id INTEGER PRIMARY KEY,
                    customer_name TEXT NOT NULL,
                    mobile_phone TEXT
                );
                CREATE TABLE customer_orders (
                    order_id INTEGER PRIMARY KEY,
                    customer_id INTEGER NOT NULL,
                    order_status TEXT NOT NULL
                );
                CREATE TABLE order_items (
                    item_id INTEGER PRIMARY KEY,
                    order_id INTEGER NOT NULL,
                    sku_code TEXT NOT NULL
                );
                INSERT INTO customers VALUES (1, 'Alice Wong', '13800138000');
                INSERT INTO customer_orders VALUES (101, 1, 'PAID');
                INSERT INTO customer_orders VALUES (102, 999, 'BROKEN_ORPHAN');
                INSERT INTO order_items VALUES (5001, 101, 'SKU-APPLE');
                INSERT INTO order_items VALUES (5002, 101, 'SKU-BOOK');
                INSERT INTO order_items VALUES (5003, 102, 'SKU-GHOST');
                """
            )
            conn.commit()
        finally:
            conn.close()

        dbv_dir = self.tmp_dir / "workspace6" / "General" / ".dbeaver"
        dbv_dir.mkdir(parents=True, exist_ok=True)
        ds_file = dbv_dir / "data-sources.json"
        cred_file = dbv_dir / "credentials-config.json"

        ds_file.write_text(
            json.dumps(
                {
                    "connections": {
                        "sqlite-local-1": {
                            "provider": "sqlite",
                            "driver": "sqlite_jdbc",
                            "name": "localhost",
                            "save-password": True,
                            "configuration": {
                                "host": "localhost",
                                "port": "",
                                "url": f"jdbc:sqlite:{sqlite_path.as_posix()}",
                                "type": "dev",
                            },
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        iv = bytes(range(1, 17))
        plain_creds = json.dumps({"sqlite-local-1": {"#connection": {"user": "", "password": ""}}}).encode("utf-8")
        cred_file.write_bytes(iv + aes_128_cbc_encrypt_pkcs7(plain_creds, DBEAVER_LOCAL_KEY, iv))

        storage_dir = self.tmp_dir / "storage"
        cfg_file = self.tmp_dir / "config.yaml"
        cfg_file.write_text(
            f"""
default_connection: "localhost"
engine: "python"
security:
  allow_direct_apply_connections:
    - "localhost"
dbeaver:
  datasources_json: "{ds_file.as_posix()}"
""",
            encoding="utf-8",
        )

        env = os.environ.copy()
        env["COPILOT_DBEAVER_CONFIG"] = str(cfg_file)
        env["COPILOT_DBEAVER_STORAGE_DIR"] = str(storage_dir)
        env["COPILOT_DBEAVER_ENGINE"] = "python"
        env["PYTHONPATH"] = str(REPO_ROOT)

        proc = subprocess.Popen(
            [sys.executable, "-m", "copilot_dbeaver_mcp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(REPO_ROOT),
            env=env,
        )
        try:
            send_rpc(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-03-26", "capabilities": {}},
                },
            )
            is_err, conns = call_tool(proc, 2, "list_connections", {})
            self.assertFalse(is_err, conns)
            self.assertEqual(conns["active_engine"], "python-fallback")

            # 1. Healthy record lineage graph (order 101 -> parent customer 1 + 2 child order_items)
            is_err, g_ok = call_tool(
                proc,
                3,
                "trace_record_graph",
                {"table": "customer_orders", "primary_key_value": 101},
            )
            self.assertFalse(is_err, g_ok)
            self.assertEqual(g_ok["anomalies_detected"], [])
            self.assertEqual(len(g_ok["parent_relations"]), 1)
            self.assertEqual(g_ok["parent_relations"][0]["parent_table"], "customers")
            # Ensure PII is masked in parent relation!
            self.assertNotIn("Alice Wong", json.dumps(g_ok["parent_relations"][0]["rows"]))
            self.assertEqual(len(g_ok["child_relations"]), 1)
            self.assertEqual(g_ok["child_relations"][0]["child_table"], "order_items")
            self.assertEqual(g_ok["child_relations"][0]["sample_row_count"], 2)

            # 2. Broken record lineage graph (order 102 -> missing customer 999 flagged!)
            is_err, g_bad = call_tool(
                proc,
                4,
                "trace_record_graph",
                {"table": "customer_orders", "primary_key_value": 102},
            )
            self.assertFalse(is_err, g_bad)
            self.assertTrue(
                any("ORPHAN_FOREIGN_KEY" in a and "999" in a for a in g_bad["anomalies_detected"]),
                f"Expected orphan FK anomaly, got: {g_bad['anomalies_detected']}",
            )

            # 3. Remediation + Rollback on PythonDbBridge
            is_err, fixed = call_tool(
                proc,
                5,
                "apply_remediation",
                {
                    "issue_summary": "Reassign orphan order 102 to customer 1",
                    "table": "customer_orders",
                    "where_clause": "order_id = 102",
                    "dml_sql": "UPDATE customer_orders SET customer_id = 1, order_status = 'RECOVERED' WHERE order_id = 102",
                    "expected_affected_rows": 1,
                },
            )
            self.assertFalse(is_err, fixed)

            is_err, rb = call_tool(
                proc,
                6,
                "rollback_by_change_id",
                {"change_id": fixed["change_id"]},
            )
            self.assertFalse(is_err, rb)
            self.assertEqual(rb["restored_or_cleaned_rows"], 1)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            finally:
                for s in (proc.stdin, proc.stdout, proc.stderr):
                    if s is not None:
                        s.close()


if __name__ == "__main__":
    unittest.main()
