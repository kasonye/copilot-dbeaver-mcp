from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from copilot_dbeaver_mcp.server import JdbcBridgeProcess, discover_default_driver_paths

REPO_ROOT = Path(__file__).resolve().parent.parent


def encrypt_dbeaver_credentials_via_java(work_dir: Path, cred_file: Path, plain_json: str) -> None:
    """Cross-platform helper (Windows/macOS/Linux) encrypting test credentials in DBeaver AES-128-CBC format."""
    java_src = work_dir / "VaultTestEnc.java"
    plain_file = work_dir / "plain_creds.json"
    plain_file.write_text(plain_json, encoding="utf-8")
    java_src.write_text(
        """
import java.nio.file.*;
import javax.crypto.Cipher;
import javax.crypto.spec.*;

public class VaultTestEnc {
    public static void main(String[] args) throws Exception {
        byte[] key = new byte[] {
            (byte)0xba, (byte)0xbb, (byte)0x4a, (byte)0x9f,
            (byte)0x77, (byte)0x4a, (byte)0xb8, (byte)0x53,
            (byte)0xc9, (byte)0x6c, (byte)0x2d, (byte)0x65,
            (byte)0x3d, (byte)0xfe, (byte)0x54, (byte)0x4a
        };
        byte[] iv = new byte[] {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        byte[] plain = Files.readAllBytes(Path.of(args[0]));
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] enc = c.doFinal(plain);
        byte[] out = new byte[16 + enc.length];
        System.arraycopy(iv, 0, out, 0, 16);
        System.arraycopy(enc, 0, out, 16, enc.length);
        Files.write(Path.of(args[1]), out);
    }
}
""",
        encoding="utf-8",
    )
    subprocess.run(["javac", "-encoding", "UTF-8", str(java_src)], check=True, timeout=20)
    subprocess.run(
        ["java", "-cp", str(work_dir), "VaultTestEnc", str(plain_file), str(cred_file)],
        check=True,
        timeout=20,
    )


def send_rpc(proc: subprocess.Popen[bytes], msg: dict) -> dict:
    assert proc.stdin is not None and proc.stdout is not None
    raw = json.dumps(msg, ensure_ascii=False).encode("utf-8") + b"\n"
    proc.stdin.write(raw)
    proc.stdin.flush()
    line = proc.stdout.readline()
    if not line:
        err = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
        raise RuntimeError(f"MCP server closed stdout unexpectedly:\n{err}")
    return json.loads(line.decode("utf-8"))


def call_tool(proc: subprocess.Popen[bytes], req_id: int, name: str, arguments: dict) -> tuple[bool, dict]:
    resp = send_rpc(
        proc,
        {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
    )
    res = resp["result"]
    return bool(res.get("isError")), json.loads(res["content"][0]["text"])


class McpEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="copilot_dbeaver_e2e_"))
        self.drivers = discover_default_driver_paths()
        has_h2 = any("h2" in p.lower() for p in self.drivers)
        if not has_h2:
            self.skipTest("H2 JDBC driver jar not found in ~/.m2/repository/com/h2database/h2")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_full_mcp_lifecycle_with_dbeaver_vault_and_mandatory_backups(self) -> None:
        h2_db_path = (self.tmp_dir / "sample_app").as_posix()
        jdbc_url = f"jdbc:h2:file:{h2_db_path};MODE=MariaDB;DATABASE_TO_LOWER=TRUE"

        bridge = JdbcBridgeProcess(self.drivers, compile_dir=self.tmp_dir / "bin")
        bridge.ensure_compiled()
        init_sql = (
            "CREATE TABLE IF NOT EXISTS customer_orders ("
            "order_id INT PRIMARY KEY, "
            "order_code VARCHAR(32) NOT NULL, "
            "order_status VARCHAR(32) NOT NULL, "
            "customer_name VARCHAR(64), "
            "national_id VARCHAR(32)"
            ")\\;"
            "DELETE FROM customer_orders\\;"
            "INSERT INTO customer_orders VALUES "
            "(101, 'ORD-2026-001', 'PAID', 'Jane Doe', 'A123456(7)'), "
            "(102, 'ORD-2026-002', 'CORRUPTED_ENUM_99', 'John Smith  ', 'B987654(3)'), "
            "(103, 'ORD-2026-003', 'ORPHAN_DUPLICATE', 'Bob Martin', 'C112233(4)');"
        )
        seed = bridge.request(
            mode="QUERY",
            jdbc_url=f"{jdbc_url};INIT={init_sql}",
            user_spec="vault_admin",
            pass_spec="VaultPass#2026",
            arg1="SELECT COUNT(*) FROM customer_orders",
        )
        bridge.close()
        self.assertTrue(seed.get("ok"), f"Failed to seed H2 test DB: {seed}")

        # Prepare mock cross-platform DBeaver workspace with AES-encrypted credentials
        dbv_dir = self.tmp_dir / "workspace6" / "General" / ".dbeaver"
        dbv_dir.mkdir(parents=True, exist_ok=True)
        ds_file = dbv_dir / "data-sources.json"
        cred_file = dbv_dir / "credentials-config.json"

        ds_file.write_text(
            json.dumps(
                {
                    "connections": {
                        "local-dev-h2": {
                            "provider": "h2",
                            "driver": "h2_embedded",
                            "name": "localhost",
                            "save-password": True,
                            "configuration": {"host": "localhost", "port": "", "url": jdbc_url, "type": "dev"},
                        },
                        "remote-staging-h2": {
                            "provider": "h2",
                            "driver": "h2_embedded",
                            "name": "staging-db",
                            "save-password": True,
                            "configuration": {"host": "10.0.1.50", "port": "3306", "url": jdbc_url, "type": "dev"},
                        },
                    }
                }
            ),
            encoding="utf-8",
        )
        encrypt_dbeaver_credentials_via_java(
            self.tmp_dir,
            cred_file,
            json.dumps(
                {
                    "local-dev-h2": {"#connection": {"user": "vault_admin", "password": "VaultPass#2026"}},
                    "remote-staging-h2": {"#connection": {"user": "vault_admin", "password": "VaultPass#2026"}},
                }
            ),
        )

        storage_dir = self.tmp_dir / "storage"
        cfg_file = self.tmp_dir / "config.yaml"
        cfg_file.write_text(
            f"""
default_connection: "localhost"
security:
  query_timeout_sec: 5
  default_max_rows: 50
  hard_max_rows: 200
  max_write_rows: 5
  mask_sensitive_data: true
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
            init_resp = send_rpc(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-03-26", "capabilities": {}},
                },
            )
            self.assertEqual(init_resp["result"]["serverInfo"]["name"], "copilot-dbeaver-mcp")

            tools_resp = send_rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            self.assertEqual(len(tools_resp["result"]["tools"]), 12)

            # 1. Read-only query + PII masking on staging-db
            is_err, diag = call_tool(
                proc,
                3,
                "diagnose_query",
                {
                    "connection": "staging-db",
                    "sql": "SELECT order_id, order_status, customer_name, national_id FROM customer_orders WHERE order_id = 102",
                },
            )
            self.assertFalse(is_err, diag)
            row = diag["rows"][0]
            self.assertNotIn("John Smith", str(row[2]))
            self.assertIn("trail_ws=2", str(row[2]))
            self.assertNotIn("B987654", str(row[3]))

            # 2. Preview + DBeaver handoff (passing script_path alone) must persist 3 backup files + audit log
            is_err, prev = call_tool(
                proc,
                4,
                "preview_remediation",
                {
                    "connection": "staging-db",
                    "issue_summary": "Fix invalid enum on order 102",
                    "table": "customer_orders",
                    "where_clause": "order_id = 102",
                    "dml_sql": "UPDATE customer_orders SET order_status = 'PENDING' WHERE order_id = 102",
                },
            )
            self.assertFalse(is_err, prev)
            self.assertFalse(prev["allow_direct_apply"])

            is_err, handoff = call_tool(
                proc,
                5,
                "open_remediation_in_dbeaver",
                {"script_path": prev["generated_dbeaver_script"], "_skip_gui_for_test": True},
            )
            self.assertFalse(is_err, handoff)
            self.assertTrue(Path(handoff["backup_json_path"]).is_file())
            self.assertTrue(Path(handoff["rollback_sql_path"]).is_file())

            # 3. Direct apply blocked on staging-db, allowed on localhost with full backup & audit
            is_err, blocked = call_tool(
                proc,
                6,
                "apply_remediation",
                {
                    "connection": "staging-db",
                    "table": "customer_orders",
                    "where_clause": "order_id = 102",
                    "dml_sql": "UPDATE customer_orders SET order_status = 'PENDING' WHERE order_id = 102",
                    "expected_affected_rows": 1,
                },
            )
            self.assertTrue(is_err)

            is_err, upd = call_tool(
                proc,
                7,
                "apply_remediation",
                {
                    "connection": "localhost",
                    "issue_summary": "Fix corrupted enum on local order 102",
                    "table": "customer_orders",
                    "where_clause": "order_id = 102",
                    "dml_sql": "UPDATE customer_orders SET order_status = 'PENDING' WHERE order_id = 102",
                    "expected_affected_rows": 1,
                },
            )
            self.assertFalse(is_err, upd)
            bkp_data = json.loads(Path(upd["backup_json_path"]).read_text(encoding="utf-8"))
            self.assertIn("John Smith  ", json.dumps(bkp_data["before_rows_unmasked"]))

            # 4. DELETE + lossless restore from generated rollback.sql
            is_err, deleted = call_tool(
                proc,
                8,
                "apply_remediation",
                {
                    "connection": "localhost",
                    "issue_summary": "Remove duplicate row 103",
                    "table": "customer_orders",
                    "where_clause": "order_id = 103",
                    "dml_sql": "DELETE FROM customer_orders WHERE order_id = 103",
                    "expected_affected_rows": 1,
                },
            )
            self.assertFalse(is_err, deleted)
            rb_lines = [
                ln
                for ln in Path(deleted["rollback_sql_path"]).read_text(encoding="utf-8").splitlines()
                if ln.strip().upper().startswith("INSERT INTO")
            ]
            self.assertEqual(len(rb_lines), 1)

            is_err, restored = call_tool(
                proc,
                9,
                "apply_remediation",
                {
                    "connection": "localhost",
                    "issue_summary": "Restore row 103 from backup",
                    "table": "customer_orders",
                    "where_clause": "order_id = 103",
                    "dml_sql": rb_lines[0].rstrip(";"),
                    "expected_affected_rows": 1,
                },
            )
            self.assertFalse(is_err, restored)

            # 5. Test open_ddl_migration_in_dbeaver (blocks DROP TABLE, snapshots schema & writes Flyway file)
            is_err, bad_ddl = call_tool(
                proc,
                10,
                "open_ddl_migration_in_dbeaver",
                {
                    "connection": "localhost",
                    "table": "customer_orders",
                    "ddl_sql": "DROP TABLE customer_orders;",
                    "rollback_ddl_sql": "-- irreversible",
                    "_skip_gui_for_test": True,
                },
            )
            self.assertTrue(is_err)

            flyway_path = self.tmp_dir / "db" / "migration" / "V2__add_order_remark.sql"
            is_err, ddl_handoff = call_tool(
                proc,
                11,
                "open_ddl_migration_in_dbeaver",
                {
                    "connection": "localhost",
                    "migration_title": "Add remark column to customer_orders",
                    "table": "customer_orders",
                    "ddl_sql": "ALTER TABLE customer_orders ADD COLUMN remark VARCHAR(128);",
                    "rollback_ddl_sql": "ALTER TABLE customer_orders DROP COLUMN remark;",
                    "migration_file_path": str(flyway_path),
                    "_skip_gui_for_test": True,
                },
            )
            self.assertFalse(is_err, ddl_handoff)
            self.assertTrue(flyway_path.is_file())
            self.assertTrue(Path(ddl_handoff["rollback_ddl_file"]).is_file())

            # 6. Test seed_dev_test_data (blocked on staging, collision-checked on localhost, 1-click cleanup)
            seed_rows = [
                {
                    "order_id": 9001,
                    "order_code": "SEED-001",
                    "order_status": "REJECTED",
                    "customer_name": "Test User One",
                    "national_id": "A999999(1)",
                },
                {
                    "order_id": 9002,
                    "order_code": "SEED-002",
                    "order_status": "TIMEOUT",
                    "customer_name": "Test User Two",
                    "national_id": "B888888(2)",
                },
            ]
            # Blocked on remote staging-db
            is_err, _ = call_tool(
                proc,
                12,
                "seed_dev_test_data",
                {"connection": "staging-db", "table": "customer_orders", "rows": seed_rows},
            )
            self.assertTrue(is_err)

            # Collision with existing PK 101 must roll back without touching DB
            is_err, collision = call_tool(
                proc,
                13,
                "seed_dev_test_data",
                {
                    "connection": "localhost",
                    "table": "customer_orders",
                    "rows": [
                        {
                            "order_id": 101,
                            "order_code": "COLLIDE",
                            "order_status": "NEW",
                            "customer_name": "Collide",
                            "national_id": "C000000(0)",
                        }
                    ],
                },
            )
            self.assertTrue(is_err)
            self.assertIn("collision", collision.get("error", "").lower())

            # Valid seed batch on localhost
            is_err, seeded = call_tool(
                proc,
                14,
                "seed_dev_test_data",
                {
                    "connection": "localhost",
                    "seed_summary": "Seed rejected & timeout orders for local integration test",
                    "table": "customer_orders",
                    "rows": seed_rows,
                },
            )
            self.assertFalse(is_err, seeded)
            self.assertEqual(seeded["inserted_rows"], 2)
            self.assertNotIn("Test User One", json.dumps(seeded["seeded_rows"]))

            # Execute 1-click batch cleanup using the returned one_click_cleanup_dml!
            is_err, cleaned_up = call_tool(
                proc,
                15,
                "apply_remediation",
                {
                    "connection": "localhost",
                    "issue_summary": "Clean up seeded integration test rows",
                    "table": "customer_orders",
                    "where_clause": seeded["cleanup_where_clause"],
                    "dml_sql": seeded["one_click_cleanup_dml"],
                    "expected_affected_rows": 2,
                },
            )
            self.assertFalse(is_err, cleaned_up)
            _, verify_zero_seed = call_tool(
                proc,
                16,
                "diagnose_query",
                {"sql": f"SELECT COUNT(*) FROM customer_orders WHERE {seeded['cleanup_where_clause']}"},
            )
            self.assertEqual(verify_zero_seed["rows"][0][0], 0)

            # 7. Verify audit ledger masks PII while tracking all 7 operations
            is_err, hist = call_tool(proc, 17, "list_modification_history", {"limit": 20})
            self.assertFalse(is_err, hist)
            self.assertEqual(hist["total_entries"], 7)
            md_ledger = Path(hist["audit_markdown_path"]).read_text(encoding="utf-8")
            self.assertNotIn("John Smith", md_ledger)
            self.assertNotIn("B987654", md_ledger)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            finally:
                for stream in (proc.stdin, proc.stdout, proc.stderr):
                    if stream is not None:
                        stream.close()


if __name__ == "__main__":
    unittest.main()
