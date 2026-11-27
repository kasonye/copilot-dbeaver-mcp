from __future__ import annotations

import unittest

from copilot_dbeaver_mcp.sql_guard import (
    DynamicDataMasker,
    build_insert_backup_sql,
    build_rollback_sql,
    build_seed_batch_sql,
    infer_sql_dialect,
    validate_ddl_migration_sql,
    validate_readonly_sql,
    validate_remediation_sql,
)


class SqlGuardUnitTests(unittest.TestCase):
    def test_valid_readonly_queries(self) -> None:
        for sql in [
            "SELECT id, status FROM orders WHERE id = 42;",
            "WITH recent AS (SELECT id FROM orders LIMIT 10) SELECT * FROM recent",
            "SHOW CREATE TABLE orders",
            "EXPLAIN SELECT * FROM orders WHERE customer_id = 7",
        ]:
            cleaned, err = validate_readonly_sql(sql)
            self.assertIsNone(err, f"Unexpected error for {sql}: {err}")
            self.assertTrue(cleaned)

    def test_blocks_dangerous_readonly_queries(self) -> None:
        dangerous = [
            "SELECT 1; DROP TABLE orders",
            "DELETE FROM orders WHERE id = 1",
            "UPDATE orders SET status = 'PAID' WHERE id = 1",
            "WITH del AS (DELETE FROM orders RETURNING *) SELECT * FROM del",
            "SELECT /*!50000 DROP TABLE orders */ 1",
            "SELECT * FROM orders FOR UPDATE",
            "SELECT * INTO OUTFILE '/tmp/dump.csv' FROM orders",
            "SELECT SLEEP(10)",
            "SELECT LOAD_FILE('/etc/passwd')",
        ]
        for sql in dangerous:
            _, err = validate_readonly_sql(sql)
            self.assertIsNotNone(err, f"Failed to block dangerous query: {sql}")

    def test_remediation_validation_rules(self) -> None:
        sel, dml, err = validate_remediation_sql(
            "orders",
            "order_id = 1001",
            "UPDATE orders SET status = 'CANCELLED' WHERE order_id = 1001;",
        )
        self.assertIsNone(err)
        self.assertEqual(sel, "SELECT * FROM orders WHERE order_id = 1001")
        self.assertEqual(dml, "UPDATE orders SET status = 'CANCELLED' WHERE order_id = 1001")

        # Block tautology & missing WHERE & DDL
        for bad_where, bad_dml in [
            ("1=1", "UPDATE orders SET status = 'PAID' WHERE 1=1"),
            ("TRUE", "DELETE FROM orders WHERE TRUE"),
            ("order_id = 1 OR 1=1", "DELETE FROM orders WHERE order_id = 1 OR 1=1"),
            ("order_id > 0", "UPDATE orders SET status = 'PAID' WHERE order_id > 0"),
            ("order_id = 1", "UPDATE orders SET status = 'PAID'"),
            ("order_id = 1", "TRUNCATE TABLE orders"),
        ]:
            _, _, b_err = validate_remediation_sql("orders", bad_where, bad_dml)
            self.assertIsNotNone(b_err, f"Failed to block unsafe remediation: {bad_dml}")

    def test_dynamic_pii_masking_preserves_anomalies(self) -> None:
        masker = DynamicDataMasker(enabled=True)
        cols = [
            {"name": "order_id", "type": "INT"},
            {"name": "status_name", "type": "VARCHAR"},
            {"name": "customer_name", "type": "VARCHAR"},
            {"name": "email", "type": "VARCHAR"},
            {"name": "notes", "type": "VARCHAR"},
        ]
        rows = [
            [101, "PENDING_REVIEW", "Alice Walker  ", "alice@example.com", "A123456(7)"],
            [102, "ACTIVE", "", None, "normal note"],
        ]
        masked, masked_cols = masker.mask_rows(cols, rows)
        self.assertEqual(masked_cols, ["customer_name", "email"])
        self.assertEqual(masked[0][0], 101)
        # Exempt technical column status_name stays readable
        self.assertEqual(masked[0][1], "PENDING_REVIEW")
        # Trailing whitespace anomaly preserved while name is masked
        self.assertNotIn("Alice", masked[0][2])
        self.assertIn("trail_ws=2", masked[0][2])
        # Email masked
        self.assertNotIn("alice@example.com", masked[0][3])
        # Value-level ID pattern detected even in generic 'notes' column
        self.assertIn("MASKED:HKID_LIKE", masked[0][4])
        # Empty string vs None preserved
        self.assertEqual(masked[1][2], "")
        self.assertIsNone(masked[1][3])

    def test_rollback_and_insert_builders(self) -> None:
        cols = [{"name": "order_id", "type": "INT"}, {"name": "status", "type": "VARCHAR"}]
        before = [[55, "BROKEN_STATE"]]
        after = [[55, "FIXED_STATE"]]

        upd_rb = build_rollback_sql(
            "orders", cols, before, after, primary_keys=["order_id"], dml_verb="UPDATE"
        )
        self.assertIn("UPDATE orders SET `status` = 'BROKEN_STATE' WHERE `order_id` = 55;", upd_rb)

        del_rb = build_rollback_sql(
            "orders", cols, before, [], primary_keys=["order_id"], dml_verb="DELETE"
        )
        self.assertIn("INSERT INTO orders (`order_id`, `status`) VALUES (55, 'BROKEN_STATE');", del_rb)

        ins_rb = build_rollback_sql(
            "orders", cols, [], after, primary_keys=["order_id"], dml_verb="INSERT"
        )
        self.assertIn("DELETE FROM orders WHERE `order_id` = 55;", ins_rb)

        cold_sql = build_insert_backup_sql("orders", cols, before, database="shop_db")
        self.assertIn("USE `shop_db`;", cold_sql)
        self.assertIn("INSERT INTO orders", cold_sql)

    def test_ddl_migration_validator(self) -> None:
        stmts, warns, err = validate_ddl_migration_sql(
            "ALTER TABLE orders ADD COLUMN remark VARCHAR(128);\nCREATE INDEX idx_orders_status ON orders(status);"
        )
        self.assertIsNone(err)
        self.assertEqual(len(stmts), 2)
        self.assertEqual(warns, [])

        # DROP COLUMN allowed with high-risk warning
        _, drop_col_warns, err2 = validate_ddl_migration_sql("ALTER TABLE orders DROP COLUMN legacy_flag;")
        self.assertIsNone(err2)
        self.assertTrue(any("DROP COLUMN" in w for w in drop_col_warns))

        # Catastrophic DDL & DML blocked
        for bad_ddl in [
            "DROP TABLE orders;",
            "DROP DATABASE prod;",
            "TRUNCATE TABLE orders;",
            "DELETE FROM orders WHERE id = 1;",
            "GRANT ALL ON orders TO 'u'@'%';",
        ]:
            _, _, b_err = validate_ddl_migration_sql(bad_ddl)
            self.assertIsNotNone(b_err, f"Failed to block unsafe DDL: {bad_ddl}")

    def test_seed_batch_builder(self) -> None:
        ins, sel, cleanup, err = build_seed_batch_sql(
            table="orders",
            rows=[
                {"order_id": 9001, "status": "PENDING"},
                {"order_id": 9002, "status": "SHIPPED"},
            ],
            primary_keys=["order_id"],
        )
        self.assertIsNone(err)
        self.assertEqual(len(ins), 2)
        self.assertEqual(sel, "SELECT * FROM orders WHERE `order_id` IN (9001, 9002)")
        self.assertIn("DELETE FROM orders WHERE `order_id` IN (9001, 9002);", cleanup)

        # Missing PK column in seed rows must error
        _, _, _, pk_err = build_seed_batch_sql(
            table="orders",
            rows=[{"status": "PENDING"}],
            primary_keys=["order_id"],
        )
        self.assertIsNotNone(pk_err)

    def test_multi_dialect_quoting_and_rollback(self) -> None:
        self.assertEqual(infer_sql_dialect("jdbc:postgresql://localhost:5432/app"), "postgres")
        self.assertEqual(infer_sql_dialect("jdbc:oracle:thin:@//127.0.0.1:1521/orcl"), "oracle")
        self.assertEqual(infer_sql_dialect("jdbc:sqlserver://localhost:1433;databaseName=db"), "mssql")

        cols = [{"name": "order_id", "type": "INT"}, {"name": "is_active", "type": "BOOLEAN"}]
        before = [[77, True]]

        pg_rb = build_rollback_sql(
            "orders", cols, before, primary_keys=["order_id"], dml_verb="UPDATE", database="public", dialect="postgres"
        )
        self.assertIn('SET search_path TO "public";', pg_rb)
        self.assertIn('UPDATE orders SET "is_active" = TRUE WHERE "order_id" = 77;', pg_rb)

        ms_rb = build_rollback_sql(
            "orders", cols, before, primary_keys=["order_id"], dml_verb="UPDATE", database="sales", dialect="mssql"
        )
        self.assertIn("USE [sales];", ms_rb)
        self.assertIn("UPDATE orders SET [is_active] = 1 WHERE [order_id] = 77;", ms_rb)

    def test_recursive_json_and_camelcase_pii_masking(self) -> None:
        masker = DynamicDataMasker(enabled=True)
        cols = [
            {"name": "id", "type": "INT"},
            {"name": "customerName", "type": "VARCHAR"},
            {"name": "ext_payload", "type": "JSON"},
        ]
        payload = '{"channel":"WEB","profile":{"mobilePhone":"13800138000","idCardNo":"A123456(7)","vipLevel":3}}'
        rows = [[1, "Jane Doe", payload]]
        masked, masked_cols = masker.mask_rows(cols, rows)
        self.assertEqual(masked_cols, ["customerName"])
        self.assertNotIn("Jane Doe", str(masked[0][1]))
        masked_json = str(masked[0][2])
        self.assertNotIn("13800138000", masked_json)
        self.assertNotIn("A123456", masked_json)
        self.assertIn('"channel": "WEB"', masked_json)
        self.assertIn('"vipLevel": 3', masked_json)


if __name__ == "__main__":
    unittest.main()
