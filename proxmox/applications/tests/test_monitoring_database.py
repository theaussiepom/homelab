import base64
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import json

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import monitoring_database as database


class MonitoringDatabaseTests(unittest.TestCase):
    @unittest.skipUnless(
        hasattr(os, "listxattr"), "Native HBA metadata uses Linux xattrs"
    )
    def test_rejected_hba_or_failed_reload_restores_original_and_keeps_hold(self):
        for failure in ("parser", "reload"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                hba = root / "pg_hba.conf"
                original = b"local all postgres peer\n"
                hba.write_bytes(original)
                hba.chmod(0o640)
                os.setxattr(hba, "user.homelab-fixture", b"preserved\x00metadata")
                metadata = hba.stat()

                def query(statement):
                    if "pg_roles" in statement or "pg_database" in statement:
                        return "0"
                    if "pg_hba_file_rules" in statement:
                        return "1" if failure == "parser" else "0"
                    if "pg_reload_conf" in statement:
                        return "f"
                    return ""

                with (
                    patch.object(database, "sql", side_effect=query),
                    patch.object(
                        database.subprocess,
                        "run",
                        return_value=SimpleNamespace(stdout=b"-- synthetic globals"),
                    ),
                ):
                    with self.assertRaises(ValueError):
                        database.provision(
                            root / "state",
                            hba,
                            hashlib.sha256(original).hexdigest(),
                            "198.18.30.50",
                            "a" * 32,
                        )
                self.assertEqual(hba.read_bytes(), original)
                self.assertEqual(hba.stat().st_mode, metadata.st_mode)
                self.assertEqual(
                    (hba.stat().st_uid, hba.stat().st_gid),
                    (metadata.st_uid, metadata.st_gid),
                )
                self.assertEqual(
                    os.getxattr(hba, "user.homelab-fixture"), b"preserved\x00metadata"
                )
                self.assertTrue((root / "state/HOLD.json").exists())
                self.assertTrue((root / "state/pg_hba.rejected").exists())
                self.assertFalse((root / "state/READY.json").exists())

    @unittest.skipUnless(sys.platform.startswith("linux"), "Native Linux HBA metadata")
    def test_native_hba_replacement_preserves_identity_mode_and_extended_attributes(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            hba = Path(directory) / "pg_hba.conf"
            hba.write_bytes(b"local all postgres peer\n")
            hba.chmod(0o640)
            if os.geteuid() == 0:
                os.chown(hba, 1000, 1001)
            os.setxattr(hba, "user.homelab-fixture", b"preserved\x00metadata")
            os.setxattr(hba, "user.another-fixture", b"second value")
            before = hba.stat()
            attributes = {
                name: base64.b64encode(os.getxattr(hba, name)).decode()
                for name in os.listxattr(hba)
            }
            content = database.hba_content(hba.read_bytes(), "198.18.30.50")
            database.replace_hba(hba, content, attributes)
            after = hba.stat()
            self.assertEqual(hba.read_bytes(), content)
            self.assertEqual(
                (after.st_uid, after.st_gid, after.st_mode),
                (before.st_uid, before.st_gid, before.st_mode),
            )
            self.assertEqual(
                {
                    name: base64.b64encode(os.getxattr(hba, name)).decode()
                    for name in os.listxattr(hba)
                },
                attributes,
            )
            self.assertFalse(list(hba.parent.glob(".homelab-zabbix-*")))

    def test_specific_allowance_precedes_role_rejects_and_preserves_original(self):
        original = (
            b"local all postgres peer\nhost all all 198.18.30.0/24 scram-sha-256\n"
        )
        result = database.hba_content(original, "198.18.30.50")
        self.assertTrue(result.endswith(original))
        self.assertLess(
            result.index(b"host zabbix zabbix"),
            result.index(b"host all zabbix 0.0.0.0/0 reject"),
        )
        self.assertIn(b"local all zabbix reject", result)
        for address in ["0.0.0.0", "127.0.0.1", "::", "invalid"]:
            with self.subTest(address=address), self.assertRaises(ValueError):
                database.hba_content(original, address)

    def test_changed_baseline_existing_role_and_hold_prevent_mutation(self):
        for scenario in ["baseline", "existing", "held", "injection"]:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                hba = root / "pg_hba.conf"
                hba.write_text("local all postgres peer\n")
                state = root / "state"
                state.mkdir(mode=0o700)
                expected = hashlib.sha256(hba.read_bytes()).hexdigest()
                password = "a" * 32
                if scenario == "baseline":
                    expected = "0" * 64
                if scenario == "held":
                    (state / "HOLD.json").write_text("{}")
                if scenario == "injection":
                    password += "';DROP ROLE x;--"
                with patch.object(database, "sql", return_value="1") as sql:
                    with self.assertRaises(ValueError):
                        database.provision(
                            state, hba, expected, "198.18.30.50", password
                        )
                    self.assertFalse(
                        any("CREATE" in call.args[0] for call in sql.call_args_list)
                    )
                self.assertEqual(hba.read_text(), "local all postgres peer\n")


class DatabaseCustodyTests(unittest.TestCase):
    def setUp(self):
        # Linux metadata calls are the unit-test boundary on every host platform.
        for name, value in (("listxattr", ["user.fixture"]), ("getxattr", b"retained")):
            mocked = patch.object(database.os, name, return_value=value, create=True)
            mocked.start()
            self.addCleanup(mocked.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.hba = self.root / "pg_hba.conf"
        self.original = b"local all postgres peer\n"
        self.hba.write_bytes(self.original)
        self.state = self.root / "state"
        self.expected = database.digest(self.original)
        self.created = False
        self.statements = []

    def query(self, statement):
        self.statements.append(statement)
        if statement.startswith("SET password_encryption"):
            self.created = True
        if "pg_roles" in statement or "pg_database" in statement:
            return "1" if self.created else "0"
        if "pg_hba_file_rules" in statement:
            return "0"
        if "pg_reload_conf" in statement:
            return "t"
        return ""

    def provision(self):
        return database.provision(
            self.state, self.hba, self.expected, "198.18.30.50", "a" * 32
        )

    def test_successful_creation_and_exact_replay_preserve_custody(self):
        with (
            patch.object(database, "sql", side_effect=self.query),
            patch.object(
                database.subprocess,
                "run",
                return_value=SimpleNamespace(stdout=b"-- globals"),
            ),
        ):
            self.assertEqual(self.provision(), {"created": True})
            self.assertFalse((self.state / "HOLD.json").exists())
            receipt = json.loads((self.state / "READY.json").read_text())
            self.assertEqual(
                receipt["hba_sha256"], database.digest(self.hba.read_bytes())
            )
            self.assertNotIn("a" * 32, json.dumps(receipt))
            self.assertEqual((self.state / "pg_hba.before").read_bytes(), self.original)
            before = {p.name: p.read_bytes() for p in self.state.iterdir()}
            self.statements.clear()
            self.assertEqual(self.provision(), {"created": False})
            self.assertFalse(any("CREATE" in q for q in self.statements))
            self.assertEqual(
                before, {p.name: p.read_bytes() for p in self.state.iterdir()}
            )
            for change in ("credential", "owner", "hba"):
                saved = (self.state / "READY.json").read_bytes()
                if change == "credential":
                    record = json.loads(saved)
                    record["credential_check"]["scrypt"] = "0" * 128
                    (self.state / "READY.json").write_text(json.dumps(record))
                elif change == "owner":
                    record = json.loads(saved)
                    record["owner"]["address"] = "198.18.30.51"
                    (self.state / "READY.json").write_text(json.dumps(record))
                else:
                    self.hba.write_bytes(self.original)
                with (
                    self.subTest(change=change),
                    self.assertRaisesRegex(ValueError, "drift"),
                ):
                    self.provision()
                (self.state / "READY.json").write_bytes(saved)

    def test_symlink_partial_state_and_previous_hba_marker_are_refused(self):
        for scenario in ("hba-link", "state-link", "partial", "marker"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                hba = root / "hba"
                hba.write_bytes(self.original)
                state = root / "state"
                if scenario == "hba-link":
                    other = root / "original"
                    hba.rename(other)
                    hba.symlink_to(other)
                elif scenario == "state-link":
                    other = root / "other"
                    other.mkdir()
                    state.symlink_to(other)
                elif scenario == "partial":
                    state.mkdir()
                    (state / "partial").write_text("retained evidence")
                else:
                    hba.write_bytes(b"# HomeLab Zabbix\n" + self.original)
                with (
                    patch.object(database, "sql") as query,
                    self.assertRaises(ValueError),
                ):
                    database.provision(
                        state,
                        hba,
                        database.digest(hba.read_bytes()),
                        "198.18.30.50",
                        "a" * 32,
                    )
                query.assert_not_called()

    def test_privilege_and_database_ownership_checks_fail_closed(self):
        for replies in (("0",), ("1", "0")):
            with (
                self.subTest(replies=replies),
                patch.object(database, "sql", side_effect=replies),
                self.assertRaises(ValueError),
            ):
                database.verify()

    def test_sql_uses_stdin_and_suppresses_private_error_output(self):
        with patch.object(
            database.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=0, stdout=" 42\n"),
        ) as run:
            self.assertEqual(database.sql("SELECT 42"), "42")
            self.assertEqual(run.call_args.kwargs["input"], "SELECT 42")
            self.assertNotIn("SELECT 42", run.call_args.args[0])
        with (
            patch.object(
                database.subprocess,
                "run",
                return_value=SimpleNamespace(returncode=1, stdout="private detail"),
            ),
            self.assertRaisesRegex(ValueError, "preserve its hold"),
        ):
            database.sql("SELECT 42")

    def test_metadata_mismatch_preserves_hba_and_removes_temporary_file(self):
        with (
            patch.object(database.os, "listxattr", return_value=[]),
            self.assertRaisesRegex(ValueError, "metadata"),
        ):
            database.replace_hba(self.hba, b"replacement", {"fixture": "value"})
        self.assertEqual(self.hba.read_bytes(), self.original)
        self.assertEqual(list(self.root.iterdir()), [self.hba])

    def test_concurrent_hba_change_after_failed_reload_is_not_overwritten(self):
        def query(statement):
            if "pg_hba_file_rules" in statement:
                self.hba.write_bytes(b"independent administrator change")
                return "1"
            return self.query(statement)

        with (
            patch.object(database, "sql", side_effect=query),
            patch.object(
                database.subprocess,
                "run",
                return_value=SimpleNamespace(stdout=b"-- globals"),
            ),
            self.assertRaisesRegex(ValueError, "changed during"),
        ):
            self.provision()
        self.assertEqual(self.hba.read_bytes(), b"independent administrator change")
        self.assertTrue((self.state / "HOLD.json").exists())

    def test_failed_hba_parser_and_reload_restore_original_and_keep_hold(self):
        for failure in ("parser", "reload"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                hba = Path(tmp) / "pg_hba.conf"
                hba.write_bytes(self.original)
                state = Path(tmp) / "state"

                def query(statement):
                    if "pg_hba_file_rules" in statement:
                        return "1" if failure == "parser" else "0"
                    if "pg_reload_conf" in statement:
                        return "f"
                    return "0"

                with (
                    patch.object(database, "sql", side_effect=query),
                    patch.object(
                        database.subprocess,
                        "run",
                        return_value=SimpleNamespace(stdout=b"globals"),
                    ),
                    self.assertRaisesRegex(ValueError, "original restored"),
                ):
                    database.provision(
                        state,
                        hba,
                        database.digest(self.original),
                        "198.18.30.50",
                        "a" * 32,
                    )
                self.assertEqual(hba.read_bytes(), self.original)
                self.assertTrue((state / "HOLD.json").is_file())
                self.assertFalse((state / "READY.json").exists())
