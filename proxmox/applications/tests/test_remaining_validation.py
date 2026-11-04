"""Retained validators reject malformed public inputs before writing private state."""

import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import foundation
import bitwarden
import guest_identity
import private_io
import monitoring


class RemainingValidationTests(unittest.TestCase):

    def test_foundation_refuses_unsupported_kind_and_zero_port(self):
        with self.assertRaisesRegex(ValueError, "port"):
            foundation.origin("https://fixture.invalid:0", "fixture")

    def test_bitwarden_rejects_nonobject_and_invalid_json_and_reader_bounds_bytes(self):
        replies = {
            "/api/alive": (200, b'"alive"'),
            "/api/config": (200, b'{"version":"2026.4.1"}'),
            "/identity/.well-known/openid-configuration": (
                200,
                b'{"issuer":"http://localhost"}',
            ),
        }
        for raw in (b"not JSON", b"[]"):
            changed = dict(replies)
            changed["/api/config"] = (200, raw)
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                bitwarden.health(changed.__getitem__, "http://localhost")
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.status = 200
        response.read.return_value = b"{}"
        opener = Mock()
        opener.open.return_value = response
        with patch.object(bitwarden, "build_opener", return_value=opener):
            self.assertEqual(
                bitwarden.reader("https://vault.example.invalid")("/api/config"),
                (200, b"{}"),
            )
            response.read.assert_called_once_with(262145)

    def test_identity_log_and_interface_selection_need_complete_unambiguous_evidence(
        self,
    ):
        with self.assertRaises(ValueError):
            guest_identity.creation_fingerprint(
                [
                    {"n": 1, "t": "Creating SSH host key 'ssh_host_ed25519_key'"},
                    {"n": 3, "t": "done: incomplete"},
                ]
            )

    def test_receipt_replacement_validates_existing_private_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            receipt = Path(tmp) / "receipt"
            private_io.write(receipt, {"before": True})
            private_io.replace_receipt(receipt, {"after": True})
            self.assertEqual(
                private_io.read_json(receipt, private=True), {"after": True}
            )
            receipt.chmod(0o644)
            with self.assertRaises(ValueError):
                private_io.replace_receipt(receipt, {"unsafe": True})
            self.assertEqual(json.loads(receipt.read_text()), {"after": True})


    def test_monitoring_source_and_cli_preserve_pinned_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            from protocol_component_fixtures import zabbix_app
            import component_proxy_files
            app = zabbix_app(database_host="postgres", images=monitoring.VERSIONS)
            rows = component_proxy_files.files(app, secrets={"database_password": b"synthetic-password"},
                records={}, public_ca=b"-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n")
            self.assertEqual({row["path"] for row in rows}, {"database-password", "proxmox-ca.pem"})
            self.assertTrue(all((row["uid"], row["gid"], row["mode"]) == (1997, 1995, "0400") for row in rows))
            config = root / "agent"
            config.write_text("{}")
            with (
                patch.object(
                    sys, "argv", ["monitoring", "--agent-config", str(config)]
                ),
                self.assertRaises(ValueError),
            ):
                runpy.run_path(str(Path(monitoring.__file__)), run_name="__main__")




    def test_identity_can_append_after_an_unrelated_terminated_host_entry(self):
        import test_guest_identity as cases

        case = cases.IdentityTests()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = case.setup_fixture(root)
            hosts = root / "hosts"
            hosts.write_text("# unrelated preserved entry\n")
            with patch.object(
                guest_identity.subprocess, "run", side_effect=case.command
            ):
                guest_identity.pin(cfg, root, "198.18.100.42", case.fetch, case.persist)
            self.assertTrue(
                hosts.read_text().startswith("# unrelated preserved entry\n")
            )
            log = [{"n": 0, "t": "unrelated progress"}, *case.log]
            self.assertEqual(
                guest_identity.creation_fingerprint(log),
                guest_identity.fingerprint(cases.public_key()),
            )
