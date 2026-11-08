"""Current component input and trust refusals exercise real owning validators."""

import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bitwarden
import proxmox_guest as pve


class ValidationEdges(unittest.TestCase):

    def test_bitwarden_cli_success_and_failed_health_do_not_emit_private_values(self):
        for failed in (False, True):
            with (
                patch.object(
                    sys,
                    "argv",
                    [
                        "health",
                        "--origin",
                        "https://vault.example.invalid",
                        "--issuer",
                        "http://localhost",
                    ],
                ),
                patch.object(bitwarden, "reader"),
                patch.object(
                    bitwarden,
                    "health",
                    **(
                        {"side_effect": ValueError("private detail")}
                        if failed
                        else {"return_value": {"status": "passed"}}
                    ),
                ),
                patch("sys.stdout", new_callable=io.StringIO) as output,
            ):
                if failed:
                    with self.assertRaises(SystemExit):
                        bitwarden.main()
                    self.assertNotIn("private detail", output.getvalue())
                else:
                    bitwarden.main()
                    self.assertEqual(json.loads(output.getvalue())["status"], "passed")



    def test_proxmox_api_read_stays_on_the_declared_tls_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            token = root / "token"
            token.write_text("fixture@pve!read=synthetic")
            token.chmod(0o600)
            cfg = {
                "site": {"api_endpoint": "https://198.18.0.1:8006/"},
                "paths": {"api_token": str(token), "ca_file": "/synthetic/ca"},
            }
            opener = MagicMock()
            opener.open.return_value.__enter__.return_value = io.StringIO(
                '{"data":[{"vmid":200}]}'
            )
            with (
                patch.object(
                    pve.ssl, "create_default_context", return_value=None
                ) as context,
                patch.object(pve, "build_opener", return_value=opener),
            ):
                self.assertEqual(
                    pve.api_get(cfg, "/nodes/fixture/lxc"), [{"vmid": 200}]
                )
                context.assert_called_once_with(cafile="/synthetic/ca")
                context.reset_mock()
                opener.open.return_value.__enter__.return_value = io.StringIO('{"data":[]}')
                self.assertEqual(pve.api_get(cfg, '/storage?type=zfspool'), [])
                context.assert_called_once_with(cafile='/synthetic/ca')
                request = opener.open.call_args.args[0]
                self.assertEqual(request.full_url, 'https://198.18.0.1:8006/api2/json/storage?type=zfspool')
            for endpoint, path in [
                ("http://198.18.0.1:8006/", "/nodes/x"),
                (cfg["site"]["api_endpoint"], "/access/users"),
                (cfg["site"]["api_endpoint"], "/storage"),
                (cfg["site"]["api_endpoint"], "/storage/local-zfs"),
                (cfg["site"]["api_endpoint"], "/storage?type=dir"),
                (cfg["site"]["api_endpoint"], "/storage?type=zfspool&other=1"),
            ]:
                cfg["site"]["api_endpoint"] = endpoint
                with self.assertRaises(ValueError):
                    pve.api_get(cfg, path)
        with self.assertRaises(pve.InputNeeded):
            pve.RefuseRedirects().redirect_request(
                None, None, 302, "Found", {}, "https://other.invalid"
            )

    def test_guest_host_key_lookup_refuses_missing_failed_empty_or_alias_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            known = root / "known"
            cfg = {
                "app": {"address": "198.18.0.2"},
                "paths": {"known_hosts": str(known)},
            }
            with self.assertRaises(pve.InputNeeded):
                pve.guest_trust(cfg, root)
            known.write_text("synthetic trust")
            for status, text in [
                (1, ""),
                (2, "private error"),
                (0, "# comment only\n"),
                (0, "*.invalid ssh-ed25519 fixture"),
            ]:
                with (
                    self.subTest(status=status, text=text),
                    patch.object(
                        pve.subprocess,
                        "run",
                        return_value=subprocess.CompletedProcess([], status, text, ""),
                    ),
                    self.assertRaises(ValueError),
                ):
                    pve.guest_trust(cfg, root)
