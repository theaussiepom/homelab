"""Read-only API verification, credential replay and pinned transfer boundaries."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import access
import bootstrap_cd as cd
import configuration
import monitoring_access as monitoring


class MonitoringReadbackTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            "schema": "homelab-zabbix-access-v1",
            "endpoint": "https://198.18.25.10:8006/",
            "node": "practice-pve",
            "address": "198.18.30.50",
            "backup_source": "nas.invalid:/fixture",
        }
        self.after = {
            "users": [{"userid": monitoring.USER, "enable": 1}],
            "roles": [
                {"roleid": monitoring.ROLE, "privs": ",".join(monitoring.PRIVILEGES)}
            ],
            "tokens": [{"tokenid": monitoring.TOKEN, "privsep": 1, "expire": 0}],
            "acl": [
                {
                    "type": kind,
                    "ugid": identity,
                    "path": "/",
                    "roleid": monitoring.ROLE,
                    "propagate": 1,
                }
                for kind, identity in [
                    ("user", monitoring.USER),
                    ("token", monitoring.IDENTITY),
                ]
            ],
            "rules": [monitoring.rule(self.config)],
            "options": {"enable": 1},
        }

    def test_inspection_filters_unrelated_authorities_and_strips_runtime_digest(self):
        base = "/nodes/practice-pve/firewall"
        replies = {
            "/access/users": [*self.after["users"], {"userid": "unrelated"}],
            "/access/roles": [*self.after["roles"], {"roleid": "unrelated"}],
            "/access/users/" + monitoring.USER + "/token": self.after["tokens"],
            "/access/acl": [
                *self.after["acl"],
                {"ugid": "unrelated", "roleid": "other"},
            ],
            base + "/rules": self.after["rules"],
            base + "/options": {"enable": 1, "digest": "runtime"},
        }
        api = Mock()
        api.call.side_effect = lambda path: {"data": replies[path]}
        self.assertEqual(monitoring.inspect(api, self.config), self.after)
        replies["/access/users"] = []
        api.reset_mock()
        self.assertEqual(monitoring.inspect(api, self.config)["tokens"], [])
        self.assertNotIn(
            "/access/users/" + monitoring.USER + "/token",
            [c.args[0] for c in api.call.call_args_list],
        )

    def test_effective_permissions_require_the_exact_read_only_scope(self):
        for effective in (
            {"/": dict.fromkeys(monitoring.PRIVILEGES, 1)},
            {"/": {"Sys.Modify": 1}},
            {"/vms/1": {"VM.Audit": 1}},
        ):
            api = Mock(ca=Path("/synthetic/ca"))
            with (
                self.subTest(effective=effective),
                patch.object(monitoring, "inspect", return_value=self.after),
                patch.object(cd.API, "configure") as configure,
                patch.object(cd.API, "call", return_value={"data": effective}),
            ):
                if set(effective.get("/", {})) == monitoring.PRIVILEGES:
                    self.assertEqual(
                        monitoring.verify(api, self.config, {"token": "synthetic"}, []),
                        self.after,
                    )
                else:
                    with self.assertRaisesRegex(ValueError, "Effective monitoring"):
                        monitoring.verify(api, self.config, {"token": "synthetic"}, [])
                configure.assert_called_once_with(
                    self.config["endpoint"], "synthetic", api.ca
                )

    def test_completed_replay_uses_preserved_credentials_and_holds_on_drift(self):
        empty = {k: [] for k in ("users", "roles", "tokens", "acl", "rules")}
        empty["options"] = self.after["options"]
        with tempfile.TemporaryDirectory() as tmp:
            root, nas = Path(tmp) / "state", Path(tmp) / "nas"
            root.mkdir(mode=0o700)
            nas.mkdir(mode=0o700)
            api = Mock()
            api.call.return_value = {
                "data": {"full-tokenid": monitoring.IDENTITY, "value": "synthetic"}
            }
            with (
                patch.object(monitoring, "check_backup"),
                patch.object(monitoring, "inspect", return_value=empty),
                patch.object(monitoring, "verify", return_value=self.after),
            ):
                self.assertTrue(
                    monitoring.initialize(api, self.config, root, nas)["created"]
                )
                api.reset_mock()
                self.assertFalse(
                    monitoring.initialize(api, self.config, root, nas)["created"]
                )
                api.call.assert_not_called()
                changed = copy.deepcopy(self.after)
                changed["options"]["enable"] = 0
                with (
                    patch.object(monitoring, "verify", return_value=changed),
                    self.assertRaisesRegex(ValueError, "option drift"),
                ):
                    monitoring.initialize(api, self.config, root, nas)
                owner = nas / "monitoring-access/owner.json"
                owner.write_text("{}")
                with self.assertRaisesRegex(ValueError, "receipts differ"):
                    monitoring.initialize(api, self.config, root, nas)


class PinnedTransportTests(unittest.TestCase):
    def test_api_transport_bounds_responses_and_redacts_every_failure(self):
        for mode in ("success", "http", "malformed", "oversized"):
            response = Mock()
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            response.read.return_value = (
                b'{"data": [1]}'
                if mode == "success"
                else (
                    b"x" * (8 * 1024 * 1024 + 1)
                    if mode == "oversized"
                    else b"private response"
                )
            )
            opener = Mock()
            opener.open.return_value = response
            if mode == "http":
                opener.open.side_effect = HTTPError(
                    "https://fixture.invalid", 403, "private", {}, None
                )
            with (
                self.subTest(mode=mode),
                patch.object(cd.ssl, "create_default_context"),
                patch.object(cd, "build_opener", return_value=opener),
            ):
                api = cd.API(
                    "https://fixture.invalid:8006/",
                    "root@pam!homelab-bootstrap-cd-900=synthetic",
                    Path("/synthetic/ca"),
                )
                if mode == "success":
                    self.assertEqual(
                        api.call("/nodes", "POST", {"key": "value"}), {"data": [1]}
                    )
                    req = opener.open.call_args.args[0]
                    self.assertEqual(req.data, b"key=value")
                    self.assertEqual(opener.open.call_args.kwargs["timeout"], 20)
                else:
                    with self.assertRaises(cd.BootstrapDiagnostic) as failure:
                        api.call("/nodes")
                    self.assertNotIn("private", str(failure.exception))
            with (
                patch.object(cd.ssl, "create_default_context"),
                patch.object(cd, "build_opener", return_value=opener),
            ):
                reader = cd.API.__new__(cd.API)
                reader.configure(
                    "https://fixture.invalid:8006/", "unused", Path("/synthetic/ca")
                )
                reader.discovery("root@pam!homelab-traefik-123=synthetic")
        with self.assertRaisesRegex(cd.BootstrapDiagnostic, "redirects"):
            cd.NoRedirect().redirect_request(
                None, None, 302, "", {}, "https://elsewhere.invalid"
            )

    def test_cached_transfer_checks_bytes_and_preserves_unknown_and_failed_outcomes(
        self,
    ):
        for mode in ("stored", "drift", "timeout", "malformed", "different"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                work = Path(tmp)
                data = b"synthetic vendor archive"
                request = {
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size_bytes": len(data),
                    "file_id": "local:vztmpl/vendor.tar.zst",
                }
                (work / "template.json").write_text(json.dumps(request))
                (work / "template.archive").write_bytes(
                    data if mode != "drift" else b"changed"
                )

                def command(args, **kwargs):
                    self.assertIn("StrictHostKeyChecking=yes", args)
                    if mode == "timeout":
                        raise subprocess.TimeoutExpired("ssh", 180)
                    result = {"status": "stored", **request}
                    if mode == "different":
                        result["sha256"] = "0" * 64
                    kwargs["stdout"].write(
                        json.dumps(result) if mode != "malformed" else "incomplete"
                    )
                    return subprocess.CompletedProcess(args, 0)

                with patch.object(access.subprocess, "run", side_effect=command) as run:
                    if mode == "stored":
                        access.upload_template(
                            work, ["ssh", "-o", "StrictHostKeyChecking=yes"]
                        )
                        self.assertEqual(
                            json.loads((work / "template-result.json").read_text())[
                                "status"
                            ],
                            "stored",
                        )
                    else:
                        with self.assertRaises(access.Refused):
                            access.upload_template(
                                work, ["ssh", "-o", "StrictHostKeyChecking=yes"]
                            )
                        if mode == "drift":
                            run.assert_not_called()
                        else:
                            self.assertFalse(
                                json.loads(
                                    (work / "template-result.json").read_text()
                                ).get("automatic_retry", False)
                            )

    def test_configuration_transport_uses_pinned_ssh_and_the_selected_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / "tofu").mkdir()
            inputs = work / "tofu/site.auto.tfvars.json"
            inputs.write_text(
                json.dumps({"site": {"api_endpoint": "https://pve.invalid:8006/"}})
            )
            real_is_file = Path.is_file
            with (
                patch.object(
                    Path,
                    "is_file",
                    lambda path: (
                        True if str(path).startswith("/keys/") else real_is_file(path)
                    ),
                ),
                patch.object(
                    configuration.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0, "{}", ""),
                ) as run,
            ):
                configuration.remote(
                    work, {"vmid": 900}, "reviewed", finish=True, attempt="fixture"
                )
                args = run.call_args.args[0]
                self.assertIn("StrictHostKeyChecking=yes", args)
                self.assertIn("root@pve.invalid", args)
                self.assertIn("reviewed", args[-1])
                self.assertIn("host_nas", args[-1])
                inputs.write_text(
                    json.dumps({"site": {"api_endpoint": "http://pve.invalid/"}})
                )
                with self.assertRaisesRegex(access.Refused, "trusted Proxmox"):
                    configuration.remote(work, {})
            with self.assertRaisesRegex(access.Refused, "SSH key"):
                configuration.remote(work, {})
