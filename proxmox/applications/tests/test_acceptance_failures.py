"""Acceptance must reject unsupported, stale, incomplete and untrusted samples."""

import io
import json
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import monitoring_verify as verification
import monitoring_templates as templates
from monitoring_configure import marker


class MonitoringAcceptanceFailures(unittest.TestCase):
    def test_each_readback_failure_is_rejected_without_exposing_private_samples(self):
        for scenario in (
            "passed",
            "api-error",
            "agent-item",
            "macro",
            "http",
            "items",
            "pending",
            "status",
            "vmids",
            "node",
            "ui",
        ):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                password = Path(tmp) / "password"
                password.write_text("synthetic password")
                config = {
                    "url": "https://fixture.invalid",
                    "password_file": str(password),
                    "not_before": 0,
                    "agents": [
                        {"hostname": "fixture-linux", "psk_identity": "fixture-linux",
                         "psk_sha256": hashlib.sha256(b"synthetic-PSK").hexdigest()}
                    ],
                    "proxmox_hostname": "fixture-pve",
                    "commissioned_vmids": [213],
                }
                now = int(verification.time.time())

                def response(request, **kwargs):
                    if isinstance(request, str):
                        ui = io.BytesIO(b"Zabbix")
                        ui.status = 503 if scenario == "ui" else 200
                        return ui
                    rpc = json.loads(request.data)
                    method = rpc["method"]
                    params = rpc["params"]
                    if method == "user.login":
                        if scenario == "api-error":
                            return io.StringIO(
                                json.dumps({"error": {"private": "withheld"}})
                            )
                        result = "fixture-token"
                    elif method == "user.logout":
                        result = True
                    elif method == "host.get":
                        if params["filter"]["host"] == ["fixture-linux"]:
                            result = [
                                {
                                    "hostid": "1",
                                    "tls_accept": "2",
                                    "description": marker("agent", "fixture-linux", "synthetic-PSK"),
                                }
                            ]
                        else:
                            result = [
                                {
                                    "hostid": "2",
                                    "macros": [
                                        {
                                            "macro": "{$HTTP.TLS.VERIFY}",
                                            "value": (
                                                "none"
                                                if scenario == "macro"
                                                else "full"
                                            ),
                                        }
                                    ],
                                }
                            ]
                    elif params.get("filter", {}).get("type") == 19:
                        result = (
                            []
                            if scenario == "http"
                            else [{"verify_peer": "1", "verify_host": "1"}]
                        )
                    elif params["filter"]["key_"] == ["system.uptime"]:
                        result = [
                            {
                                "type": "0" if scenario == "agent-item" else "7",
                                "state": "0",
                                "lastclock": str(now),
                                "lastvalue": "1",
                            }
                        ]
                    else:
                        inventory = {"data": [{"type": "node"}, {"vmid": 213}]}
                        if scenario == "vmids":
                            inventory["data"].pop()
                        if scenario == "node":
                            inventory["data"].pop(0)
                        result = [
                            {
                                "key_": "proxmox.api.available",
                                "state": "0",
                                "lastclock": str(now),
                                "lastvalue": "500" if scenario == "status" else "200",
                            },
                            {
                                "key_": "proxmox.cluster.resources",
                                "state": "0",
                                "lastclock": str(0 if scenario == "pending" else now),
                                "lastvalue": json.dumps(inventory),
                            },
                        ]
                        if scenario == "items":
                            result.pop()
                    return io.StringIO(json.dumps({"result": result}))

                opener = Mock()
                opener.open.side_effect = response
                with patch.object(verification, "build_opener", return_value=opener):
                    if scenario == "passed":
                        self.assertEqual(
                            verification._verify_once(config)["status"], "passed"
                        )
                    else:
                        with self.assertRaises(verification.AcceptanceFailure) as error:
                            verification._verify_once(config)
                        self.assertNotIn("withheld", str(error.exception))

    def test_collection_wait_is_explicitly_bounded_and_templates_remain_pinned(self):
        for bound in (-1, 601, True, "60"):
            with (
                self.subTest(bound=bound),
                self.assertRaises(verification.AcceptanceFailure),
            ):
                verification.verify({"collection_wait_seconds": bound})
        document = templates.prepared("template_app_proxmox.yaml")
        templates.check_readback(json.dumps(document))
        with self.assertRaises(ValueError):
            templates.prepared("unreviewed.yaml")
        other = next(
            name
            for name in templates.monitoring.VERSIONS["templates"]
            if name != "template_app_proxmox.yaml"
        )
        self.assertIsInstance(templates.prepared(other), dict)
