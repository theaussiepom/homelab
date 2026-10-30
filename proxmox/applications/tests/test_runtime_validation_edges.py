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
import foundation
import pegaprox
import proxmox_guest as pve
from test_pegaprox import stack as pegaprox_stack
from test_foundation import fixture as foundation_fixture
import test_bitwarden_runtime as runtime_cases


class ValidationEdges(unittest.TestCase):
    def test_bitwarden_schema_service_identity_and_network_edges(self):
        base = runtime_cases.RuntimeTests()
        base.setUp()
        self.addCleanup(base.doCleanups)
        for change in (
            "extra",
            "kind",
            "provider",
            "public-bind",
            "public-db",
            "services",
            "service-field",
            "image",
        ):
            cfg = copy.deepcopy(base.stack)
            if change == "extra":
                cfg["arbitrary"] = True
            elif change == "kind":
                cfg["kind"] = "other"
            elif change == "provider":
                cfg["bitwarden"]["database_provider"] = "postgres"
            elif change == "public-bind":
                cfg["bitwarden"]["bind_address"] = "8.8.8.8"
            elif change == "public-db":
                cfg["bitwarden"]["database_server"] = "8.8.8.8"
            elif change == "services":
                cfg["services"]["extra"] = {}
            elif change == "service-field":
                cfg["services"]["bitwarden"]["cap_add"] = ["SYS_ADMIN"]
            else:
                cfg["services"]["bitwarden"]["image"] = "other/product:latest"
            with self.subTest(change=change), self.assertRaises(ValueError):
                bitwarden.validate(cfg)
        import render

        base.stack["services"]["bitwarden"]["environment"]["TZ"] = "Australia/Brisbane"
        self.assertEqual(
            render.compose(base.stack)["services"]["bitwarden"]["environment"]["TZ"],
            "Australia/Brisbane",
        )

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

    def test_foundation_refuses_inline_secrets_uid_overrides_and_untrusted_sources(
        self,
    ):
        for kind, field, value in [
            ("identity", "user", "0"),
            ("identity", "environment", {"UNDECLARED": "value"}),
            ("db-tools", "user", "0"),
            ("db-tools", "environment", {"UNDECLARED": "value"}),
            ("ingress", "environment", {"UNDECLARED": "value"}),
        ]:
            with (
                self.subTest(kind=kind, field=field),
                tempfile.TemporaryDirectory() as tmp,
            ):
                cfg = foundation_fixture(tmp, kind)
                service = {
                    "identity": "server",
                    "db-tools": "pgadmin",
                    "ingress": "traefik",
                }[kind]
                cfg["services"][service][field] = value
                with self.assertRaises(ValueError):
                    foundation.validate(cfg)
        for field, value in [
            ("provider_slug", "bad/slug"),
            ("proxmox_token_id", "not-a-token"),
            ("acme_email", "invalid"),
        ]:
            kind = "db-tools" if field == "provider_slug" else "ingress"
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                cfg = foundation_fixture(tmp, kind)
                cfg["foundation"][field] = value
                with self.assertRaises(ValueError):
                    foundation.validate(cfg)
        for origin in ("https://host:invalid", "https://host:70000"):
            with self.assertRaises(ValueError):
                foundation.origin(origin, "fixture")
        for path in ("relative", "/absolute/../escape"):
            with self.assertRaises(ValueError):
                foundation.file_path(path)
        for resolvers in (None, [False]):
            with self.assertRaises(ValueError):
                foundation.dns_resolvers(resolvers)
        self.assertEqual(foundation.files({"kind": "automation"}), [])
        self.assertEqual(foundation.source_files({"kind": "automation"}), [])
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "ca"
            p.write_text("PRIVATE KEY")
            p.chmod(0o600)
            with self.assertRaises(ValueError):
                foundation.read_private(p, certificate=True)

    def test_pegaprox_deployment_listener_key_nic_and_ingress_must_match(self):
        stack = pegaprox_stack()
        cfg = {
            "app": {
                "pegaprox": {"key_source": "/synthetic/key"},
                "memory_mib": stack["guest_memory_mib"],
                "address": stack["bind_address"],
                "health_checks": pegaprox.health_checks(),
            },
            "guest": {
                "interfaces": [{"mac": "02:00:00:00:00:01", "ipv6": "manual"}],
                "keyctl": False,
                "nesting": True,
                "rules": [
                    {
                        "direction": "in",
                        "proto": "tcp",
                        "port": "22",
                        "source": "198.18.0.1/32",
                    },
                    {
                        "direction": "in",
                        "proto": "tcp",
                        "port": "5000",
                        "source": "198.18.25.0/24",
                        "destination": stack["bind_address"] + "/32",
                    },
                ],
            },
        }
        pegaprox.validate_deployment(cfg, stack)
        for change in (
            "capture",
            "key",
            "nic",
            "port",
            "ssh-subnet",
            "management-subnet",
            "destination",
            "no-client",
            "proxy-not-admitted",
            "budget",
        ):
            value = copy.deepcopy(cfg)
            if change == "capture":
                value["app"]["capture"] = {}
            elif change == "key":
                value["app"]["pegaprox"]["key_source"] = "relative"
            elif change == "nic":
                value["guest"]["nesting"] = False
            elif change == "port":
                value["guest"]["rules"][0]["port"] = "80"
            elif change == "ssh-subnet":
                value["guest"]["rules"][0]["source"] = "198.18.0.0/24"
            elif change == "management-subnet":
                value["guest"]["rules"][1]["source"] = "198.18.0.0/16"
            elif change == "destination":
                value["guest"]["rules"][1]["destination"] = "198.18.0.99/32"
            elif change == "no-client":
                value["guest"]["rules"] = []
            elif change == "proxy-not-admitted":
                value["guest"]["rules"][1]["source"] = "198.18.0.0/24"
            else:
                value["app"]["memory_mib"] += 1
            with self.subTest(change=change), self.assertRaises(ValueError):
                pegaprox.validate_deployment(value, stack)

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
            for endpoint, path in [
                ("http://198.18.0.1:8006/", "/nodes/x"),
                (cfg["site"]["api_endpoint"], "/access/users"),
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
