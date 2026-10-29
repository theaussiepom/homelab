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
import render
import foundation
import bitwarden
import guest_identity
import guest_contract
import private_io
import runtime_secrets
import monitoring
import test_render as render_cases
import test_foundation as foundation_cases
import test_monitoring as monitoring_cases


class RemainingValidationTests(unittest.TestCase):
    def test_renderer_rejects_non_scalar_values_missing_services_and_unsafe_mounts(
        self,
    ):
        with self.assertRaises(ValueError):
            render.literal({})
        with self.assertRaises(ValueError):
            render.required({"value": "invalid\n"}, "value")
        cfg = render_cases.fixture("automation")
        cfg["services"].pop("mqtt")
        with self.assertRaises(ValueError):
            render.compose(cfg)
        cfg = render_cases.fixture("identity")
        cfg.pop("foundation")
        with self.assertRaisesRegex(ValueError, "file-based foundation"):
            render.compose(cfg)
        for target in ("/var/run/docker.sock", "/data"):
            cfg = render_cases.fixture("automation")
            cfg["services"]["node_red"]["extra_mounts"] = [
                {"source": "/srv/homelab/data/config", "target": target}
            ]
            with self.subTest(target=target), self.assertRaises(ValueError):
                render.compose(cfg)
        cfg = render_cases.fixture("automation")
        cfg["node_red_oidc"] = {"client_id": "invalid secret"}
        with self.assertRaises(ValueError):
            render.compose(cfg)

    def test_foundation_refuses_unsupported_kind_and_zero_port(self):
        with self.assertRaises(ValueError):
            foundation.validate({"kind": "dns", "foundation": {}})
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
        for interfaces in ([], [{"ipv4": "manual"}], [{"ipv4": "dhcp"}] * 17):
            with self.subTest(interfaces=interfaces), self.assertRaises(ValueError):
                guest_contract.required_network_interfaces(
                    {"guest": {"interfaces": interfaces}}
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

    def test_dns_preparation_has_no_undeclared_foundation_secret_files(self):
        cfg = {"app": {"kind": "dns"}}
        stack = render_cases.fixture("dns")
        self.assertEqual(
            runtime_secrets.prepare_stack(cfg, stack, Path("/synthetic"), {}), {}
        )

    def test_monitoring_source_and_cli_preserve_pinned_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = monitoring_cases.fixture(root)
            self.assertEqual(
                set(monitoring.source_files(cfg)),
                {str(root / "password"), str(root / "ca")},
            )
            config = root / "agent"
            config.write_text("{}")
            with (
                patch.object(
                    sys, "argv", ["monitoring", "--agent-config", str(config)]
                ),
                self.assertRaises(ValueError),
            ):
                runpy.run_path(str(Path(monitoring.__file__)), run_name="__main__")

    def test_mdns_startup_and_pgadmin_published_address_are_explicit(self):
        cfg = render_cases.fixture("automation")
        ha = cfg["services"]["homeassistant"]
        ha["environment"]["HOMELAB_HA_IPV4"] = "198.18.100.20"
        ha["cap_add"] = ["NET_ADMIN"]
        with self.assertRaisesRegex(ValueError, "startup directory"):
            render.compose(cfg)
        with tempfile.TemporaryDirectory() as tmp:
            cfg = foundation_cases.fixture(tmp, "db-tools")
            cfg["pgadmin_bind_address"] = "127.0.0.1"
            with self.assertRaisesRegex(ValueError, "backend IPv4"):
                render.compose(cfg)

    def test_ansible_preparation_and_native_application_share_the_selected_trust(self):
        import ansible_guest
        import deployment_inputs
        from fixtures import guest

        for phase in ("preparation", "mariadb"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                cfg = guest(root)
                cfg["app"]["service_health_checks"] = {"mariadb": []}

                def quiet(command, environment, log):
                    log.write_text("changed=0\n")

                with (
                    patch.object(
                        deployment_inputs, "binding", return_value={"approved": True}
                    ),
                    patch.object(ansible_guest.proxmox_guest, "guest_trust"),
                    patch.object(ansible_guest, "quiet", side_effect=quiet),
                ):
                    result = ansible_guest.run_phase(
                        cfg, root / "site", root, root, {"approved": True}, phase
                    )
                    self.assertFalse(result["changed"])
                    variables = private_io.read_json(
                        root / phase / "variables.json", private=True
                    )
                    self.assertEqual(
                        variables["app"]["start_services"], phase != "preparation"
                    )

    def test_renderer_cli_without_generated_foundation_files_still_writes_only_private_artifacts(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "config"
            config.write_text(json.dumps(render_cases.fixture("dns")))
            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(render.__file__)),
                    "--config",
                    str(config),
                    "--output",
                    str(root / "output"),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                (root / "output/compose.yml").stat().st_mode & 0o777, 0o600
            )

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

    def test_identity_source_files_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = foundation_cases.fixture(tmp, "identity")
            self.assertEqual(
                set(foundation.source_files(cfg)),
                set(cfg["foundation"]["secret_files"].values()),
            )
