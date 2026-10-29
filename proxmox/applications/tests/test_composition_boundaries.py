"""Framework-owned composition and runtime contracts, independent of site profiles."""

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import guest_contract as contract
import render
import ansible_guest
import deployment_inputs
import runtime_secrets
import pegaprox
from fixtures import guest
from test_render import fixture
from test_foundation import fixture as foundation_fixture
from test_pegaprox import stack as pegaprox_stack
import test_bitwarden_runtime as bitwarden_cases


class CompositionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def configuration(self, kind, stack, address="198.18.25.8"):
        cfg = guest(self.root)
        cfg["app"].pop("database")
        cfg["deployment"]["capabilities"] = contract.BLUEPRINTS[kind]["capabilities"]
        cfg["app"].update(
            kind=kind,
            **(
                {"node_red_authentication": "authentik-oidc"}
                if kind == "automation"
                else {}
            ),
            memory_mib=stack["guest_memory_mib"],
            address=address,
            exclusive_writer_confirmed=True,
            required_paths=copy.deepcopy(contract.BLUEPRINTS[kind]["required_paths"]),
            service_health_checks={
                p: [{"name": p, "argv": ["true"]}]
                for p in contract.BLUEPRINTS[kind]["applications"]
            },
            stack_config=str(self.root / "stack.json"),
        )
        cfg["guest"]["memory_mib"] = stack["guest_memory_mib"]
        cfg["guest"]["interfaces"][0]["ipv4"] = address + "/24"
        return cfg

    def test_zigbee_compose_preserves_radio_paths_and_refuses_overrides(self):
        stack = fixture("zigbee2mqtt")
        rendered = render.compose(stack)["services"]["zigbee2mqtt"]
        self.assertEqual(
            rendered["devices"],
            ["/dev/serial/by-id/usb-fixture:/dev/serial/by-id/usb-fixture:rw"],
        )
        self.assertIn("8099:8099/tcp", rendered["ports"][0])
        for key, value in [
            ("environment", {"UNDECLARED": "x"}),
            ("extra_mounts", ["/tmp:/app/data"]),
            ("command", None),
            ("entrypoint", []),
            ("user", "0"),
        ]:
            changed = copy.deepcopy(stack)
            changed["services"]["zigbee2mqtt"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                render.compose(changed)

    def test_owned_dns_cannot_be_frozen_by_an_environment_override(self):
        stack = fixture("dns")
        stack["dns_records"] = {"broker.mqtt": "198.18.40.21"}
        stack["services"]["pihole"]["environment"]["FTLCONF_dns_hosts"] = "old"
        with self.assertRaisesRegex(ValueError, "writable"):
            render.compose(stack)

    def test_foundation_bindings_match_assigned_interfaces(self):
        for kind in ("identity", "ingress", "db-tools"):
            with self.subTest(kind=kind):
                stack = foundation_fixture(self.root, kind)
                address = (
                    stack["foundation"]["bind_address"]
                    if kind != "db-tools"
                    else stack["pgadmin_bind_address"]
                )
                cfg = self.configuration(kind, stack, address)
                self.assertEqual(contract.validate(cfg, stack), cfg["guest"]["vmid"])
                cfg["guest"]["interfaces"][0]["ipv4"] = "198.18.25.99/24"
                cfg["app"]["address"] = "198.18.25.99"
                with self.assertRaisesRegex(ValueError, "assigned interface"):
                    contract.validate(cfg, stack)

    def test_automation_discovery_and_all_data_bind_forms(self):
        stack = fixture("automation")
        cfg = self.configuration("automation", stack)
        self.assertEqual(contract.validate(cfg, stack), cfg["guest"]["vmid"])
        stack["services"]["homeassistant"].setdefault("environment", {})[
            "HOMELAB_HA_IPV4"
        ] = cfg["app"]["address"]
        stack["services"]["homeassistant"]["cap_add"] = ["NET_ADMIN"]
        stack["services"]["homeassistant"]["extra_mounts"].append(
            {
                "source": "/srv/homelab/data/ha-startup",
                "target": "/startup",
                "read_only": True,
            }
        )
        contract.validate(cfg, stack)
        stack["services"]["homeassistant"]["environment"][
            "HOMELAB_HA_IPV4"
        ] = "198.18.25.99"
        with self.assertRaisesRegex(ValueError, "assigned address"):
            contract.validate(cfg, stack)
        self.assertEqual(
            contract.data_bind_sources(
                {
                    "services": {
                        "x": {
                            "volumes": [
                                "/tmp/unmanaged:/tmp/unmanaged",
                                "/srv/homelab/data/a:/a",
                                {"source": "/srv/homelab/data/b"},
                                {"source": "/tmp/b"},
                            ]
                        },
                        "y": {},
                    }
                }
            ),
            {"/srv/homelab/data/a", "/srv/homelab/data/b"},
        )

    def test_pegaprox_uses_the_shared_guest_contract_and_ignores_egress_as_ingress(
        self,
    ):
        stack = pegaprox_stack()
        cfg = self.configuration("pegaprox", stack, stack["bind_address"])
        cfg["app"].update(
            pegaprox={"key_source": "/synthetic/key"},
            health_checks=pegaprox.health_checks(),
        )
        cfg["guest"].update(
            keyctl=False,
            nesting=True,
            rules=[
                {"direction": "out", "proto": "udp", "port": "53"},
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
                    "source": "198.18.0.0/24",
                    "destination": stack["bind_address"] + "/32",
                },
            ],
        )
        cfg["guest"]["interfaces"][0]["ipv6"] = "manual"
        self.assertEqual(contract.runtime_images(stack), {"pegaprox": stack})
        self.assertEqual(contract.validate(cfg, stack), cfg["guest"]["vmid"])
        self.assertEqual(
            render.compose(stack)["services"]["pegaprox"]["restart"], "always"
        )

    def test_bitwarden_secret_binding_is_external_to_source(self):
        runtime = bitwarden_cases.RuntimeTests()
        runtime.setUp()
        self.addCleanup(runtime.doCleanups)
        runtime.stack["services"]["bitwarden"]["environment"] = {}
        extra = runtime_secrets.prepare_stack(runtime.cfg, runtime.stack, self.root, {})
        self.assertEqual(extra, {})
        self.assertEqual(
            runtime.stack["services"]["bitwarden"]["environment"], runtime.value
        )

    def test_frontend_routing_and_radio_contracts_use_the_assigned_interface(self):
        stack = foundation_fixture(self.root, "ingress")
        address = stack["foundation"]["bind_address"]
        cfg = self.configuration("ingress", stack, address)
        nic = cfg["guest"]["interfaces"][0]
        cfg["app"]["frontend_routing"] = {
            "address": nic["ipv4"],
            "mac": nic["mac"],
            "gateway": address.rsplit(".", 1)[0] + ".1",
        }
        cfg["guest"]["interfaces"].append(
            {"ipv4": "198.18.25.8/24", "mac": "02:00:00:00:00:09"}
        )
        contract.validate(cfg, stack)
        cfg["app"]["frontend_routing"]["mac"] = "02:00:00:00:00:99"
        with self.assertRaisesRegex(ValueError, "Routing must match"):
            contract.validate(cfg, stack)
        stack = fixture("zigbee2mqtt")
        cfg = self.configuration("zigbee2mqtt", stack, stack["zigbee"]["bind_address"])
        cfg["paths"].update(
            host_device_key=str(self.root / "host-key"),
            host_known_hosts=str(self.root / "host-trust"),
        )
        cfg["guest"]["serial_device"] = {"path": stack["zigbee"]["serial_device"]}
        contract.validate(cfg, stack)

    def test_preserved_image_archives_are_rechecked_and_passed_to_ansible(self):
        stack = fixture("automation")
        cfg = self.configuration("automation", stack)
        archive = self.root / "image.tar"
        archive.write_bytes(b"synthetic image archive")
        import hashlib

        stack["services"]["mqtt"].update(
            image="sha256:" + "1" * 64,
            archive=str(archive),
            archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        )
        destination = self.root / "inputs/automation" / ("a" * 64)
        cfg["app"]["stack_config"] = str(destination / "stack.json")
        packet = self.root / "packet.json"
        packet.write_text(
            json.dumps(
                {
                    "schema": contract.SCHEMA,
                    "kind": "automation",
                    "enabled": True,
                    "identity": "a" * 64,
                    "files": {
                        "site.json": json.dumps(cfg),
                        "stack.json": json.dumps(stack),
                    },
                }
            )
        )
        prepared, path = deployment_inputs.prepare(
            packet, self.root / "inputs", {"NODE_RED_API_TOKEN": "synthetic"}
        )
        operation = self.root / "operation"
        operation.mkdir(mode=0o700)

        def quiet(argv, environment, log):
            log.write_text("ok=1 changed=0 failed=0")

        with (
            patch.object(deployment_inputs, "binding", return_value="expected"),
            patch.object(ansible_guest.proxmox_guest, "guest_trust"),
            patch.object(ansible_guest, "required_network_interfaces", return_value=[]),
            patch.object(ansible_guest, "quiet", side_effect=quiet),
        ):
            ansible_guest.run_phase(
                prepared, path, self.root, operation, "expected", "mqtt"
            )
        variables = json.loads((operation / "mqtt/variables.json").read_text())
        self.assertEqual(
            variables["app"]["image_archives"]["mqtt"]["archive"], str(archive)
        )
        archive.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "image archive"):
            deployment_inputs.prepare(
                packet, self.root / "inputs", {"NODE_RED_API_TOKEN": "synthetic"}
            )

    def test_foundation_preparation_binds_only_declared_existing_secrets(self):
        from secret_contract import BINDINGS

        stack = foundation_fixture(self.root, "identity")
        cfg = self.configuration("identity", stack, stack["foundation"]["bind_address"])
        environment = {
            binding.environment: "synthetic-" + name
            for name, binding in BINDINGS["identity"].items()
        }
        stack["foundation"]["secret_files"] = {
            name: str(self.root / binding.filename)
            for name, binding in BINDINGS["identity"].items()
        }
        prepared = runtime_secrets.prepare_stack(cfg, stack, self.root, environment)
        self.assertEqual(
            set(prepared),
            {binding.filename for binding in BINDINGS["identity"].values()},
        )
        self.assertEqual(
            set(prepared.values()), {value.encode() for value in environment.values()}
        )
