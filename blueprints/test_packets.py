"""The framework compiles synthetic compositions without a stack repository."""

import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import compile as compiler

APPS = Path(__file__).resolve().parents[1] / "proxmox/applications"
sys.path.insert(0, str(APPS / "tests"))
from fixtures import guest
from test_render import fixture as compose_fixture


class PacketTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.catalogue = {name: compiler.CATALOGUE[name] for name in ("dns", "mariadb")}
        patcher = patch.object(compiler, "CATALOGUE", self.catalogue)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.overlay = {
            "schema": "homelab-site-v3",
            "routes": {},
            "values": {},
            "common": {},
            "guests": {},
            "images": {},
            "accepted": {},
        }
        self.save(
            "stack.json",
            {
                "schema": "homelab-stack-v2",
                "routes": {},
                "values": {"zone": "fixture.invalid"},
                "guests": {
                    name: {"depends_on": [], "prerequisites": []}
                    for name in self.catalogue
                },
            },
        )
        self.save("common.json", {})
        self.save(
            "images.json",
            {
                "fixture": {
                    "repository": "example/service",
                    "tag": None,
                    "digest": "sha256:" + "1" * 64,
                }
            },
        )
        for index, name in enumerate(self.catalogue, 8):
            cfg = guest(self.root)
            cfg.pop("deployment")
            cfg["guest"].update(
                vmid=800 + index,
                hostname=name,
                platform="debian-lxc",
                dns_servers=["9.9.9.9"],
                rules=[],
            )
            cfg["guest"]["interfaces"][0].update(
                ipv4=f"198.18.25.{index}/24", mac=f"02:00:00:00:00:{index:02x}"
            )
            cfg["app"].update(
                kind=name,
                **(
                    {"node_red_authentication": "authentik-oidc"}
                    if name == "automation"
                    else {}
                ),
                vmid=800 + index,
                hostname=name,
                address=f"198.18.25.{index}",
                mac=f"02:00:00:00:00:{index:02x}",
                service_health_checks={
                    phase: [{"name": phase, "argv": ["true"], "expect": ""}]
                    for phase in self.catalogue[name]["applications"]
                },
            )
            stack = None
            if name == "dns":
                cfg["app"].pop("database")
                cfg["app"]["packages"] = ["docker-ce=5:28.0.0-1"]
                cfg["app"]["exclusive_writer_confirmed"] = True
                cfg["app"]["stack_config"] = "${inputs}/stack.json"
                stack = compose_fixture(name)
                stack["guest_memory_mib"] = cfg["guest"]["memory_mib"]
                for row in stack["services"].values():
                    row.pop("image")
                    row["image_ref"] = "fixture"
            self.save(
                f"guests/{name}/profile.json",
                {
                    "config": cfg,
                    "stack": stack,
                    "files": {"settings.txt": "${zone}\n${inputs}/retained"},
                },
            )
        self.save("site.json", self.overlay)

    def save(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    def test_packets_are_deterministic_and_bind_abstract_inputs_after_hashing(self):
        first = compiler.compile_stack(self.root, self.overlay, [])
        self.assertEqual(first, compiler.compile_stack(self.root, self.overlay, []))
        for name, packet in first.items():
            self.assertTrue(packet["enabled"])
            self.assertIn(packet["identity"], packet["files"]["settings.txt"])
            self.assertIn("fixture.invalid", packet["files"]["settings.txt"])
            cfg = json.loads(packet["files"]["site.json"])
            self.assertEqual(cfg["app"]["kind"], name)
            self.assertNotIn("platform", cfg["guest"])
        self.assertIn("stack.json", first["dns"]["files"])
        self.assertNotIn("stack.json", first["mariadb"]["files"])

    def test_dhcp_packet_preserves_allocation_and_binds_only_qualified_endpoint(self):
        profile = compiler.read(self.root / "guests/dns/profile.json")
        nic = profile["config"]["guest"]["interfaces"][0]
        nic.update(ipv4="dhcp", ipv4_endpoint="198.18.25.8/27", gateway=None)
        self.save("guests/dns/profile.json", profile)
        packet = compiler.compile_stack(self.root, self.overlay)["dns"]
        cfg = json.loads(packet["files"]["site.json"])
        self.assertEqual(cfg["guest"]["interfaces"][0]["ipv4"], "dhcp")
        self.assertEqual(cfg["app"]["address"], "198.18.25.8")
        first = packet["identity"]
        nic["ipv4_endpoint"] = "198.18.25.8/28"
        self.save("guests/dns/profile.json", profile)
        self.assertNotEqual(compiler.compile_stack(self.root, self.overlay)["dns"]["identity"], first)
        nic.pop("ipv4_endpoint")
        self.save("guests/dns/profile.json", profile)
        with self.assertRaisesRegex(ValueError, "qualified IPv4 endpoint"):
            compiler.compile_stack(self.root, self.overlay)

    def test_merge_and_preserved_image_contracts(self):
        self.assertEqual(
            compiler.merge({"a": {"b": 1}, "c": 2}, {"a": {"d": 3}, "c": 4}),
            {"a": {"b": 1, "d": 3}, "c": 4},
        )
        value = {
            "local_id": "sha256:" + "2" * 64,
            "archive": "/synthetic/retained.tar",
            "archive_sha256": "3" * 64,
        }
        self.assertEqual(compiler.image(value)["archive"], value["archive"])
        with self.assertRaises(ValueError):
            compiler.image(dict(value, archive="relative"))
        actual = subprocess.check_output(
            ["git", "-C", str(APPS.parents[1]), "rev-parse", "HEAD"], text=True
        ).strip()
        compiler.check_revision(APPS.parents[1], actual)
        with self.assertRaises(ValueError):
            compiler.check_revision(APPS.parents[1], "0" * 40)

    def test_compiler_cli_checks_admission_and_exclusive_outputs(self):
        with patch.object(compiler.guest_contract, "BLUEPRINTS", self.catalogue):
            for arguments in (
                ["--check"],
                ["--guest", "dns", "--output", str(self.root / "packet.json")],
            ):
                with patch.object(
                    sys,
                    "argv",
                    [
                        "compile",
                        "--stack",
                        str(self.root),
                        "--site",
                        str(self.root / "site.json"),
                        *arguments,
                    ],
                ):
                    runpy.run_path(str(Path(compiler.__file__)), run_name="__main__")
            before = (self.root / "packet.json").read_bytes()
            for args in (
                [],
                ["--guest", "dns", "--output", str(self.root / "packet.json")],
                [
                    "--guest",
                    "dns",
                    "--output",
                    str(self.root / "new.json"),
                    "--admit",
                    "--disabled",
                    '["dns"]',
                ],
            ):
                with (
                    patch.object(
                        sys,
                        "argv",
                        [
                            "compile",
                            "--stack",
                            str(self.root),
                            "--site",
                            str(self.root / "site.json"),
                            *args,
                        ],
                    ),
                    self.assertRaises((ValueError, FileExistsError)),
                ):
                    runpy.run_path(str(Path(compiler.__file__)), run_name="__main__")
            with patch.object(
                sys,
                "argv",
                [
                    "compile",
                    "--stack",
                    str(self.root),
                    "--site",
                    str(self.root / "site.json"),
                    "--guest",
                    "dns",
                    "--output",
                    str(self.root / "new.json"),
                    "--admit",
                    "--disabled",
                    "[]",
                ],
            ):
                runpy.run_path(str(Path(compiler.__file__)), run_name="__main__")
            self.assertTrue(json.loads((self.root / "new.json").read_text())["enabled"])
            self.assertEqual((self.root / "packet.json").read_bytes(), before)
