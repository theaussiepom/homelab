"""Preflight the retained SSH key before binding persistent credentials."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import credentials


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("selected", "other"):
            subprocess.run(
                [
                    "ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    "retained-" + name,
                    "-f",
                    str(self.root / name),
                ],
                check=True,
                capture_output=True,
            )
        self.directory = self.root / "credentials"
        self.directory.mkdir(mode=0o700)
        self.token = self.directory / "token"
        self.key = self.directory / "key"
        self.public = " ".join((self.root / "selected.pub").read_text().split()[:2])
        self.value = {
            "schema": "homelab-guest-deployment-v2",
            "enabled": True,
            "files": {
                "site.json": json.dumps(
                    {
                        "paths": {
                            "api_token": str(self.token),
                            "private_key": str(self.key),
                        },
                        "ssh_public_keys": [self.public],
                    }
                )
            },
        }
        self.packet = self.root / "packet.json"
        self.environment = {
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "push",
            "PROXMOX_APP_TOKEN": "fixture@pve!applications=synthetic",
            "APPLICATION_SSH_KEY": (self.root / "selected").read_text(),
        }

    def save(self):
        self.packet.write_text(json.dumps(self.value))

    def test_command_line_binds_private_credentials_and_suppresses_failed_input(self):
        import os

        self.save()
        result = subprocess.run(
            [
                sys.executable,
                str(Path(credentials.__file__)),
                "--packet",
                str(self.packet),
            ],
            env=dict(os.environ, **self.environment),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["files_created"], 2)
        self.assertNotIn(
            self.environment["PROXMOX_APP_TOKEN"], result.stdout + result.stderr
        )
        failed = subprocess.run(
            [
                sys.executable,
                str(Path(credentials.__file__)),
                "--packet",
                str(self.root / "missing"),
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("Credential binding held", failed.stderr)

    def test_late_bootstrap_hold_stops_next_phase_before_packet_or_actual_credential_writes(self):
        import workflows
        import test_workflow_materialization as oracle
        from deployment_state import bootstrap_closed

        stack = self.root / "stack"; stack.mkdir(); oracle.fixture(stack)
        job = workflows.models(stack)["guest-automation.yml"]["jobs"]["deploy"]
        for marker in ("CONFIGURING", "BOOTSTRAP-CD-HOLD.json"):
            for phase in oracle.PHASES["automation"][1:]:
                with self.subTest(marker=marker, phase=phase):
                    case = self.root / (marker + "-" + phase); case.mkdir()
                    bootstrap = case / "bootstrap"; bootstrap.mkdir()
                    initial = job["steps"][0]["run"].replace("/var/lib/homelab-bootstrap", str(bootstrap))
                    self.assertEqual(subprocess.run(["bash", "-e", "-c", initial], capture_output=True).returncode, 0)
                    (bootstrap / marker).write_text("synthetic late hold")
                    self.packet = case / "packet.json"
                    self.directory = case / "credentials"; self.directory.mkdir(mode=0o700)
                    self.token, self.key = self.directory / "token", self.directory / "key"
                    cfg = json.loads(self.value["files"]["site.json"])
                    cfg["paths"] = {"api_token": str(self.token), "private_key": str(self.key)}
                    self.value["files"]["site.json"] = json.dumps(cfg)
                    index = next(i for i, step in enumerate(job["steps"])
                                 if step["name"] == "Check inputs" and step["env"]["PHASE"] == phase)
                    start = index - 1 if job["steps"][index - 1]["name"] == "Check readiness" else index
                    events = []; blocked = False
                    for step in job["steps"][start:index + 3]:
                        if step["name"] == "Check readiness":
                            # Only remap the fixed marker directory into this temporary fixture.
                            script = step["run"].replace("/var/lib/homelab-bootstrap", str(bootstrap))
                            if subprocess.run(["bash", "-e", "-c", script], capture_output=True).returncode:
                                blocked = True; break
                        elif step["name"] == "Check inputs":
                            events.append("compile"); self.save()
                        elif step["name"] == "Load credentials":
                            events.append("credentials"); credentials.bind(self.packet, self.environment)
                        else:
                            events.append("deploy")
                            try: bootstrap_closed(bootstrap)
                            except ValueError: blocked = True; break
                    self.assertTrue(blocked)
                    self.assertEqual({"events": events, "packet": self.packet.exists(),
                                      "token": self.token.exists(), "key": self.key.exists()},
                                     {"events": [], "packet": False, "token": False, "key": False})
                    self.assertEqual((bootstrap / marker).read_text(), "synthetic late hold")

    def test_matching_key_binds_once_without_rotation(self):
        self.save()
        self.assertEqual(
            credentials.bind(self.packet, self.environment)["files_created"], 2
        )
        before = {p.name: p.read_bytes() for p in self.directory.iterdir()}
        self.assertEqual(
            credentials.bind(self.packet, self.environment)["files_created"], 0
        )
        self.assertEqual(
            before, {p.name: p.read_bytes() for p in self.directory.iterdir()}
        )
        self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)

    def test_mismatched_key_is_refused_before_either_credential_is_written(self):
        cfg = json.loads(self.value["files"]["site.json"])
        cfg["ssh_public_keys"] = [
            " ".join((self.root / "other.pub").read_text().split()[:2])
        ]
        self.value["files"]["site.json"] = json.dumps(cfg)
        self.save()
        with self.assertRaises(ValueError):
            credentials.bind(self.packet, self.environment)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_unusable_private_key_is_refused_without_persistent_writes(self):
        self.save()
        self.environment["APPLICATION_SSH_KEY"] = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\ninvalid\n-----END OPENSSH PRIVATE KEY-----\n"
        )
        with self.assertRaises(ValueError):
            credentials.bind(self.packet, self.environment)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_encrypted_key_is_refused_without_prompting_or_persistent_writes(self):
        subprocess.run(
            [
                "ssh-keygen",
                "-p",
                "-P",
                "",
                "-N",
                "synthetic-passphrase",
                "-f",
                str(self.root / "selected"),
            ],
            check=True,
            capture_output=True,
        )
        self.environment["APPLICATION_SSH_KEY"] = (self.root / "selected").read_text()
        self.save()
        with self.assertRaises(ValueError):
            credentials.bind(self.packet, self.environment)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_existing_credential_drift_is_preserved(self):
        self.save()
        credentials.bind(self.packet, self.environment)
        self.token.write_text("different retained token")
        before = {p.name: p.read_bytes() for p in self.directory.iterdir()}
        with self.assertRaises(ValueError):
            credentials.bind(self.packet, self.environment)
        self.assertEqual(
            before, {p.name: p.read_bytes() for p in self.directory.iterdir()}
        )

    def test_aliased_credential_paths_refuse_before_partial_binding(self):
        cfg = json.loads(self.value["files"]["site.json"])
        cfg["paths"]["private_key"] = str(self.token)
        self.value["files"]["site.json"] = json.dumps(cfg)
        self.save()
        with self.assertRaises(ValueError):
            credentials.bind(self.packet, self.environment)
        self.assertEqual(list(self.directory.iterdir()), [])
