"""Existing-container startup convergence must not become migration replay."""

import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bitwarden_startup_guest as guest


class FakeDocker:
    def __init__(self):
        self.value = {
            "Id": "a" * 64,
            "Name": "/homelab-bitwarden-bitwarden-1",
            "Image": "sha256:" + "b" * 64,
            "Config": {
                "Env": ["BW_DB_PASSWORD=synthetic-never-print"],
                "Labels": {"com.docker.compose.service": "bitwarden"},
            },
            "HostConfig": {
                "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                "Memory": 1536,
            },
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": "/existing/data",
                    "Destination": "/etc/bitwarden",
                    "RW": True,
                },
                {
                    "Type": "bind",
                    "Source": "/existing/logs",
                    "Destination": "/var/log/bitwarden",
                    "RW": True,
                },
            ],
            "State": {"Running": True, "Status": "running"},
        }
        self.commands = []
        self.fail_update = False

    def __call__(self, argv):
        self.commands.append(argv)
        if argv[1] == "inspect":
            return json.dumps([copy.deepcopy(self.value)])
        if argv[1] == "update":
            if self.fail_update:
                raise subprocess.CalledProcessError(1, argv)
            self.value["HostConfig"]["RestartPolicy"]["Name"] = argv[3]
        else:
            raise AssertionError("Unselected Docker operation")
        return ""


class GuestTests(unittest.TestCase):
    def setUp(self):
        self.docker = FakeDocker()
        self.selected = {
            "id": "a" * 64,
            "name": "homelab-bitwarden-bitwarden-1",
            "image": "sha256:" + "b" * 64,
            "fingerprint_sha256": guest.fingerprint(self.docker.value),
        }

    def test_policy_update_preserves_container_image_mounts_credentials_and_is_idempotent(
        self,
    ):
        original = copy.deepcopy(self.docker.value)
        result = guest.reconcile(self.selected, self.docker)
        self.assertTrue(result["changed"])
        self.assertEqual(
            [a for a in self.docker.commands if a[1] != "inspect"],
            [["docker", "update", "--restart", "unless-stopped", "a" * 64]],
        )
        original["HostConfig"]["RestartPolicy"]["Name"] = "unless-stopped"
        self.assertEqual(self.docker.value, original)
        self.assertNotIn("synthetic-never-print", json.dumps(result))
        self.docker.commands.clear()
        self.assertFalse(guest.reconcile(self.selected, self.docker)["changed"])
        self.assertTrue(all(a[1] == "inspect" for a in self.docker.commands))

    def test_stopped_exact_container_is_held_without_start_or_policy_change(self):
        self.docker.value["State"].update(Running=False, Status="exited")
        with self.assertRaises(ValueError):
            guest.reconcile(self.selected, self.docker)
        self.assertTrue(all(a[1] == "inspect" for a in self.docker.commands))

    def test_identity_image_mount_environment_or_unexpected_policy_drift_blocks_every_mutation(
        self,
    ):
        base = copy.deepcopy(self.docker.value)
        for kind in (
            "id",
            "image",
            "name",
            "mount",
            "environment",
            "policy",
            "service",
        ):
            self.docker.value = copy.deepcopy(base)
            self.docker.commands.clear()
            if kind == "id":
                self.docker.value["Id"] = "c" * 64
            elif kind == "image":
                self.docker.value["Image"] = "sha256:" + "c" * 64
            elif kind == "name":
                self.docker.value["Name"] = "/other"
            elif kind == "mount":
                self.docker.value["Mounts"][0]["Source"] = "/other/data"
            elif kind == "environment":
                self.docker.value["Config"]["Env"] = ["BW_DB_PASSWORD=changed"]
            elif kind == "service":
                self.docker.value["Config"]["Labels"][
                    "com.docker.compose.service"
                ] = "other"
            else:
                self.docker.value["HostConfig"]["RestartPolicy"]["Name"] = "always"
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                guest.reconcile(self.selected, self.docker)
            self.assertTrue(all(a[1] == "inspect" for a in self.docker.commands))

    def test_failed_policy_change_never_falls_through_to_start(self):
        self.docker.fail_update = True
        with self.assertRaises(subprocess.CalledProcessError):
            guest.reconcile(self.selected, self.docker)
        self.assertFalse(any(a[1] == "start" for a in self.docker.commands))

    def test_observation_redacts_private_configuration(self):
        value = guest.observe("a" * 64, self.docker)
        self.assertEqual(
            value["fingerprint_sha256"], self.selected["fingerprint_sha256"]
        )
        self.assertNotIn("synthetic-never-print", json.dumps(value))


if __name__ == "__main__":
    unittest.main()
