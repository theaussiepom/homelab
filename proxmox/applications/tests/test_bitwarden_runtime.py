"""Ordinary Bitwarden consumes final private runtime settings without migration."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bitwarden_runtime as runtime
import render


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.path = Path(td.name) / "runtime.json"
        self.value = {
            "BW_DB_PROVIDER": "mysql",
            "BW_DB_SERVER": "198.18.32.24",
            "BW_DB_DATABASE": "vault",
            "BW_DOMAIN": "vault.example.invalid",
            "PUID": "1000",
            "PGID": "1000",
            **{
                k: "synthetic"
                for k in [
                    "BW_DB_USERNAME",
                    "BW_DB_PASSWORD",
                    "BW_INSTALLATION_ID",
                    "BW_INSTALLATION_KEY",
                    "globalSettings__identityServer__certificatePassword",
                ]
            },
        }
        self.path.write_text(json.dumps(self.value))
        self.path.chmod(0o600)
        self.cfg = {
            "app": {
                "kind": "bitwarden",
                "exclusive_writer_confirmed": True,
                "bitwarden": {
                    "schema": "homelab-bitwarden-runtime-v1",
                    "public_origin": "https://vault.example.invalid",
                    "issuer": "http://localhost",
                    "runtime_env_file": str(self.path),
                    "environment_sha256": hashlib.sha256(
                        self.path.read_bytes()
                    ).hexdigest(),
                },
            }
        }
        self.cfg["routes"] = {
            "vault": {
                "host": "vault.example.invalid",
                "url": "http://198.18.30.35:8080",
            }
        }
        self.stack = {
            "kind": "bitwarden",
            "guest_memory_mib": 2048,
            "bitwarden": {
                "schema": "homelab-bitwarden-runtime-v1",
                "bind_address": "198.18.30.35",
                "image_id": "sha256:" + "1" * 64,
                "database_server": "198.18.32.24",
                "database_provider": "mysql",
                "database_name": "vault",
                "data_uid": 1000,
                "data_gid": 1000,
            },
            "services": {
                "bitwarden": {
                    "image": "ghcr.io/bitwarden/lite:latest",
                    "memory_mib": 1536,
                    "cpus": 1,
                    "pids_limit": 256,
                    "environment": dict(self.value),
                }
            },
        }

    def test_ordinary_contract_uses_final_environment_and_no_restore_inputs(self):
        self.assertEqual(runtime.environment(self.cfg, self.stack), self.value)
        runtime.validate(self.cfg, self.stack)
        self.assertNotIn("capture", self.cfg["app"])
        self.assertNotIn("restore_receipt", self.cfg["app"]["bitwarden"])

    def test_bitwarden_uses_the_shared_restart_convention(self):
        selected = self.stack["services"]["bitwarden"]
        selected.pop("restart", None)
        self.assertEqual(
            render.compose(self.stack)["services"]["bitwarden"]["restart"], "always"
        )
        for policy in ("always", "unless-stopped", "no"):
            selected["restart"] = policy
            runtime.validate(self.cfg, self.stack)
            self.assertEqual(
                render.compose(self.stack)["services"]["bitwarden"]["restart"], policy
            )
        for policy in (None, False, "sometimes", [], {}):
            selected["restart"] = policy
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                runtime.validate(self.cfg, self.stack)

    def test_endpoint_identity_and_private_file_drift_are_holds_not_conversions(self):
        for key, value in [("database_server", "198.18.30.24"), ("data_uid", 999)]:
            old = self.stack["bitwarden"][key]
            self.stack["bitwarden"][key] = value
            with self.assertRaises(ValueError):
                runtime.environment(self.cfg, self.stack)
            self.stack["bitwarden"][key] = old
        self.path.write_text(json.dumps(dict(self.value, BW_DB_PASSWORD="changed")))
        with self.assertRaises(ValueError):
            runtime.environment(self.cfg, self.stack)

    def test_public_or_symlinked_secret_file_cannot_be_read(self):
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            runtime.environment(self.cfg, self.stack)
        self.path.chmod(0o600)
        other = self.path.with_suffix(".link")
        other.symlink_to(self.path)
        self.cfg["app"]["bitwarden"]["runtime_env_file"] = str(other)
        with self.assertRaises((ValueError, OSError)):
            runtime.environment(self.cfg, self.stack)

    def test_stack_preparation_reads_the_existing_runtime_authority(self):
        import runtime_secrets

        self.stack["services"]["bitwarden"]["environment"] = {}
        self.assertEqual(
            runtime_secrets.prepare_stack(self.cfg, self.stack, self.path.parent, {}),
            {},
        )
        self.assertEqual(self.stack["services"]["bitwarden"]["environment"], self.value)
        with self.assertRaisesRegex(ValueError, "outside source packets"):
            runtime_secrets.prepare_stack(self.cfg, self.stack, self.path.parent, {})
