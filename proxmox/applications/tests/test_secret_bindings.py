"""One fixed secret contract connects injection, validation and rendered files."""

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import foundation
import private_io
import render
import runtime_secrets
from secret_contract import BINDINGS
from test_foundation import fixture


class SecretBindingTests(unittest.TestCase):
    def test_existing_values_reach_only_the_selected_private_runtime_files(self):
        for kind in BINDINGS:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                cfg = fixture(directory, kind)
                cfg["foundation"]["secret_files"] = {
                    key: str(root / binding.filename)
                    for key, binding in BINDINGS[kind].items()
                }
                environment = {
                    binding.environment: "synthetic-retained-" + key
                    for key, binding in BINDINGS[kind].items()
                    if binding.environment
                }
                identity = "fixture@pve!discovery"
                provider = root / "provider.json"
                private_io.write_new(
                    provider,
                    private_io.encoded(
                        {
                            "schema": "homelab-service-discovery-v1",
                            "identity": identity,
                            "token": identity + "=retained-token",
                        }
                    ),
                )
                if kind == "ingress":
                    cfg["foundation"]["proxmox_token_id"] = identity
                values = runtime_secrets.secret_inputs(
                    kind, cfg, root, environment, provider, identity
                )
                for name, value in values.items():
                    private_io.write_new(root / name, value)
                artifacts = {row["path"]: row for row in foundation.files(cfg)}
                compose = json.dumps(render.compose(cfg))
                for key, binding in BINDINGS[kind].items():
                    if key == "proxmox_token":
                        static = json.loads(artifacts["traefik.yml"]["content"])
                        self.assertEqual(
                            static["providers"]["plugin"]["traefik-proxmox-provider"][
                                "apiToken"
                            ],
                            "retained-token",
                        )
                    else:
                        self.assertEqual(
                            artifacts[binding.filename]["content"],
                            environment[binding.environment],
                        )
                    self.assertNotIn("synthetic-retained-" + key, compose)
                    self.assertEqual(
                        (root / binding.filename).stat().st_mode & 0o777, 0o600
                    )

    def test_optional_secret_is_optional_and_required_or_unknown_names_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = fixture(directory, "identity")
            del cfg["foundation"]["secret_files"]["smtp_password"]
            foundation.validate(cfg)
            env = {
                binding.environment: "retained"
                for binding in BINDINGS["identity"].values()
            }
            cfg["foundation"]["secret_files"] = {
                key: str(root / BINDINGS["identity"][key].filename)
                for key in cfg["foundation"]["secret_files"]
            }
            result = runtime_secrets.secret_inputs(
                "identity", cfg, root, env, root / "unused", ""
            )
            self.assertNotIn("smtp-password", result)
            for change in ("missing", "unknown"):
                bad = copy.deepcopy(cfg)
                if change == "missing":
                    bad["foundation"]["secret_files"].pop("secret_key")
                else:
                    bad["foundation"]["secret_files"]["arbitrary"] = str(
                        root / "unapproved"
                    )
                with self.subTest(change=change), self.assertRaises(ValueError):
                    foundation.validate(bad)
                with self.subTest(change=change), self.assertRaises(ValueError):
                    runtime_secrets.secret_inputs(
                        "identity", bad, root, env, root / "unused", ""
                    )
