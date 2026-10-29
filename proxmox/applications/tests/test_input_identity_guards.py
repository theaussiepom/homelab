"""Immutable input hashes and guest trust must fail closed on independent drift."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import deployment_inputs as inputs
import guest_identity as identity
import test_guest_identity as identity_cases


class InputBindingTests(unittest.TestCase):
    def test_binding_tracks_all_external_authorities_and_source_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "applications"
            source.mkdir()
            (root / "common").mkdir()
            (source / "helper.py").write_text("first source")
            ignored = source / "__pycache__"
            ignored.mkdir()
            (ignored / "noise").write_bytes(b"ignored")
            paths = {}
            for name in (
                "site",
                "ca",
                "stack",
                "runtime",
                "key",
                "repository",
                "database",
                "foundation",
            ):
                paths[name] = str(root / name)
                Path(paths[name]).write_text("{}" if name == "stack" else name)
            cfg = {
                "guest": {"vmid": 6101},
                "paths": {"ca_file": paths["ca"]},
                "app": {
                    "kind": "bitwarden",
                    "stack_config": paths["stack"],
                    "bitwarden": {"runtime_env_file": paths["runtime"]},
                    "repositories": [{"key_path": paths["repository"]}],
                    "database": {"config_files": [{"source": paths["database"]}]},
                },
            }
            with (
                patch.object(inputs, "SOURCE", source),
                patch.object(
                    inputs.foundation,
                    "source_files",
                    return_value=[paths["foundation"]],
                ),
            ):
                before = inputs.binding(cfg, Path(paths["site"]))
                self.assertEqual(
                    set(before["input_hashes"]),
                    {
                        paths[n]
                        for n in (
                            "ca",
                            "stack",
                            "runtime",
                            "repository",
                            "database",
                            "foundation",
                        )
                    },
                )
                (ignored / "noise").write_bytes(b"changed but not executable source")
                self.assertEqual(inputs.binding(cfg, Path(paths["site"])), before)
                (source / "helper.py").write_text("changed source")
                self.assertNotEqual(
                    inputs.binding(cfg, Path(paths["site"]))["source_sha256"],
                    before["source_sha256"],
                )
                Path(paths["runtime"]).write_text("changed private runtime")
                self.assertNotEqual(inputs.input_hashes(cfg), before["input_hashes"])
                cfg["app"]["kind"] = "pegaprox"
                cfg["app"]["pegaprox"] = {"key_source": paths["key"]}
                self.assertIn(paths["key"], inputs.input_hashes(cfg))
                self.assertNotIn(paths["runtime"], inputs.input_hashes(cfg))

    def test_guest_identity_refusals_never_write_trust_or_completion(self):
        for scenario in (
            "ipv6",
            "guest",
            "interfaces",
            "private-mode",
            "lookup",
            "existing-ambiguous",
            "window",
            "actor",
            "scan",
        ):
            case = identity_cases.IdentityTests()
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                cfg = case.setup_fixture(root)
                address = "198.18.100.42"
                if scenario == "ipv6":
                    address = "2001:db8::1"
                if scenario == "guest":
                    case.config["hostname"] = "unrelated"
                if scenario == "interfaces":
                    cfg["guest"]["interfaces"] = []
                if scenario == "private-mode":
                    (root / "hosts").chmod(0o644)
                if scenario == "window":
                    (root / "apply-window.json").write_text(
                        json.dumps({"plan_sha256": "different"})
                    )
                if scenario == "actor":
                    (root / "api").write_text("unscoped=synthetic")

                def command(args, **kwargs):
                    if args[0] == "ssh-keygen" and scenario in (
                        "lookup",
                        "existing-ambiguous",
                    ):
                        return subprocess.CompletedProcess(
                            args, 2 if scenario == "lookup" else 0, "", ""
                        )
                    if args[0] == "ssh-keyscan" and scenario == "scan":
                        return subprocess.CompletedProcess(args, 1, "", "")
                    return case.command(args, **kwargs)

                before = (root / "hosts").read_bytes()
                with (
                    patch.object(identity.subprocess, "run", side_effect=command),
                    self.assertRaises(ValueError),
                ):
                    identity.pin(cfg, root, address, case.fetch, case.persist)
                self.assertEqual((root / "hosts").read_bytes(), before)
                self.assertFalse((root / "host-key-evidence.json").exists())
