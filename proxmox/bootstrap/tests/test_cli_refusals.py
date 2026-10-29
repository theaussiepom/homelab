"""Native helper entry points stop on incomplete input before any external operation."""

import contextlib
import io
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import host_api
import host_nas
import host_access

ROOT = Path(__file__).resolve().parents[1]


class EntryPointRefusalTests(unittest.TestCase):
    def test_remote_helpers_refuse_incomplete_requests_without_native_commands(self):
        for name in (
            "host_access.py",
            "host_api.py",
            "host_cd_access.py",
            "host_template.py",
        ):
            with (
                self.subTest(name=name),
                patch.object(sys, "argv", [name, "{}"]),
                patch(
                    "sys.stdin",
                    type("Input", (), {"buffer": io.BytesIO(b"synthetic")})(),
                ),
                patch(
                    "subprocess.run",
                    side_effect=AssertionError("native command forbidden"),
                ) as command,
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                with self.assertRaises(SystemExit):
                    runpy.run_path(str(ROOT / name), run_name="__main__")
                command.assert_not_called()
                self.assertNotIn("synthetic", output.getvalue())

    def test_operator_entrypoints_hold_on_missing_private_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            arguments = {
                "access.py": ["--work", str(root)],
                "runner.py": ["--work", str(root)],
                "configuration.py": [
                    "--work",
                    str(root),
                    "--deployment",
                    str(root / "missing"),
                ],
                "cd_access.py": ["--bundle", str(root), "--out", str(root / "output")],
                "bootstrap_cd.py": ["--config", str(root / "missing")],
            }
            for name, args in arguments.items():
                with (
                    self.subTest(name=name),
                    patch.object(sys, "argv", [name, *args]),
                    patch("platform.system", return_value="Darwin"),
                    patch("os.umask"),
                    patch(
                        "subprocess.run",
                        side_effect=AssertionError("external operation forbidden"),
                    ) as command,
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    with self.assertRaises(SystemExit):
                        runpy.run_path(str(ROOT / name), run_name="__main__")
                    command.assert_not_called()

    def test_host_read_wrappers_keep_failure_diagnostics_bounded(self):
        for module in (host_api, host_nas, host_access):
            with (
                self.subTest(module=module.__name__),
                patch.object(
                    module.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess(
                        [], 0, "fixture output\n", ""
                    ),
                ),
            ):
                self.assertEqual(
                    module.command(["fixture"]),
                    ("fixture output" if module is host_access else "fixture output\n"),
                )
            with (
                patch.object(
                    module.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess(
                        [], 1, "", "synthetic error"
                    ),
                ),
                self.assertRaises(RuntimeError),
            ):
                module.command(["fixture"])

    def test_deployment_acl_scope_rejects_invalid_paths_ids_and_cardinality(self):
        base = {
            "node": "pve",
            "vmid": 900,
            "storage_id": "local",
            "template_storage": "local",
            "bridge": "vmbr0",
            "vlan": 25,
        }
        for change in (
            {"storage_id": "invalid/path"},
            {"vlan": True},
            {"vlan": 0},
            {"vmid": 4914},
            {"applications": {}},
            {"applications": [{}]},
            {
                "applications": [
                    {
                        "vmid": 200,
                        "storage_id": "local",
                        "template_storage": "local",
                        "interfaces": [],
                    }
                ]
            },
        ):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                host_access.declared_grants(dict(base, **change))
