"""Operator bootstrap access routines use synthetic GitHub and SSH adapters."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cd_access
import host_cd_access
import host_template


class CDOperatorBoundaryTests(unittest.TestCase):
    def test_github_api_uses_stdin_and_never_debug_logs_private_payload(self):
        for body in ('{"ready":true}', ""):
            with patch.object(
                cd_access.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, body, ""),
            ) as command:
                value = cd_access.github(
                    "fixture/repository",
                    "/environments",
                    "PUT",
                    {"private": "synthetic"},
                )
                self.assertEqual(value, {"ready": True} if body else None)
                self.assertEqual(
                    command.call_args.kwargs["input"],
                    json.dumps({"private": "synthetic"}),
                )
                self.assertEqual(command.call_args.kwargs["env"]["GH_DEBUG"], "")
        with (
            patch.object(
                cd_access.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 1, "private", "private"),
            ),
            self.assertRaises(ValueError),
        ):
            cd_access.github("fixture/repository", "")

    def test_fresh_setup_and_verified_replay_do_not_rotate_credentials(self):
        for scenario in ("success", "ssh", "upload", "node"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                bundle = root / "bundle"
                bundle.mkdir()
                (bundle / "tofu").mkdir()
                (bundle / "settings.json").write_text(
                    json.dumps({"repository": "fixture/repository"})
                )
                (bundle / "tofu/site.auto.tfvars.json").write_text(
                    json.dumps(
                        {
                            "site": {
                                "node": "fixture",
                                "api_endpoint": "https://198.18.0.1:8006/",
                            }
                        }
                    )
                )
                key = root / "key"
                hosts = root / "hosts"
                key.write_text("synthetic key")
                hosts.write_text("synthetic trust")
                out = root / "output"
                calls = []

                def execute(argv, **kwargs):
                    calls.append(argv)
                    if argv[0] == "ssh":
                        kwargs["stdout"].write(
                            json.dumps(
                                {
                                    "status": "credential_created_acl_pending",
                                    "token": "root@pam!fixture=synthetic-token",
                                }
                            )
                            + "\n"
                            + json.dumps(
                                {"status": "ready", "token_id": "root@pam!fixture"}
                            )
                            + "\n"
                        )
                        return subprocess.CompletedProcess(
                            argv, 1 if scenario == "ssh" else 0
                        )
                    self.assertEqual(argv[:3], ["gh", "secret", "set"])
                    self.assertEqual(
                        kwargs["input"], "root@pam!fixture=synthetic-token"
                    )
                    return subprocess.CompletedProcess(
                        argv, 1 if scenario == "upload" else 0
                    )

                class API:
                    def __init__(self, *args):
                        pass

                    def call(self, path):
                        return (
                            {
                                "data": (
                                    [] if scenario == "node" else [{"node": "fixture"}]
                                )
                            }
                            if path == "/nodes"
                            else {"data": {"expire": 0, "privsep": 1}}
                        )

                with (
                    patch.dict(
                        os.environ,
                        {
                            "HOMELAB_SSH_KEY": str(key),
                            "HOMELAB_KNOWN_HOSTS": str(hosts),
                        },
                    ),
                    patch.object(cd_access.os, "umask"),
                    patch.object(cd_access, "environment"),
                    patch.object(cd_access, "verify_environment_and_secret"),
                    patch.object(cd_access, "API", API),
                    patch.object(cd_access.subprocess, "run", side_effect=execute),
                ):
                    if scenario == "success":
                        self.assertEqual(
                            cd_access.setup(bundle, out)["status"], "ready"
                        )
                        before = len(calls)
                        self.assertFalse(cd_access.setup(bundle, out)["changed"])
                        self.assertEqual(len(calls), before)
                        self.assertEqual((out / "token").stat().st_mode & 0o777, 0o600)
                    else:
                        with self.assertRaises(ValueError):
                            cd_access.setup(bundle, out)
                        self.assertTrue((out / "attempt.json").is_file())
                        self.assertFalse((out / "result.json").exists())
                        with self.assertRaises(ValueError):
                            cd_access.setup(bundle, out)

    def test_native_command_wrappers_decode_only_their_supported_output(self):
        for module in (host_cd_access, host_template):
            with patch.object(
                module.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, '{"ok":true}', ""),
            ):
                self.assertEqual(
                    module.command(["fixture", "--output-format", "json"]),
                    {"ok": True} if module is host_cd_access else '{"ok":true}',
                )
                self.assertEqual(
                    module.command(["fixture"]),
                    None if module is host_cd_access else '{"ok":true}',
                )
        with (
            patch.object(
                host_template.subprocess,
                "run",
                return_value=subprocess.CompletedProcess(
                    [], 1, "", "synthetic failure"
                ),
            ),
            self.assertRaises(RuntimeError),
        ):
            host_template.command(["fixture"])
