"""Bootstrap tool sequencing and remote outcomes are verified with inert processes."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bootstrap
import native
import runner
import configuration
import test_configuration as configuration_cases


class OperationAdapters(unittest.TestCase):
    def test_saved_plan_apply_and_drift_verification_use_the_current_bytes(self):
        for scenario in ("success", "verify-drift", "plan-changed", "command-failed"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                work = Path(tmp)
                tofu = work / "tofu"
                tofu.mkdir()
                (tofu / "backend.tf").write_text('terraform { backend "local" {} }')
                plan = {
                    "resource_changes": [
                        {
                            "address": 'module.guests["deploy"].proxmox_virtual_environment_container.guest',
                            "change": {"actions": ["no-op"]},
                        }
                    ]
                }

                def execute(args, **kwargs):
                    if args[1] == "show":
                        kwargs["stdout"].write(json.dumps(plan))
                    if args[1] == "output":
                        kwargs["stdout"].write(
                            json.dumps({"deploy_identity": {"value": {"vmid": 900}}})
                        )
                    if args[1] == "plan" and any(
                        str(a).startswith("-out=") for a in args
                    ):
                        Path(
                            next(
                                str(a).removeprefix("-out=")
                                for a in args
                                if str(a).startswith("-out=")
                            )
                        ).write_bytes(b"reviewed plan")
                    code = (
                        7
                        if scenario == "command-failed"
                        else (
                            2
                            if scenario == "verify-drift"
                            and "-detailed-exitcode" in args
                            else 0
                        )
                    )
                    return subprocess.CompletedProcess(args, code)

                with (
                    patch.object(native.platform, "system", return_value="Linux"),
                    patch.object(native.subprocess, "run", side_effect=execute),
                    patch.object(
                        native,
                        "apply_process",
                        return_value=subprocess.CompletedProcess([], 0),
                    ),
                ):
                    if scenario == "command-failed":
                        with self.assertRaises(bootstrap.Refused):
                            native.run_locked("plan", work)
                        continue
                    native.run_locked("plan", work)
                    saved = json.loads((work / "saved-plan.json").read_text())
                    self.assertEqual(Path(saved["plan"]).read_bytes(), b"reviewed plan")
                    if scenario == "plan-changed":
                        Path(saved["plan"]).write_bytes(b"changed")
                        with self.assertRaises(bootstrap.Refused):
                            native.run_locked("apply", work)
                        self.assertTrue((work / "HOLD.json").is_file())
                    else:
                        native.run_locked("apply", work)
                        if scenario == "verify-drift":
                            with self.assertRaises(bootstrap.Refused):
                                native.run_locked("verify", work)
                        else:
                            self.assertEqual(
                                native.run_locked("verify", work)["status"], "passed"
                            )

    def test_container_backup_selects_private_destination_without_any_docker_execution(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "workspace"
            work.mkdir()
            with patch.object(
                bootstrap.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0),
            ) as command:
                result = bootstrap.container_backup(work, root / "backup")
            self.assertEqual(result["backup_directory"], str(root / "backup"))
            self.assertIn("--network", command.call_args.args[0])
            self.assertIn("none", command.call_args.args[0])

    def test_runner_host_allowance_distinguishes_stored_unknown_and_malformed(self):
        for outcome in ("ready", "malformed", "timeout", "failed"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                result = subprocess.CompletedProcess(
                    [],
                    1 if outcome == "failed" else 0,
                    (
                        '{"status":"stored"}'
                        if outcome == "ready"
                        else "incomplete response"
                    ),
                    "private details",
                )
                with patch.object(
                    runner.subprocess,
                    "run",
                    **(
                        {"side_effect": subprocess.TimeoutExpired("ssh", 90)}
                        if outcome == "timeout"
                        else {"return_value": result}
                    ),
                ):
                    if outcome == "ready":
                        self.assertEqual(
                            runner.allow_host_api(root, ["ssh", "fixture"], {})[
                                "status"
                            ],
                            "stored",
                        )
                    else:
                        with self.assertRaises(bootstrap.Refused):
                            runner.allow_host_api(root, ["ssh", "fixture"], {})
                        receipt = json.loads(
                            (root / "host-firewall-result.json").read_text()
                        )
                        self.assertFalse(receipt["automatic_retry"])

    def test_configuration_dhcp_and_host_key_refusals_preserve_attempt_custody(self):
        for scenario in (
            "dhcp",
            "dhcp-ambiguous",
            "missing-address",
            "bad-key",
            "finish",
        ):
            case = configuration_cases.ConfigurationTests()
            case.setUp()
            try:
                if scenario.startswith("dhcp"):
                    value = bootstrap.read(case.work / "tofu/site.auto.tfvars.json")
                    value["deploy"]["ipv4"] = "dhcp"
                    bootstrap.write(case.work / "tofu/site.auto.tfvars.json", value)
                if scenario == "dhcp-ambiguous":
                    case.report["addresses"].append("198.18.25.11")
                if scenario == "missing-address":
                    case.report["addresses"] = []
                if scenario == "bad-key":
                    case.report["guest_host_key"] = "ssh-rsa invalid"

                def remote(*args, **kwargs):
                    if scenario == "finish" and kwargs.get("finish"):
                        return subprocess.CompletedProcess([], 1, "{}", "")
                    return case.remote(*args, **kwargs)

                with (
                    self.subTest(scenario=scenario),
                    patch.object(configuration, "remote", side_effect=remote),
                    patch.object(
                        configuration.subprocess,
                        "run",
                        return_value=subprocess.CompletedProcess([], 0),
                    ),
                ):
                    plan = configuration.configure(case.work, case.deployment)
                    if scenario == "dhcp":
                        self.assertEqual(
                            configuration.configure(
                                case.work, case.deployment, plan["plan_sha256"]
                            )["status"],
                            "configured",
                        )
                    else:
                        with self.assertRaises(bootstrap.Refused):
                            configuration.configure(
                                case.work, case.deployment, plan["plan_sha256"]
                            )
                        self.assertTrue(
                            (case.work / "CONFIGURATION-HOLD.json").is_file()
                        )
            finally:
                case.tearDown()
