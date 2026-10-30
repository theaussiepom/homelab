"""CD adapter dispatch and failure evidence remain separate from native execution."""

import io
import json
import os
import runpy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bootstrap_cd as cd
import test_bootstrap_cd as cd_cases
import test_provider_access as provider_cases


class CDEvidenceEdges(unittest.TestCase):
    def test_main_passes_only_validated_current_inputs_to_the_existing_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "config"
            config.write_text(json.dumps(cd_cases.config()))
            packet = root / "packet"
            packet.write_text('{"reviewed":true}')
            for resume in (False, True):
                with (
                    self.subTest(resume=resume),
                    patch.object(
                        sys,
                        "argv",
                        [
                            "cd",
                            "--config",
                            str(config),
                            *(["--resume-discovery", str(packet)] if resume else []),
                        ],
                    ),
                    patch.dict(os.environ, {"PROXMOX_BOOTSTRAP_TOKEN": "synthetic"}),
                    patch.object(cd.os, "umask"),
                    patch.object(cd, "API") as api,
                    patch.object(cd, "run", return_value={"status": "passed"}) as run,
                    patch.object(sys, "stdout", io.StringIO()) as output,
                ):
                    cd.main()
                    self.assertEqual(json.loads(output.getvalue())["status"], "passed")
                    self.assertEqual(
                        run.call_args.kwargs["resume"],
                        {"reviewed": True} if resume else None,
                    )
                    self.assertEqual(api.call_args.args[1], "synthetic")

    def test_discovery_allows_only_delegated_reads(self):
        reader = object.__new__(cd.DiscoveryAPI)
        with patch.object(cd.API, "call", return_value={"data": []}) as call:
            self.assertEqual(reader.call("/nodes"), {"data": []})
            call.assert_called_once_with("/nodes", "GET", None)

    def test_reload_poll_keeps_the_same_native_task_until_completion(self):
        case = cd_cases.BootstrapCDTests()
        case.setUp()
        try:
            actual = case.api.call
            seen = []

            def call(path, *args, **kwargs):
                if path.endswith("/status") and not seen:
                    seen.append(path)
                    return {"data": {"status": "running"}}
                return actual(path, *args, **kwargs)

            with (
                patch.object(case.api, "call", side_effect=call),
                patch.object(cd.time, "sleep") as sleep,
            ):
                self.assertEqual(case.run_cd()["status"], "passed")
                sleep.assert_called_once_with(2)
        finally:
            case.doCleanups()

    def test_failed_archival_rollback_preserves_the_original_error_and_mixed_evidence(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hold = root / "HOLD"
            marker = root / "MARKER"
            evidence = root / "evidence"
            evidence.mkdir(mode=0o700)
            for path in (hold, marker):
                path.write_text(path.name)
                path.chmod(0o600)
            original = Path.rename

            def rename(path, destination):
                if path == marker:
                    raise OSError("primary archival failure")
                if path.name == "HOLD.original":
                    raise OSError("rollback failure")
                return original(path, destination)

            with (
                patch.object(Path, "rename", rename),
                self.assertRaisesRegex(OSError, "primary archival"),
            ):
                cd.archive_markers(hold, marker, evidence)
            self.assertFalse(hold.exists())
            self.assertEqual((evidence / "HOLD.original").read_text(), "HOLD")
            self.assertEqual(marker.read_text(), "MARKER")

    def test_failed_nas_evidence_copy_keeps_the_local_continuation_failure(self):
        case = provider_cases.DiscoveryTests()
        case.setUp()
        try:
            packet = case.failed_mint_packet()
            rename = Path.rename
            save = cd.save

            def archive(path, destination):
                if path.name == "CONFIGURING":
                    raise OSError("primary marker failure")
                return rename(path, destination)

            def retain(path, value):
                if path.name == "continuation-failure.json" and path.is_relative_to(
                    case.nas
                ):
                    raise OSError("NAS unavailable")
                return save(path, value)

            with (
                patch.object(Path, "rename", archive),
                patch.object(cd, "save", side_effect=retain),
                self.assertRaisesRegex(OSError, "primary marker"),
            ):
                case.continue_cd(packet)
            local = case.root / packet["attempt"] / "continuation-failure.json"
            self.assertEqual(json.loads(local.read_text())["status"], "completion-held")
        finally:
            case.doCleanups()

    def test_credential_cli_reports_a_fixed_diagnostic_before_any_native_call(self):
        import bootstrap

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tofu").mkdir()
            (root / "settings.json").write_text('{"repository":"invalid"}')
            (root / "tofu/site.auto.tfvars.json").write_text(
                '{"site":{"api_endpoint":"https://fixture.invalid:8006/"}}'
            )
            with (
                patch.object(
                    sys,
                    "argv",
                    ["credentials", "--bundle", str(root), "--out", str(root / "out")],
                ),
                patch("os.umask"),
                patch("subprocess.run") as command,
                self.assertRaisesRegex(SystemExit, "Use an owner/repository"),
            ):
                runpy.run_path(
                    str(bootstrap.HERE / "cd_access.py"), run_name="__main__"
                )
            command.assert_not_called()

    def test_configuration_cli_plans_without_executing_ansible_and_plan_timeout_keeps_evidence(
        self,
    ):
        import bootstrap
        import configuration
        import subprocess
        import test_configuration as cases

        case = cases.ConfigurationTests()
        case.setUp()
        try:
            original = Path.is_file

            def is_file(path):
                return True if str(path).startswith("/keys/") else original(path)

            with (
                patch.object(
                    sys,
                    "argv",
                    [
                        "configuration",
                        "--work",
                        str(case.work),
                        "--deployment",
                        str(case.deployment),
                    ],
                ),
                patch("platform.system", return_value="Linux"),
                patch.object(Path, "is_file", is_file),
                patch("subprocess.run", side_effect=case.remote) as command,
                patch.object(sys, "stdout", io.StringIO()) as output,
            ):
                runpy.run_path(
                    str(bootstrap.HERE / "configuration.py"), run_name="__main__"
                )
                self.assertEqual(json.loads(output.getvalue())["phase"], "plan")
                self.assertEqual(command.call_args.args[0][0], "ssh")
            with (
                patch.object(
                    configuration,
                    "remote",
                    side_effect=subprocess.TimeoutExpired("ssh", 300),
                ),
                self.assertRaisesRegex(bootstrap.Refused, "timed out"),
            ):
                configuration.configure(case.work, case.deployment)
            self.assertFalse((case.work / "CONFIGURATION-HOLD.json").exists())
        finally:
            case.tearDown()
