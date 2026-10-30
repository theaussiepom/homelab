"""Incomplete preparation, copying and execution retain custody without retries."""

import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bootstrap
import native
import access
import configuration
import test_bootstrap as preparation_cases


class CustodyEdges(unittest.TestCase):
    def inputs(self, root):
        case = preparation_cases.BootstrapTests()
        case.setUp()
        catalog, settings = root / "site.json", root / "settings.json"
        bootstrap.write(catalog, case.catalog)
        bootstrap.write(settings, case.settings)
        return case, catalog, settings

    def test_invalid_guest_private_destination_and_static_networking_are_refused(self):
        for scenario in ("guest", "private", "static"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                case, catalog, settings = self.inputs(root)
                if scenario == "guest":
                    case.catalog["guests"][0]["vmid"] = 1
                if scenario == "private":
                    case.catalog["site"]["environment"] = "production"
                if scenario == "static":
                    case.settings["dns_servers"] = []
                bootstrap.write(catalog, case.catalog)
                bootstrap.write(settings, case.settings)
                with (
                    patch.object(bootstrap, "ROOT", root),
                    self.assertRaises(bootstrap.Refused),
                ):
                    bootstrap.prepare(catalog, settings, root / "out")
                if scenario != "static":
                    self.assertFalse((root / "out").exists())

    def test_container_replay_and_incomplete_or_private_output_never_run_docker(self):
        for scenario in ("replay", "incomplete", "private"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                case, catalog, settings = self.inputs(root)
                out = root / "out"
                if scenario == "replay":
                    bootstrap.prepare(catalog, settings, out / "bundle")
                if scenario == "incomplete":
                    out.mkdir()
                if scenario == "private":
                    case.catalog["site"]["environment"] = "production"
                    bootstrap.write(catalog, case.catalog)
                with (
                    patch.object(
                        bootstrap,
                        "ROOT",
                        root if scenario == "private" else root / "public",
                    ),
                    patch.object(bootstrap.subprocess, "run") as command,
                ):
                    if scenario == "replay":
                        self.assertFalse(
                            bootstrap.container_prepare(catalog, settings, out)[
                                "changed"
                            ]
                        )
                    else:
                        with self.assertRaises(bootstrap.Refused):
                            bootstrap.container_prepare(catalog, settings, out)
                    command.assert_not_called()

    def test_copied_template_corruption_preserves_failed_preparation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            case, catalog, settings = self.inputs(root)
            archive = root / "vendor.tar.zst"
            archive.write_bytes(b"verified fixture")
            case.catalog["guests"][0][
                "template_file_id"
            ] = "local:vztmpl/vendor.tar.zst"
            case.settings["template"] = {
                "file": str(archive),
                "file_name": archive.name,
                "sha256": bootstrap.sha(archive),
                "datastore_id": "local",
            }
            bootstrap.write(catalog, case.catalog)
            bootstrap.write(settings, case.settings)
            original = bootstrap.shutil.copyfile

            def corrupt(source, destination, *args, **kwargs):
                result = original(source, destination, *args, **kwargs)
                if Path(destination).name == "template.archive":
                    Path(destination).write_bytes(b"changed")
                return result

            with (
                patch.object(bootstrap.shutil, "copyfile", side_effect=corrupt),
                self.assertRaisesRegex(bootstrap.Refused, "copy changed"),
            ):
                bootstrap.prepare(catalog, settings, root / "out")
            self.assertEqual((root / "out/template.archive").read_bytes(), b"changed")
            self.assertFalse((root / "out/preparation.json").exists())

    def test_snapshot_top_level_link_and_backup_destinations_are_not_adopted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            public = root / "public"
            (public / "proxmox").mkdir(parents=True)
            (public / "proxmox/bootstrap").symlink_to(root, target_is_directory=True)
            with (
                patch.object(bootstrap, "ROOT", public),
                self.assertRaisesRegex(bootstrap.Refused, "Source symlinks"),
            ):
                bootstrap.snapshot(root / "snapshot")
            existing = root / "existing"
            existing.mkdir()
            for destination in (
                public / "backup",
                existing,
                root / "absent-parent/backup",
            ):
                with (
                    self.subTest(destination=destination),
                    patch.object(bootstrap, "ROOT", public),
                    patch.object(bootstrap.subprocess, "run") as command,
                ):
                    with self.assertRaises(bootstrap.Refused):
                        bootstrap.container_backup(root, destination)
                    command.assert_not_called()
            with self.assertRaisesRegex(bootstrap.Refused, "public checkout"):
                native.backup(root, bootstrap.ROOT / "private-backup")

    def test_bounded_rehearsal_runner_checks_expected_status_and_retains_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for code in (0, 7):
                with patch.object(
                    bootstrap.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], code),
                ) as command:
                    if code:
                        with self.assertRaises(bootstrap.Refused):
                            bootstrap.log_run(["fixture"], root, root / "log")
                    else:
                        bootstrap.log_run(["fixture"], root, root / "log")
                    self.assertEqual(command.call_args.kwargs["timeout"], 180)

    def test_access_preconditions_and_bad_receipts_never_repeat_credentials(self):
        for scenario in ("saved", "template", "endpoint", "keys", "malformed"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                case, catalog, settings = self.inputs(root)
                work = root / "bundle"
                bootstrap.prepare(catalog, settings, work)
                values = bootstrap.read(work / "tofu/site.auto.tfvars.json")
                if scenario == "saved":
                    bootstrap.write(work / "access.json", {"status": "pending"})
                if scenario == "template":
                    values["template"] = {}
                if scenario == "endpoint":
                    values["site"]["api_endpoint"] = "http://invalid/"
                bootstrap.write(work / "tofu/site.auto.tfvars.json", values)
                original = Path.is_file

                def is_file(path):
                    return (
                        scenario != "keys"
                        if str(path).startswith("/keys/")
                        else original(path)
                    )

                def command(args, **kwargs):
                    kwargs["stdout"].write("partial response")
                    return subprocess.CompletedProcess(args, 0)

                with (
                    patch.object(Path, "is_file", is_file),
                    patch.object(
                        access.subprocess, "run", side_effect=command
                    ) as remote,
                ):
                    with self.assertRaises(bootstrap.Refused):
                        access.setup(work, 3600)
                    self.assertEqual(remote.call_count, int(scenario == "malformed"))
                if scenario == "malformed":
                    self.assertEqual(
                        bootstrap.read(work / "access-result.json")["status"], "held"
                    )

    def test_native_state_and_workspace_copy_failures_preserve_source(self):
        for scenario in ("lineage", "link", "corrupt"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                work = root / "work"
                (work / "tofu").mkdir(parents=True)
                state = work / "tofu/terraform.tfstate"
                bootstrap.write(
                    state,
                    {
                        "lineage": "" if scenario == "lineage" else "fixture",
                        "serial": 0,
                    },
                )
                if scenario == "link":
                    (work / "tofu/other.tf").symlink_to(state)
                before = state.read_bytes()
                original = native.shutil.copyfile

                def copied(source, destination):
                    original(source, destination)
                    if (
                        scenario == "corrupt"
                        and Path(destination).name == "terraform.tfstate"
                    ):
                        Path(destination).write_bytes(b"corrupt")

                with (
                    patch.object(native.shutil, "copyfile", side_effect=copied),
                    self.assertRaises(bootstrap.Refused),
                ):
                    native.copy_workspace(work, root / "copy")
                self.assertEqual(state.read_bytes(), before)

    def test_native_dispatch_refuses_wrong_platform_missing_bundle_and_existing_hold(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            with (
                patch.object(native.platform, "system", return_value="Darwin"),
                self.assertRaises(bootstrap.Refused),
            ):
                native.run_locked("plan", work)
            with (
                patch.object(native.platform, "system", return_value="Linux"),
                self.assertRaises(bootstrap.Refused),
            ):
                native.run_locked("plan", work)
            (work / "tofu").mkdir()
            (work / "tofu/backend.tf").write_text("backend")
            (work / "HOLD.json").write_text("{}")
            with (
                patch.object(native.platform, "system", return_value="Linux"),
                self.assertRaises(bootstrap.Refused),
            ):
                native.run_locked("apply", work)
            with patch.object(
                native, "run_locked", return_value={"status": "fixture"}
            ) as locked:
                self.assertEqual(native.run("plan", work), {"status": "fixture"})
                locked.assert_called_once()
            with (
                patch.object(native.platform, "system", return_value="Linux"),
                patch.object(
                    native.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0),
                ),
                self.assertRaisesRegex(bootstrap.Refused, "Unknown native"),
            ):
                native.run_locked("unknown", work)

    def test_native_timeout_cleanup_failure_cannot_erase_the_unknown_outcome(self):
        child = Mock()
        child.wait.side_effect = subprocess.TimeoutExpired("fixture", 1)
        child.poll.return_value = None
        child.terminate.side_effect = OSError("cleanup failure")
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(native.subprocess, "Popen", return_value=child),
            self.assertRaises(subprocess.TimeoutExpired),
        ):
            native.apply_process(["fixture"], Path(tmp), None, None)

    def test_configuration_schema_and_reviewed_plan_are_immutable(self):
        import test_configuration as cases

        for scenario in ("fields", "restart", "unprotect", "expiry", "partial-access"):
            case = cases.ConfigurationTests()
            case.setUp()
            try:
                value = bootstrap.read(case.deployment)
                if scenario == "fields":
                    value["extra"] = True
                if scenario == "restart":
                    value["restart_deploy"] = "yes"
                if scenario == "unprotect":
                    value["temporarily_unprotect_deploy"] = "yes"
                if scenario == "expiry":
                    value["expires_at"] = 25000
                bootstrap.write(case.deployment, value)
                with (
                    self.subTest(scenario=scenario),
                    patch.object(configuration, "remote", side_effect=case.remote),
                    patch.object(configuration.subprocess, "run"),
                ):
                    if scenario in ("fields", "restart", "unprotect"):
                        with self.assertRaises(bootstrap.Refused):
                            configuration.configure(case.work, case.deployment)
                    else:
                        result = configuration.configure(case.work, case.deployment)
                        if scenario == "partial-access":
                            response = (
                                json.dumps(
                                    {"step": "access", "result": {"status": "pending"}}
                                )
                                + "\n"
                                + json.dumps(case.report)
                            )
                            with (
                                patch.object(
                                    configuration,
                                    "remote",
                                    return_value=subprocess.CompletedProcess(
                                        [], 0, response, ""
                                    ),
                                ),
                                self.assertRaises(bootstrap.Refused),
                            ):
                                configuration.configure(
                                    case.work, case.deployment, result["plan_sha256"]
                                )
                        else:
                            self.assertTrue(result["plan_sha256"])
            finally:
                case.tearDown()

    def test_bootstrap_cli_help_does_not_start_native_tools(self):
        with (
            patch.object(sys, "argv", ["bootstrap", "--help"]),
            patch.object(bootstrap.subprocess, "run") as command,
        ):
            with self.assertRaises(SystemExit) as stopped:
                runpy.run_path(
                    str(bootstrap.HERE / "bootstrap.py"), run_name="__main__"
                )
            self.assertEqual(stopped.exception.code, 0)
            command.assert_not_called()

    def test_runner_trust_and_dhcp_refusals_precede_handover_and_native_install(self):
        import os
        import runner
        import test_state_handover as cases

        for scenario in (
            "protected",
            "missing-key",
            "bad-host-key",
            "no-address",
            "dhcp",
            "ansible",
        ):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                work = cases.StateHandoverTests().workspace(root)
                keys = root / "keys"
                keys.mkdir()
                for name in ("bootstrap-key", "known_hosts", "pve-ca.pem"):
                    (keys / name).write_text("synthetic")
                bootstrap.write(
                    work / "tofu/site.auto.tfvars.json",
                    {
                        "site": {
                            "node": "pve",
                            "api_endpoint": "https://198.18.25.2:8006/",
                        },
                        "deploy": {
                            "vmid": 4914 if scenario == "protected" else 900,
                            "ipv4": "dhcp",
                        },
                    },
                )
                bootstrap.write(
                    work / "settings.json",
                    {"repository": "fixture/private", "runner_name": "fixture"},
                )
                bootstrap.write(
                    work / "inventory.json", {"all": {"hosts": {"deploy": {}}}}
                )
                if scenario == "missing-key":
                    (keys / "pve-ca.pem").unlink()

                def path(value):
                    return keys if str(value) == "/keys" else Path(value)

                def command(args, **kwargs):
                    if args[0] == "ssh":
                        return subprocess.CompletedProcess(
                            args,
                            0,
                            (
                                "invalid key"
                                if scenario == "bad-host-key"
                                else "ssh-ed25519 AAAAsynthetic\n"
                                + (
                                    "::1 169.254.1.1"
                                    if scenario == "no-address"
                                    else "::1 169.254.1.1 198.18.25.90"
                                )
                            ),
                            "",
                        )
                    self.assertEqual(args[0], "ansible-playbook")
                    return subprocess.CompletedProcess(
                        args, 1 if scenario == "ansible" else 0
                    )

                with (
                    patch.dict(
                        os.environ, {"PROXMOX_VE_API_TOKEN": "synthetic"}, clear=True
                    ),
                    patch.object(runner, "Path", side_effect=path),
                    patch.object(native, "run_locked"),
                    patch.object(runner, "allow_host_api"),
                    patch.object(runner.subprocess, "run", side_effect=command),
                ):
                    if scenario == "dhcp":
                        runner.install_locked(work)
                        self.assertEqual(
                            bootstrap.read(work / "inventory.json")["all"]["hosts"][
                                "deploy"
                            ]["ansible_host"],
                            "198.18.25.90",
                        )
                    else:
                        with self.assertRaises(bootstrap.Refused):
                            runner.install_locked(work)
                    self.assertEqual(
                        (work / "HANDOVER.json").exists(),
                        scenario in ("dhcp", "ansible"),
                    )

    def test_held_firewall_json_and_workstation_errors_keep_the_refusal(self):
        import runner

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with (
                patch.object(
                    runner.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess(
                        [], 0, '{"status":"held"}', ""
                    ),
                ),
                self.assertRaises(bootstrap.Refused),
            ):
                runner.allow_host_api(root, ["ssh", "fixture"], {})
            with (
                patch.object(sys, "argv", ["workstation", str(root), "fixture"]),
                patch("subprocess.run", side_effect=OSError("private detail")),
                self.assertRaisesRegex(SystemExit, "Workstation execution failed"),
            ):
                runpy.run_path(
                    str(bootstrap.HERE / "workstation.py"), run_name="__main__"
                )

    def test_missing_template_is_refused_before_container_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            case, catalog, settings = self.inputs(root)
            case.settings["template"] = {
                "file": str(root / "absent"),
                "file_name": "debian.tar.zst",
                "sha256": "a" * 64,
                "datastore_id": "local",
            }
            bootstrap.write(settings, case.settings)
            with (
                patch.object(bootstrap, "ROOT", root),
                patch.object(bootstrap, "snapshot"),
                patch.object(
                    bootstrap.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0),
                ) as command,
                self.assertRaisesRegex(bootstrap.Refused, "cached template file"),
            ):
                bootstrap.container_prepare(catalog, settings, root / "output")
            self.assertEqual(command.call_count, 1)
