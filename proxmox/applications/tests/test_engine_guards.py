"""Current infrastructure/SSH/backup guards; native engines use conforming fakes."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import commands
import deployment_inputs as inputs
import private_io as io
import proxmox_guest as pve
import plan_policy
from test_plan import fixture as plan_fixture
from component_process_fixtures import configuration

def guest(root):
    return configuration(root)[0]


class EvidenceLogGuardTests(unittest.TestCase):
    def test_evidence_log_drift_is_refused_before_subprocess(self):
        import commands

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "log"
            path.write_bytes(b"original evidence")
            path.chmod(0o644)
            with (
                patch.object(commands.subprocess, "run") as run,
                self.assertRaises(ValueError),
            ):
                commands.quiet(["fixture"], {}, path)
            self.assertEqual(path.read_bytes(), b"original evidence")
            run.assert_not_called()
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            link = Path(td) / "link"
            link.symlink_to(path)
            with (
                patch.object(commands.subprocess, "run") as run,
                self.assertRaises(OSError),
            ):
                commands.quiet(["fixture"], {}, link)
            run.assert_not_called()


class InfrastructureCallerTests(unittest.TestCase):
    def test_fresh_creation_has_an_apply_window_before_trusted_identity_pinning(self):
        for failed in (False, True):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                cfg = guest(root)
                cfg["guest"]["vmid"] = cfg["app"]["vmid"] = 6100
                cfg["site"]["node"] = "pve-lab"
                work = root / "work"
                work.mkdir()
                operation = root / "attempt"
                operation.mkdir()
                (root / "api").write_text("fixture@pve!deploy=synthetic")
                (root / "api").chmod(0o600)

                def command(argv, env, log):
                    if "plan" in argv:
                        (operation / "guest.tfplan").write_bytes(b"saved-plan")
                    if "apply" in argv:
                        window = json.loads((operation / "apply-window.json").read_text())
                        self.assertEqual(window["plan_sha256"], io.sha(operation / "guest.tfplan"))
                        self.assertNotIn("finished_at_ns", window)
                        if failed:
                            raise ValueError("synthetic apply failure")
                        (work / "terraform.tfstate").write_text("created")

                def pin(cfg, directory, *args):
                    self.assertEqual(directory, operation)
                    window = json.loads((directory / "apply-window.json").read_text())
                    self.assertEqual(
                        window["plan_sha256"], io.sha(directory / "guest.tfplan")
                    )
                    self.assertLessEqual(window["started_at_ns"], window["finished_at_ns"])

                with (
                    patch.object(inputs, "binding", return_value={"approved": True}),
                    patch.object(pve, "backup"),
                    patch.object(pve, "quiet", side_effect=command),
                    patch.object(
                        pve.subprocess,
                        "check_output",
                        return_value=json.dumps(plan_fixture()).encode(),
                    ),
                    patch.object(pve.guest_identity, "pin", side_effect=pin) as identity,
                ):
                    if failed:
                        with self.assertRaisesRegex(ValueError, "synthetic apply failure"):
                            pve.infrastructure(cfg, root / "site", work, operation, {"approved": True})
                        identity.assert_not_called()
                        window = json.loads((operation / "apply-window.json").read_text())
                        self.assertNotIn("finished_at_ns", window)
                        self.assertTrue((operation / "plan.json").is_file())
                    else:
                        self.assertTrue(
                            pve.infrastructure(
                                cfg, root / "site", work, operation, {"approved": True}
                            )["created"]
                        )
                        identity.assert_called_once()

    def test_radio_capability_brackets_api_reconciliation_without_api_device_ownership(
        self,
    ):
        for attached in (False, True):
            with self.subTest(attached=attached), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                cfg = guest(root)
                cfg["guest"].update(
                    vmid=6100, serial_device={"path": "/dev/serial/by-id/usb-fixture"}
                )
                cfg["app"]["vmid"] = 6100
                cfg["site"]["node"] = "pve-lab"
                work, operation = root / "work", root / "attempt"
                work.mkdir()
                operation.mkdir()
                (work / "terraform.tfstate").write_bytes(b"existing backend")
                io.write_new(root / "api", b"fixture@pve!deploy=synthetic")
                value = plan_fixture()
                for row in value["resource_changes"]:
                    row["change"].update(
                        actions=["no-op"], before=copy.deepcopy(row["change"]["after"])
                    )
                events = []

                def command(argv, env, log):
                    events.append("plan" if "plan" in argv else "init")
                    self.assertNotIn("apply", argv)
                    variables = json.loads(
                        (operation / "tofu/site.auto.tfvars.json").read_text()
                    )
                    self.assertNotIn("serial_device", variables["guest"])
                    if "plan" in argv:
                        (operation / "guest.tfplan").write_bytes(b"saved plan")

                with (
                    patch.object(inputs, "binding", return_value={}),
                    patch.object(
                        pve.host_devices,
                        "check",
                        side_effect=lambda *_: events.append("check"),
                    ),
                    patch.object(
                        pve.host_devices,
                        "attach",
                        side_effect=lambda *_: (events.append("attach"), attached)[1],
                    ),
                    patch.object(
                        pve,
                        "backup",
                        side_effect=lambda _c, _s, label: events.append(label),
                    ),
                    patch.object(pve, "quiet", side_effect=command),
                    patch.object(
                        pve.subprocess,
                        "check_output",
                        return_value=json.dumps(value).encode(),
                    ),
                ):
                    result = pve.infrastructure(cfg, root / "site", work, operation, {})
                self.assertEqual(
                    result,
                    {
                        "changed": attached,
                        "created": False,
                        "state_sha256": io.sha(work / "terraform.tfstate"),
                    },
                )
                self.assertEqual(
                    events,
                    [
                        "check",
                        "before-ordinary",
                        "init",
                        "plan",
                        "attach",
                        "after-ordinary",
                    ],
                )
                blocked = root / "blocked"
                blocked.mkdir()
                with (
                    patch.object(
                        pve.host_devices,
                        "check",
                        side_effect=ValueError("capability unavailable"),
                    ),
                    patch.object(pve, "backup") as backup,
                    patch.object(pve, "quiet") as run,
                    self.assertRaisesRegex(ValueError, "capability unavailable"),
                ):
                    pve.infrastructure(cfg, root / "site", work, blocked, {})
                backup.assert_not_called()
                run.assert_not_called()
                self.assertEqual(list(blocked.iterdir()), [])


class BackendBoundaryTests(unittest.TestCase):
    def test_recovery_refuses_a_symlinked_mount_and_another_filesystem(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = guest(root)
            source = root / "terraform.tfstate"
            source.write_bytes(b"synthetic backend")
            actual_mount = root / "actual-nas"
            actual_mount.mkdir()
            mount = root / "nas"
            mount.symlink_to(actual_mount, target_is_directory=True)
            with (
                patch.object(pve.os.path, "ismount", return_value=True),
                self.assertRaises((ValueError, OSError)),
            ):
                pve.backup(cfg, source, "fixture")
            self.assertEqual(list(actual_mount.iterdir()), [])
            mount.unlink()
            mount.mkdir()
            (mount / "backups").mkdir()
            original_fstat = pve.os.fstat
            calls = 0

            def filesystem_drift(fd):
                nonlocal calls
                info = original_fstat(fd)
                calls += 1
                if calls == 2:
                    values = list(info)
                    values[2] = info.st_dev + 1
                    return os.stat_result(values)
                return info

            with (
                patch.object(pve.os.path, "ismount", return_value=True),
                patch.object(
                    pve.subprocess,
                    "check_output",
                    return_value="nfs4 " + cfg["paths"]["backup_source"] + "\n",
                ),
                patch.object(pve.os, "fstat", side_effect=filesystem_drift),
                self.assertRaisesRegex(ValueError, "recovery filesystem"),
            ):
                pve.backup(cfg, source, "fixture")
            self.assertFalse((mount / "backups/808").exists())

    def test_recovery_path_changes_cannot_redirect_writes_or_report_success(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = guest(root)
            source = root / "terraform.tfstate"
            source.write_bytes(b"synthetic backend")
            destination = root / "nas/backups/808"
            destination.mkdir(parents=True)
            outside = root / "outside"
            outside.mkdir()
            moved = destination.with_name("preserved")

            def changed_path(name, **options):
                destination.rename(moved)
                destination.symlink_to(outside, target_is_directory=True)
                return io.private_writer(name, **options)

            with (
                patch.object(pve.os.path, "ismount", return_value=True),
                patch.object(
                    pve.subprocess,
                    "check_output",
                    return_value="nfs4 " + cfg["paths"]["backup_source"] + "\n",
                ),
                patch.object(pve, "private_writer", side_effect=changed_path),
                self.assertRaises((ValueError, OSError)),
            ):
                pve.backup(cfg, source, "fixture")
            self.assertEqual(list(outside.iterdir()), [])
            self.assertEqual(
                next(moved.glob("*.tfstate")).read_bytes(), b"synthetic backend"
            )

    def test_descriptor_relative_private_writes_refuse_path_escape(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for path in ("../outside", str(root / "absolute"), "subdir/nested"):
                    with self.subTest(path=path), self.assertRaises(ValueError):
                        io.write_new(path, b"must not be written", dir_fd=descriptor)
                io.write_new("receipt", b"private evidence", dir_fd=descriptor)
                self.assertEqual(
                    io.sha("receipt", dir_fd=descriptor), io.digest(b"private evidence")
                )
                self.assertEqual({path.name for path in root.iterdir()}, {"receipt"})
            finally:
                os.close(descriptor)

    def test_recovery_refuses_destination_symlinks_before_writing(self):
        for selected in ("backups", "backups/808"):
            with self.subTest(path=selected), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                cfg = guest(root)
                mount = root / "nas"
                mount.mkdir()
                outside = root / "outside"
                outside.mkdir()
                link = mount / selected
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(outside, target_is_directory=True)
                source = root / "terraform.tfstate"
                source.write_bytes(b"synthetic backend")
                with (
                    patch.object(pve.os.path, "ismount", return_value=True),
                    patch.object(
                        pve.subprocess,
                        "check_output",
                        return_value="nfs4 " + cfg["paths"]["backup_source"] + "\n",
                    ),
                    self.assertRaises((ValueError, OSError)),
                ):
                    pve.backup(cfg, source, "fixture")
                self.assertEqual(list(outside.iterdir()), [])
                self.assertTrue(link.is_symlink())

    def test_token_bearing_api_requests_never_follow_redirects(self):
        with self.assertRaises(pve.InputNeeded):
            pve.RefuseRedirects().redirect_request(
                None, None, 302, "redirect", {}, "https://other.invalid"
            )

    def test_state_recovery_requires_the_selected_nas_and_proves_readback(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = guest(root)
            source = root / "terraform.tfstate"
            source.write_bytes(b"retained backend bytes")
            with (
                patch.object(pve.os.path, "ismount", return_value=False),
                self.assertRaises(ValueError),
            ):
                pve.backup(cfg, source, "fixture")
            self.assertFalse((root / "nas").exists())
            (root / "nas").mkdir()
            with (
                patch.object(pve.os.path, "ismount", return_value=True),
                patch.object(
                    pve.subprocess, "check_output", return_value="nfs4 wrong:/source\n"
                ),
                self.assertRaises(ValueError),
            ):
                pve.backup(cfg, source, "fixture")
            with (
                patch.object(pve.os.path, "ismount", return_value=True),
                patch.object(
                    pve.subprocess,
                    "check_output",
                    return_value="nfs4 " + cfg["paths"]["backup_source"] + "\n",
                ),
            ):
                pve.backup(cfg, source, "fixture")
            copied = list((root / "nas/backups/808").glob("*.tfstate"))
            self.assertEqual(len(copied), 1)
            self.assertEqual(copied[0].read_bytes(), source.read_bytes())
            self.assertEqual(copied[0].stat().st_mode & 0o777, 0o600)

    def test_per_guest_ssh_trust_cannot_change_or_normalize_permission_drift(self):
        from test_guest_identity import public_key
        import subprocess

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = guest(root)
            Path(cfg["paths"]["known_hosts"]).touch(mode=0o600)

            def result(byte):
                return subprocess.CompletedProcess(
                    [],
                    0,
                    cfg["app"]["address"] + " ssh-ed25519 " + public_key(byte) + "\n",
                    "",
                )

            with patch.object(pve.subprocess, "run", return_value=result(1)):
                pve.guest_trust(cfg, root)
                pve.guest_trust(cfg, root)
            record = root / "ssh-trust.json"
            original = record.read_bytes()
            with (
                patch.object(pve.subprocess, "run", return_value=result(2)),
                self.assertRaises(ValueError),
            ):
                pve.guest_trust(cfg, root)
            self.assertEqual(record.read_bytes(), original)
            record.chmod(0o644)
            with (
                patch.object(pve.subprocess, "run", return_value=result(1)),
                self.assertRaises(ValueError),
            ):
                pve.guest_trust(cfg, root)
            self.assertEqual(record.stat().st_mode & 0o777, 0o644)



if __name__=="__main__":unittest.main()
