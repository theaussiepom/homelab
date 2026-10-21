#!/usr/bin/env python3
"""Offline installer contract tests: no systemd or host network mutations."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("network_recovery_installer", Path(__file__).with_name("install.py"))
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


def info(mode, uid=0, links=1):
    return types.SimpleNamespace(st_mode=mode, st_uid=uid, st_nlink=links)


class PathGuards(unittest.TestCase):
    def inspect(self, leaf, entries):
        def fake_lstat(path):
            if str(path) in entries:
                return entries[str(path)]
            raise FileNotFoundError(path)
        with patch.object(Path, "lstat", fake_lstat):
            mod.secure_path(Path(leaf), leaf_file=True)

    def test_root_regular_file_passes(self):
        self.inspect("/safe/file", {"/": info(stat.S_IFDIR | 0o755), "/safe": info(stat.S_IFDIR | 0o755),
                                    "/safe/file": info(stat.S_IFREG | 0o644)})

    def test_symlink_ancestor_rejected(self):
        with self.assertRaisesRegex(mod.InstallError, "symlink"):
            self.inspect("/safe/file", {"/safe": info(stat.S_IFLNK | 0o777)})

    def test_group_writable_ancestor_rejected(self):
        with self.assertRaisesRegex(mod.InstallError, "unsafe destination"):
            self.inspect("/safe/file", {"/safe": info(stat.S_IFDIR | 0o775)})

    def test_nonroot_owner_rejected(self):
        with self.assertRaisesRegex(mod.InstallError, "unsafe destination"):
            self.inspect("/safe/file", {"/safe": info(stat.S_IFDIR | 0o755, uid=1000)})

    def test_hardlinked_destination_rejected(self):
        with self.assertRaisesRegex(mod.InstallError, "unique regular"):
            self.inspect("/safe/file", {"/safe/file": info(stat.S_IFREG | 0o644, links=2)})

    def test_source_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "real").write_text("ok")
            (root / "source").symlink_to(root / "real")
            with self.assertRaises(OSError):
                mod.source_bytes(root / "source")

    def test_host_guard_and_root_guard(self):
        installer = mod.Installer(Path("/unused"))
        with patch.object(mod.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(mod.InstallError, "root"):
                installer.preflight()
        with patch.object(mod.os, "geteuid", return_value=0), patch.object(mod.socket, "gethostname", return_value="wrong"):
            with self.assertRaisesRegex(mod.InstallError, "ben-beast"):
                installer.preflight()

    def test_audit_requires_success_and_explicit_true(self):
        for code, output in [(2, '{"healthy":true}'), (0, '{}'), (0, '{"healthy":1}'), (0, '{"healthy":false}'), (0, 'text')]:
            with self.subTest(code=code, output=output), self.assertRaises(mod.InstallError):
                mod.audit_healthy(types.SimpleNamespace(returncode=code, stdout=output))
        self.assertTrue(mod.audit_healthy(types.SimpleNamespace(returncode=0, stdout='{"healthy":true}'))["healthy"])


class FakeSystem:
    def __init__(self):
        self.calls = []
        self.timer_enabled = "disabled"
        self.timer_active = "inactive"
        self.service_active = "inactive"
        self.audit_healthy = True
        self.fail_verify = False
        self.fail_start_once = False
        self.fail_timer_verification_with_active_service = False
        self.started = False
        self.mounts = [{"target": "/", "source": "/dev/test-volume", "fstype": "ext4"}]
        self.after_audit = None

    def run(self, args, *, check=True, timeout=30):
        self.calls.append(tuple(args))
        if args[0] == "/usr/bin/findmnt":
            return types.SimpleNamespace(returncode=0, stdout=json.dumps({"filesystems": self.mounts}))
        if args[0].endswith("systemd-analyze"):
            if self.fail_verify:
                raise mod.InstallError("verify failed")
            return types.SimpleNamespace(returncode=0, stdout="")
        if args[0] == "/usr/bin/python3":
            if "--apply" in args:
                raise AssertionError("installer invoked a repair")
            if self.after_audit:
                self.after_audit()
            return types.SimpleNamespace(returncode=0 if self.audit_healthy else 2,
                                         stdout=json.dumps({"healthy": self.audit_healthy}))
        raise AssertionError(args)

    def ctl(self, *args, check=True):
        self.calls.append(("systemctl", *args))
        operation = args[0]
        if operation == "show":
            return types.SimpleNamespace(returncode=0, stdout="")
        if operation == "is-active":
            if args[1] == mod.TIMER and self.started and self.fail_timer_verification_with_active_service:
                self.service_active = "active"
                return types.SimpleNamespace(returncode=3, stdout="inactive")
            value = self.timer_active if args[1] == mod.TIMER else self.service_active
        elif operation == "is-enabled":
            value = self.timer_enabled
        elif operation == "stop":
            self.timer_active = "inactive"
            value = ""
        elif operation == "disable":
            self.timer_enabled = "disabled"
            value = ""
        elif operation == "enable":
            self.timer_enabled = "enabled"
            value = ""
        elif operation == "start":
            if self.fail_start_once:
                self.fail_start_once = False
                raise mod.InstallError("timer start failed")
            self.timer_active = "active"
            self.started = True
            value = ""
        elif operation == "daemon-reload":
            value = ""
        else:
            raise AssertionError(args)
        return types.SimpleNamespace(returncode=0, stdout=value)


class Installation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "candidate"
        self.source.mkdir()
        self.runtime = self.root / "runtime"
        self.units = self.root / "units"
        self.config = self.root / "etc" / "network-recovery.json"
        self.state = self.root / "state"
        self.system = FakeSystem()
        required = {}
        for name, (_, mode) in mod.REQUIRED.items():
            dest = self.config if name.endswith(".json") else (self.units if name.endswith((".service", ".timer")) else self.runtime) / name
            required[name] = (dest, mode)
            content = b'{}\n' if name.endswith(".json") else b'# fixture\n'
            (self.source / name).write_bytes(content)

        # Path security has dedicated tests above. These transaction tests use an
        # unprivileged private temp tree, never actual installation destinations.
        def confined(path, **kwargs):
            self.assertTrue(path.is_relative_to(self.root), path)
            walk = path
            while walk != self.root.parent:
                if walk.is_symlink():
                    raise mod.InstallError("test tree symlink")
                walk = walk.parent
        self.patches = [patch.object(mod, "REQUIRED", required), patch.object(mod, "RUNTIME", self.runtime),
                        patch.object(mod, "UNITS", self.units), patch.object(mod, "CONFIG", self.config),
                        patch.object(mod, "STATE", self.state), patch.object(mod, "secure_path", confined),
                        patch.object(mod.os, "geteuid", return_value=0), patch.object(mod.os, "fchown"),
                        patch.object(mod.os, "chown"), patch.object(mod.socket, "gethostname", return_value="ben-beast")]
        for item in self.patches:
            item.start()
        self.installer = mod.Installer(self.source, self.system)

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temporary.cleanup()

    def old_files(self):
        for name, (path, mode) in self.installer.files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("old:" + name)
            path.chmod(mode)
        self.state.mkdir(exist_ok=True)
        (self.state / "attempts.json").write_text('preserve existing safety state')

    def assert_old_restored(self):
        for name, (path, _) in self.installer.files.items():
            self.assertEqual(path.read_text(), "old:" + name)
        self.assertEqual((self.state / "attempts.json").read_text(), 'preserve existing safety state')
        receipts = list((self.state / "installations").glob("*/receipt.json"))
        self.assertEqual(len(receipts), 1)
        receipt = json.loads(receipts[0].read_text())
        self.assertTrue(receipt["rollback"]["complete"])
        self.assertEqual(receipt["status"], "failed")

    def test_dry_run_no_files_or_mutating_commands(self):
        result = self.installer.install()
        self.assertEqual(result["status"], "dry_run")
        self.assertFalse(self.state.exists())
        self.assertFalse(self.runtime.exists())
        self.assertTrue(all(call[0] == "/usr/bin/findmnt" or call[1] in ("show", "is-active", "is-enabled")
                            for call in self.system.calls))

    def test_success_audits_before_timer_and_preserves_runtime_state(self):
        self.old_files()
        result = self.installer.install(apply=True)
        self.assertEqual(result["status"], "installed")
        audit_index = next(i for i, call in enumerate(self.system.calls) if call[0] == "/usr/bin/python3")
        enable_index = self.system.calls.index(("systemctl", "enable", mod.TIMER))
        self.assertLess(audit_index, enable_index)
        self.assertEqual(self.system.timer_active, "active")
        self.assertEqual((self.state / "attempts.json").read_text(), 'preserve existing safety state')
        for name, (path, mode) in self.installer.files.items():
            self.assertEqual(path.read_bytes(), (self.source / name).read_bytes())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)

    def test_verify_failure_restores_original_files_and_disabled_timer(self):
        self.old_files()
        self.system.fail_verify = True
        with self.assertRaises(mod.InstallError):
            self.installer.install(apply=True)
        self.assert_old_restored()
        self.assertEqual(self.system.timer_enabled, "disabled")
        self.assertFalse(any(call[0] == "/usr/bin/python3" for call in self.system.calls))

    def test_unhealthy_audit_restores_enabled_active_old_timer(self):
        self.old_files()
        self.system.timer_enabled = "enabled"
        self.system.timer_active = "active"
        self.system.audit_healthy = False
        with self.assertRaises(mod.InstallError):
            self.installer.install(apply=True)
        self.assert_old_restored()
        self.assertEqual(self.system.timer_enabled, "enabled")
        self.assertEqual(self.system.timer_active, "active")

    def test_new_install_failed_start_removes_new_managed_files(self):
        self.system.fail_start_once = True
        with self.assertRaises(mod.InstallError):
            self.installer.install(apply=True)
        self.assertTrue(all(not path.exists() for path, _ in self.installer.files.values()))
        self.assertEqual(self.system.timer_enabled, "disabled")
        self.assertEqual(self.system.timer_active, "inactive")

    def test_running_recovery_refuses_to_replace_files(self):
        self.old_files()
        self.system.service_active = "active"
        with self.assertRaises(mod.InstallError):
            self.installer.install(apply=True)
        self.assert_old_restored()
        self.assertFalse(any(call[0] == "/usr/bin/python3" for call in self.system.calls))

    def test_existing_installation_lock_prevents_mutations(self):
        self.state.mkdir()
        lock = os.open(self.state / ".installation.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            mod.fcntl.flock(lock, mod.fcntl.LOCK_EX | mod.fcntl.LOCK_NB)
            with self.assertRaisesRegex(mod.InstallError, "installation lock"):
                self.installer.install(apply=True)
            self.assertFalse(self.runtime.exists())
            self.assertFalse((self.state / "installations").exists())
        finally:
            os.close(lock)

    def test_existing_core_lock_prevents_payload_replacement(self):
        self.old_files()
        lock = os.open(self.state / "lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            mod.fcntl.flock(lock, mod.fcntl.LOCK_EX | mod.fcntl.LOCK_NB)
            with self.assertRaises(mod.InstallError):
                self.installer.install(apply=True)
            self.assert_old_restored()
        finally:
            os.close(lock)

    def test_local_filesystem_guard_rejects_nfs_runtime(self):
        self.system.mounts.append({"target": str(self.runtime.parent), "source": "nas:/export", "fstype": "nfs4"})
        with self.assertRaisesRegex(mod.InstallError, "local block filesystem"):
            self.installer.install(apply=True)
        self.assertFalse(self.state.exists())

    def test_local_filesystem_guard_rejects_autofs_ancestor(self):
        self.system.mounts.extend([
            {"target": str(self.root), "source": "auto", "fstype": "autofs"},
            {"target": str(self.runtime), "source": "/dev/other", "fstype": "ext4"}])
        with self.assertRaisesRegex(mod.InstallError, "automounted"):
            self.installer.install(apply=True)
        self.assertFalse(self.state.exists())

    def test_running_service_after_timer_start_defers_payload_rollback(self):
        self.old_files()
        self.system.fail_timer_verification_with_active_service = True
        with self.assertRaisesRegex(mod.InstallError, "rollback complete=False"):
            self.installer.install(apply=True)
        self.assertEqual((self.runtime / "recovery.py").read_bytes(), (self.source / "recovery.py").read_bytes())
        self.assertEqual(self.system.timer_active, "inactive")
        self.assertEqual(self.system.timer_enabled, "disabled")
        self.assertNotIn(("systemctl", "stop", mod.SERVICE), self.system.calls)

    def test_manual_core_runner_after_audit_defers_payload_rollback(self):
        self.old_files()
        self.system.audit_healthy = False
        acquired = []

        def take_lock():
            fd = os.open(self.state / "lock", os.O_RDWR)
            acquired.append(fd)
            mod.fcntl.flock(fd, mod.fcntl.LOCK_EX | mod.fcntl.LOCK_NB)

        self.system.after_audit = take_lock
        try:
            with self.assertRaisesRegex(mod.InstallError, "rollback complete=False"):
                self.installer.install(apply=True)
            self.assertEqual((self.runtime / "recovery.py").read_bytes(), (self.source / "recovery.py").read_bytes())
            self.assertEqual(self.system.timer_active, "inactive")
            self.assertEqual(self.system.timer_enabled, "disabled")
        finally:
            for fd in acquired:
                os.close(fd)

    def test_invalid_python_refuses_before_writing_state(self):
        (self.source / "fdb.py").write_text("def malformed(")
        with self.assertRaises(SyntaxError):
            self.installer.install(apply=True)
        self.assertFalse(self.state.exists())

    def test_rollback_failure_is_recorded_and_schedule_stays_stopped(self):
        self.old_files()
        self.system.timer_enabled = "enabled"
        self.system.timer_active = "active"
        self.system.audit_healthy = False
        real_write = mod.atomic_write

        def fail_restore(path, data, mode, **kwargs):
            if path == self.runtime / "recovery.py" and data == b"old:recovery.py":
                raise mod.InstallError("simulated restore failure")
            return real_write(path, data, mode, **kwargs)

        with patch.object(mod, "atomic_write", fail_restore), self.assertRaisesRegex(mod.InstallError, "rollback complete=False"):
            self.installer.install(apply=True)
        self.assertEqual(self.system.timer_active, "inactive")
        self.assertEqual(self.system.timer_enabled, "disabled")
        receipt_file = next((self.state / "installations").glob("*/receipt.json"))
        receipt = json.loads(receipt_file.read_text())
        self.assertFalse(receipt["rollback"]["complete"])
        self.assertEqual(receipt["rollback"]["errors"], ["simulated restore failure"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
