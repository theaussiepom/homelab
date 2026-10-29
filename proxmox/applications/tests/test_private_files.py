"""Shared file custody across renderers, evidence logs and source/state hashes."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import commands
import foundation
import monitoring
import private_io
from test_monitoring import fixture as monitoring_fixture


class PrivateFileTests(unittest.TestCase):
    def test_hardlinked_outputs_are_refused_before_truncation_or_append(self):
        for append in (False, True):
            for relative in (False, True):
                with (
                    self.subTest(append=append, relative=relative),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    root = Path(directory)
                    original, alias = root / "retained", root / "output"
                    private_io.write_new(original, b"original evidence")
                    os.link(original, alias)
                    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        with self.assertRaises(ValueError):
                            with private_io.private_writer(
                                alias.name if relative else alias,
                                append=append,
                                dir_fd=fd if relative else None,
                            ) as stream:
                                stream.write(b"replacement")
                    finally:
                        os.close(fd)
                    self.assertEqual(original.read_bytes(), b"original evidence")
                    self.assertEqual(alias.read_bytes(), b"original evidence")
                    self.assertEqual(original.stat().st_nlink, 2)

    def test_readonly_secret_inputs_are_preserved_without_permission_normalization(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = monitoring_fixture(root)
            password = root / "password"
            for mode in (0o400, 0o600):
                password.chmod(mode)
                self.assertEqual(
                    foundation.read_private(password), "synthetic-fixture-password"
                )
                files = {row["path"]: row["content"] for row in monitoring.files(cfg)}
                self.assertEqual(
                    files["database-password"], "synthetic-fixture-password"
                )
                self.assertEqual(password.stat().st_mode & 0o777, mode)

    def test_monitoring_source_refuses_public_or_symlinked_secret_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = monitoring_fixture(root)
            password = root / "password"
            password.chmod(0o644)
            with self.assertRaises(ValueError):
                monitoring.files(cfg)
            self.assertEqual(password.stat().st_mode & 0o777, 0o644)
            password.chmod(0o600)
            link = root / "link"
            link.symlink_to(password)
            cfg["monitoring"]["secret_files"]["database_password"] = str(link)
            with self.assertRaises(OSError):
                monitoring.files(cfg)
            self.assertTrue(link.is_symlink())
            self.assertEqual(password.read_text(), "synthetic-fixture-password")

    def test_writer_refuses_changed_ownership_without_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "existing"
            private_io.write_new(path, b"original")
            with (
                patch.object(private_io.os, "getuid", return_value=os.getuid() + 1),
                self.assertRaises(ValueError),
            ):
                private_io.write_bytes(path, b"replacement")
            self.assertEqual(path.read_bytes(), b"original")

    def test_hashes_cannot_follow_a_replaced_source_or_backend_link(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state"
            path.write_bytes(b"authoritative")
            link = Path(directory) / "link"
            link.symlink_to(path)
            self.assertEqual(private_io.sha(path), private_io.digest(b"authoritative"))
            with self.assertRaises(OSError):
                private_io.sha(link)
            self.assertTrue(link.is_symlink())

    def test_failed_commands_preserve_private_evidence_and_later_logs_append(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.log"
            with self.assertRaises(subprocess.CalledProcessError):
                commands.quiet(
                    [
                        sys.executable,
                        "-c",
                        "print('first evidence'); raise SystemExit(1)",
                    ],
                    os.environ.copy(),
                    path,
                )
            commands.quiet(
                [sys.executable, "-c", "print('second evidence')"],
                os.environ.copy(),
                path,
            )
            self.assertEqual(path.read_text(), "first evidence\nsecond evidence\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
