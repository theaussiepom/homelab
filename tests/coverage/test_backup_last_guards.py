"""Backup CLI and verification-root races preserve failed evidence."""

import importlib.util
from pathlib import Path
import runpy
import sys
from unittest.mock import patch
import pytest

ROOT = Path(__file__).resolve().parents[2] / "services/database-backup"


def test_patch_cli_and_recovery_cli_preserve_refused_inputs(tmp_path):
    source = tmp_path / "native"
    source.write_bytes(b"unreviewed source")
    with (
        patch.object(sys, "argv", ["patch", str(source)]),
        pytest.raises(RuntimeError, match="source"),
    ):
        runpy.run_path(str(ROOT / "patch-native-hooks.py"), run_name="__main__")
    assert source.read_bytes() == b"unreviewed source"
    with (
        patch.object(sys, "argv", ["recovery", "invalid"]),
        patch("os.umask"),
        pytest.raises(RuntimeError, match="invalid_hook_context"),
    ):
        runpy.run_path(str(ROOT / "recovery-bundle.py"), run_name="__main__")


@pytest.mark.parametrize("race", [False, True])
def test_s3_root_symlink_is_refused_before_creating_any_receipts(tmp_path, race):
    spec = importlib.util.spec_from_file_location(
        "s3_guard", ROOT / "verify-s3-download.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    root = tmp_path / "backup/database-recovery/s3-verification"
    other = tmp_path / "replacement"
    other.mkdir()
    if not race:
        (tmp_path / "backup").symlink_to(other, target_is_directory=True)

    def path(value):
        return (
            tmp_path / str(value).lstrip("/")
            if str(value).startswith("/backup")
            else Path(value)
        )

    original = Path.mkdir
    replaced = [False]

    def mkdir(path, *args, **kwargs):
        result = original(path, *args, **kwargs)
        if race and path == root and not replaced[0]:
            replaced[0] = True
            path.rmdir()
            path.symlink_to(other, target_is_directory=True)
        return result

    with (
        patch.object(module, "Path", side_effect=path),
        patch.object(Path, "mkdir", mkdir),
        patch.object(module.os, "umask"),
        patch.object(sys, "argv", ["verify", "--not-before", "2026-10-29T00:00:00Z"]),
        patch.object(module.subprocess, "run") as command,
    ):
        with pytest.raises(RuntimeError, match="symlinked"):
            module.main()
        command.assert_not_called()
    assert not list(other.iterdir())
