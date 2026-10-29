"""Installation refusals preserve files, runtime state and incomplete rollback evidence."""

import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch
import pytest

ROOT = Path(__file__).resolve().parents[2] / "services/network-recovery"
sys.path.insert(0, str(ROOT))
import test_install as cases


@pytest.mark.parametrize(
    "scenario",
    [
        "metadata",
        "dropins",
        "fragment",
        "active",
        "masked",
        "timer-file",
        "timer-link",
        "json",
    ],
)
def test_preflight_refuses_ambiguous_installation_authority(scenario):
    case = cases.Installation()
    case.setUp()
    module = cases.mod
    try:
        original = case.system.ctl

        def ctl(*args, **kwargs):
            if scenario == "dropins" and "--property=DropInPaths" in args:
                return SimpleNamespace(stdout="/unmanaged/override.conf")
            if scenario == "fragment" and "--property=FragmentPath" in args:
                return SimpleNamespace(stdout="/unmanaged/unit.service")
            if scenario == "active" and args[0] == "is-active":
                return SimpleNamespace(stdout="activating")
            if scenario == "masked" and args[0] == "is-enabled":
                return SimpleNamespace(stdout="masked")
            return original(*args, **kwargs)

        case.system.ctl = ctl
        if scenario == "metadata":
            case.system.mounts = []
        if scenario in ("timer-file", "timer-link"):
            link = case.units / "timers.target.wants" / module.TIMER
            link.parent.mkdir(parents=True)
            if scenario == "timer-file":
                link.write_text("unmanaged")
            else:
                link.symlink_to(case.root / "elsewhere")
        if scenario == "json":
            (case.source / "network-recovery.json").write_text("[]")
        with pytest.raises(module.InstallError):
            case.installer.install(apply=True)
        assert not case.runtime.exists()
        assert not case.state.exists()
        assert not any(call[0] == "/usr/bin/python3" for call in case.system.calls)
    finally:
        case.tearDown()


def test_process_wrapper_bounds_commands_and_hides_private_output():
    module = cases.mod
    for code in (0, 1):
        result = SimpleNamespace(
            returncode=code, stdout="private output", stderr="private diagnostics"
        )
        with patch.object(module.subprocess, "run", return_value=result) as command:
            if code:
                with pytest.raises(module.InstallError) as failure:
                    module.System().ctl("status", module.TIMER)
                assert "private" not in str(failure.value)
            else:
                assert module.System().ctl("status", module.TIMER) is result
            assert command.call_args.kwargs["timeout"] == 30
            assert command.call_args.kwargs["stdin"] == subprocess.DEVNULL


@pytest.mark.parametrize("path", ["relative", "/unsafe/../destination"])
def test_destination_paths_must_be_absolute_and_normalized(path):
    with pytest.raises(cases.mod.InstallError, match="absolute normalized"):
        cases.mod.secure_path(Path(path))


def test_atomic_write_failure_removes_temporary_file_and_preserves_original(tmp_path):
    target = tmp_path / "file"
    target.write_bytes(b"original")
    with (
        patch.object(cases.mod, "secure_path"),
        patch.object(cases.mod.os, "fchown", side_effect=PermissionError),
    ):
        with pytest.raises(PermissionError):
            cases.mod.atomic_write(target, b"new", 0o600)
    assert target.read_bytes() == b"original"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["file"]


@pytest.mark.parametrize("failure", ["stop", "reload", "checksum", "restore"])
def test_failed_rollback_retains_explicit_incomplete_evidence(failure):
    case = cases.Installation()
    case.setUp()
    module = cases.mod
    try:
        case.old_files()
        case.system.audit_healthy = False
        original_ctl, original_write = case.system.ctl, module.atomic_write
        auditing = [False]

        def after_audit():
            auditing[0] = True
            if failure == "checksum":
                backups = list((case.state / "installations").glob("*/*.before"))
                assert backups
                backups[0].write_bytes(b"corrupted backup")

        case.system.after_audit = after_audit

        def ctl(*args, **kwargs):
            if auditing[0] and args[0] == failure:
                raise module.InstallError("synthetic rollback failure")
            if auditing[0] and args[0] == "daemon-reload" and failure == "reload":
                raise module.InstallError("synthetic reload failure")
            return original_ctl(*args, **kwargs)

        def write(*args, **kwargs):
            if (
                auditing[0]
                and failure == "restore"
                and args[0] in {path for path, _ in case.installer.files.values()}
            ):
                raise OSError("synthetic restore failure")
            return original_write(*args, **kwargs)

        case.system.ctl = ctl
        with (
            patch.object(module, "atomic_write", side_effect=write),
            pytest.raises(module.InstallError, match="rollback complete=False"),
        ):
            case.installer.install(apply=True)
        receipt = json.loads(
            next((case.state / "installations").glob("*/receipt.json")).read_text()
        )
        assert receipt["rollback"]["complete"] is False
        assert receipt["rollback"]["errors"]
        assert (
            case.state / "attempts.json"
        ).read_text() == "preserve existing safety state"
    finally:
        case.tearDown()
