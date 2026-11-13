"""Attended launch ordering is exercised with synthetic media and an inert exec adapter."""

from datetime import datetime, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch
import pytest

ROOT = Path(__file__).resolve().parents[2] / "proxmox/iso"
sys.path.insert(0, str(ROOT / "src"))
import launch
import build_single_usb as build
from homelab_installer import core

spec = importlib.util.spec_from_file_location(
    "current_launch_facts", ROOT / "tests/test_launch.py"
)
facts_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(facts_module)


@pytest.mark.parametrize("scenario", ["install", "check", "mode", "drift", "runtime"])
def test_attended_entrypoint_rechecks_before_any_native_exec(tmp_path, scenario):
    cfg, obs, native = facts_module.facts()
    first = launch.check_hardware(cfg, obs, native)
    runtime = b"synthetic native binary"
    cfg["runtime_sha256"] = core.sha(runtime)
    cdrom = tmp_path / "cdrom"
    cdrom.mkdir()
    run = tmp_path / "run"
    run.mkdir()
    binary = tmp_path / "runtime"
    binary.write_bytes(b"changed" if scenario == "runtime" else runtime)
    template = build.template(
        cfg,
        "$6$synthetic$" + "A" * 86,
        (ROOT / "config/fixture-ssh.pub").read_text().strip(),
        json.loads((ROOT / "config/fixture-site.json").read_text()),
    )
    (cdrom / "answer.toml").write_bytes(template)
    cmdline = tmp_path / "cmdline"
    cmdline.write_text(
        "homelab.mode="
        + (
            "check"
            if scenario == "check"
            else "invalid" if scenario == "mode" else "install"
        )
    )

    def path(value):
        value = str(value)
        if value == "/cdrom":
            return cdrom
        if value == "/proc/cmdline":
            return cmdline
        if value == launch.RUNTIME:
            return binary
        if value.startswith("/run/"):
            return run / Path(value).name
        return Path(value)

    inert_os = Mock()
    for name in ("O_RDWR", "O_NOCTTY", "O_RDONLY", "O_NOFOLLOW"):
        setattr(inert_os, name, getattr(os, name))
    inert_os.open.return_value = 321
    inert_os.dup.return_value = 322
    inert_os.replace.side_effect = os.replace
    console_in = MagicMock()
    console_in.__enter__.return_value.fileno.return_value = 322
    console_out = MagicMock()
    console_out.__enter__.return_value = io.StringIO()
    inert_os.fdopen.side_effect = [console_in, console_out]
    second = dict(first, boot_id="different") if scenario == "drift" else first
    stdin = SimpleNamespace(buffer=io.BytesIO(template + b"\n"))
    with (
        patch.object(launch, "Path", side_effect=path),
        patch.object(launch, "os", inert_os),
        patch.object(launch, "verify_media", return_value=cfg) as verify,
        patch.object(launch, "live", side_effect=[first, second]),
        patch.object(launch, "read_confirmation") as confirmation,
        patch.object(launch, "hold", side_effect=core.Refusal("check-only hold")),
        patch.object(sys, "stdin", stdin),
        patch.object(sys, "argv", ["launch", "--manifest-sha256", "1" * 64]),
    ):
        if scenario == "install":
            launch.main()
            inert_os.execv.assert_called_once_with(launch.RUNTIME, [launch.RUNTIME])
            assert verify.call_count == 2
            confirmation.assert_called_once()
            assert (run / "homelab-install-admission.json").is_file()
            assert (
                json.loads((run / "homelab-install-admission.json").read_text())[
                    "targets"
                ]
                == first["targets"]
            )
        else:
            with pytest.raises(core.Refusal):
                launch.main()
            inert_os.execv.assert_not_called()
            if scenario in ("check", "mode", "drift"):
                assert not (run / "homelab-install-admission.json").exists()


@pytest.mark.parametrize("kind", ["rom", "part", "disk"])
def test_boot_media_is_resolved_to_its_single_whole_device(kind):
    rows = [
        {
            "source": "/dev/sdz1" if kind == "part" else "/dev/sdz",
            "fstype": "iso9660",
            "options": "ro,nosuid",
        }
    ]
    block = {
        "path": rows[0]["source"],
        "type": kind,
        "pkname": "/dev/sdz" if kind == "part" else None,
    }
    outputs = [
        SimpleNamespace(stdout=json.dumps({"filesystems": rows})),
        SimpleNamespace(stdout=json.dumps({"blockdevices": [block]})),
    ]
    with (
        patch.object(launch.subprocess, "run", side_effect=outputs),
        patch.object(launch.os.path, "realpath", side_effect=lambda x: x),
        patch.object(
            launch.os, "stat", return_value=SimpleNamespace(st_mode=stat.S_IFBLK)
        ),
    ):
        assert launch.boot_media_disk() == (None if kind == "rom" else "/dev/sdz")


def test_live_guard_binds_the_fresh_observation_and_excludes_boot_media():
    cfg, obs, native = facts_module.facts()
    obs["captured_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    with (
        patch.object(launch, "boot_media_disk", return_value="/dev/sdz"),
        patch.object(launch, "observe", return_value=obs),
        patch.object(
            launch.core, "read_file", return_value=json.dumps(native).encode()
        ),
    ):
        result = launch.live(cfg)
        assert (
            result["boot_media_disk"] == "/dev/sdz"
            and "captured_at" not in result["observation"]
        )
    obs["captured_at"] = "2000-01-01T00:00:00Z"
    with (
        patch.object(launch, "boot_media_disk", return_value=None),
        patch.object(launch, "observe", return_value=obs),
        pytest.raises(core.Refusal, match="expired"),
    ):
        launch.live(cfg)


def test_guarded_failure_holds_without_exposing_untyped_private_errors():
    for error, message in (
        (core.Refusal("explicit refusal"), "explicit refusal"),
        (ValueError("private payload"), "ValueError"),
    ):
        with (
            patch.object(launch, "main", side_effect=error),
            patch.object(launch, "hold") as hold,
        ):
            launch.guarded_main()
            assert hold.call_args.args[0] == "HOMELAB_REFUSED: " + message
    with (
        patch.object(
            launch.time, "sleep", side_effect=RuntimeError("bounded test stop")
        ) as sleep,
        pytest.raises(RuntimeError),
    ):
        launch.hold("fixture hold")
    sleep.assert_called_once_with(3600)


def test_confirmation_refuses_closed_and_oversized_input():
    for chunk in (b"", b"X" * 512):
        with (
            patch.object(launch.select, "select", return_value=([42], [], [])),
            patch.object(launch.os, "read", return_value=chunk),
            pytest.raises(core.Refusal),
        ):
            launch.read_confirmation(42, "INSTALL A B")
