"""Device/media identity and authorization readback are required before acceptance."""

from pathlib import Path
import sys
from unittest.mock import patch
import pytest

ISO = Path(__file__).resolve().parents[2] / "proxmox/iso"
sys.path.insert(0, str(ISO / "src"))
sys.path.insert(0, str(ISO / "tests"))
from homelab_installer import core, observe
import launch
import thunderbolt as tb
import test_thunderbolt as cases


def test_media_verification_checks_every_member_before_returning_config(tmp_path):
    members = [
        "answer.toml",
        "auto-installer-mode.toml",
        "proxmox-first-boot",
        "homelab/config.json",
        "homelab/launch.py",
        "homelab/thunderbolt.py",
        "homelab/src/homelab_installer/core.py",
        "homelab/src/homelab_installer/observe.py",
        "homelab/src/homelab_installer/__init__.py",
    ]
    hashes = {}
    for name in members:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(
            b'{"fixture":true}'
            if name == "homelab/config.json"
            else b"synthetic member"
        )
        hashes[name] = core.sha(path.read_bytes())
    body = core.canonical(
        {
            "schema": "homelab-static-media-build-v1",
            "build_approval": {"fixture": True},
            "files": hashes,
        }
    )
    (tmp_path / "homelab/manifest.json").write_bytes(body)
    assert launch.verify_media(tmp_path, core.sha(body)) == {"fixture": True}
    (tmp_path / "answer.toml").write_bytes(b"changed")
    with pytest.raises(core.Refusal, match="media member changed"):
        launch.verify_media(tmp_path, core.sha(body))


@pytest.mark.parametrize("scenario", ["identity", "authorization", "revocation"])
def test_authorization_and_revocation_readbacks_cannot_be_assumed(tmp_path, scenario):
    adapter = cases.machine(tmp_path)
    read = Path.read_text
    write = Path.write_text
    counts = {"identity": 0, "state": 0}

    def readback(path, *args, **kwargs):
        if path == adapter / "unique_id":
            counts["identity"] += 1
            if scenario == "identity" and counts["identity"] >= 2:
                return cases.OTHER
        if path == adapter / "authorized":
            counts["state"] += 1
            if scenario == "authorization" and counts["state"] == 2:
                return "0"
        return read(path, *args, **kwargs)

    def recorded(path, value, *args, **kwargs):
        if (
            scenario == "revocation"
            and path == adapter / "authorized"
            and value == "0\n"
        ):
            return 2
        return write(path, value, *args, **kwargs)

    with (
        patch.object(Path, "read_text", readback),
        patch.object(Path, "write_text", recorded),
        patch.object(
            tb,
            "wait_for_mac",
            **(
                {"side_effect": ValueError("missing MAC")}
                if scenario == "revocation"
                else {}
            ),
        ),
    ):
        with pytest.raises(RuntimeError if scenario == "revocation" else ValueError):
            tb.authorize(cases.profile(), root=tmp_path, timeout=0)
    assert (adapter / "authorized").read_text().strip() == (
        "1" if scenario == "revocation" else "0"
    )


def test_no_device_profile_skips_udev_and_invalid_profile_has_no_hold_side_effect():
    with (
        patch.object(sys, "argv", ["thunderbolt"]),
        patch.object(tb, "THUNDERBOLT_PROFILE", {"machine_uuid": None, "devices": []}),
        patch.object(tb, "settle_devices") as settle,
    ):
        tb.main()
        settle.assert_not_called()
    with (
        patch.object(sys, "argv", ["thunderbolt"]),
        patch.object(tb, "THUNDERBOLT_PROFILE", None),
        patch.object(launch, "hold") as hold,
    ):
        with pytest.raises(ValueError):
            tb.main()
        hold.assert_not_called()


def test_malformed_timestamps_and_both_absent_serials_have_explicit_semantics():
    with pytest.raises(core.Refusal):
        core.timestamp("invalidZ")
    assert observe.checked_disk_properties(
        {"DEVNAME": "/dev/vda"}, {"DEVNAME": "/dev/vda"}, "/dev/vda"
    ) == {"DEVNAME": "/dev/vda"}
