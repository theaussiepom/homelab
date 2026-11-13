"""Startup authorisation remains bound to media, machine and exact device identity."""

import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import patch
import pytest

ISO = Path(__file__).resolve().parents[2] / "proxmox/iso"
sys.path.insert(0, str(ISO / "src"))
sys.path.insert(0, str(ISO / "tests"))
import thunderbolt as tb
import launch
import test_thunderbolt as cases

spec = importlib.util.spec_from_file_location("startup_hook", ISO / "src/first_boot.py")
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)


@pytest.mark.parametrize("scenario", ["list", "fields", "uuid", "mac", "duplicate"])
def test_invalid_device_selections_refuse_before_any_authorization(scenario):
    devices = cases.profile()["devices"]
    if scenario == "list":
        devices = {}
    if scenario == "fields":
        devices[0]["extra"] = True
    if scenario == "uuid":
        devices[0]["unique_id"] = "invalid"
    if scenario == "mac":
        devices[0]["mac"] = "invalid"
    if scenario == "duplicate":
        devices *= 2
    with pytest.raises(ValueError):
        tb.validate_devices(devices)


@pytest.mark.parametrize(
    "scenario",
    ["empty", "profile", "uuid", "location", "security", "state", "ambiguous", "wait"],
)
def test_authorization_guards_do_not_write_to_unapproved_devices(tmp_path, scenario):
    adapter = cases.machine(tmp_path)
    value = cases.profile()
    if scenario == "empty":
        tb.authorize({"devices": [], "machine_uuid": None}, tmp_path)
        assert (adapter / "authorized").read_text().strip() == "0"
        return
    if scenario == "profile":
        value["extra"] = True
    if scenario == "uuid":
        value["machine_uuid"] = "invalid"
    if scenario == "location":
        adapter.rename(adapter.with_name("unexpected"))
    if scenario == "security":
        (adapter.parent / "domain0/security").write_text("none")
    if scenario == "state":
        (adapter / "authorized").write_text("2")
    if scenario == "ambiguous":
        other = adapter.with_name("0-2")
        other.mkdir()
        (other / "unique_id").write_text(cases.DEVICE)
    if scenario == "wait":
        (adapter / "unique_id").write_text(cases.OTHER)
        with (
            patch.object(tb.time, "monotonic", side_effect=[0, 0, 2]),
            patch.object(tb.time, "sleep") as sleep,
        ):
            with pytest.raises(ValueError, match="missing"):
                tb.authorize(value, tmp_path, timeout=1)
            sleep.assert_called_once_with(0.2)
        return
    with pytest.raises(ValueError):
        tb.authorize(value, tmp_path, timeout=0)


def test_mac_wait_ignores_incomplete_enumeration_and_checks_uniqueness(tmp_path):
    (tmp_path / "incomplete").mkdir()
    with (
        patch.object(tb.time, "monotonic", side_effect=[0, 2]),
        patch.object(tb.time, "sleep") as sleep,
    ):
        with pytest.raises(ValueError, match="did not appear"):
            tb.wait_for_mac(tmp_path, cases.MAC, 1)
        sleep.assert_called_once_with(0.2)
    for name in ("one", "two"):
        directory = tmp_path / name
        directory.mkdir()
        (directory / "address").write_text(cases.MAC)
    with pytest.raises(ValueError, match="Ambiguous"):
        tb.wait_for_mac(tmp_path, cases.MAC, 0)


@pytest.mark.parametrize("media", [False, True])
def test_startup_validates_embedded_or_verified_media_before_device_access(media):
    cfg = {
        "machine_uuid": cases.MACHINE,
        "thunderbolt_devices": cases.profile()["devices"],
    }
    argv = ["thunderbolt", "--manifest-sha256", "a" * 64] if media else ["thunderbolt"]
    with (
        patch.object(sys, "argv", argv),
        patch.object(tb, "THUNDERBOLT_PROFILE", cases.profile()),
        patch.object(launch, "verify_media", return_value=cfg) as verify,
        patch.object(launch, "validate_config") as validate,
        patch.object(tb, "authorize") as authorize,
        patch.object(tb, "settle_devices") as settle,
    ):
        tb.main()
        authorize.assert_called_once_with(cases.profile())
        settle.assert_called_once()
        assert verify.call_count == validate.call_count == int(media)
    with patch.object(tb.subprocess, "run") as command:
        tb.settle_devices()
        assert command.call_args.kwargs == {"check": True, "timeout": 25}


@pytest.mark.parametrize("live_root", [False, True])
def test_first_boot_persists_private_selected_helper_and_refuses_existing_files(
    tmp_path,
    live_root,
):
    hw = json.loads((ISO / "config/fixture-hardware.json").read_text())
    site = json.loads((ISO / "config/fixture-site.json").read_text())
    profile = {
        "expected": {name: mac for mac, name in hw["interface_names"].items()},
        **{k: site[k] for k in ("management", "storage", "admin_vlans", "fast_vlans")},
        "machine_uuid": cases.MACHINE,
        "thunderbolt_devices": cases.profile()["devices"],
    }
    target = tmp_path / "etc/network/interfaces"
    target.parent.mkdir(parents=True)
    target.write_text("original vendor configuration\n")
    for name, mac in profile["expected"].items():
        directory = tmp_path / "sys/class/net" / name
        directory.mkdir(parents=True)
        (directory / "address").write_text(mac)
    with (
        patch.object(boot, "PROFILE", profile),
        patch.object(boot, "THUNDERBOLT_HELPER", None),
    ):
        with pytest.raises(ValueError, match="helper missing"):
            boot.thunderbolt_assets(tmp_path)
    with (
        patch.object(boot, "PROFILE", profile),
        patch.object(boot, "THUNDERBOLT_HELPER", "# verified helper\n"),
        patch.object(boot, "authorize") as authorize,
        patch.object(
            boot,
            "Path",
            side_effect=lambda value: (
                tmp_path if live_root and str(value) == "/" else Path(value)
            ),
        ),
        patch.object(boot, "settle_devices") as settle,
    ):
        boot.install(tmp_path)
        assert settle.call_count == int(live_root)
        authorize.assert_called_once_with(cases.profile(), root=tmp_path)
        helper = tmp_path / "usr/local/libexec/homelab-thunderbolt.py"
        assert helper.stat().st_mode & 0o777 == 0o755
        assert (
            target.parent / "interfaces.before-homelab"
        ).read_text() == "original vendor configuration\n"
        required = (
            tmp_path
            / "etc/systemd/system/networking.service.requires/homelab-thunderbolt.service"
        )
        assert required.is_symlink() and required.resolve().is_file()
        with pytest.raises(ValueError, match="require review"):
            boot.thunderbolt_assets(tmp_path)
    with (
        patch.object(boot, "PROFILE", None),
        pytest.raises(ValueError, match="No embedded"),
    ):
        boot.configuration({})
