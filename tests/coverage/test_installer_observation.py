"""Installer observation reads a synthetic Linux filesystem through mocked device APIs."""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch
import pytest

ROOT = Path(__file__).resolve().parents[2] / "proxmox/iso"
sys.path.insert(0, str(ROOT / "src"))
from homelab_installer import core
from homelab_installer import observe as observation


@pytest.mark.parametrize("scenario", ["valid", "inventory", "serial", "nic", "runtime"])
def test_linux_observer_binds_fresh_kernel_and_vendor_metadata(tmp_path, scenario):
    fs = tmp_path / "linux"
    fs.mkdir()

    def write(name, value):
        p = fs / name.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(value)
        return p

    write("/cdrom/.pve-cd-id.txt", "fixture")
    snapshot = {
        "disks": {"0": {"DEVNAME": "/dev/vda", "ID_SERIAL_SHORT": "fixture"}},
        "nics": {"eth0": {"ID_NET_NAME_MAC": "enx020000000001"}},
    }
    write("/run/proxmox-installer/run-env-udev.json", json.dumps(snapshot))
    write("/dev/vda", "synthetic block device")
    aliases = fs / "dev/disk/by-id"
    aliases.mkdir(parents=True)
    (aliases / "plain-file").touch()
    (aliases / "regular-alias").symlink_to(aliases / "plain-file")
    (aliases / "dangling").symlink_to(fs / "missing")
    (aliases / "fixture").symlink_to(fs / "dev/vda")
    for name, value in {
        "/sys/dev/block/0:0/size": "1024",
        "/sys/dev/block/0:0/ro": "0",
        "/sys/dev/block/0:0/removable": "0",
        "/sys/class/net/eth0/address": "02:00:00:00:00:01",
        "/usr/bin/proxmox-auto-installer": "fixture runtime",
        "/proc/sys/kernel/random/boot_id": "22222222-2222-4222-8222-222222222222",
        "/sys/class/dmi/id/product_uuid": "11111111-1111-4111-8111-111111111111",
    }.items():
        write(name, value)
    (fs / "sys/firmware/efi").mkdir(parents=True)
    if scenario == "runtime":
        write("/usr/sbin/proxmox-auto-installer", "second runtime")

    def path(value, *parts):
        text = str(value)
        base = fs / text.lstrip("/") if text.startswith("/") else Path(value)
        return base.joinpath(*parts)

    native_stat = os.stat

    def device_stat(value, *args, **kwargs):
        return (
            SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=0)
            if kwargs.get("follow_symlinks", True)
            and str(value) in ("/dev/vda", str(aliases / "fixture"))
            else native_stat(value, *args, **kwargs)
        )

    def execute(argv, **kwargs):
        if argv[0] == "lsblk":
            stdout = json.dumps(
                {
                    "blockdevices": [
                        {
                            "path": (
                                "/dev/other" if scenario == "inventory" else "/dev/vda"
                            ),
                            "type": "disk",
                        },
                        {"path": "/dev/sr0", "type": "rom"},
                    ]
                }
            ).encode()
        elif "--name" in argv:
            stdout = (
                "DEVNAME=/dev/vda\nID_SERIAL_SHORT="
                + ("changed" if scenario == "serial" else "fixture")
                + "\n"
            )
        else:
            stdout = (
                "ID_NET_NAME_MAC="
                + ("changed" if scenario == "nic" else "enx020000000001")
                + "\n"
            )
        return subprocess.CompletedProcess(argv, 0, stdout, "")

    with (
        patch.object(observation, "Path", side_effect=path),
        patch.object(observation.sys, "platform", "linux"),
        patch.object(observation.os, "stat", side_effect=device_stat),
        patch.object(observation.subprocess, "run", side_effect=execute),
    ):
        if scenario == "valid":
            result = observation.observe()
            assert (
                result["disks"][0]["size_bytes"] == 512 * 1024
                and result["nics"][0]["mac"] == "02:00:00:00:00:01"
            )
            assert result["uefi"] is True and result["disks"][0]["by_ids"] == [
                str(aliases / "fixture")
            ]
        else:
            with pytest.raises(core.Refusal):
                observation.observe()


def test_observer_cli_refuses_native_failure_and_writes_private_success(
    tmp_path, capsys
):
    for outcome in ({"fixture": True}, core.Refusal("wrong machine")):
        target = tmp_path / (
            "failed" if isinstance(outcome, Exception) else "observation"
        )
        with patch.object(
            observation,
            "observe",
            **(
                {"side_effect": outcome}
                if isinstance(outcome, Exception)
                else {"return_value": outcome}
            ),
        ):
            assert observation.main(["--out", str(target)]) == (
                3 if isinstance(outcome, Exception) else 0
            )
        if not isinstance(outcome, Exception):
            assert target.stat().st_mode & 0o777 == 0o600
    assert "erase_authorized" in capsys.readouterr().out


@pytest.mark.parametrize("data", [b"[]", b'{"x":1,"x":2}', b'{"x":NaN}'])
def test_media_json_refuses_ambiguous_or_nonobject_data(data):
    with pytest.raises(core.Refusal):
        core.decode_json(data)


@pytest.mark.parametrize(
    "value", [None, "not-a-uuid", "00000000-0000-0000-0000-000000000000"]
)
def test_media_uuid_identity_is_literal_and_nonzero(value):
    with pytest.raises(core.Refusal):
        core.identifier(value, "fixture")


@pytest.mark.parametrize(
    "value",
    ["not encoded", "ssh-rsa invalid", "ssh-ed25519 notbase64!", "ssh-ed25519 YQ=="],
)
def test_media_public_keys_require_the_actual_ed25519_wire_structure(value):
    with pytest.raises(core.Refusal):
        core.ssh_key(value)


def test_protected_input_ownership_and_bounded_read_are_checked(tmp_path):
    p = tmp_path / "private"
    p.write_bytes(b"input")
    p.chmod(0o600)
    with (
        patch.object(core.os, "geteuid", return_value=p.stat().st_uid + 1),
        pytest.raises(core.Refusal, match="owner"),
    ):
        core.read_file(p, protected=True)
    with pytest.raises(core.Refusal, match="limit"):
        core.read_file(p, limit=2)
    p.chmod(0o644)
    with pytest.raises(core.Refusal, match="permissions"):
        core.read_file(p, protected=True)
