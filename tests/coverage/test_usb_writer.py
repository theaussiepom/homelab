"""USB orchestration targets a disposable file; every device API is substituted."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import sys
from unittest.mock import patch
import pytest

ROOT = Path(__file__).resolve().parents[2]


def load():
    spec = importlib.util.spec_from_file_location(
        "usb_writer_contract", ROOT / "proxmox/iso/scripts/write-usb.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "scenario",
    [
        "write",
        "multi-block",
        "inspection-drift",
        "practice",
        "image-metadata",
        "not-admitted",
        "preview",
        "root",
        "receipt",
        "capacity",
        "changed-before",
        "not-char",
        "short-read",
        "digest",
        "changed-after",
        "unmount",
    ],
)
def test_writer_receipts_bind_all_bytes_and_keep_failure_evidence(tmp_path, scenario):
    module = load()
    (tmp_path / ".local").mkdir()
    (tmp_path / "evidence").mkdir()
    builddir = tmp_path / "build/single-usb-production"
    builddir.mkdir(parents=True)
    image = builddir / "Proxmox-9.2-1-production.iso"
    content = b"x" * (5 * 1024**2) if scenario == "multi-block" else b"synthetic image"
    image.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    (builddir / "build-receipt.json").write_text(
        json.dumps(
            {
                "environment": "production",
                "iso": str(image),
                "bytes": len(content),
                "sha256": digest,
            }
        )
    )
    (tmp_path / "evidence/media-acceptance.json").write_text(
        json.dumps({"usb_write_admitted": True, "production_iso_sha256": digest})
    )
    if scenario in ("practice", "image-metadata"):
        path = builddir / "build-receipt.json"
        changed = json.loads(path.read_text())
        if scenario == "practice":
            changed["environment"] = "fixture"
        else:
            changed["bytes"] += 1
        path.write_text(json.dumps(changed))
    if scenario == "not-admitted":
        (tmp_path / "evidence/media-acceptance.json").write_text(
            json.dumps({"usb_write_admitted": False})
        )
    identity = {
        "DeviceIdentifier": "disk999",
        "WholeDisk": True,
        "Internal": False,
        "BusProtocol": "USB",
        "IORegistryEntryName": "Fixture USB",
        "TotalSize": 65536 + len(content) + (0 if scenario == "capacity" else 1024),
        "WritableMedia": True,
        "SystemImage": False,
        "DeviceTreePath": "fixture/device",
    }
    expected = {"identity": identity, "partitions": []}
    (tmp_path / ".local/usb.json").write_text(json.dumps(expected))
    receipt = tmp_path / "evidence/usb-write-receipt.json"
    if scenario == "receipt":
        receipt.write_text("retained evidence")
    raw = tmp_path / "raw-device.fixture"
    raw.write_bytes(b"\0" * identity["TotalSize"])
    original_open = os.open
    original_read = os.read

    def open_local(path, *args, **kwargs):
        return (
            original_open(raw, *args, **kwargs)
            if str(path) == "/dev/rdisk999"
            else original_open(path, *args, **kwargs)
        )

    snapshots = iter(
        [
            {"changed": True} if scenario == "inspection-drift" else expected,
            {"changed": True} if scenario == "changed-before" else expected,
        ]
    )

    def checked(argv):
        if "unmountDisk" in argv and scenario == "unmount":
            raise OSError("fixture unmount failed")
        if "info" in argv:
            return plistlib.dumps(
                dict(identity, TotalSize=1) if scenario == "changed-after" else identity
            )
        return b""

    def read(fd, size):
        return (
            b""
            if scenario == "short-read"
            else b"X" * size if scenario == "digest" else original_read(fd, size)
        )

    arguments = [
        "usb",
        "--device",
        "/dev/disk999",
        *([] if scenario == "preview" else ["--write"]),
    ]
    with (
        patch.object(module, "ROOT", tmp_path),
        patch.object(module.sys, "platform", "darwin"),
        patch.object(sys, "argv", arguments),
        patch.object(module, "snapshot", side_effect=lambda *_: next(snapshots)),
        patch.object(module, "checked", side_effect=checked),
        patch.object(module.os, "geteuid", return_value=1 if scenario == "root" else 0),
        patch.object(module.os, "open", side_effect=open_local),
        patch.object(module.stat, "S_ISCHR", return_value=scenario != "not-char"),
        patch.object(module.os, "read", side_effect=read),
    ):
        if scenario in ("write", "preview", "multi-block"):
            module.main()
        else:
            with pytest.raises((ValueError, PermissionError, OSError)):
                module.main()
    if scenario in ("write", "multi-block"):
        record = json.loads(receipt.read_text())
        assert record["written"] and record["readback_verified"] and record["ejected"]
        assert raw.read_bytes()[: len(content)] == content
    elif scenario in (
        "changed-before",
        "not-char",
        "short-read",
        "digest",
        "changed-after",
        "unmount",
    ):
        record = json.loads(receipt.read_text())
        assert not record["ejected"] and "error" in record
    elif scenario == "receipt":
        assert receipt.read_text() == "retained evidence"
    else:
        assert not receipt.exists()


def test_partial_write_loop_and_zero_progress_are_handled():
    module = load()
    with patch.object(module.os, "write", side_effect=[2, 2]) as write:
        module.write_all(10, b"abcd")
        assert write.call_count == 2
    with (
        patch.object(module.os, "write", return_value=0),
        pytest.raises(OSError, match="Short"),
    ):
        module.write_all(10, b"data")


def test_snapshot_includes_partition_identity_and_refuses_other_devices():
    module = load()
    identity = {
        "DeviceIdentifier": "disk999",
        "WholeDisk": True,
        "Internal": False,
        "BusProtocol": "USB",
        "IORegistryEntryName": "Fixture USB",
        "TotalSize": 100000,
        "WritableMedia": True,
        "SystemImage": False,
        "DeviceTreePath": "fixture/device",
    }
    rows = [
        identity,
        {"WholeDisks": ["disk999"]},
        {
            "AllDisksAndPartitions": [
                {
                    "DeviceIdentifier": "disk999",
                    "Partitions": [
                        {
                            "DeviceIdentifier": "disk999s1",
                            "Size": 100,
                            "Content": "test",
                        }
                    ],
                }
            ]
        },
        {"PartitionUUID": "fixture-uuid"},
    ]
    with patch.object(module, "checked", side_effect=[plistlib.dumps(r) for r in rows]):
        assert (
            module.snapshot("/dev/disk999")["partitions"][0]["uuid"] == "fixture-uuid"
        )
    with (
        patch.object(
            module,
            "checked",
            side_effect=[
                plistlib.dumps(identity),
                plistlib.dumps({"WholeDisks": ["disk999", "disk998"]}),
            ],
        ),
        pytest.raises(ValueError, match="Disconnect"),
    ):
        module.snapshot("/dev/disk999")


def test_inspection_and_platform_refusals_cannot_enter_write_mode(tmp_path):
    module = load()
    with (
        patch.object(module.sys, "platform", "linux"),
        patch.object(sys, "argv", ["usb"]),
        pytest.raises(ValueError, match="macOS"),
    ):
        module.main()
    with (
        patch.object(module.sys, "platform", "darwin"),
        patch.object(sys, "argv", ["usb", "--inspect", "/dev/disk999", "--write"]),
        pytest.raises(ValueError, match="combined"),
    ):
        module.main()
    with (
        patch.object(module.sys, "platform", "darwin"),
        patch.object(
            sys,
            "argv",
            [
                "usb",
                "--inspect",
                "/dev/disk999",
                "--save",
                str(tmp_path / "inspection"),
            ],
        ),
        patch.object(module, "snapshot", return_value={"fixture": True}),
    ):
        module.main()
    assert (tmp_path / "inspection").stat().st_mode & 0o777 == 0o600


def test_checked_command_and_inspect_without_save_never_open_a_device():
    import subprocess

    module = load()
    with patch.object(
        module.subprocess,
        "run",
        return_value=subprocess.CompletedProcess([], 0, b"fixture"),
    ) as command:
        assert module.checked(["diskutil", "list"]) == b"fixture"
        assert command.call_args.kwargs["check"] is True
    with (
        patch.object(module.sys, "platform", "darwin"),
        patch.object(sys, "argv", ["usb", "--inspect", "/dev/disk999"]),
        patch.object(module, "snapshot", return_value={"fixture": True}),
        patch.object(module.os, "open") as device,
    ):
        module.main()
        device.assert_not_called()


def test_snapshot_refuses_partition_listing_for_a_different_disk():
    module = load()
    identity = {
        "DeviceIdentifier": "disk999",
        "WholeDisk": True,
        "Internal": False,
        "BusProtocol": "USB",
        "IORegistryEntryName": "Fixture",
        "TotalSize": 100000,
        "WritableMedia": True,
        "SystemImage": False,
        "DeviceTreePath": "fixture",
    }
    rows = [
        identity,
        {"WholeDisks": ["disk999"]},
        {"AllDisksAndPartitions": [{"DeviceIdentifier": "disk998"}]},
    ]
    with (
        patch.object(
            module, "checked", side_effect=[plistlib.dumps(row) for row in rows]
        ),
        pytest.raises(ValueError, match="partition listing"),
    ):
        module.snapshot("/dev/disk999")
