"""Static ISO orchestration uses synthetic archives and command readbacks only."""

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
from unittest.mock import patch
import pytest

ROOT = Path(__file__).resolve().parents[2] / "proxmox/iso"
sys.path.insert(0, str(ROOT / "src"))


def load():
    spec = importlib.util.spec_from_file_location(
        "static_iso_builder", ROOT / "src/build_single_usb.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("production", [False, True, "thunderbolt"])
def test_static_media_build_and_packaging_bind_every_readback(tmp_path, production):
    module = load()
    work = tmp_path / "work"
    (work / "build/vendor").mkdir(parents=True)
    (work / "build/assistant-root/usr/bin").mkdir(parents=True)
    (work / "evidence").mkdir()
    (work / "config").mkdir()
    (work / ".local").mkdir()
    shutil.copytree(ROOT / "src", work / "src")
    config = json.loads((ROOT / "config/fixture-hardware.json").read_text())
    site = json.loads((ROOT / "config/fixture-site.json").read_text())
    public = (ROOT / "config/fixture-ssh.pub").read_text()
    for name in ("fixture-hardware.json", "fixture-site.json", "fixture-ssh.pub"):
        shutil.copyfile(ROOT / "config" / name, work / "config" / name)
    config["environment"] = "production"
    site["fqdn"] = "pve.unit.example.org"
    site["mailto"] = "operator@unit.example.org"
    for row in config["disk_members"] + config["protected_disks"]:
        row["disk_serial"] = (
            row["disk_serial"]
            .replace("LAB-NEW", "UNIT-NEW")
            .replace("LAB-OLD", "UNIT-OLD")
        )
        row["disk_by_id"] = (
            row["disk_by_id"]
            .replace("LAB-NEW", "UNIT-NEW")
            .replace("LAB-OLD", "UNIT-OLD")
        )
    approval = {
        "approved_by": "Fixture operator",
        "scope": "build-and-prepare-removable-media-only",
        "production_boot_or_erase_authorized": False,
    }
    hardware = {
        k: config[k]
        for k in ("machine_uuid", "disk_members", "protected_disks", "interface_names")
    }
    if production == "thunderbolt":
        hardware["thunderbolt_devices"] = [
            {
                "unique_id": "22222222-2222-4222-8222-222222222222",
                "mac": next(
                    mac
                    for mac, name in hardware["interface_names"].items()
                    if name == "fast0"
                ),
            }
        ]
    for name, content in [
        ("hardware.json", json.dumps(hardware)),
        ("site.json", json.dumps(site)),
        ("media-approval.json", json.dumps(approval)),
        ("root-ssh.pub", public),
        ("root-recovery-password.hash", "$6$synthetic$" + "A" * 86),
    ]:
        path = work / ".local" / name
        path.write_text(content)
        path.chmod(0o600)
    iso = work / "build/vendor/proxmox-ve_9.2-1.iso"
    iso.write_bytes(b"vendor iso")
    helper = work / "build/assistant-root/usr/bin/proxmox-auto-install-assistant"
    helper.write_bytes(b"helper binary")
    startup = b"/usr/bin/proxmox-low-level-installer dump-env\nif /usr/bin/proxmox-auto-installer </run/automatic-installer-answers; then\n\ndhclient -v\n"
    (work / "build/unconfigured.sh").write_bytes(startup)
    (work / "build/vendor-files.pseudo").write_bytes(
        b"/ D 0 755 0 0\nusr/sbin/unconfigured.sh R 0 755 0 0 0 1\n# START OF DATA - DO NOT MODIFY\nsource data"
    )
    (work / "build/vendor-grub.cfg").write_text(
        "set vendor=true\nif [ -f auto-installer-mode.toml ]; then\n"
    )
    name = "production" if production else "fixture"
    out = work / "build" / ("single-usb-" + name)
    runtime = b"native runtime"
    commands = []

    def execute(argv, **kwargs):
        args = [str(a) for a in argv]
        commands.append(args)
        stdout = b""
        if args[0] == str(helper) and args[1] == "prepare-iso":
            Path(args[-1]).write_bytes(b"prepared iso")
        elif args[0] == "mksquashfs":
            Path(args[2]).write_bytes(b"synthetic filesystem")
        elif args[:2] == ["unsquashfs", "-cat"]:
            stdout = (
                (out / "unconfigured-patched.sh").read_bytes()
                if args[-1].endswith("unconfigured.sh")
                else runtime
            )
        elif args[0] == "xorriso" and "-report_system_area" in args:
            stdout = (
                b"UEFI BIOS"
                if "-report_el_torito" in args
                else b"-volume_date uuid '2026102900000000'\n"
            )
        elif args[0] == "xorriso" and "-extract" in args:
            index = args.index("-extract")
            source = args[index + 1]
            destination = Path(args[index + 2])
            if (
                source == "/auto-installer-mode.toml"
                and destination.parent.name == "stage"
            ):
                destination.write_bytes(b"from iso")
            elif source == "/homelab":
                shutil.copytree(out / "stage/homelab", destination)
            else:
                shutil.copyfile(
                    (
                        out / "grub.cfg"
                        if source.endswith("grub.cfg")
                        else out / "stage" / Path(source).name
                    ),
                    destination,
                )
        return subprocess.CompletedProcess(args, 0, stdout, b"")

    with (
        patch.object(module, "ROOT", work),
        patch.object(module, "ISO", iso),
        patch.object(module, "HELPER", helper),
        patch.object(module, "STARTUP_SHA", hashlib.sha256(startup).hexdigest()),
        patch.object(
            module.core, "ISO_SHA256", hashlib.sha256(iso.read_bytes()).hexdigest()
        ),
        patch.object(
            module.core,
            "ASSISTANT_SHA256",
            hashlib.sha256(helper.read_bytes()).hexdigest(),
        ),
        patch.object(
            module.core, "RUNTIME_SHA256", hashlib.sha256(runtime).hexdigest()
        ),
        patch.object(module.subprocess, "run", side_effect=execute),
        patch.object(sys, "argv", ["build", *([] if production else ["--fixture"])]),
    ):
        module.main()
        receipt = json.loads((out / "build-receipt.json").read_text())
        assert (
            receipt["environment"] == name.replace("fixture", "synthetic")
            and receipt["production_boot_or_erase_authorized"] is False
        )
        assert receipt["embedded_payload_readback"] == "passed"
        assert all("/dev/" not in item for command in commands for item in command)
        with pytest.raises(module.core.Refusal, match="overwrite"):
            module.finish(out)
        target = out / "stage/homelab/config.json"
        target.write_bytes(target.read_bytes() + b"\n")
        with pytest.raises(module.core.Refusal, match="member changed"):
            module.finish(out)


def test_builder_records_private_command_failure_and_resume_is_explicit(tmp_path):
    module = load()
    (tmp_path / "evidence").mkdir()
    with (
        patch.object(module, "ROOT", tmp_path),
        patch.object(
            module.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(
                [], 8, b"output", b"failed command"
            ),
        ),
    ):
        with pytest.raises(RuntimeError, match="failed command"):
            module.run(["fixture-command"])
    record = json.loads(
        (tmp_path / "evidence/latest-build-command-failure.json").read_text()
    )
    assert record["exit"] == 8
    with (
        patch.object(module, "ROOT", tmp_path),
        patch.object(module, "finish") as finish,
        patch.object(sys, "argv", ["build", "--fixture", "--resume-packaging"]),
    ):
        module.main()
        finish.assert_called_once_with(tmp_path / "build/single-usb-fixture")
