"""Read-only, Linux installer-session observation. No installer or device writes."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

from .core import PUBLIC_ROOT, Refusal, canonical, new_file, read_file, require, sha, stamp


def checked_disk_properties(saved: dict, current: dict, devname: str) -> dict:
    """Retain serial absence only when both observations agree it is absent."""
    require(type(saved) is dict and type(current) is dict,
            "disk properties are not objects")
    require("DEVNAME" in saved and "DEVNAME" in current
            and saved["DEVNAME"] == current["DEVNAME"] == devname,
            "fresh and vendor disk DEVNAME differ or are incomplete")
    serial = "ID_SERIAL_SHORT"
    require((serial in saved) == (serial in current),
            "fresh and vendor disk serial presence differs")
    result = {"DEVNAME": devname}
    if serial in saved:
        require(saved[serial] == current[serial], "fresh and vendor disk serial differs")
        result[serial] = saved[serial]
    return result


def checked_inventory(current: set, vendor: set, media_disk=None):
    if media_disk is not None:
        require(media_disk in current, 'mounted USB media is not in current disk inventory')
        # Native Proxmox omits ISO9660 installer media. Exclude only the actual
        # read-only /cdrom filesystem's whole device, never a glob or other disk.
        if media_disk not in vendor:
            current = current - {media_disk}
    require(current == vendor, 'current and vendor whole-disk inventories differ')


def observe(media_disk=None) -> dict:
    require(sys.platform == "linux", "observe only in the attended Linux installer environment")
    require(Path("/cdrom/.pve-cd-id.txt").is_file(), "installer media marker missing")
    snapshot_path = Path("/run/proxmox-installer/run-env-udev.json")
    snapshot_bytes = read_file(snapshot_path)
    snapshot = json.loads(snapshot_bytes)
    require(type(snapshot.get("disks")) is dict and type(snapshot.get("nics")) is dict,
            "vendor installer inventory unavailable")
    block = subprocess.run(["lsblk", "--json", "--bytes", "--nodeps", "--output", "PATH,TYPE"],
                           check=True, capture_output=True, timeout=15)
    disks_now = {d["path"] for d in json.loads(block.stdout)["blockdevices"] if d["type"] == "disk"}
    checked_inventory(disks_now, {d.get("DEVNAME") for d in snapshot["disks"].values()}, media_disk)
    aliases = {}
    for link in sorted(Path("/dev/disk/by-id").iterdir()):
        if not link.is_symlink():
            continue
        try:
            info = link.stat()
        except FileNotFoundError:
            continue
        if stat.S_ISBLK(info.st_mode):
            aliases.setdefault(info.st_rdev, []).append(str(link))
    disks = []
    for props in snapshot["disks"].values():
        devname = props.get("DEVNAME")
        require(type(devname) is str and devname in disks_now, "vendor device name missing")
        info = os.stat(devname)
        require(stat.S_ISBLK(info.st_mode), "observed device is not a block device")
        native = subprocess.run(["udevadm", "info", "--query=property", "--name", devname],
                                check=True, capture_output=True, text=True, timeout=15)
        current = dict(line.split("=", 1) for line in native.stdout.splitlines() if "=" in line)
        checked = checked_disk_properties(props, current, devname)
        sysfs = Path("/sys/dev/block") / f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
        disks.append({"devname": devname, "by_ids": aliases.get(info.st_rdev, []),
                      "size_bytes": int((sysfs / "size").read_text()) * 512,
                      "read_only": (sysfs / "ro").read_text().strip() != "0",
                      "removable": (sysfs / "removable").read_text().strip() != "0",
                      "udev": checked})
    nics = []
    for name, props in snapshot["nics"].items():
        require(Path(name).name == name and name != "lo", "unexpected vendor interface name")
        root = Path("/sys/class/net") / name
        require(root.is_dir(), "vendor NIC is no longer present")
        current = subprocess.run(["udevadm", "info", "--query=property", "--path", str(root)],
                                 check=True, capture_output=True, text=True, timeout=15)
        fresh = dict(line.split("=", 1) for line in current.stdout.splitlines() if "=" in line)
        require(fresh.get("ID_NET_NAME_MAC") == props.get("ID_NET_NAME_MAC") and "ID_NET_NAME_MAC" in props,
                "fresh and vendor NIC properties differ or are incomplete")
        nics.append({"name": name, "mac": (root / "address").read_text().strip().lower(),
                     "udev": {"ID_NET_NAME_MAC": props["ID_NET_NAME_MAC"]}})
    binaries = [p for p in (Path("/usr/bin/proxmox-auto-installer"), Path("/usr/sbin/proxmox-auto-installer")) if p.is_file()]
    require(len(binaries) == 1, "ambiguous or missing runtime binary")
    return {"schema": "homelab-installer-observation-v1", "context": "installer-live",
            "captured_at": stamp(datetime.now(timezone.utc)),
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "machine_uuid": Path("/sys/class/dmi/id/product_uuid").read_text().strip().lower(),
            "uefi": Path("/sys/firmware/efi").is_dir(),
            "runtime_binary_path": str(binaries[0]),
            "runtime_binary_sha256": sha(read_file(binaries[0], limit=32 * 1024**2)),
            "vendor_udev_snapshot_sha256": sha(snapshot_bytes), "disks": disks, "nics": nics}


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        require(not args.out.resolve().is_relative_to(PUBLIC_ROOT), "private observation output must be outside public implementation")
        new_file(args.out, canonical(observe()))
        print(json.dumps({"observation_written": True, "erase_authorized": False}))
        return 0
    except (Refusal, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(json.dumps({"refused": True, "reason": str(error) if isinstance(error, Refusal) else type(error).__name__}), file=sys.stderr)
        return 3
