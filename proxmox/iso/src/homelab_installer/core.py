"""Fail-closed input compiler. The stock ISO is not a hardware approval engine."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile
import tomllib
import uuid
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

NAMESPACE = "homelab-installer-build-v1"
PURPOSE = "compile-installer-inputs-only"
ISO_VERSION = "9.2-1"
ISO_SHA256 = "4e88fe416df9b527624a175f24c9aa07c714d3332afb1ee3dbf3879573ef2c6c"
ASSISTANT_VERSION = "9.2.8"
SOURCE_COMMIT = "ba2007cd7cc383d64e028c2a798e8f0a065a9b49"
# Reviewed public artifact identities; the operational receipts remain private.
ASSISTANT_SHA256 = "19c786bf633e9c10631932cc8bcf1920153776995a25002c5c2fa818e405183e"
RELEASE_FINGERPRINT = "24B30F06ECC1836A4E5EFECBA7BCD1420BFE778E"
VENDOR_RECEIPT_SHA256 = "62bab52b62b5686c1b1ee5a6b8d1bb497607e0b367a55a9e5e622930a23e14f1"
RUNTIME_RECEIPT_SHA256 = "ba0c9394695057d43ad751fe9beb877a4813452d6b77ed178360cf53516334c2"
RUNTIME_SHA256 = "e0c76415d3511ad018c0949c7a9e5df4a5e1751ba729a37472264904c971b03e"
RUNTIME_PATH = "/usr/bin/proxmox-auto-installer"
PUBLIC_ROOT = Path(__file__).resolve().parents[2]
SHA = re.compile(r"[0-9a-f]{64}\Z")
DEV = re.compile(r"/dev/(?:sd[a-z]+|vd[a-z]+|nvme[0-9]+n[0-9]+)\Z")
MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z")


class Refusal(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise Refusal(reason)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_file(path: Path, *, protected: bool = False, limit: int = 4 * 1024**2) -> bytes:
    # Final-component symlinks and nonregular files never supply an input.
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), "input must be a regular file")
        require(before.st_size <= limit, "input exceeds size limit")
        if protected:
            require(before.st_mode & 0o077 == 0, "protected input has group/other permissions")
            require(before.st_uid == os.geteuid(), "protected input has another owner")
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(limit + 1)
        after = os.fstat(fd)
        require(len(data) <= limit, "input exceeds size limit")
        require((before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_ino, after.st_size, after.st_mtime_ns), "input changed while reading")
        return data
    finally:
        os.close(fd)


def decode_json(data: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    value = json.loads(data, object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(Refusal("nonfinite JSON value")))
    require(type(value) is dict, "JSON root must be an object")
    return value


def exact(value: object, fields: set[str], label: str) -> dict:
    require(type(value) is dict and set(value) == fields, f"{label}: missing or unsupported fields")
    return value


def integer(value, lower: int, upper: int, label: str) -> int:
    require(type(value) is int and lower <= value <= upper, f"{label}: invalid integer")
    return value


def literal(value, label: str, pattern=r"[A-Za-z0-9_.:+/-]{1,160}") -> str:
    require(type(value) is str and re.fullmatch(pattern, value) is not None,
            f"{label}: empty, nonliteral or unsupported value")
    return value


def digest(value, label: str) -> str:
    require(type(value) is str and SHA.fullmatch(value) is not None and value != "0" * 64,
            f"{label}: missing digest")
    return value


def identifier(value, label: str) -> str:
    try:
        parsed = uuid.UUID(value)
        require(parsed.int != 0 and str(parsed) == value.lower(), f"{label}: invalid UUID")
    except (ValueError, TypeError, AttributeError):
        raise Refusal(f"{label}: invalid UUID") from None
    return str(parsed)


def timestamp(value: str) -> datetime:
    try:
        require(type(value) is str and value.endswith("Z"), "timestamp must be UTC with Z")
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        raise Refusal("invalid UTC timestamp") from None
    return result


def stamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def compiler_digest() -> str:
    source = Path(__file__).parent
    return sha(b"".join(p.name.encode() + b"\0" + p.read_bytes() for p in sorted(source.glob("*.py"))))


def ssh_key(value: str) -> str:
    require(type(value) is str, "public key must be a string")
    parts = value.split()
    require(len(parts) in (2, 3) and parts[0] == "ssh-ed25519", "only Ed25519 public keys are accepted")
    try:
        raw = base64.b64decode(parts[1], validate=True)
    except (ValueError, TypeError):
        raise Refusal("invalid public key encoding") from None
    require(len(raw) == 51 and raw[:19] == b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20",
            "invalid Ed25519 public key structure")
    return " ".join(parts[:2])


def vendor_literal_matches(properties: list[dict], filters: dict) -> list[int]:
    """Model the reviewed all-filter matcher only for our two literal filters.

    Source: pve-installer ba2007cd7cc383d64e028c2a798e8f0a065a9b49,
    proxmox-auto-installer/src/utils.rs:get_matched_udev_indexes.
    Missing properties are skipped by that source; a present mismatch excludes
    the device. This is not evidence of the embedded runtime's behavior.
    """
    exact(filters, {"DEVNAME", "ID_SERIAL_SHORT"}, "literal vendor filters")
    literal(filters["DEVNAME"], "vendor device filter", DEV.pattern)
    literal(filters["ID_SERIAL_SHORT"], "vendor serial filter", r"[A-Za-z0-9_.:-]{1,128}")
    require(type(properties) is list and all(type(p) is dict for p in properties),
            "invalid vendor disk properties")
    return [i for i, props in enumerate(properties)
            if all(key not in props or props[key] == value for key, value in filters.items())]


def release_identity(release: dict, inputs: dict[str, bytes]) -> dict:
    require(type(release) is dict, "release must be an object")
    kind = release.get("runtime_identity", "versioned")
    require(kind in {"versioned", "iso-runtime-sha256-v1"}, "unsupported runtime identity")
    fields = {"iso_version", "iso_sha256", "assistant_version", "assistant_sha256",
              "runtime_version", "runtime_source_commit", "runtime_binary_sha256", "vendor_receipt_sha256"}
    if "runtime_identity" in release:
        fields.add("runtime_identity")
    if kind == "iso-runtime-sha256-v1":
        fields |= {"runtime_binary_path", "runtime_receipt_sha256", "release_fingerprint"}
    exact(release, fields, "release")
    require(release["iso_version"] == ISO_VERSION and release["iso_sha256"] == ISO_SHA256,
            "unqualified installer ISO release")
    require(release["assistant_version"] == ASSISTANT_VERSION, "unqualified assistant version")
    for name in ("assistant_sha256", "runtime_binary_sha256", "vendor_receipt_sha256"):
        digest(release[name], name)
    proof_names = {"vendor_receipt", "runtime_receipt"}
    if kind == "versioned":
        require(not proof_names.intersection(inputs), "versioned identity cannot ignore provenance receipts")
        literal(release["runtime_version"], "runtime version", r"[0-9]+\.[0-9]+\.[0-9]+")
        literal(release["runtime_source_commit"], "runtime source pin", r"[0-9a-f]{40}")
    else:
        require(proof_names <= set(inputs), "content identity requires both provenance receipts")
        require(release["runtime_version"] is None and release["runtime_source_commit"] is None,
                "content identity must preserve unknown runtime version and source as null")
        require(release["assistant_sha256"] == ASSISTANT_SHA256, "unexpected preparation assistant binary")
        require(release["runtime_binary_path"] == RUNTIME_PATH
                and release["runtime_binary_sha256"] == RUNTIME_SHA256,
                "unexpected admitted runtime path or binary")
        require(release["release_fingerprint"] == RELEASE_FINGERPRINT, "unexpected release trust anchor")
        for name, pin in (("vendor_receipt", VENDOR_RECEIPT_SHA256),
                          ("runtime_receipt", RUNTIME_RECEIPT_SHA256)):
            require(sha(inputs[name]) == release[name + "_sha256"] == pin,
                    "expected reviewed " + name.replace("_", " ") + " bytes and binding")
        vendor = decode_json(inputs["vendor_receipt"])
        require(vendor.get("iso_sha256") == release["iso_sha256"]
                and type(vendor.get("bytes")) is int and vendor["bytes"] == 1706178560,
                "vendor receipt binds another ISO")
        require(vendor.get("release_fingerprint") == release["release_fingerprint"],
                "vendor receipt trust anchor mismatch")
        require(type(vendor.get("signature_exit")) is int and vendor["signature_exit"] == 0
                and vendor.get("signature_verified") is True,
                "vendor receipt does not record successful signature verification")
        status = vendor.get("signature_output")
        require(type(status) is str, "vendor receipt signature status missing")
        records = [line.split() for line in status.splitlines() if line.startswith("[GNUPG:] ")]
        require(any(len(r) == 12 and r[1] == "VALIDSIG"
                    and r[2] == r[-1] == RELEASE_FINGERPRINT for r in records),
                "vendor receipt VALIDSIG does not bind the release trust anchor")
        require(not any(len(r) > 1 and r[1] in {"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG"}
                        for r in records), "vendor receipt contains failed signature status")
        require(vendor.get("assistant_version") == release["assistant_version"],
                "vendor receipt preparation assistant mismatch")
        extracted = decode_json(inputs["runtime_receipt"])
        require(extracted.get("source_iso_sha256") == release["iso_sha256"],
                "runtime receipt binds another ISO")
        require(type(extracted.get("readback_exit_code")) is int and extracted["readback_exit_code"] == 0
                and extracted.get("source_ISO_changed") is False, "runtime extraction did not complete unchanged")
        binary = extracted.get("embedded_auto_installer")
        require(type(binary) is dict and binary.get("path") == RUNTIME_PATH.lstrip("/")
                and binary.get("sha256") == release["runtime_binary_sha256"]
                and type(binary.get("bytes")) is int and binary["bytes"] == 5490040,
                "runtime receipt binary path, digest or size mismatch")
        require("package_version" in binary and binary["package_version"] is None
                and binary.get("source_commit") is None, "runtime receipt must preserve unknown build mapping")
        if "embedded_init" in extracted:
            require(type(extracted["embedded_init"]) is dict
                    and extracted["embedded_init"].get("source_iso_sha256") == release["iso_sha256"],
                    "runtime receipt init evidence binds another ISO")
        # Reviewed source comparisons in the receipt are not a claimed binary build mapping.
    return {"kind": kind, "iso": {"version": release["iso_version"], "sha256": release["iso_sha256"]},
            "assistant": {"version": release["assistant_version"], "sha256": release["assistant_sha256"]},
            "runtime_version": release["runtime_version"], "runtime_source_commit": release["runtime_source_commit"],
            "runtime_binary": {"path": release.get("runtime_binary_path"), "sha256": release["runtime_binary_sha256"]},
            "vendor_receipt_sha256": release["vendor_receipt_sha256"],
            "runtime_receipt_sha256": release.get("runtime_receipt_sha256"),
            "release_fingerprint": release.get("release_fingerprint"), "runtime_behavior_qualified": False}


def context(inputs: dict[str, bytes], now: datetime) -> dict:
    cat = decode_json(inputs["catalog"])
    hardware = cat.get("hardware", {})
    require(type(hardware) is dict, "hardware must be an object")
    require(hardware.get("disk_layout") != "zfs-mirror",
            "unsupported legacy zfs-mirror compiler contract; use the static ISO builder")
    return _single_context(inputs, now)


def _single_context(inputs: dict[str, bytes], now: datetime) -> dict:
    required_inputs = {"catalog", "hardware", "observation", "password_hash", "first_boot"}
    require(required_inputs <= set(inputs) <= required_inputs | {"vendor_receipt", "runtime_receipt"},
            "wrong compiler input set")
    cat, hw, obs = (decode_json(inputs[k]) for k in ("catalog", "hardware", "observation"))
    require(type(cat.get("schema_version")) is int and cat["schema_version"] == 1, "unsupported site catalog schema")
    site, disk = cat.get("site", {}), cat.get("hardware", {})
    require(type(site) is dict and type(disk) is dict, "site and hardware must be objects")
    env = site.get("environment")
    require(env in {"synthetic", "production"}, "site environment missing")
    literal(site.get("id"), "site id", r"[a-z0-9][a-z0-9-]{0,62}")
    require(type(site.get("ssh_public_keys")) is list and len(site["ssh_public_keys"]) > 0,
            "catalog must bind at least one root public key")
    keys = [ssh_key(k) for k in site["ssh_public_keys"]]
    require(len(keys) == len(set(keys)), "duplicate root public keys")
    serial = literal(disk.get("disk_serial"), "disk serial", r"[A-Za-z0-9_.:-]{1,128}")
    by_id = literal(disk.get("disk_by_id"), "disk by-id", r"/dev/disk/by-id/[A-Za-z0-9_.:+-]{1,200}")
    size = integer(disk.get("disk_size_bytes"), 1024**3, 64 * 1024**4, "disk size")
    require(disk.get("firmware") == "uefi", "only the selected UEFI flow is supported")
    fqdn = literal(disk.get("fqdn"), "FQDN", r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+")
    install = exact(cat.get("installer"), {"keyboard", "country", "timezone", "mailto", "network_source", "partition_label", "zfs_arc_max_mib"}, "catalog installer")
    literal(install["keyboard"], "keyboard", r"[a-z][a-z0-9-]{0,23}")
    literal(install["country"], "country", r"[a-z]{2}")
    literal(install["mailto"], "email", r"[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+")
    literal(install["timezone"], "timezone")
    try:
        ZoneInfo(install["timezone"])
    except ZoneInfoNotFoundError:
        raise Refusal("unknown timezone") from None
    literal(install["partition_label"], "answer filesystem label", r"[A-Z0-9_]{1,11}")
    integer(install["zfs_arc_max_mib"], 64, 4096, "ZFS ARC limit")
    require(install["network_source"] in {"from-answer", "from-dhcp"}, "unsupported network source")
    require(env == "synthetic" or install["network_source"] == "from-answer", "production requires explicit installer network")
    exact(hw, {"schema", "catalog_sha256", "machine_uuid", "target_kind", "release", "observation_max_age_seconds"}, "hardware manifest")
    require(hw["schema"] == "homelab-installer-hardware-v1", "unsupported hardware schema")
    require(hw["catalog_sha256"] == sha(inputs["catalog"]), "hardware manifest binds another catalog")
    machine = identifier(hw["machine_uuid"], "machine UUID")
    require(hw["target_kind"] == ("synthetic-vm" if env == "synthetic" else "physical"), "hardware/environment mismatch")
    age = integer(hw["observation_max_age_seconds"], 30, 300, "observation age policy")
    release = hw["release"]
    identity = release_identity(release, inputs)
    observation_fields = {"schema", "context", "captured_at", "boot_id", "machine_uuid", "uefi", "runtime_binary_sha256", "vendor_udev_snapshot_sha256", "disks", "nics"}
    if identity["kind"] == "iso-runtime-sha256-v1" or "runtime_binary_path" in obs:
        observation_fields.add("runtime_binary_path")
    exact(obs, observation_fields, "observation")
    require(obs["schema"] == "homelab-installer-observation-v1" and obs["context"] == "installer-live", "fresh installer observation required")
    require(-5 <= (now - timestamp(obs["captured_at"])).total_seconds() <= age, "observation is stale or from the future")
    boot = identifier(obs["boot_id"], "boot id")
    require(identifier(obs["machine_uuid"], "observed machine UUID") == machine, "wrong machine UUID")
    require(obs["uefi"] is True, "installer did not boot in UEFI mode")
    require(obs["runtime_binary_sha256"] == release["runtime_binary_sha256"], "unexpected embedded runtime binary")
    if "runtime_binary_path" in obs:
        require(obs["runtime_binary_path"] in {"/usr/bin/proxmox-auto-installer", "/usr/sbin/proxmox-auto-installer"},
                "unexpected observed runtime path")
    if identity["kind"] == "iso-runtime-sha256-v1":
        require(obs["runtime_binary_path"] == identity["runtime_binary"]["path"], "observed runtime path mismatch")
    digest(obs["vendor_udev_snapshot_sha256"], "vendor udev snapshot")
    require(type(obs["disks"]) is list and 0 < len(obs["disks"]) <= 64, "missing disk inventory")
    aliases, names, serial_hits, by_id_hits = set(), set(), [], []
    for i, entry in enumerate(obs["disks"]):
        exact(entry, {"devname", "by_ids", "size_bytes", "read_only", "removable", "udev"}, "disk observation")
        require(type(entry["devname"]) is str and DEV.fullmatch(entry["devname"]), "unsupported whole disk name")
        require(entry["devname"] not in names, "duplicate disk device")
        names.add(entry["devname"])
        require(type(entry["read_only"]) is bool and type(entry["removable"]) is bool, "unknown disk writability/removability")
        integer(entry["size_bytes"], 1, 64 * 1024**4, "observed size")
        require(type(entry["by_ids"]) is list, "missing disk aliases")
        for alias in entry["by_ids"]:
            literal(alias, "observed by-id", r"/dev/disk/by-id/[A-Za-z0-9_.:+-]{1,200}")
            require(alias not in aliases, "duplicate disk alias")
            aliases.add(alias)
        props = entry["udev"]
        require(type(props) is dict and "DEVNAME" in props,
                "incomplete disk properties; DEVNAME is required on every disk")
        require(props["DEVNAME"] == entry["devname"], "udev/devname disagreement")
        if "ID_SERIAL_SHORT" in props:
            literal(props["ID_SERIAL_SHORT"], "observed serial", r"[A-Za-z0-9_.:-]{1,128}")
            if props["ID_SERIAL_SHORT"] == serial:
                serial_hits.append(i)
        if by_id in entry["by_ids"]:
            by_id_hits.append(i)
    require(len(serial_hits) == 1 and len(by_id_hits) == 1, "missing or ambiguous exact disk identity")
    require(serial_hits == by_id_hits, "by-id and serial identify different disks")
    target = obs["disks"][serial_hits[0]]
    require(target["size_bytes"] == size, "disk capacity mismatch")
    require(not target["read_only"] and not target["removable"], "target is read-only or removable")
    matches = vendor_literal_matches([entry["udev"] for entry in obs["disks"]],
                                     {"DEVNAME": target["devname"], "ID_SERIAL_SHORT": serial})
    require(matches == serial_hits, "vendor filter selection differs from the single intended target")
    nics = obs["nics"]
    require(type(nics) is list and 0 < len(nics) <= 64, "missing NIC inventory")
    mac = disk.get("installer_mac")
    require(type(mac) is str and MAC.fullmatch(mac), "missing literal installer MAC")
    selected = []
    for nic in nics:
        exact(nic, {"name", "mac", "udev"}, "NIC observation")
        require(type(nic["udev"]) is dict, "missing NIC properties")
        if nic["mac"] == mac:
            selected.append(nic)
    require(len(selected) == 1, "missing or ambiguous installer NIC")
    nic = selected[0]
    require(type(nic["udev"]) is dict and nic["udev"].get("ID_NET_NAME_MAC") == "enx" + mac.replace(":", ""), "missing exact MAC-derived NIC property")
    require(sum(n.get("udev", {}).get("ID_NET_NAME_MAC") == nic["udev"]["ID_NET_NAME_MAC"] for n in nics) == 1, "ambiguous vendor NIC filter")
    if install["network_source"] == "from-dhcp":
        require(env == "synthetic" and len(nics) == 1, "DHCP fixture requires one synthetic NIC")
    else:
        try:
            address = ipaddress.IPv4Interface(disk["installer_cidr"])
            gateway = ipaddress.IPv4Address(disk["installer_gateway"])
            dns = disk["installer_dns"]
            require(type(dns) is list and len(dns) == 1, "one explicit installer DNS address required")
            ipaddress.IPv4Address(dns[0])
            require(gateway in address.network and gateway != address.ip, "installer gateway does not match subnet")
        except (KeyError, ValueError, TypeError):
            raise Refusal("invalid explicit installer network") from None
    password = inputs["password_hash"].decode().strip()
    require(re.fullmatch(r"\$6\$(?:rounds=[0-9]+\$)?[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{86}", password) is not None,
            "supported SHA512 crypt hash required; plaintext is forbidden")
    payload = inputs["first_boot"]
    require(0 < len(payload) <= 1024**2 and payload.startswith(b"#!/bin/sh\n") and b"\x00" not in payload,
            "bounded self-contained shell first-boot payload required")
    return {"catalog": cat, "hardware": hw, "observation": obs, "target": target, "release_identity": identity,
            "nic": nic, "password": password, "keys": keys, "boot_id": boot,
            "bindings": {k: sha(v) for k, v in inputs.items()} | {"compiler": compiler_digest()}}


def request_for(ctx: dict, now: datetime, ttl: int = 300) -> dict:
    integer(ttl, 30, 600, "approval lifetime")
    return {"schema": "homelab-installer-request-v1", "purpose": PURPOSE,
            "site_id": ctx["catalog"]["site"]["id"],
            "environment": ctx["catalog"]["site"]["environment"], "bindings": ctx["bindings"],
            "boot_id": ctx["boot_id"], "issued_at": stamp(now), "expires_at": stamp(now + timedelta(seconds=ttl)),
            "nonce": secrets.token_hex(16), "attended_prewrite_required": True, "erase_authorized": False}


def verify_request(data: bytes, ctx: dict, now: datetime, signature: Path, allowed_signers: Path, identity: str) -> tuple[dict, bytes]:
    """Return the approved request and exact verified signature for compilation."""
    request = decode_json(data)
    exact(request, {"schema", "purpose", "site_id", "environment", "bindings", "boot_id", "issued_at", "expires_at", "nonce", "attended_prewrite_required", "erase_authorized"}, "approval request")
    require(data == canonical(request), "approval request is not canonical JSON")
    require(request["schema"] == "homelab-installer-request-v1" and request["purpose"] == PURPOSE,
            "wrong approval purpose")
    require(request["bindings"] == ctx["bindings"] and request["boot_id"] == ctx["boot_id"], "request input or installer boot changed")
    require(request["site_id"] == ctx["catalog"]["site"]["id"] and request["environment"] == ctx["catalog"]["site"]["environment"], "request site mismatch")
    require(request["attended_prewrite_required"] is True and request["erase_authorized"] is False, "build approval cannot grant erase authority")
    issued, expiry = timestamp(request["issued_at"]), timestamp(request["expires_at"])
    require(0 <= (now - issued).total_seconds() and now < expiry and 30 <= (expiry - issued).total_seconds() <= 600,
            "approval expired, future-dated or overlong")
    literal(request["nonce"], "approval nonce", r"[0-9a-f]{32}")
    literal(identity, "signer identity", r"[A-Za-z0-9_.@+-]{1,128}")
    sig = read_file(signature, protected=True, limit=16384)
    trust = read_file(allowed_signers, protected=True, limit=16384)
    # Verify captured bytes, not paths that could be replaced after validation.
    with tempfile.TemporaryDirectory(prefix="installer-signature-") as tmp:
        signature_copy, trust_copy = Path(tmp) / "signature", Path(tmp) / "allowed-signers"
        new_file(signature_copy, sig)
        new_file(trust_copy, trust)
        try:
            result = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(trust_copy),
                                     "-I", identity, "-n", NAMESPACE, "-s", str(signature_copy)],
                                    input=data, capture_output=True, timeout=15)
        except subprocess.SubprocessError:
            raise Refusal("signature verification process failed") from None
    require(result.returncode == 0, "build signature verification failed")
    return request, sig


def answer(ctx: dict) -> bytes:
    require(ctx.get("disk_layout") != "zfs-mirror",
            "unsupported legacy zfs-mirror compiler contract; use the static ISO builder")
    return _single_answer(ctx)


def _single_answer(ctx: dict) -> bytes:
    cat, target = ctx["catalog"], ctx["target"]
    cfg, hardware = cat["installer"], cat["hardware"]
    q = json.dumps
    rows = ["[global]", f"keyboard = {q(cfg['keyboard'])}", f"country = {q(cfg['country'])}",
            f"fqdn = {q(hardware['fqdn'])}", f"mailto = {q(cfg['mailto'])}",
            f"timezone = {q(cfg['timezone'])}", f"root-password-hashed = {q(ctx['password'])}",
            "root-ssh-keys = " + q(ctx["keys"]), "", "[first-boot]", 'source = "from-iso"',
            'ordering = "before-network"', "", "[network]", f"source = {q(cfg['network_source'])}"]
    if cfg["network_source"] == "from-answer":
        rows += [f"cidr = {q(hardware['installer_cidr'])}", f"gateway = {q(hardware['installer_gateway'])}",
                 f"dns = {q(hardware['installer_dns'][0])}",
                 f"filter.ID_NET_NAME_MAC = {q(ctx['nic']['udev']['ID_NET_NAME_MAC'])}"]
    rows += ["", "[disk-setup]", 'filesystem = "zfs"', 'zfs.raid = "raid0"', 'zfs.ashift = 12',
             'zfs.checksum = "on"', 'zfs.compress = "lz4"', 'zfs.copies = 1',
             f"zfs.arc-max = {cfg['zfs_arc_max_mib']}", 'filter-match = "all"',
             f"filter.ID_SERIAL_SHORT = {q(hardware['disk_serial'])}", f"filter.DEVNAME = {q(target['devname'])}", ""]
    result = "\n".join(rows).encode()
    parsed = tomllib.loads(result.decode())
    require(set(parsed["disk-setup"]["filter"]) == {"ID_SERIAL_SHORT", "DEVNAME"}, "internal filter error")
    return result


def new_file(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def manifest_for(ctx: dict, request: dict, request_bytes: bytes, inputs: dict[str, bytes], *, rendered: bytes | None = None) -> dict:
    require(ctx.get("disk_layout") != "zfs-mirror",
            "unsupported legacy zfs-mirror compiler contract; use the static ISO builder")
    if rendered is None:
        rendered = answer(ctx)
    return _single_manifest_for(ctx, request, request_bytes, inputs, rendered)


def _single_manifest_for(ctx: dict, request: dict, request_bytes: bytes, inputs: dict[str, bytes], rendered: bytes) -> dict:
    return {"schema": "homelab-installer-bundle-v1", "request_sha256": sha(request_bytes),
                "release_identity": ctx["release_identity"],
                "bindings": ctx["bindings"], "answer_sha256": sha(rendered),
                "first_boot_sha256": sha(inputs["first_boot"]), "expires_at": request["expires_at"],
                "boot_id": ctx["boot_id"], "target": {k: ctx["target"][k] for k in ("devname", "size_bytes", "by_ids")},
                "filesystem_label": ctx["catalog"]["installer"]["partition_label"],
                "vendor_checks": {"literal_serial_and_devname": True, "capacity": False,
                                  "machine_uuid": False, "unique_match": False, "absent_property_rejection": False},
                "attended_prewrite_required": True, "erase_authorized": False,
                "native_answer_validation": "pending", "media_boot_qualification": "pending"}


def compile_bundle(ctx: dict, request: dict, request_bytes: bytes, signature_bytes: bytes, inputs: dict[str, bytes], out: Path) -> dict:
    """Use the request and captured signature returned together by verify_request."""
    require(not out.resolve().is_relative_to(PUBLIC_ROOT), "private compilation output must be outside public implementation")
    require(out.parent.resolve() == out.parent.absolute(), "output parent has a symlink component")
    rendered = answer(ctx)
    manifest = manifest_for(ctx, request, request_bytes, inputs, rendered=rendered)
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, data in {"answer.toml": rendered, "first-boot.sh": inputs["first_boot"],
                       "request.json": request_bytes, "request.json.sig": signature_bytes,
                       "manifest.json": canonical(manifest)}.items():
        new_file(out / name, data)
    return manifest


def media_plan(ctx: dict, bundle: Path, base_iso: Path, prepared_base: Path, answer_iso: Path) -> dict:
    label = ctx["catalog"]["installer"]["partition_label"]
    require(not prepared_base.exists() and not answer_iso.exists(), "refuse media overwrite")
    return {"executed": False, "erase_authorized": False,
            "native_validation": ["proxmox-auto-install-assistant", "validate-answer", str(bundle / "answer.toml")],
            "prepare_base_once": ["proxmox-auto-install-assistant", "prepare-iso", str(base_iso),
                                  "--fetch-from", "partition", "--partition-label", label,
                                  "--on-first-boot", str(bundle / "first-boot.sh"), "--output", str(prepared_base)],
            "answer_iso": {"tool": "xorriso", "argv": ["xorriso", "-as", "mkisofs", "-V", label, "-iso-level", "3", "-R", "-o", str(answer_iso), "PRIVATE_ANSWER_ONLY_DIRECTORY"],
                           "stage_only": ["answer.toml"], "filesystem": "ISO9660 with Rock Ridge", "bootable": False},
            "holds": ["Verify exact native binaries and source ISO hashes before preparation",
                      "Verify native answer validation; no --answer-file with fetch-from partition",
                      "Do not place first-boot keys or manifest in the answer-only ISO",
                      "Inspect exactly one matching filesystem label across attached media",
                      "Fresh installer-session hardware check and separate attended erase decision remain mandatory",
                      "ISO9660 label/file lookup and positive/refusal boot evidence are separate qualification"]}
