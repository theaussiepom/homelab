"""Shared local/CI catalog and synthetic execution implementation.

The PVE production adapter deliberately refuses until its remaining contracts
are implemented and qualified. A synthetic pass never grants PVE admission.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
from typing import Any

import jsonschema

ROOT = Path(__file__).resolve().parents[2]
ROOTS = ("foundation", "critical", "application_guests", "security_VM")
RESOURCE_TYPES = {
    "proxmox_virtual_environment_container", "proxmox_virtual_environment_vm",
    "proxmox_virtual_environment_network_linux_bridge",
    "proxmox_virtual_environment_storage_zfspool",
    "proxmox_virtual_environment_firewall_options",
    "proxmox_virtual_environment_firewall_rules",
    "proxmox_network_linux_bridge", "proxmox_storage_zfspool",
}


class Refusal(ValueError):
    """An explicit hold, reported without private payload values."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def read_json(path: Path) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for k, v in items:
            if k in result:
                raise Refusal("duplicate JSON key")
            result[k] = v
        return result
    if path.is_symlink():
        raise Refusal("symlink input refused")
    if path.stat().st_size > 8 * 1024 * 1024:
        raise Refusal("JSON input exceeds bounded size")
    return json.loads(path.read_text(), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Refusal("non-finite JSON")))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise Refusal("symlink output refused")
    fd, temporary = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(canonical(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def unresolved(value: Any, path: str = "") -> list[str]:
    if value is None:
        return [path]
    if isinstance(value, dict):
        return [p for k, v in value.items() for p in unresolved(v, path + "/" + k)]
    if isinstance(value, list):
        return [p for i, v in enumerate(value) for p in unresolved(v, path + "/" + str(i))]
    return []


def validate_catalog(catalog: dict, schema_path: Path | None = None) -> dict:
    schema = read_json(schema_path or ROOT / "schemas/site.schema.json")
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    failures = sorted(validator.iter_errors(catalog), key=lambda e: str(list(e.path)))
    if failures:
        locations = ["/" + "/".join(map(str, e.path)) for e in failures[:30]]
        raise Refusal("schema validation failed at " + ", ".join(locations))
    seen: dict[str, set[Any]] = {"key": set(), "vmid": set(), "ip": set(), "mac": set()}
    seen["mac"].update(
        value.lower() for field in ("management_mac", "spare_mac", "installer_mac")
        if (value := catalog["hardware"][field]) is not None
    )
    for guest in catalog["guests"]:
        for name in ("key", "vmid"):
            value = guest[name]
            if value is not None:
                if value in seen[name]:
                    raise Refusal("duplicate guest " + name)
                seen[name].add(value)
        if guest["runtime"] == "vm" and guest["state_root"] != "security_VM":
            raise Refusal("VM state owner mismatch")
        if guest["runtime"] == "unprivileged_lxc" and guest["state_root"] == "security_VM":
            raise Refusal("LXC state owner mismatch")
        if len({m["slot"] for m in guest["mounts"]}) != len(guest["mounts"]):
            raise Refusal("duplicate volume slot")
        paths = [m["path"] for m in guest["mounts"] if m["path"]]
        if len(set(paths)) != len(paths):
            raise Refusal("duplicate volume path")
        for mount in guest["mounts"]:
            if guest["runtime"] == "vm" and mount["slot"] is not None:
                if not re.fullmatch(r"(?:scsi|virtio|sata)[0-9]+", mount["slot"]) or mount["slot"] == "scsi0":
                    raise Refusal("invalid VM data disk slot or root disk conflict")
            if mount["path"] and (not mount["path"].startswith("/") or ".." in Path(mount["path"]).parts):
                raise Refusal("unsafe volume path")
            if not mount["backup"]:
                raise Refusal("staging/managed volume exclusion requires separate accepted coverage")
        if sum(i["main_default"] is True for i in guest["interfaces"]) > 1:
            raise Refusal("multiple main default routes")
        vlans = [i["vlan"] for i in guest["interfaces"]]
        if len(set(vlans)) != len(vlans):
            raise Refusal("duplicate guest VLAN")
        for interface in guest["interfaces"]:
            for name, field in (("ip", "ipv4"), ("mac", "mac")):
                value = interface[field]
                if value is not None:
                    value = value.lower()
                    if value in seen[name]:
                        raise Refusal("duplicate interface " + name)
                    seen[name].add(value)
            if interface["ipv4"]:
                ipaddress.IPv4Address(interface["ipv4"])
            if interface["vlan"] == 30 and interface["main_default"] is True:
                raise Refusal("backend VLAN cannot own a default route")
    if len({p["key"] for p in catalog["fleet"]}) != len(catalog["fleet"]):
        raise Refusal("duplicate fleet identity")
    if not catalog["guests"] and not catalog["fleet"]:
        raise Refusal("site has no managed assets")
    if catalog["states"] != list(ROOTS):
        raise Refusal("four-state order/owner contract changed")
    return {"valid": True, "environment": catalog["site"]["environment"],
            "guests": len(catalog["guests"]), "unresolved_fields": unresolved(catalog),
            "production_admitted": False}


def ensure_synthetic(catalog: dict) -> None:
    validate_catalog(catalog)
    if catalog["site"]["environment"] != "synthetic":
        raise Refusal("PVE adapter held: I01/I03/I04/I05/I08/I11/I14/I16/I23; synthetic target only")
    if unresolved(catalog):
        raise Refusal("synthetic fixture has unresolved fields")
    net = ipaddress.ip_network("198.18.0.0/15")
    for guest in catalog["guests"]:
        for interface in guest["interfaces"]:
            if ipaddress.ip_address(interface["ipv4"]) not in net:
                raise Refusal("synthetic fixture uses an address outside the isolated example range")


@contextlib.contextmanager
def execution_lock(workspace: Path):
    workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
    if workspace.is_symlink():
        raise Refusal("symlink workspace refused")
    lock = workspace / "execution.lock"
    try:
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise Refusal("execution lock occupied; investigate owner, no automatic stale-lock deletion") from exc
    owned = os.fstat(fd)
    try:
        os.write(fd, canonical({"pid": os.getpid(), "target": "synthetic"}))
        os.fsync(fd)
        yield
    finally:
        os.close(fd)
        try:
            current = lock.lstat()
        except FileNotFoundError as exc:
            raise Refusal("execution lock disappeared; investigate owner") from exc
        if (current.st_dev, current.st_ino) != (owned.st_dev, owned.st_ino):
            raise Refusal("execution lock replaced; preserve current lock and investigate")
        lock.unlink()


def state(workspace: Path) -> dict:
    path = workspace / "synthetic-state.json"
    return read_json(path) if path.exists() else {"serial": 0, "objects": {}}


def desired_objects(catalog: dict) -> dict:
    return {g["key"]: g for g in catalog["guests"]} | {"pi:" + p["key"]: p for p in catalog["fleet"]}


def synthetic_plan(catalog: dict, workspace: Path) -> dict:
    ensure_synthetic(catalog)
    with execution_lock(workspace):
        current = state(workspace)
        objects = desired_objects(catalog)
        changes = [{"key": key, "before": current["objects"].get(key), "after": value}
                   for key, value in objects.items() if current["objects"].get(key) != value]
        if set(current["objects"]) - set(objects):
            raise Refusal("removal needs a separate destructive change scope")
        plan = {"format": "homelab-synthetic-plan-v1", "target": "synthetic",
                "catalog_sha256": digest(catalog), "base_state_sha256": digest(current),
                "base_serial": current["serial"], "changes": changes}
        for change in changes:
            before, after = change["before"], change["after"]
            if before and before != after:
                assert_guest_update(before, after)
        write_json(workspace / "plan.json", plan)
        return {"target": "synthetic", "changes": len(changes), "plan_sha256": digest(plan),
                "base_serial": current["serial"], "PVE_contacted": False}


def assert_guest_update(before: dict, after: dict) -> None:
    # Full-object comparison catches nested identity/disk/filter changes.
    allowed = {"cpu", "memory_mib"}
    if set(before) != set(after):
        raise Refusal("guest schema changed in routine update")
    changed = {k for k in before if before[k] != after[k]}
    if changed - allowed:
        raise Refusal("protected guest field update; rebuild/migration scope required")


def sign_approval(plan: dict, key: bytes, *, expires: str) -> dict:
    payload = {"target": "synthetic", "plan_sha256": digest(plan),
               "catalog_sha256": plan["catalog_sha256"], "expires": expires}
    return {"payload": payload, "signature": hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()}


def check_approval(approval: dict, plan: dict, key: bytes) -> None:
    if not isinstance(approval, dict) or not isinstance(approval.get("payload"), dict):
        raise Refusal("invalid approval document")
    payload = approval.get("payload", {})
    if payload.get("target") != "synthetic" or payload.get("plan_sha256") != digest(plan):
        raise Refusal("approval target/plan mismatch")
    if payload.get("catalog_sha256") != plan.get("catalog_sha256"):
        raise Refusal("approval catalog mismatch")
    try:
        expiry = dt.datetime.fromisoformat(payload["expires"])
        if expiry.tzinfo is None or expiry <= dt.datetime.now(dt.timezone.utc):
            raise Refusal("approval expired or has no timezone")
    except (KeyError, ValueError) as exc:
        raise Refusal("invalid approval expiry") from exc
    expected = hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, approval.get("signature", "")):
        raise Refusal("approval signature mismatch")


def synthetic_approve(catalog: dict, workspace: Path) -> dict:
    ensure_synthetic(catalog)
    with execution_lock(workspace):
        plan = read_json(workspace / "plan.json")
        if plan["catalog_sha256"] != digest(catalog):
            raise Refusal("catalog changed since preview")
        path = workspace / "synthetic-approval-key.json"
        if not path.exists():
            write_json(path, {"key": secrets.token_hex(32)})
        key = bytes.fromhex(read_json(path)["key"])
        expires = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=30)).isoformat()
        write_json(workspace / "approval.json", sign_approval(plan, key, expires=expires))
        return {"target": "synthetic", "approval_created": True, "expires": expires,
                "production_authority": False}


def synthetic_apply(catalog: dict, workspace: Path) -> dict:
    ensure_synthetic(catalog)
    with execution_lock(workspace):
        plan = read_json(workspace / "plan.json")
        current = state(workspace)
        if plan.get("target") != "synthetic" or plan.get("format") != "homelab-synthetic-plan-v1":
            raise Refusal("unknown plan format/target")
        if plan["catalog_sha256"] != digest(catalog):
            raise Refusal("catalog changed since preview")
        if plan["base_state_sha256"] != digest(current) or plan["base_serial"] != current["serial"]:
            raise Refusal("state changed since preview")
        key = bytes.fromhex(read_json(workspace / "synthetic-approval-key.json")["key"])
        check_approval(read_json(workspace / "approval.json"), plan, key)
        # Recompute every intended change. A signed file is not a substitute
        # for comparing its content to the selected current catalog/state.
        wanted = desired_objects(catalog)
        expected = [{"key": k, "before": current["objects"].get(k), "after": v}
                    for k, v in wanted.items() if current["objects"].get(k) != v]
        if plan["changes"] != expected or set(current["objects"]) - set(wanted):
            raise Refusal("plan content differs from selected catalog transition")
        for change in expected:
            if change["before"]:
                assert_guest_update(change["before"], change["after"])
        if not expected:
            return {"target": "synthetic", "changed": False, "serial": current["serial"]}
        run_id = secrets.token_hex(12)
        write_json(workspace / "history" / (run_id + "-pre.json"), current)
        new = {"serial": current["serial"] + 1, "objects": wanted}
        write_json(workspace / "synthetic-state.json", new)
        write_json(workspace / "history" / (run_id + "-post.json"), new)
        write_json(workspace / "history" / (run_id + "-receipt.json"),
                   {"plan_sha256": digest(plan), "pre": digest(current), "post": digest(new),
                    "target": "synthetic", "history_is_not_distributed_or_immutable": True})
        return {"target": "synthetic", "changed": True, "serial": new["serial"], "PVE_contacted": False}


def synthetic_verify(catalog: dict, workspace: Path) -> dict:
    ensure_synthetic(catalog)
    with execution_lock(workspace):
        current = state(workspace)
        if current["objects"] != desired_objects(catalog):
            raise Refusal("synthetic effective state differs")
        return {"verified": True, "target": "synthetic", "serial": current["serial"],
                "PVE_or_application_acceptance": False}


def guard_tofu_plan(plan: dict, change_class: str = "routine") -> dict:
    if not isinstance(plan, dict):
        raise Refusal("plan must be a JSON object")
    if plan.get("format_version") != "1.2":
        raise Refusal("unqualified OpenTofu plan JSON format")
    checked = 0
    for resource in plan.get("resource_changes", []):
        change = resource.get("change", {})
        actions = change.get("actions")
        if actions in (["no-op"], ["read"]):
            continue
        checked += 1
        if resource.get("type") not in RESOURCE_TYPES:
            raise Refusal("unknown resource type in change")
        if any(x in (actions or []) for x in ("delete", "forget")):
            raise Refusal("delete/replace/forget is outside routine/initial scope")
        if any_true(change.get("after_unknown", {})):
            raise Refusal("changed resource contains unknown values")
        before, after = change.get("before"), change.get("after")
        kind = resource["type"]
        if actions == ["create"] and change_class == "initial":
            if kind.endswith("_container"):
                if not (after.get("unprivileged") is True and after.get("protection") is True
                        and after.get("started") is False and after.get("start_on_boot") is False):
                    raise Refusal("initial LXC must be protected, stopped and unprivileged")
                if not all(i.get("firewall") is True for i in after.get("network_interface", [])):
                    raise Refusal("initial LXC interface filter missing")
                if not all(m.get("backup") is True for m in after.get("mount_point", [])):
                    raise Refusal("initial LXC mount backup inclusion missing")
            elif kind.endswith("_vm"):
                if not (after.get("protection") is True and after.get("started") is False
                        and after.get("on_boot") is False):
                    raise Refusal("initial VM must be protected and stopped")
            elif kind.endswith("_firewall_options"):
                if after.get("enabled") is not True or after.get("input_policy") != "DROP":
                    raise Refusal("initial guest filtering disabled/open")
            else:
                raise Refusal("foundation/rule create needs separate qualified field policy")
        elif actions == ["update"] and kind.endswith(("_container", "_vm")):
            permitted = {"cpu", "memory", "description", "tags"}
            if before is None or after is None:
                raise Refusal("missing before/after object")
            changed = {k for k in set(before) | set(after) if before.get(k) != after.get(k)}
            if changed - permitted:
                raise Refusal("nested protected disk/network/identity/lifecycle update")
            # Only core-count and dedicated-memory changes are qualified here.
            for block, field in (("cpu", "cores"), ("memory", "dedicated")):
                a, b = before.get(block, []), after.get(block, [])
                if len(a) != len(b) or len(a) > 1:
                    raise Refusal("unqualified resource block shape")
                if a and {k: v for k, v in a[0].items() if k != field} != {k: v for k, v in b[0].items() if k != field}:
                    raise Refusal("unqualified nested CPU/memory field")
        else:
            raise Refusal("change class/action not admitted")
    return {"guard_passed": True, "checked_changes": checked, "production_authority": False}


def any_true(value: Any) -> bool:
    if isinstance(value, dict):
        return any(any_true(v) for v in value.values())
    if isinstance(value, list):
        return any(any_true(v) for v in value)
    return value is True


def disk_preflight(expected: dict, observed: list[dict]) -> dict:
    required = ("by_id", "serial", "size_bytes")
    if any(expected.get(k) in (None, "", 0) for k in required):
        raise Refusal("unresolved installation disk identity")
    if any(c in expected["serial"] for c in "*?[]"):
        raise Refusal("wildcard disk selector refused")
    matches = [d for d in observed if all(d.get(k) == expected[k] for k in required)]
    if len(matches) != 1:
        raise Refusal("disk absent, mismatched or ambiguous")
    if matches[0].get("read_only") is not False:
        raise Refusal("disk read-only state unknown or true")
    return {"identity_matched": True, "erase_authorized": False}


def verify_recovery_files(manifest: dict, root: Path) -> dict:
    root = root.resolve(strict=True)
    if manifest.get("format") != "homelab-recovery-files-v1" or not manifest.get("files"):
        raise Refusal("empty/unknown recovery manifest")
    seen = set()
    for item in manifest["files"]:
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts or str(relative) in seen:
            raise Refusal("unsafe/duplicate recovery path")
        seen.add(str(relative))
        p = root / relative
        if any(x.is_symlink() for x in [p, *list(p.parents)[:len(relative.parts) - 1]]):
            raise Refusal("symlink recovery member refused")
        if not p.is_file() or p.stat().st_size == 0 or p.stat().st_size != item["size_bytes"]:
            raise Refusal("missing/empty/wrong-size recovery member")
        if not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]):
            raise Refusal("invalid recovery checksum")
        with p.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if not hmac.compare_digest(actual, item["sha256"]):
            raise Refusal("recovery checksum differs")
    return {"files_verified": len(seen), "native_restore_verified": False,
            "off_host_independence_or_erase_authority": False}
