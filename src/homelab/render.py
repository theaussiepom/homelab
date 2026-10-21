"""Render reviewed local drafts. Never invokes SSH, PVE, Ansible or OpenTofu."""
from __future__ import annotations

import json
from pathlib import Path
import shutil

from .core import ROOT, Refusal, digest, unresolved, validate_catalog, write_json


def render(catalog: dict, destination: Path) -> dict:
    result = validate_catalog(catalog)
    destination = destination.absolute()
    if destination.exists() or destination.is_symlink():
        raise Refusal("render destination must be new; preserve prior drafts/edits")
    if catalog["site"]["environment"] == "production" and destination.is_relative_to(ROOT):
        raise Refusal("production render cannot be inside the public implementation tree")
    destination.mkdir(parents=True, mode=0o700)
    source = ROOT / "infrastructure/proxmox"
    shutil.copytree(source, destination / "proxmox", ignore=shutil.ignore_patterns(
        ".terraform", "*.tfstate*", "*.tfplan", "crash.log"))
    guests = {g["key"]: g for g in catalog["guests"]}
    projection = {"site": catalog["site"], "foundation": catalog["foundation"], "guests": guests}
    for name in ("foundation", "critical", "application-guests", "security-vm"):
        write_json(destination / "proxmox" / name / "site.auto.tfvars.json", projection)
    # Proxmox LXC primary network files are excluded from Ansible ownership.
    inventory = {"all": {"children": {"pve_guests": {"hosts": {}}, "physical_pis": {"hosts": {}}}}}
    for guest in catalog["guests"]:
        management = next((i for i in guest["interfaces"] if i["vlan"] == 25), None)
        inventory["all"]["children"]["pve_guests"]["hosts"][guest["key"]] = {
            "ansible_host": management["ipv4"] if management else None,
            "guest_catalog": guest, "homelab_allow_mutation": False,
            "homelab_preserve_uid_gid": True, "homelab_expected_identity": None,
        }
    for pi in catalog["fleet"]:
        inventory["all"]["children"]["physical_pis"]["hosts"][pi["key"]] = {
            "ansible_host": pi["host"], "ansible_user": pi["ansible_user"],
            "fleet_catalog": pi, "homelab_allow_mutation": False,
            "homelab_preserve_uid_gid": True,
        }
    write_json(destination / "inventory.json", inventory)
    report = {"draft": True, "catalog_sha256": digest(catalog),
              "guests": len(guests), "deploy_included": "deploy" in guests,
              "unresolved_fields": unresolved(catalog), "production_admitted": False,
              "PVE_contacted": False, "target": str(destination)}
    write_json(destination / "render-report.json", report)
    return {k: v for k, v in report.items() if k != "unresolved_fields"} | {
        "unresolved_field_count": len(result["unresolved_fields"])}


def installer_answer(catalog: dict, password_hash: str) -> str:
    # A native installer is destructive at boot. This draft generator is
    # deliberately limited to synthetic fixtures, even when given a password.
    from .core import ensure_synthetic
    ensure_synthetic(catalog)
    h = catalog["hardware"]
    if not password_hash.startswith(("$y$", "$6$")) or "\n" in password_hash:
        raise Refusal("installer requires a supplied hashed root password")
    if any(c in h["disk_serial"] for c in "*?[]"):
        raise Refusal("wildcard installation selector refused")
    # json.dumps strings are TOML basic-string compatible for these fields.
    q = json.dumps
    return f'''# SYNTHETIC DRAFT. Do not boot this answer on production hardware.
# Native answer-parser / complete ISO / tagged-firstboot qualification pending.
[global]
keyboard = "en-us"
country = "au"
fqdn = {q(h['fqdn'])}
mailto = "operator@example.invalid"
timezone = "Australia/Brisbane"
root-password-hashed = {q(password_hash)}

[network]
source = "from-answer"
cidr = {q(h['installer_cidr'])}
gateway = {q(h['installer_gateway'])}
dns = {q(h['installer_dns'][0])}
filter.ID_NET_NAME_MAC = {q('enx' + h['installer_mac'].replace(':', ''))}

[disk-setup]
filesystem = "zfs"
zfs.raid = "raid0"
zfs.ashift = 12
zfs.compress = "lz4"
zfs.arc-max = 2048
filter-match = "all"
filter.ID_SERIAL_SHORT = {q(h['disk_serial'])}

[first-boot]
source = "from-iso"
ordering = "before-network"
'''
