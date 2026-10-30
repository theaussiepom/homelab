"""Closed source selection for exact completed commissioning groups; no I/O."""

from pathlib import Path
import re
from private_io import require, digest, encoded

SCHEMA = "homelab-coordinated-custody-v1"
ROLES = {
    "homelab-postgresql-cutover-v1": ("postgresql", "identity", "db-tools"),
    "homelab-database-server-cutover-v1": ("mariadb",),
}
RECORDS = {"request.json", "claim.json", "complete.json"}


def shape(value, keys):
    require(isinstance(value, dict) and set(value) == set(keys), "Use closed coordinated custody fields")


def fingerprint(value, length=64):
    require(isinstance(value, str) and re.fullmatch("[0-9a-f]{" + str(length) + "}", value),
            "Pin an exact coordinated evidence digest")


def absolute(value):
    require(isinstance(value, str) and len(value) <= 4096 and Path(value).is_absolute()
            and ".." not in Path(value).parts and str(Path(value)) == value,
            "Use canonical absolute custody paths")


def selection(cfg):
    """Validate one full group, independently of which configured members run."""
    if "coordinated_custody" not in cfg:
        require("coordinated_custody_inputs" not in cfg.get("paths", {}),
                "Custody inputs require an exact group selection")
        return None
    value = cfg["coordinated_custody"]
    shape(value, {"schema", "group"})
    require(value["schema"] == SCHEMA, "Select the current coordinated custody contract")
    group = value["group"]
    shape(group, {"directory", "schema", "operation", "records", "catalogue", "acceptance", "recovery", "members"})
    require(isinstance(group["schema"], str) and group["schema"] in ROLES,
            "Select only the reviewed completed group types")
    roles = ROLES[group["schema"]]
    engine = roles[0]
    operation = group["operation"]
    require(isinstance(operation, str) and re.fullmatch(engine + r"-[a-z0-9][a-z0-9-]{0,63}", operation),
            "Bind the original commissioning operation")
    prefix = "database-network-cutover-" if engine == "postgresql" else "database-server-cutover-"
    require(group["directory"] == prefix + operation,
            "Bind the exact existing group directory")
    shape(group["records"], RECORDS)
    for value_hash in group["records"].values():
        fingerprint(value_hash)
    require(group["records"]["request.json"] == group["records"]["claim.json"],
            "Keep identical request and claim bytes")
    for name in ("catalogue", "acceptance"):
        row = group[name]
        shape(row, {"file", "sha256"})
        require(isinstance(row["file"], str) and re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", row["file"])
                and row["file"] not in {"site.json", "stack.json", "prepared.json"},
                "Use bounded immutable custody input filenames")
        fingerprint(row["sha256"])
    require(group["catalogue"]["file"] != group["acceptance"]["file"], "Keep custody source proofs distinct")
    recovery = group["recovery"]
    shape(recovery, {"mount", "directory", "source"})
    for name in ("mount", "directory"):
        absolute(recovery[name])
    require(Path(recovery["mount"]) in Path(recovery["directory"]).parents
            and isinstance(recovery["source"], str) and recovery["source"] and len(recovery["source"]) <= 4096,
            "Bind the existing recovery filesystem and directory")
    shape(group["members"], roles)
    ids = []
    for role, member in group["members"].items():
        shape(member, {"vmid", "node", "installed_site", "overlay", "initial_state_sha256", "initial_ordinary"})
        require(type(member["vmid"]) is int and member["vmid"] >= 100
                and member["vmid"] not in {900, 4914, 4915, 4920}, "Preserve commissioned guest identities")
        ids.append(member["vmid"])
        require(isinstance(member["node"], str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}", member["node"]),
                "Bind the commissioned node")
        absolute(member["installed_site"])
        shape(member["overlay"], {"directory", "sha256"})
        require(isinstance(member["overlay"]["directory"], str)
                and re.fullmatch(r"database-network-apply-[0-9a-f]{64}", member["overlay"]["directory"]),
                "Bind the original immutable network overlay")
        fingerprint(member["overlay"]["sha256"])
        fingerprint(member["initial_state_sha256"])
        initial = member["initial_ordinary"]
        if initial is not None:
            shape(initial, {"operation", "sha256", "source_sha256"})
            require(isinstance(initial["operation"], str) and re.fullmatch(r"ordinary-[1-9][0-9]*-[1-9][0-9]*", initial["operation"]),
                    "Name the existing immutable initial operation copy")
            fingerprint(initial["sha256"])
            fingerprint(initial["source_sha256"])
    require(len(ids) == len(set(ids)), "Keep group member identities distinct")
    role = cfg["app"]["kind"]
    require(role in group["members"] and group["members"][role]["vmid"] == cfg["guest"]["vmid"]
            and group["members"][role]["node"] == cfg["site"]["node"],
            "A custody selection belongs only to its exact guest and role")
    for key, selected in (("backup_mount", "mount"), ("backup_directory", "directory"), ("backup_source", "source")):
        require(cfg["paths"][key] == recovery[selected], "Keep the selected recovery custody identity")
    require("coordinated_custody_inputs" in cfg["paths"], "Declare the immutable custody input directory")
    absolute(cfg["paths"]["coordinated_custody_inputs"])
    return group


def selection_digest(cfg):
    return digest(encoded(cfg["coordinated_custody"]))


def configured_closure(resolved):
    """Require every configured copy, including disabled members, without enabling it."""
    for cfg, _, files in resolved.values():
        group = selection(cfg)
        if group is None:
            continue
        for role, member in group["members"].items():
            require(role in resolved, "Keep every configured group member")
            peer, _, _ = resolved[role]
            require(selection(peer) == group and peer["guest"]["vmid"] == member["vmid"],
                    "Configured group provenance copies must agree, including disabled members")
        for key in ("catalogue", "acceptance"):
            row = group[key]
            require(row["file"] in files and digest(files[row["file"]].encode()) == row["sha256"],
                    "Bind the complete immutable custody source inputs")
