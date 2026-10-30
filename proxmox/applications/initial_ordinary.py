"""Closed initial ordinary selection for qualified Influx and Automation profiles."""

from pathlib import Path
import re
from coordinated_contract import absolute, fingerprint, shape
from coordinated_generation import initial_copy
from custody_records import Snapshot, decode, no_markers
from private_io import digest, encoded, private_directory, require

SCHEMA = "homelab-influx-initial-ordinary-v1"
AUTOMATION_SCHEMA = "homelab-automation-initial-ordinary-v1"
KINDS = {SCHEMA: "influxdb", AUTOMATION_SCHEMA: "automation"}
BINDING = "initial_ordinary_sha256"


def selection(cfg):
    """Require every exact initial pin; no inference from old receipt contents."""
    if "initial_ordinary" not in cfg:
        return None
    value = cfg["initial_ordinary"]
    require(isinstance(value, dict), "Use a closed initial ordinary selection")
    automation = value.get("schema") == AUTOMATION_SCHEMA
    shape(value, {"schema", "vmid", "node", "installed_site", "installed_site_sha256",
                  "initial_state_sha256", "receipt"} | ({"incomplete_operations"} if automation else set()))
    require(isinstance(value["schema"], str) and value["schema"] in KINDS
            and cfg["app"]["kind"] == KINDS[value["schema"]]
            and "coordinated_custody" not in cfg
            and "coordinated_custody_inputs" not in cfg["paths"],
            "Select only a reviewed standalone initial ordinary profile")
    require(type(value["vmid"]) is int and value["vmid"] >= 100
            and value["vmid"] not in {900, 4914, 4915, 4920}
            and value["vmid"] == cfg["guest"]["vmid"] == cfg["app"]["vmid"]
            and isinstance(value["node"], str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}", value["node"])
            and value["node"] == cfg["site"]["node"],
            "Bind the exact installed guest and node")
    absolute(value["installed_site"])
    for key in ("installed_site_sha256", "initial_state_sha256"):
        fingerprint(value[key])
    receipt = value["receipt"]
    shape(receipt, {"operation", "sha256", "immutable_sha256", "source_sha256"})
    require(isinstance(receipt["operation"], str)
            and re.fullmatch(r"ordinary-[1-9][0-9]*-[1-9][0-9]*", receipt["operation"]),
            "Select the exact successful initial immutable operation")
    for key in ("sha256", "immutable_sha256", "source_sha256"):
        fingerprint(receipt[key])
    member = dict(vmid=value["vmid"], node=value["node"],
                  initial_state_sha256=value["initial_state_sha256"], initial_ordinary=receipt)
    if automation:
        operations = value["incomplete_operations"]
        require(isinstance(operations, list) and len(operations) <= 16
                and all(isinstance(name, str) and re.fullmatch(r"ordinary-[1-9][0-9]*-[1-9][0-9]*", name)
                        for name in operations)
                and len(set(operations)) == len(operations)
                and all(int(name.split("-")[1]) < int(receipt["operation"].split("-")[1]) for name in operations),
                "Select only exact unique qualified pre-anchor incomplete operations")
        member["incomplete_operations"] = operations
    return member


def selection_digest(cfg):
    return digest(encoded(cfg["initial_ordinary"]))


def inspect(cfg):
    """Bind immutable old site/receipt/trust bytes, without freezing mutable state."""
    member = selection(cfg)
    if member is None:
        return {}, None, None
    selected = cfg["initial_ordinary"]
    work = Path(cfg["paths"]["state_root"]) / str(member["vmid"])
    private_directory(work)
    for name in member.get("incomplete_operations", []):
        historical = work / name
        private_directory(historical)
        no_markers(historical)
        complete = historical / "complete.json"
        require(not complete.exists() and not complete.is_symlink(),
                "Preserve the selected incomplete history; never relabel it successful")
    copy = work / selected["receipt"]["operation"] / "complete.json"
    private_directory(copy.parent)
    no_markers(copy.parent)
    snapshot = Snapshot()
    baseline = initial_copy(work, member, raw=snapshot.read(copy))
    old = decode(baseline)
    installed_raw = snapshot.read(Path(selected["installed_site"]))
    require(digest(installed_raw) == selected["installed_site_sha256"]
            == old["binding"].get("site_sha256"), "Preserve the qualified installed site")
    installed = decode(installed_raw)
    require(installed["guest"]["vmid"] == member["vmid"]
            and installed["app"]["kind"] == cfg["app"]["kind"]
            and installed["site"]["node"] == member["node"]
            and all(installed["paths"][key] == cfg["paths"][key]
                    for key in ("state_root", "backup_mount", "backup_directory", "backup_source")),
            "Preserve installed identity and custody paths")
    previous_inputs = old["binding"].get("input_hashes")
    require(isinstance(previous_inputs, dict)
            and previous_inputs.get(installed["paths"]["ca_file"])
            == digest(snapshot.read(Path(cfg["paths"]["ca_file"]), private=False)),
            "Preserve the qualified initial CA trust")
    snapshot.read(work / "ssh-trust.json")
    return snapshot.finish(), member, baseline
