"""Explicit initial ordinary receipt selection for one standalone Influx profile."""

from pathlib import Path
import re
from coordinated_contract import absolute, fingerprint, shape
from coordinated_generation import initial_copy
from custody_records import Snapshot, decode, no_markers
from private_io import digest, encoded, private_directory, require

SCHEMA = "homelab-influx-initial-ordinary-v1"
BINDING = "initial_ordinary_sha256"


def selection(cfg):
    """Require every exact initial pin; no inference from old receipt contents."""
    if "initial_ordinary" not in cfg:
        return None
    value = cfg["initial_ordinary"]
    shape(value, {"schema", "vmid", "node", "installed_site", "installed_site_sha256",
                  "initial_state_sha256", "receipt"})
    require(value["schema"] == SCHEMA and cfg["app"]["kind"] == "influxdb"
            and "coordinated_custody" not in cfg
            and "coordinated_custody_inputs" not in cfg["paths"],
            "Select only a standalone Influx initial ordinary receipt")
    require(type(value["vmid"]) is int and value["vmid"] >= 100
            and value["vmid"] not in {900, 4914, 4915, 4920}
            and value["vmid"] == cfg["guest"]["vmid"] == cfg["app"]["vmid"]
            and isinstance(value["node"], str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}", value["node"])
            and value["node"] == cfg["site"]["node"],
            "Bind the exact installed Influx guest and node")
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
    return dict(vmid=value["vmid"], node=value["node"],
                initial_state_sha256=value["initial_state_sha256"], initial_ordinary=receipt)


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
    copy = work / selected["receipt"]["operation"] / "complete.json"
    private_directory(copy.parent)
    no_markers(copy.parent)
    snapshot = Snapshot()
    baseline = initial_copy(work, member, raw=snapshot.read(copy))
    old = decode(baseline)
    installed_raw = snapshot.read(Path(selected["installed_site"]))
    require(digest(installed_raw) == selected["installed_site_sha256"]
            == old["binding"].get("site_sha256"), "Preserve the qualified installed Influx site")
    installed = decode(installed_raw)
    require(installed["guest"]["vmid"] == member["vmid"]
            and installed["app"]["kind"] == "influxdb"
            and installed["site"]["node"] == member["node"]
            and all(installed["paths"][key] == cfg["paths"][key]
                    for key in ("state_root", "backup_mount", "backup_directory", "backup_source")),
            "Preserve installed Influx identity and custody paths")
    previous_inputs = old["binding"].get("input_hashes")
    require(isinstance(previous_inputs, dict)
            and previous_inputs.get(installed["paths"]["ca_file"])
            == digest(snapshot.read(Path(cfg["paths"]["ca_file"]), private=False)),
            "Preserve the qualified Influx CA trust")
    snapshot.read(work / "ssh-trust.json")
    return snapshot.finish(), member, baseline
