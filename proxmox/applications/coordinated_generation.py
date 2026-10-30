"""Closed backend identity and ordinary receipt relationships; no state writes."""

from pathlib import Path
import re
from private_io import require, digest, encoded, private_directory
from plan_policy import RESOURCES
from custody_records import decode, read_existing
from coordinated_contract import shape


def backend(work, member):
    """Project identity without freezing mutable attributes or serial/hash."""
    raw = read_existing(work / "terraform.tfstate")
    value = decode(raw)
    require(isinstance(value, dict) and value.get("version") == 4
            and isinstance(value.get("lineage"), str) and 0 < len(value["lineage"]) <= 128
            and type(value.get("serial")) is int and value["serial"] >= 0
            and isinstance(value.get("resources"), list) and len(value["resources"]) == len(RESOURCES),
            "Preserve the authoritative backend generation")
    identities = {}
    for row in value["resources"]:
        require(isinstance(row, dict) and row.get("mode") == "managed", "Preserve managed backend identities")
        address = ".".join(str(row.get(k, "")) for k in ("module", "type", "name"))
        require(address in RESOURCES and address not in identities
                and isinstance(row.get("instances"), list) and len(row["instances"]) == 1,
                "Keep exactly the commissioned backend resources")
        instance = row["instances"][0]
        require(isinstance(instance, dict) and instance.get("index_key") is None and instance.get("deposed") is None,
                "Preserve an unambiguous backend instance")
        attrs = instance.get("attributes", {})
        key = RESOURCES[address]
        require(isinstance(attrs, dict) and type(attrs.get(key)) is int and attrs[key] == member["vmid"]
                and attrs.get("node_name") == member["node"] and isinstance(attrs.get("id"), str)
                and 0 < len(attrs["id"]) <= 256, "Preserve backend VMID, node and resource ID")
        identities[address] = {"id": attrs["id"], "vmid": attrs[key], "node": attrs["node_name"]}
    return digest(raw), {"lineage": value["lineage"], "resources": identities}


def plan_identity(value, identity):
    """A reviewed existing plan must not alter the admitted provider IDs."""
    for row in value["resource_changes"]:
        expected = identity["resources"][row["address"]]["id"]
        require(all(row["change"][side].get("id") == expected for side in ("before", "after"))
                and not row["change"].get("after_unknown", {}).get("id"),
                "The plan changed or deferred an admitted backend resource ID")


def initial_copy(work, member, *, raw=None):
    initial = member["initial_ordinary"]
    if initial is None:
        return None
    raw = read_existing(work / initial["operation"] / "complete.json") if raw is None else raw
    require(digest(raw) == initial["sha256"], "Preserve the exact initial immutable ordinary copy")
    value = decode(raw)
    shape(value, {"status", "binding", "state_sha256", "result"})
    require(value["status"] == "passed" and value["state_sha256"] == member["initial_state_sha256"]
            and isinstance(value["binding"], dict) and value["binding"].get("vmid") == member["vmid"]
            and value["binding"].get("source_sha256") == initial["source_sha256"],
            "Bind only the exact qualified initial ordinary success")
    return raw


def latest_success(attempt, member):
    """An older anchor/pointer cannot supersede any recorded later F success."""
    found = {}
    for path in attempt.work.iterdir():
        if not re.fullmatch(r"ordinary-[1-9][0-9]*-[1-9][0-9]*", path.name):
            continue
        private_directory(path)
        active = path == attempt.operation and attempt.hold.exists()
        complete = path / "complete.json"
        if active:
            require(not complete.exists() and not complete.is_symlink(), "Preserve interrupted final receipt custody")
            continue
        raw = read_existing(complete)
        value = decode(raw)
        require(isinstance(value, dict), "Preserve unexpected ordinary operation custody")
        binding = value.get("binding", {})
        if isinstance(binding, dict) and "coordinated_custody_sha256" in binding:
            require(binding["coordinated_custody_sha256"] == attempt.binding["coordinated_custody_sha256"]
                    and binding.get("vmid") == member["vmid"] and value.get("status") == "passed"
                    and value.get("operation") == str(path) and value.get("workflow") == attempt.workflow
                    and type(value.get("run_number")) is int and value["run_number"] > 0,
                    "Preserve foreign or failed coordinated ordinary history")
            number = value["run_number"]
            require(number not in found, "Preserve ambiguous ordinary run history")
            found[number] = raw
    return found[max(found)] if found else None


def classify(attempt, member, lineage, baseline):
    """Own-run continuation precedes latest F success, then the exact first anchor."""
    state_hash, identity = backend(attempt.work, member)
    require(identity["lineage"] == lineage, "Preserve the commissioned backend lineage")
    attempt._select_run()
    canonical = attempt.receipt
    raw = read_existing(canonical) if canonical.exists() or canonical.is_symlink() else None
    latest = latest_success(attempt, member)
    require(latest is None or raw == latest, "Preserve the latest ordinary success; no older anchor fallback")
    if attempt.hold.exists() or attempt.hold.is_symlink():
        held = decode(read_existing(attempt.hold))
        require(isinstance(held, dict), "Preserve malformed ordinary custody")
        previous = held.pop("previous_ordinary_sha256", "missing")
        require(encoded(held) == encoded(attempt.marker)
                and previous == (None if raw is None else digest(raw)), "Preserve foreign or changed ordinary custody")
        ready = decode(read_existing(attempt.operation / "infrastructure-complete.json"))
        require(isinstance(ready, dict) and ready.get("binding") == attempt.binding and ready.get("state_sha256") == state_hash
                and ready.get("state_identity") == identity, "Preserve incomplete or changed infrastructure custody")
    else:
        previous = None if raw is None else digest(raw)
        if raw is not None:
            if baseline is not None and raw == baseline:
                require(state_hash == member["initial_state_sha256"], "The initial backend has unproven changes")
            else:
                value = decode(raw)
                shape(value, {"status", "binding", "state_sha256", "state_identity", "result", "workflow", "run_number", "site_revision", "operation"})
                operation = value["operation"]
                require(isinstance(operation, str) and Path(operation).parent == attempt.work
                        and re.fullmatch(r"ordinary-[1-9][0-9]*-[1-9][0-9]*", Path(operation).name),
                        "Keep this member's immutable ordinary operation")
                require(read_existing(Path(operation) / "complete.json") == raw
                        and value["status"] == "passed" and value["state_sha256"] == state_hash
                        and value["state_identity"] == identity
                        and isinstance(value["binding"], dict) and value["binding"].get("vmid") == member["vmid"]
                        and value["binding"].get("coordinated_custody_sha256") == attempt.binding["coordinated_custody_sha256"],
                        "Preserve the latest exact ordinary success; no anchor fallback")
        else:
            require(baseline is None and state_hash == member["initial_state_sha256"],
                    "Require the selected initial ordinary disposition and backend")
    attempt.previous_ordinary_sha256 = previous
    attempt.marker["previous_ordinary_sha256"] = previous
    return identity
