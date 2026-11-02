"""Read only explicitly reviewed current-contract failed infrastructure checkpoints.

This never releases a hold or declares an application successful. An operator
must first preserve the exact own failed hold inside its immutable operation.
Every unselected or changed failure continues to refuse ordinary deployment.
"""
from pathlib import Path
import re
from coordinated_contract import fingerprint, shape
from custody_records import decode, no_markers, read_existing
from private_io import digest, private_directory, require


def historical_network_paths(attributes):
    """Bind the denied path to its pinned past backend, not future profiles."""
    interfaces = attributes.get("network_interface")
    require(isinstance(interfaces, list) and 0 < len(interfaces) <= 16,
            "Bind the frozen failed backend network interfaces")
    paths = set()
    for nic in interfaces:
        require(isinstance(nic, dict) and isinstance(nic.get("bridge"), str)
                and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,14}", nic["bridge"]),
                "Bind the frozen failed backend network interfaces")
        vlan = nic.get("vlan_id")
        require(vlan is None or type(vlan) is int and 0 <= vlan <= 4094,
                "Bind the frozen failed backend network interfaces")
        if vlan:
            paths.add(f"/sdn/zones/localnetwork/{nic['bridge']}/{vlan}")
    return paths


def infrastructure_review(attempt, member, path, held, ready, row):
    """Read an exact operator-reviewed SDN refusal; never complete or retry it."""
    from coordinated_generation import backend

    shape(ready, {"schema", "status", "binding", "operation", "previous_operation",
                  "previous_state_sha256", "state_sha256", "state_identity", "plan_sha256",
                  "failure_kind", "permission_path", "configuration_unchanged", "guest_healthy"})
    permission = ready["permission_path"]
    require(ready["schema"] == "homelab-reviewed-infrastructure-failure-v1"
            and ready["status"] == "reviewed_failure"
            and ready["failure_kind"] == "pve_sdn_use_denied_before_update"
            and ready["configuration_unchanged"] is True and ready["guest_healthy"] is True
            and isinstance(permission, str)
            and ready["binding"] == held["binding"] and ready["operation"] == str(path),
            "Require the exact reviewed pre-update SDN refusal, not a successful checkpoint")
    previous = ready["previous_operation"]
    require(isinstance(previous, str) and re.fullmatch(r"ordinary-[1-9][0-9]*-[1-9][0-9]*", previous)
            and tuple(map(int, previous.split("-")[1:])) < tuple(map(int, path.name.split("-")[1:])),
            "Keep the prior immutable success before this failed attempt")
    previous_raw = read_existing(attempt.work / previous / "complete.json")
    previous_value = decode(previous_raw)
    require(isinstance(previous_value, dict) and digest(previous_raw) == row["previous_ordinary_sha256"]
            and previous_value.get("status") == "passed"
            and previous_value.get("state_sha256") == ready["previous_state_sha256"],
            "Preserve the exact prior success and its original backend")
    state_hash, identity = backend(path / "infrastructure", member)
    require(state_hash == row["state_sha256"] == ready["state_sha256"]
            and identity == ready["state_identity"],
            "Bind the frozen failed backend identity; never restore or adopt it")
    def guest_attributes(folder):
        value = decode(read_existing(folder / "terraform.tfstate"))
        return next(r["instances"][0]["attributes"] for r in value["resources"]
                    if r["type"] == "proxmox_virtual_environment_container")
    failed_guest = guest_attributes(path / "infrastructure")
    require(permission in historical_network_paths(failed_guest),
            "Require the exact reviewed pre-update SDN refusal, not a successful checkpoint")
    plan = decode(read_existing(path / "plan.json"))
    window = decode(read_existing(path / "apply-window.json"))
    shape(window, {"plan_sha256", "started_at_ns"})
    require(plan.get("binding") == held["binding"] and plan.get("existing_guest") is True
            and plan.get("changed") is True and type(window["started_at_ns"]) is int
            and window["started_at_ns"] > 0
            and digest(read_existing(path / "guest.tfplan")) == ready["plan_sha256"]
            == plan.get("plan_sha256") == window["plan_sha256"],
            "Preserve the exact unfinished saved-plan attempt")
    log = read_existing(path / "infrastructure.log")
    require(("received an HTTP 403 response - Reason: Permission check failed (" + permission + ", SDN.Use)").encode() in log
            and b"Modifications complete" not in log,
            "A different or partially completed apply needs separate review")
    previous_folder = path / "infrastructure" / "previous"
    previous_hash, previous_identity = backend(previous_folder, member)
    require(previous_hash == ready["previous_state_sha256"] and previous_identity == identity,
            "Keep the exact prior backend and all resource identities across the failed apply")
    return identity, {"before": failed_guest,
                      "after": guest_attributes(previous_folder)}


def selection(cfg):
    rows = cfg.get("reviewed_ordinary_failures", [])
    require(isinstance(rows, list) and len(rows) <= 16, "Use bounded reviewed ordinary failures")
    require(not rows or "coordinated_custody" in cfg or "initial_ordinary" in cfg,
            "Reviewed failures require selected ordinary custody")
    seen = set()
    for row in rows:
        shape(row, {"operation", "phase", "hold_sha256", "infrastructure_sha256", "log_sha256",
                    "previous_ordinary_sha256", "state_sha256"})
        name = row["operation"]
        require(isinstance(name, str) and re.fullmatch(r"ordinary-[1-9][0-9]*-[1-9][0-9]*", name)
                and name not in seen, "Select each exact failed ordinary operation once")
        seen.add(name)
        require(isinstance(row["phase"], str)
                and (re.fullmatch(r"[a-z][a-z0-9_]{0,31}", row["phase"])
                     or row["phase"] == "zabbix-agent"),
                "Select a fixed failed application phase")
        for key in row.keys() - {"operation", "phase"}:
            fingerprint(row[key])
    return rows


def inspect(attempt, member, binding_key):
    found = {}
    for row in selection(attempt.cfg):
        path = attempt.work / row["operation"]
        infrastructure = row["phase"] == "infrastructure"
        require(path != attempt.operation and (infrastructure or row["phase"] in attempt.phases),
                "A reviewed failure cannot replay as the current operation")
        private_directory(path)
        no_markers(path)
        private_directory(path / row["phase"])
        no_markers(path / row["phase"])
        require(not any((path / name).exists() or (path / name).is_symlink()
                        for name in ("complete.json", row["phase"] + "-complete.json")),
                "A failed checkpoint cannot replace a completed operation")
        names = {"hold_sha256": "preserved-failed-hold.json",
                 "infrastructure_sha256": ("infrastructure/review.json" if infrastructure else "infrastructure-complete.json"),
                 "log_sha256": ("infrastructure.log" if infrastructure else row["phase"] + "/application.log")}
        raw = {key: read_existing(path / name) for key, name in names.items()}
        require(all(digest(value) == row[key] for key, value in raw.items()),
                "Preserve exact reviewed failed operation bytes")
        held, ready = decode(raw["hold_sha256"]), decode(raw["infrastructure_sha256"])
        require(isinstance(held, dict) and isinstance(ready, dict), "Preserve typed failed operation records")
        binding = held.get("binding", {})
        require(isinstance(binding, dict) and binding.get("vmid") == member["vmid"]
                and binding.get(binding_key) == attempt.binding[binding_key]
                and held.get("operation") == str(path) and held.get("workflow") == attempt.workflow
                and type(held.get("run_number")) is int and 0 < held["run_number"] < attempt.run_number
                and held.get("automatic_retry") is False
                and held.get("previous_ordinary_sha256") == row["previous_ordinary_sha256"],
                "Preserve the exact own failed workflow and prior success")
        if infrastructure:
            identity, reviewed_drift = infrastructure_review(attempt, member, path, held, ready, row)
        else:
            require(read_existing(path / (row["phase"] + "-started.json")) == raw["hold_sha256"]
                    and ready.get("binding") == binding and ready.get("state_sha256") == row["state_sha256"]
                    and isinstance(ready.get("state_identity"), dict),
                    "Bind only the failed attempt's completed infrastructure checkpoint")
            identity = ready["state_identity"]
        found[row["operation"]] = dict(row, identity=identity,
                                      **({"reviewed_drift": reviewed_drift} if infrastructure else {}))
    return found
