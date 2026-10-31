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
        require(isinstance(row["phase"], str) and re.fullmatch(r"[a-z][a-z0-9_]{0,31}", row["phase"]),
                "Select a fixed failed application phase")
        for key in row.keys() - {"operation", "phase"}:
            fingerprint(row[key])
    return rows


def inspect(attempt, member, binding_key):
    found = {}
    for row in selection(attempt.cfg):
        path = attempt.work / row["operation"]
        require(path != attempt.operation and row["phase"] in attempt.phases,
                "A reviewed failure cannot replay as the current operation")
        private_directory(path)
        no_markers(path)
        private_directory(path / row["phase"])
        no_markers(path / row["phase"])
        require(not any((path / name).exists() or (path / name).is_symlink()
                        for name in ("complete.json", row["phase"] + "-complete.json")),
                "A failed checkpoint cannot replace a completed operation")
        names = {"hold_sha256": "preserved-failed-hold.json",
                 "infrastructure_sha256": "infrastructure-complete.json",
                 "log_sha256": row["phase"] + "/application.log"}
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
        require(read_existing(path / (row["phase"] + "-started.json")) == raw["hold_sha256"]
                and ready.get("binding") == binding and ready.get("state_sha256") == row["state_sha256"]
                and isinstance(ready.get("state_identity"), dict),
                "Bind only the failed attempt's completed infrastructure checkpoint")
        found[row["operation"]] = dict(row, identity=ready["state_identity"])
    return found
