"""Materialize one immutable current deployment packet with existing secrets."""

import json
import hashlib
import foundation
from guest_contract import SOURCE
import os
from pathlib import Path
import re
from private_io import (
    require,
    regular,
    private_directory,
    write_new,
    encoded,
    digest,
    sha,
    read_json,
)
import guest_contract as contract
import runtime_secrets
import coordinated_contract
import coordinated_evidence
import initial_ordinary


def prepare(
    packet_path, inputs=Path("/var/lib/homelab-inputs/ordinary"), environment=None
):
    packet = read_json(packet_path)
    require(
        set(packet) == {"schema", "enabled", "kind", "identity", "files"}
        and packet["schema"] == contract.SCHEMA
        and packet["enabled"] is True
        and packet["kind"] in contract.BLUEPRINTS,
        "Enable a current reviewed guest packet",
    )
    kind, identity = packet["kind"], packet["identity"]
    require(
        isinstance(identity, str) and re.fullmatch("[0-9a-f]{64}", identity),
        "Bind the reviewed ordinary input identity",
    )
    destination = inputs / kind / identity
    payload = {name: value.encode() for name, value in packet["files"].items()}
    require(
        "site.json" in payload
        and all(re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", n) for n in payload),
        "Use bounded ordinary input file names",
    )
    cfg = json.loads(payload["site.json"])
    contract.phases(cfg)
    require(
        cfg["app"]["kind"] == kind
        and "capture" not in cfg["app"]
        and "ha_http" not in cfg["app"],
        "Ordinary deployment cannot migrate or restore data",
    )
    stack = json.loads(payload["stack.json"]) if "stack.json" in payload else None
    contract.validate(cfg, stack)
    group = coordinated_contract.selection(cfg)
    if group is not None:
        require(cfg["paths"]["coordinated_custody_inputs"] == str(destination),
                "Bind custody source evidence to this immutable packet directory")
        for name in ("catalogue", "acceptance"):
            proof = group[name]
            require(proof["file"] in payload and digest(payload[proof["file"]]) == proof["sha256"],
                    "Preserve custody source proof bytes before preparation")
    require(
        "docker" not in cfg["deployment"]["capabilities"]
        or cfg["app"]["exclusive_writer_confirmed"] is True,
        "Complete separate data/configuration preparation and writer fencing",
    )
    if "stack.json" in payload:
        require(
            cfg["app"]["stack_config"] == str(destination / "stack.json"),
            "Bind the ordinary stack to its private input directory",
        )
        extra = runtime_secrets.prepare_stack(
            cfg, stack, destination, os.environ if environment is None else environment
        )
        require(
            not extra.keys() & payload.keys(),
            "Runtime secret files cannot replace source inputs",
        )
        payload.update(extra)
        payload["stack.json"] = encoded(stack)

    if stack is not None:
        for service in contract.archive_inputs(stack).values():
            archive = Path(service["archive"])
            require(
                archive.is_file()
                and not archive.is_symlink()
                and sha(archive) == service["archive_sha256"],
                "Preserve the original selected custom image archive before guest operations",
            )
    manifest = encoded(
        {
            "packet_sha256": sha(packet_path),
            "files": {n: digest(raw) for n, raw in payload.items()},
        }
    )
    for folder in (inputs.parent, inputs, inputs / kind):
        private_directory(folder, create=not folder.exists())
    if destination.exists() or destination.is_symlink():
        private_directory(destination)
        require(
            {p.name for p in destination.iterdir()} == set(payload) | {"prepared.json"}
            and regular(destination / "prepared.json", private=True) == manifest
            and all(
                regular(destination / n, private=True) == raw
                for n, raw in payload.items()
            ),
            "Ordinary inputs differ or preparation was interrupted; preserve them for review",
        )
    else:
        private_directory(destination, create=True)
        for name, raw in payload.items():
            write_new(destination / name, raw)
        write_new(destination / "prepared.json", manifest)
    return cfg, destination / "site.json"


def binding(cfg, site):
    result = {
        "vmid": cfg["guest"]["vmid"],
        "site_sha256": sha(site),
        "source_sha256": source_hash(),
        "blueprint_sha256": sha(
            Path(__file__).resolve().parents[2] / "blueprints/catalogue.json"
        ),
        "input_hashes": input_hashes(cfg),
    }
    if coordinated_contract.selection(cfg) is not None:
        result["coordinated_custody_sha256"] = coordinated_contract.selection_digest(cfg)
    if initial_ordinary.selection(cfg) is not None:
        result[initial_ordinary.BINDING] = initial_ordinary.selection_digest(cfg)
    return result


def source_hash():
    result = hashlib.sha256()
    for path in sorted([*SOURCE.rglob("*"), *(SOURCE.parent / "common").rglob("*")]):
        if path.is_file() and not any(
            p in {".terraform", "__pycache__", ".work"} for p in path.parts
        ):
            result.update(str(path.relative_to(SOURCE.parent)).encode())
            result.update(bytes.fromhex(sha(path)))
    return result.hexdigest()


def input_hashes(cfg):
    """Bind external configuration and trust files as well as the top-level site JSON."""
    paths = [cfg["paths"]["ca_file"]]
    if cfg["guest"].get("serial_device"):
        paths.extend(
            cfg["paths"][name] for name in ("host_device_key", "host_known_hosts")
        )
    app = cfg["app"]
    if "stack_config" in app:
        paths.append(app["stack_config"])
        stack = json.loads(Path(app["stack_config"]).read_text())
        paths.extend(foundation.source_files(stack))
        if app.get("kind") == "bitwarden":
            paths.append(app["bitwarden"]["runtime_env_file"])
    if app.get("kind") == "pegaprox":
        paths.append(app["pegaprox"]["key_source"])
    paths.extend(item["key_path"] for item in app.get("repositories", []))
    paths.extend(
        item["source"] for item in app.get("database", {}).get("config_files", [])
    )
    result = {path: sha(path) for path in sorted(set(paths))}
    proofs, _, _ = coordinated_evidence.inspect(cfg)
    result.update(proofs)
    initial_proofs, _, _ = initial_ordinary.inspect(cfg)
    result.update(initial_proofs)
    return result
