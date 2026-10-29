#!/usr/bin/env python3
"""Compile the whole composition into current per-guest deployment packets.

Pure input handling: this module never reads credentials, contacts targets or
runs deployers. Runtime admission is deliberately separate from offline previews.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
import subprocess

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT / "proxmox/applications"))
sys.path.insert(0, str(ROOT / "blueprints"))
import connections
import guest_contract
import service_bindings
import routes

CATALOGUE = guest_contract.BLUEPRINTS
PIN = re.compile(
    r"^\s*uses: ([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/\.github/workflows/([a-z-]+\.yml)@([0-9a-f]{40})\s*$",
    re.M,
)
TOKEN = re.compile(r"\$\{([a-z][a-z0-9_.-]*)\}")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def read(path):
    def unique(pairs):
        result = {}
        for k, v in pairs:
            require(k not in result, "Duplicate JSON field")
            result[k] = v
        return result

    require(path.is_file() and not path.is_symlink(), "Use a regular source file")
    return json.loads(path.read_text(), object_pairs_hook=unique)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def workflow_selection(path, workflow):
    pins = PIN.findall(path.read_text())
    require(
        len(pins) == 1 and pins[0][1] == workflow,
        "Use one immutable workflow selection",
    )
    return {"repository": pins[0][0], "revision": pins[0][2]}


def check_revision(path, revision):
    actual = subprocess.check_output(
        ["git", "-C", str(path), "rev-parse", "HEAD"], text=True
    ).strip()
    require(
        actual == revision, "Checked out source differs from the workflow selection"
    )


def merge(base, override):
    if isinstance(base, dict) and isinstance(override, dict):
        result = copy.deepcopy(base)
        for key, value in override.items():
            result[key] = merge(result.get(key), value)
        return result
    return copy.deepcopy(override)


def substitute(value, values):
    if isinstance(value, dict):
        return {k: substitute(v, values) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, values) for v in value]
    if not isinstance(value, str):
        return value

    def replacement(match):
        key = match[1]
        if key == "inputs" and key not in values:
            return match[0]
        require(
            key in values and isinstance(values[key], (str, int)),
            "Supply every declared central value",
        )
        return str(values[key])

    return TOKEN.sub(replacement, value)


def manifest(root):
    spec = read(root / "stack.json")
    require(
        set(spec) == {"schema", "values", "guests", "routes"}
        and spec["schema"] == "homelab-stack-v2",
        "Use the stack contract",
    )
    guests = spec["guests"]
    require(
        set(guests) == set(CATALOGUE), "Keep a permanent path for every prepared guest"
    )
    for name, row in guests.items():
        require(
            set(row) == {"depends_on", "prerequisites"}
            and isinstance(row["depends_on"], list)
            and len(set(row["depends_on"])) == len(row["depends_on"])
            and name not in row["depends_on"]
            and set(row["depends_on"]) <= set(guests)
            and isinstance(row["prerequisites"], list)
            and all(re.fullmatch("[a-z][a-z0-9-]*", s) for s in row["prerequisites"]),
            "Use explicit guest dependencies and prerequisites",
        )

    def visit(name, path):
        require(name not in path, "Guest dependency cycle")
        for parent in guests[name]["depends_on"]:
            visit(parent, path | {name})

    for name in guests:
        visit(name, set())
    return spec


def parse_disabled(value):
    """An omitted/blank workflow input disables no guests."""
    if value == "":
        return []
    disabled = json.loads(value)
    require(isinstance(disabled, list), "Use a JSON disabled guest list")
    return disabled


def selection(spec, disabled=None):
    if disabled is None:
        disabled = []
    require(
        isinstance(disabled, list)
        and all(isinstance(name, str) for name in disabled)
        and len(set(disabled)) == len(disabled)
        and set(disabled) <= set(spec["guests"]),
        "Disable only unique known guest names",
    )
    enabled = [name for name in spec["guests"] if name not in disabled]
    for name in enabled:
        require(
            set(spec["guests"][name]["depends_on"]) <= set(enabled),
            "Cannot disable a prerequisite while its consumers remain active",
        )
    return enabled


def image(value):
    if value == {
        "repository": "ghcr.io/bitwarden/lite",
        "tag": "latest",
        "digest": None,
    }:
        return {"image": "ghcr.io/bitwarden/lite:latest"}
    # A local image ID is a retained private archive selection, never an update.
    if set(value) == {"local_id", "archive", "archive_sha256"}:
        require(
            re.fullmatch(r"sha256:[0-9a-f]{64}", value["local_id"])
            and Path(value["archive"]).is_absolute()
            and re.fullmatch("[0-9a-f]{64}", value["archive_sha256"]),
            "Supply the preserved custom image and archive identity",
        )
        return {
            "image": value["local_id"],
            "archive": value["archive"],
            "archive_sha256": value["archive_sha256"],
        }
    require(
        set(value) == {"repository", "tag", "digest"}
        and re.fullmatch(r"[a-z0-9./_-]+", value["repository"])
        and (value["tag"] is None or re.fullmatch(r"[A-Za-z0-9_.-]+", value["tag"]))
        and re.fullmatch(r"sha256:[0-9a-f]{64}", value["digest"]),
        "Keep a repository, optional recorded tag and immutable digest",
    )
    return {
        "image": value["repository"]
        + (":" + value["tag"] if value["tag"] else "")
        + "@"
        + value["digest"]
    }


def _resolve_guest(root, overlay, name, spec):
    values = merge(spec["values"], overlay["values"])
    profile = read(root / "guests" / name / "profile.json")
    require(
        set(profile) == {"config", "files", "stack"}, "Use the guest profile fields"
    )
    overrides = overlay["guests"].get(name, {})
    require(
        set(overrides) <= {"config", "stack"},
        "Override only selected guest configuration or stack fields",
    )
    cfg = substitute(
        merge(
            merge(read(root / "common.json"), profile["config"]),
            merge(overlay["common"], overrides.get("config", {})),
        ),
        values,
    )
    require(
        "deployment" not in cfg
        and cfg["app"]["kind"] == name
        and "capture" not in cfg["app"]
        and "ha_http" not in cfg["app"]
        and "clean_install_confirmed" not in cfg["app"],
        "Ordinary deployment cannot include migration or account bootstrap",
    )
    require(
        cfg["guest"].get("platform", "debian-lxc") == "debian-lxc",
        "Only Debian LXC is implemented",
    )
    cfg["guest"].pop("platform", None)
    cfg["deployment"] = {"contract": 2, "capabilities": CATALOGUE[name]["capabilities"]}
    cfg["app"]["required_paths"] = list(
        {
            row["path"]: row
            for row in [
                *CATALOGUE[name]["required_paths"],
                *cfg["app"].get("required_paths", []),
            ]
        }.values()
    )
    require(
        cfg["app"]["vmid"] == cfg["guest"]["vmid"]
        and cfg["app"]["hostname"] == cfg["guest"]["hostname"]
        and cfg["app"]["memory_mib"] == cfg["guest"]["memory_mib"],
        "Keep the selected guest identity consistent",
    )
    nics = cfg["guest"]["interfaces"]
    require(
        any(
            n["mac"] == cfg["app"]["mac"]
            and n["ipv4"].split("/")[0] == cfg["app"]["address"]
            for n in nics
        ),
        "Bind application SSH to an assigned interface",
    )
    require(
        set(cfg["app"]["service_health_checks"]) == set(CATALOGUE[name]["applications"])
        and all(cfg["app"]["service_health_checks"].values()),
        "Every application needs a bounded health check",
    )
    files = {k: substitute(v, values) for k, v in profile["files"].items()}
    require(
        all(
            re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", k) and isinstance(v, str)
            for k, v in files.items()
        ),
        "Use bounded text input files",
    )
    stack = substitute(
        (
            merge(profile["stack"], overrides.get("stack", {}))
            if profile["stack"] is not None
            else None
        ),
        values,
    )
    if stack is not None:
        images = merge(read(root / "images.json"), overlay["images"])
        for row in guest_contract.runtime_images(stack).values():
            row.update(image(images[row.pop("image_ref")]))
    return cfg, stack, files


def _compile_guest(name, cfg, stack, files, enabled):
    if stack is not None:
        files["stack.json"] = encoded(stack).decode()
    # The identity hashes the abstract input slot before binding absolute paths.
    identity = hashlib.sha256(encoded({"config": cfg, "files": files})).hexdigest()
    destination = "/var/lib/homelab-inputs/ordinary/" + name + "/" + identity
    cfg = substitute(cfg, {"inputs": destination})
    files = {k: v.replace("${inputs}", destination) for k, v in files.items()}
    guest_contract.validate(
        cfg, json.loads(files["stack.json"]) if "stack.json" in files else None
    )
    files["site.json"] = encoded(cfg).decode()
    return cfg, {
        "schema": guest_contract.SCHEMA,
        "kind": name,
        "enabled": name in enabled,
        "identity": identity,
        "files": files,
    }


def compile_stack(root, overlay, disabled=None, *, admit=False):
    """Resolve the composition once; reject identity collisions before admission."""
    spec = manifest(root)
    enabled = selection(spec, disabled)
    require(
        set(overlay)
        == {"schema", "values", "common", "guests", "images", "accepted", "routes"}
        and overlay["schema"] == "homelab-site-v3"
        and set(overlay["guests"]) <= set(CATALOGUE),
        "Use a thin private overlay",
    )
    require(
        isinstance(overlay["accepted"], dict)
        and set(overlay["accepted"]) <= set(CATALOGUE),
        "Record explicit prerequisite acceptance",
    )
    resolved = {name: _resolve_guest(root, overlay, name, spec) for name in CATALOGUE}
    route_records = routes.bind(
        resolved,
        substitute(
            merge(spec["routes"], overlay["routes"]),
            merge(spec["values"], overlay["values"]),
        ),
    )
    service_bindings.bind(resolved, route_records)
    compiled = {
        name: _compile_guest(name, *value, enabled) for name, value in resolved.items()
    }
    vmids = [cfg["guest"]["vmid"] for cfg, _ in compiled.values()]
    require(
        len(vmids) == len(set(vmids)), "Each guest needs a unique composition identity"
    )
    connections.validate(
        {name: cfg for name, (cfg, _) in compiled.items()},
        external_routes=(
            resolved["ingress"][1].get("routing", {}).get("routes", {})
            if "ingress" in resolved
            else {}
        ),
    )
    if admit:
        require(enabled, "Keep disabled guests outside deployment admission")
        for name in enabled:
            cfg, packet = compiled[name]
            missing = set(spec["guests"][name]["prerequisites"]) - set(
                overlay["accepted"].get(name, [])
            )
            require(
                not missing,
                name
                + ": missing prerequisite acceptance: "
                + ", ".join(sorted(missing)),
            )
            require(
                cfg["ssh_public_keys"]
                and all(
                    "AAAAAAAAAAAAAAAA" not in key for key in cfg["ssh_public_keys"]
                ),
                "Supply the approved SSH public key",
            )
            require(
                not any("0" * 64 in raw for raw in packet["files"].values()),
                "Replace private image and runtime identity placeholders",
            )
            require(
                "docker" not in CATALOGUE[name]["capabilities"]
                or cfg["app"]["exclusive_writer_confirmed"] is True,
                "Confirm the exclusive writer separately",
            )
    return {name: packet for name, (_, packet) in compiled.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stack", type=Path, required=True)
    parser.add_argument("--site", type=Path, required=True)
    parser.add_argument("--guest", choices=CATALOGUE)
    parser.add_argument(
        "--disabled",
        default="[]",
        help="JSON guest names to exclude; default [] runs all",
    )
    parser.add_argument("--admit", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    overlay = read(args.site)
    disabled = parse_disabled(args.disabled)
    if args.check:
        compile_stack(args.stack, overlay, disabled)
        print("All guest profiles compile offline; no credentials or targets accessed.")
    else:
        require(args.guest and args.output, "Supply a guest and new packet output")
        packets = compile_stack(args.stack, overlay, disabled, admit=args.admit)
        if args.admit:
            require(
                packets[args.guest]["enabled"],
                "Keep disabled guests outside deployment admission",
            )
        with args.output.open("x") as stream:
            stream.write(encoded(packets[args.guest]).decode())


if __name__ == "__main__":
    main()
