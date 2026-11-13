#!/usr/bin/env python3
"""Root-owned, forced-command SSH capability for one declared LXC device."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys

SCHEMA = "homelab-host-device-v1"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def implementation_digest():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate request field")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=unique)


def device_spec(path):
    require(
        isinstance(path, str)
        and re.fullmatch(r"/dev/serial/by-id/[A-Za-z0-9_.:+-]{1,240}", path),
        "Declare one persistent serial device",
    )
    return {"path": path, "uid": 0, "gid": 20, "mode": "0660", "deny_write": False}


def validate(policy):
    require(
        isinstance(policy, dict)
        and set(policy) == {"schema", "node", "vmid", "hostname", "mac", "device"}
        and policy["schema"] == SCHEMA,
        "Use the closed host-device policy",
    )
    require(
        type(policy["vmid"]) is int
        and policy["vmid"] >= 100
        and policy["vmid"] not in {900, 4914, 4915, 4920},
        "Preserve protected guests",
    )
    require(
        all(
            isinstance(policy[k], str)
            and re.fullmatch(r"[a-z][a-z0-9-]{0,62}", policy[k])
            for k in ("node", "hostname")
        ),
        "Use literal node and guest identities",
    )
    require(
        isinstance(policy["mac"], str)
        and re.fullmatch(r"02(?::[0-9a-f]{2}){5}", policy["mac"]),
        "Select the guest MAC",
    )
    require(
        isinstance(policy["device"], dict)
        and type(policy["device"].get("uid")) is int
        and type(policy["device"].get("gid")) is int
        and type(policy["device"].get("deny_write")) is bool
        and policy["device"] == device_spec(policy["device"].get("path")),
        "Keep the fixed device access settings",
    )
    return policy


def read_policy(path):
    require(os.getuid() == 0, "Run only as the host capability account")
    parent = path.parent.lstat()
    require(
        stat.S_ISDIR(parent.st_mode)
        and parent.st_uid == 0
        and stat.S_IMODE(parent.st_mode) == 0o700,
        "Use the root-owned policy directory",
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_size <= 16384,
            "Use one bounded root-owned private policy",
        )
        raw = stream.read(16385)
    require(len(raw) <= 16384, "Policy grew beyond its bound")
    return validate(decode(raw))


def command(argv):
    return subprocess.check_output(argv, text=True, timeout=30)


def config(policy, execute):
    value = decode(
        execute(
            [
                "/usr/bin/pvesh",
                "get",
                "/nodes/" + policy["node"] + "/lxc/" + str(policy["vmid"]) + "/config",
                "--output-format",
                "json",
                "--current",
                "1",
            ]
        )
    )
    require(
        value.get("hostname") == policy["hostname"]
        and value.get("unprivileged") == 1
        and value.get("protection") == 1,
        "Guest identity or protection differs",
    )
    networks = [
        dict(part.split("=", 1) for part in row.split(",") if "=" in part)
        for key, row in value.items()
        if re.fullmatch(r"net[0-9]+", key)
    ]
    require(
        sum(row.get("hwaddr", "").lower() == policy["mac"] for row in networks) == 1,
        "Guest MAC differs",
    )
    return value


def attached(value, device):
    keys = [key for key in value if re.fullmatch(r"dev[0-9]+", key)]
    require(not keys or keys == ["dev0"], "Preserve other device attachments")
    if not keys:
        return False
    fields = value["dev0"].split(",")
    parts = dict(
        part.split("=", 1) if "=" in part else ("path", part) for part in fields
    )
    expected = {
        "path": device["path"],
        "uid": "0",
        "gid": "20",
        "mode": "0660",
        "deny-write": "0",
    }
    require(len(fields) == len(parts), "Device fields must be unique")
    parts.setdefault("deny-write", "0")
    require(parts == expected, "Never replace or modify an existing device attachment")
    return True


def perform(policy, action, request, execute=command):
    validate(policy)
    require(
        action in {"check", "attach"} and request == policy,
        "Request differs from the registered capability",
    )
    require(
        socket.gethostname() == policy["node"], "Capability belongs to another host"
    )
    device = policy["device"]
    require(
        stat.S_ISCHR(os.stat(device["path"]).st_mode),
        "Coordinator must resolve to a character device",
    )
    result = {
        "schema": SCHEMA,
        "vmid": policy["vmid"],
        "policy_sha256": hashlib.sha256(encoded(policy)).hexdigest(),
        "helper_sha256": implementation_digest(),
        "changed": False,
    }
    if action == "check":
        return result
    current = config(policy, execute)
    pending = decode(
        execute(
            [
                "/usr/bin/pvesh",
                "get",
                "/nodes/" + policy["node"] + "/lxc/" + str(policy["vmid"]) + "/pending",
                "--output-format",
                "json",
            ]
        )
    )
    require(
        isinstance(pending, list)
        and all(
            isinstance(row, dict)
            and isinstance(row.get("key"), str)
            and not (
                re.fullmatch(r"dev[0-9]+", row["key"])
                and ("pending" in row or row.get("delete", 0))
            )
            for row in pending
        ),
        "Preserve pending device changes",
    )
    if not attached(current, device):
        require(
            re.fullmatch(r"[0-9a-f]{40}", current.get("digest", "")),
            "Require the current configuration digest",
        )
        argument = device["path"] + ",uid=0,gid=20,mode=0660,deny-write=0"
        execute(
            [
                "/usr/sbin/pct",
                "set",
                str(policy["vmid"]),
                "--dev0",
                argument,
                "--digest",
                current["digest"],
            ]
        )
        require(
            attached(config(policy, execute), device),
            "Device attachment did not verify",
        )
        result["changed"] = True
    execute(
        [
            "/usr/sbin/pct",
            "exec",
            str(policy["vmid"]),
            "--",
            "/usr/bin/test",
            "-c",
            device["path"],
        ]
    )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    args = parser.parse_args()
    try:
        policy = read_policy(args.policy)
        raw = sys.stdin.buffer.read(16385)
        require(len(raw) <= 16384, "Request exceeds the bound")
        result = perform(
            policy, os.environ.get("SSH_ORIGINAL_COMMAND", ""), decode(raw)
        )
        print(json.dumps(result, sort_keys=True))
    except Exception:
        raise SystemExit(
            "Host device capability refused; preserve the original configuration and inspect its policy."
        ) from None


if __name__ == "__main__":
    main()
