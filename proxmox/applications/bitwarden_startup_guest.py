"""Update only an already-running Bitwarden container's restart policy."""

import argparse
import copy
import hashlib
import json
import re
import subprocess
import sys


def require(value):
    if not value:
        raise ValueError("Bitwarden container identity or startup contract differs")


def fingerprint(value):
    retained = {
        k: copy.deepcopy(value[k])
        for k in ("Id", "Name", "Image", "Config", "HostConfig", "Mounts")
    }
    retained["HostConfig"].pop("RestartPolicy", None)
    return hashlib.sha256(
        json.dumps(retained, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def docker(argv):
    result = subprocess.run(
        argv, capture_output=True, text=True, check=True, timeout=30
    )
    require(len(result.stdout.encode()) <= 1024 * 1024)
    return result.stdout


def observe(container_id, command=docker):
    require(
        isinstance(container_id, str) and re.fullmatch("[0-9a-f]{64}", container_id)
    )
    rows = json.loads(command(["docker", "inspect", container_id]))
    require(isinstance(rows, list) and len(rows) == 1)
    value = rows[0]
    require(
        value["Id"] == container_id
        and value["Config"].get("Labels", {}).get("com.docker.compose.service")
        == "bitwarden"
    )
    mounts = value["Mounts"]
    require(
        len(mounts) == 2
        and {m["Destination"] for m in mounts}
        == {"/etc/bitwarden", "/var/log/bitwarden"}
        and all(m["Type"] == "bind" and m["RW"] is True for m in mounts)
    )
    policy = value["HostConfig"]["RestartPolicy"]
    require(
        policy.get("MaximumRetryCount", 0) == 0
        and policy["Name"] in ("no", "unless-stopped")
    )
    require(
        value["State"]["Status"] in ("running", "exited")
        and type(value["State"]["Running"]) is bool
    )
    return {
        "id": value["Id"],
        "name": value["Name"].removeprefix("/"),
        "image": value["Image"],
        "fingerprint_sha256": fingerprint(value),
        "restart": policy["Name"],
        "running": value["State"]["Running"],
    }


def admitted(selected, current):
    require(set(selected) == {"id", "name", "image", "fingerprint_sha256"})
    require(all(current[k] == v for k, v in selected.items()))


def reconcile(selected, command=docker):
    before = observe(selected["id"], command)
    admitted(selected, before)
    require(before["running"])
    changed = False
    if before["restart"] != "unless-stopped":
        command(["docker", "update", "--restart", "unless-stopped", selected["id"]])
        changed = True
    after = observe(selected["id"], command)
    admitted(selected, after)
    require(after["restart"] == "unless-stopped" and after["running"])
    return {"status": "passed", "changed": changed, "container": after}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observe", metavar="FULL_CONTAINER_ID")
    args = parser.parse_args()
    try:
        if args.observe:
            result = observe(args.observe)
        else:
            raw = sys.stdin.buffer.read(16385)
            require(0 < len(raw) <= 16384)
            result = reconcile(json.loads(raw))
        print(json.dumps(result))
    except Exception:
        raise SystemExit(
            "Bitwarden startup held; inspect private evidence. No automatic retry."
        ) from None


if __name__ == "__main__":
    main()
