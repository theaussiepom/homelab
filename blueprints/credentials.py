"""Bind existing GitHub Secrets to the selected private runner paths.

No key generation or rotation. Files that already exist must match exactly.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "proxmox/applications"))
import private_io as files
from guest_contract import SCHEMA


def bind(packet, environment=os.environ):
    files.require(
        environment.get("GITHUB_REF") == "refs/heads/main"
        and environment.get("GITHUB_EVENT_NAME") == "push",
        "Only reviewed main pushes bind deployment Secrets",
    )
    value = json.loads(files.regular(packet))
    files.require(
        value["enabled"] is True and value["schema"] == SCHEMA,
        "A disabled guest cannot bind deployment credentials",
    )
    cfg = json.loads(value["files"]["site.json"])
    token = environment.get("PROXMOX_APP_TOKEN", "").strip()
    key = environment.get("APPLICATION_SSH_KEY", "").rstrip("\n")
    files.require(
        re.fullmatch(r"[A-Za-z0-9@!._-]+=[A-Za-z0-9-]+", token) and len(token) <= 512,
        "Supply the existing PVE application token",
    )
    files.require(
        key.startswith("-----BEGIN OPENSSH PRIVATE KEY-----\n")
        and key.endswith("\n-----END OPENSSH PRIVATE KEY-----")
        and "\r" not in key
        and len(key) <= 8192,
        "Supply the existing application SSH key",
    )
    public_keys = cfg["ssh_public_keys"]
    files.require(
        isinstance(public_keys, list)
        and public_keys
        and all(
            isinstance(public, str)
            and re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+", public)
            for public in public_keys
        ),
        "Supply the approved deployment public keys",
    )
    with tempfile.TemporaryDirectory(
        prefix="homelab-key-check-", dir=packet.parent
    ) as directory:
        temporary = Path(directory) / "key"
        files.write_new(temporary, (key + "\n").encode())
        result = subprocess.run(
            ["ssh-keygen", "-y", "-P", "", "-f", str(temporary)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        files.require(
            result.returncode == 0
            and " ".join(result.stdout.split()[:2]) in public_keys,
            "The retained private key must match an approved guest public key",
        )
    selected = [
        (Path(cfg["paths"]["api_token"]), token),
        (Path(cfg["paths"]["private_key"]), key),
    ]
    files.require(
        len({path for path, _ in selected}) == len(selected),
        "Use distinct credential paths",
    )
    missing = []
    for path, expected in selected:
        files.private_directory(path.parent)
        if path.exists() or path.is_symlink():
            files.require(
                files.regular(path, private=True).decode().rstrip("\n") == expected,
                "Existing credential differs; never rotate implicitly",
            )
        else:
            missing.append((path, expected))
    for path, expected in missing:
        files.write_new(path, (expected + "\n").encode())
    return {"credentials_bound": True, "files_created": len(missing)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(bind(args.packet)))
    except Exception:
        raise SystemExit(
            "Credential binding held; review existing Secrets and private paths."
        ) from None
