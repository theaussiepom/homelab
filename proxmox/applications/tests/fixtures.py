"""Synthetic current guest definitions shared by deployment boundary tests."""

from pathlib import Path


def guest(root):
    root = Path(root)
    return {
        "deployment": {"contract": 2, "capabilities": ["linux"]},
        "guest": {
            "vmid": 808,
            "hostname": "fixture",
            "memory_mib": 1024,
            "interfaces": [
                {
                    "ipv4": "198.18.25.8/24",
                    "mac": "02:00:00:00:00:08",
                    "bridge": "vmbr0",
                    "vlan": 25,
                }
            ],
        },
        "site": {"node": "fixture-pve", "api_endpoint": "https://198.18.25.10:8006/"},
        "ssh_public_keys": ["ssh-ed25519 fixture-public-key"],
        "paths": {
            "state_root": str(root / "state"),
            "backup_mount": str(root / "nas"),
            "backup_directory": str(root / "nas" / "backups"),
            "backup_source": "nas.example.invalid:/backups",
            "api_token": str(root / "api"),
            "ca_file": str(root / "ca"),
            "private_key": str(root / "key"),
            "known_hosts": str(root / "hosts"),
        },
        "app": {
            "kind": "mariadb",
            "vmid": 808,
            "hostname": "fixture",
            "memory_mib": 1024,
            "address": "198.18.25.8",
            "mac": "02:00:00:00:00:08",
            "packages": ["mariadb-server=1:11.8.6-0+deb13u1"],
            "database": {
                "account_mode": "fixed",
                "user": "mysql",
                "group": "mysql",
                "uid": 1000,
                "gid": 1000,
            },
            "health_checks": [{"name": "database", "argv": ["true"], "expect": ""}],
            "service_health_checks": {
                "mariadb": [{"name": "database", "argv": ["true"], "expect": ""}]
            },
            "required_paths": [],
        },
    }


def github_source(root):
    """A private-source history for real local ancestry checks, without publication."""
    import subprocess

    source = Path(root) / "caller-source"
    source.mkdir()
    subprocess.run(
        ["git", "init", "-q", "--initial-branch=main", str(source)], check=True
    )
    command = [
        "git",
        "-C",
        str(source),
        "-c",
        "commit.gpgsign=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "user.name=fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-q",
        "--allow-empty",
    ]
    revisions = []
    for message in ("first reviewed merge", "next reviewed merge"):
        subprocess.run([*command, "-m", message], check=True)
        revisions.append(
            subprocess.check_output(
                ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
            ).strip()
        )
    return source, revisions
