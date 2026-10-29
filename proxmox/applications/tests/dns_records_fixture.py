#!/usr/bin/env python3
"""Verify owned DNS record reconciliation in an isolated pinned Pi-hole instance."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import dns_records
import render

# This fixture image is independent of any site's live image selection.
IMAGE = "pihole/pihole@sha256:70a9c11171ded2eee735d88c127996da209284a329d50f5ae59c06b861d401b3"


def run(output, tools_image):
    output.mkdir(mode=0o700)
    project = "homelab-dns-" + uuid.uuid4().hex[:12]
    compose = output / "compose.json"
    config = {
        "kind": "dns",
        "guest_memory_mib": 1024,
        "dns_records": {"broker.mqtt": "198.18.40.21"},
        "services": {
            name: {"image": IMAGE, "memory_mib": 256, "cpus": 1, "pids_limit": 128}
            for name in ("pihole", "unbound")
        },
    }
    document = render.compose(config)
    document["name"] = project
    document["volumes"] = {"pihole-data": {}}
    pihole = document["services"]["pihole"]
    pihole.update(
        network_mode="none",
        volumes=["pihole-data:/etc/pihole"],
        tmpfs=["/var/log/pihole:rw,size=64m"],
        entrypoint=[
            "/bin/sh",
            "-c",
            'if [ ! -f /etc/pihole/gravity.db ]; then pihole-FTL sqlite3 /etc/pihole/gravity.db < /etc/.pihole/advanced/Templates/gravity.db.sql; fi; if [ ! -f /etc/pihole/pihole.toml ]; then pihole-FTL --config dns.hosts \'["198.18.40.240 BROKER.MQTT. retained.alias","198.18.40.99 retained.example"]\'; fi; exec /usr/bin/start.sh',
        ],
    )
    pihole["environment"]["FTLCONF_webserver_api_password"] = ""
    compose.write_text(json.dumps(document))
    command = ["docker", "compose", "-f", str(compose)]

    def execute(argv):
        return subprocess.run(argv, capture_output=True, text=True, timeout=45)

    def ready():
        for _ in range(30):
            probe = execute(
                [
                    *command,
                    "exec",
                    "-T",
                    "pihole",
                    "dig",
                    "+time=1",
                    "+tries=1",
                    "+short",
                    "@127.0.0.1",
                    "broker.mqtt",
                    "A",
                ]
            )
            if probe.returncode == 0 and probe.stdout.strip():
                return probe.stdout.splitlines()
            time.sleep(1)
        raise ValueError("Isolated Pi-hole did not become ready")

    try:
        started = execute([*command, "up", "-d", "--no-deps", "pihole"])
        if started.returncode:
            raise ValueError(started.stderr)
        before = ready()
        if before != ["198.18.40.240"]:
            raise ValueError("Fixture must begin with the superseded MQTT address")
        changed = dns_records.reconcile(config["dns_records"], compose)
        if not changed:
            raise ValueError("The changed broker record must be reconciled")
        restarted = execute([*command, "restart", "--no-deps", "pihole"])
        if restarted.returncode:
            raise ValueError(restarted.stderr)
        after = ready()
        if after != ["198.18.40.21"] or dns_records.reconcile(
            config["dns_records"], compose
        ):
            raise ValueError("Exact DNS replacement and unchanged repeat must succeed")
        container = execute([*command, "ps", "-q", "pihole"]).stdout.strip()
        source = Path(__file__).resolve().parents[3]
        for name, address in (
            ("broker.mqtt", "198.18.40.21"),
            ("retained.alias", "198.18.40.240"),
            ("retained.example", "198.18.40.99"),
        ):
            result = execute(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--platform",
                    "linux/amd64",
                    "--network",
                    "container:" + container,
                    "--read-only",
                    "--tmpfs",
                    "/tmp:rw,nosuid,nodev,size=64m",
                    "-v",
                    str(source) + ":/src:ro",
                    "-e",
                    "PYTHONDONTWRITEBYTECODE=1",
                    tools_image,
                    "python3",
                    "/src/proxmox/applications/dns_records.py",
                    "probe",
                    name,
                    address,
                ]
            )
            if result.returncode or json.loads(result.stdout) != {
                "read_only_dns_check": "passed"
            }:
                raise ValueError("Native DNS answers or retained aliases differ")
        result = {
            "passed": True,
            "changed": changed,
            "repeat_changed": False,
            "unrelated_records_preserved": True,
            "network": "none",
            "image": IMAGE,
        }
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result))
    finally:
        logs = execute([*command, "logs", "--no-color"])
        (output / "container.log").write_text(logs.stdout + logs.stderr)
        cleaned = execute([*command, "down", "--volumes", "--remove-orphans"])
        if cleaned.returncode:
            raise ValueError("Owned fixture cleanup was not confirmed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tools-image", default="homelab-app-test")
    args = parser.parse_args()
    run(args.output.resolve(), args.tools_image)
