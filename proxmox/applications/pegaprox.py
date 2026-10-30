#!/usr/bin/env python3
"""Render a PegaProx Compose preview; no target, credential reads or deployment."""
import re
import ipaddress
from pathlib import Path

from resources import positive
from container_policy import restart_policy
from discovery import PRIVATE_BACKENDS

KEY_SOURCE = "/opt/homelab-app/runtime/pegaprox-db-key"
FIELDS = {
    "kind",
    "image",
    "bind_address",
    "trusted_proxy",
    "guest_memory_mib",
    "container_memory_mib",
    "cpus",
    "pids_limit",
}


def compose(cfg):
    """Render a stack; only the independent CD selection admits deployment."""
    if set(cfg) - {"restart"} != FIELDS or cfg.get("kind") != "pegaprox":
        raise ValueError("Use the closed PegaProx runtime stack fields")
    if not re.fullmatch(
        r"ghcr\.io/pegaprox/pegaprox(?::[A-Za-z0-9_.-]+)?@sha256:[0-9a-f]{64}",
        cfg["image"],
    ):
        raise ValueError("Use an immutable official PegaProx image selection")
    address = ipaddress.IPv4Address(cfg["bind_address"])
    if (
        address.is_unspecified
        or address.is_loopback
        or address.is_multicast
        or address.is_link_local
        or address.is_reserved
        or not (address.is_private or address in ipaddress.IPv4Network("198.18.0.0/15"))
    ):
        raise ValueError(
            "Select a management IPv4 address, never a wildcard or public listener"
        )
    if not isinstance(cfg["trusted_proxy"], str):
        raise ValueError("Select one canonical private ingress IPv4 /32")
    proxy = ipaddress.IPv4Network(cfg["trusted_proxy"], strict=True)
    if (
        str(proxy) != cfg["trusted_proxy"]
        or proxy.prefixlen != 32
        or proxy.network_address == address
        or not any(proxy.subnet_of(network) for network in PRIVATE_BACKENDS)
    ):
        raise ValueError(
            "Select one canonical private ingress IPv4 /32 distinct from PegaProx"
        )
    memory = positive(cfg["container_memory_mib"], "container_memory_mib", 1024)
    budget = positive(cfg["guest_memory_mib"], "guest_memory_mib", 2048)
    if memory + 512 > budget:
        raise ValueError(
            "Reserve at least 512 MiB for Debian and Docker outside the container"
        )
    cpus = positive(cfg["cpus"], "cpus")
    pids = positive(cfg["pids_limit"], "pids_limit")
    if (
        cpus > 2
        or pids > 512
        or type(pids) is not int
        or type(memory) is not int
        or type(budget) is not int
    ):
        raise ValueError("Review a larger resource allocation separately")
    root = "/srv/homelab/data/pegaprox"
    mounts = [
        {
            "type": "bind",
            "source": f"{root}/{name}",
            "target": f"/app/{name}",
            "bind": {"create_host_path": False},
        }
        for name in ("config", "logs")
    ]
    mounts.append(
        {
            "type": "bind",
            "source": KEY_SOURCE,
            "target": "/run/secrets/pegaprox-db-key",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    )
    return {
        "name": "homelab-pegaprox",
        "services": {
            "pegaprox": {
                "image": cfg["image"],
                "platform": "linux/amd64",
                "pull_policy": "missing",
                "restart": restart_policy(cfg),
                "read_only": True,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "tmpfs": ["/tmp:rw,nosuid,nodev,size=64m"],
                "mem_limit": f"{memory}m",
                "cpus": cpus,
                "pids_limit": pids,
                "stop_grace_period": "60s",
                "logging": {
                    "driver": "json-file",
                    "options": {"max-size": "10m", "max-file": "3"},
                },
                "ports": [f"{address}:5000:5000/tcp"],
                "volumes": mounts,
                "environment": {
                    "PEGAPROX_BEHIND_PROXY": "true",
                    "PEGAPROX_HOST": "0.0.0.0",
                    "PEGAPROX_TRUSTED_PROXIES": cfg["trusted_proxy"],
                    "PEGAPROX_KEY_FILE": "/run/secrets/pegaprox-db-key",
                    "PEGAPROX_SUPERVISED": "1",
                    "PEGAPROX_SSH_STRICT_HOST_KEYS": "1",
                    "PEGAPROX_PW_HASH_CONCURRENCY": "2",
                    "TZ": "Etc/UTC",
                },
            }
        },
    }


def health_checks():
    return [
        {
            "name": "PegaProx health and closed initial setup",
            "argv": ["python3", "/opt/homelab-app/pegaprox-health.py"],
            "expect": "PegaProx verification passed",
        }
    ]


def validate_deployment(cfg, stack):
    """Validate the current listener, retained key and bounded runtime probe."""
    import re

    app = cfg.get("app", {})
    if "capture" in app or cfg["guest"].get("volumes"):
        raise ValueError("PegaProx deployment has no capture or shared volumes")
    selected = app.get("pegaprox", {})
    if (
        set(selected) != {"key_source"}
        or not Path(selected["key_source"]).is_absolute()
    ):
        raise ValueError("Select the retained database-key file")
    compose(stack)
    guest = cfg["guest"]
    nics = guest["interfaces"]
    if (
        len(nics) != 1
        or not re.fullmatch(r"02(?::[0-9a-fA-F]{2}){5}", str(nics[0].get("mac")))
        or nics[0].get("ipv6") != "manual"
        or guest.get("keyctl") is not False
        or guest.get("nesting") is not True
    ):
        raise ValueError(
            "Select one admitted management NIC, MAC and unprivileged Docker compatibility settings"
        )
    client_rules = []
    for rule in guest["rules"]:
        if rule.get("direction") != "in":
            continue
        if rule.get("proto") != "tcp" or rule.get("port") not in {"22", "5000"}:
            raise ValueError(
                "Initial PegaProx ingress admits only runner SSH and the management HTTP listener"
            )
        source = ipaddress.IPv4Network(rule.get("source", ""), strict=True)
        if rule["port"] == "22" and source.prefixlen != 32:
            raise ValueError("Name the individual deployment SSH client")
        if rule["port"] == "5000" and (
            source.prefixlen < 24
            or not (
                source.is_private
                or source.subnet_of(ipaddress.IPv4Network("198.18.0.0/15"))
            )
        ):
            raise ValueError(
                "Use an explicit private management client subnet between /24 and /32"
            )
        if rule["port"] == "5000":
            if rule.get("destination") != stack["bind_address"] + "/32":
                raise ValueError("Bind client allowances to this management listener")
            client_rules.append(rule)
    if not 1 <= len(client_rules) <= 8:
        raise ValueError(
            "Select the finite management client allowance before deployment"
        )
    proxy = ipaddress.IPv4Network(stack["trusted_proxy"])
    if not any(
        proxy.subnet_of(ipaddress.IPv4Network(rule["source"])) for rule in client_rules
    ):
        raise ValueError(
            "The trusted ingress proxy must have an admitted management client allowance"
        )
    if (
        stack["guest_memory_mib"] != app["memory_mib"]
        or stack["bind_address"] != app["address"]
        or app.get("health_checks") != health_checks()
    ):
        raise ValueError(
            "PegaProx listener, budget and fixed verification must match the guest"
        )
