#!/usr/bin/env python3
"""Render one application guest from private inputs; never print its credentials."""
import argparse
from resources import positive
from container_policy import restart_policy
from private_io import private_directory, read_json, regular, write_bytes
import json
import ipaddress
from pathlib import Path
import re
from urllib.parse import urlsplit

import bitwarden
import monitoring
import foundation
import dns_records
import zigbee2mqtt

KINDS = {
    "automation": {"homeassistant", "node_red", "mqtt"},
    "identity": {"server", "worker", "redis"},
    "dns": {"pihole", "unbound"},
    "ingress": {"traefik"},
    "db-tools": {"pgadmin"},
    "bitwarden": {"bitwarden"},
    "zigbee2mqtt": {"zigbee2mqtt"},
}


def literal(value):
    """Compose interpolates dollar signs even in quoted YAML/JSON scalars."""
    if not isinstance(value, (str, int, float, bool)):
        raise ValueError("Environment values must be scalar")
    return str(value).replace("$", "$$")


def required(cfg, key):
    value = cfg.get(key)
    if not isinstance(value, str) or not value or "\n" in value or "\x00" in value:
        raise ValueError(f"Missing or invalid {key}")
    return value


def preserved(value, field):
    """Keep container-shell expansion literal through Compose interpolation."""
    if value is None and field in ("command", "entrypoint"):
        return None
    if isinstance(value, str):
        return literal(value)
    if (
        field in ("command", "entrypoint")
        and isinstance(value, list)
        and all(isinstance(v, str) for v in value)
    ):
        return [literal(v) for v in value]
    raise ValueError(
        f"Use a string, string argv or null for {field}; user requires a string"
    )


def compose(cfg):
    """Keep placement fixed; site-specific images, restored data and routes are inputs."""
    if cfg.get("kind") == "monitoring":
        return monitoring.compose(cfg)
    kind = cfg.get("kind")
    if kind == "pegaprox":
        import pegaprox

        return pegaprox.compose(cfg)
    if kind not in KINDS:
        raise ValueError(
            "Choose dns, identity, ingress, automation, db-tools, bitwarden or zigbee2mqtt; databases are native"
        )
    inputs = cfg.get("services", {})
    if set(inputs) != KINDS[kind]:
        raise ValueError("Supply exactly the services for this guest")
    if kind == "zigbee2mqtt":
        radio = inputs["zigbee2mqtt"]
        if (
            set(radio.get("environment", {})) - {"TZ"}
            or radio.get("extra_mounts")
            or any(key in radio for key in ("command", "entrypoint", "user"))
        ):
            raise ValueError(
                "Preserve Zigbee configuration without environment, command or mount overrides"
            )
    if kind == "identity" and inputs["server"].get("image") != inputs["worker"].get(
        "image"
    ):
        raise ValueError("Authentik server and worker require the same pinned image")
    root = cfg.get("data_root", "/srv/homelab/data")
    if root != "/srv/homelab/data":
        raise ValueError("Restored application data belongs under /srv/homelab/data")
    budget = positive(cfg.get("guest_memory_mib"), "guest_memory_mib")
    total = sum(positive(s.get("memory_mib"), "memory_mib") for s in inputs.values())
    if total + 256 > budget:
        raise ValueError(
            "Leave at least 256 MiB for the guest OS outside container limits"
        )
    foundation.validate(cfg)
    if kind == "bitwarden":
        bitwarden.validate(cfg)
    if kind in {"identity", "ingress", "db-tools"} and "foundation" not in cfg:
        raise ValueError("Use the current file-based foundation contract")
    result = {"name": f"homelab-{kind}", "services": {}}
    for name, value in inputs.items():
        image = value.get("image", "")
        if kind == "bitwarden" and image == "ghcr.io/bitwarden/lite:latest":
            # Explicit service policy: the operator selected latest, without a version pin.
            policy = "always"
        elif re.fullmatch(r"sha256:[0-9a-f]{64}", image):
            if not str(value.get("archive", "")).startswith("/") or not re.fullmatch(
                r"[0-9a-f]{64}", value.get("archive_sha256", "")
            ):
                raise ValueError(
                    "A local image needs its SHA256-verified image archive"
                )
            policy = "never"
        elif re.fullmatch(r"[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}", image):
            policy = "missing"
        else:
            raise ValueError(
                "Pin each image by registry digest or verified local image ID"
            )
        service = {
            "image": image,
            "pull_policy": policy,
            "restart": restart_policy(value),
            "mem_limit": f"{value['memory_mib']}m",
            "cpus": positive(value.get("cpus"), "cpus"),
            "pids_limit": positive(value.get("pids_limit"), "pids_limit"),
            "stop_grace_period": "60s",
            "logging": {
                "driver": "json-file",
                "options": {"max-size": "10m", "max-file": "3"},
            },
            "environment": {
                k: literal(v) for k, v in value.get("environment", {}).items()
            },
            "volumes": [],
            "network_mode": "host",
        }
        service["environment"]["TZ"] = literal(cfg.get("timezone", "Etc/UTC"))
        if "extra_hosts" in value:
            hosts = value["extra_hosts"]
            if (
                kind not in {"automation", "zigbee2mqtt"}
                or not isinstance(hosts, dict)
                or len(hosts) > 32
                or any(
                    not isinstance(host, str)
                    or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,252}", host)
                    for host in hosts
                )
            ):
                raise ValueError("Use a finite service hostname-to-address map")
            for address in hosts.values():
                ip = ipaddress.IPv4Address(address)
                if ip.is_unspecified or ip.is_multicast or ip.is_link_local:
                    raise ValueError(
                        "Service host aliases require usable literal IPv4 addresses"
                    )
            service["extra_hosts"] = dict(hosts)
        # These paths refer to the restored capture, never to the source production host.
        mounts = {
            "homeassistant": [("homeassistant/config", "/config")],
            "node_red": [("node-red/data", "/data"), ("node-red/config", "/config")],
            "mqtt": [
                ("mqtt/config", "/mosquitto/config"),
                ("mqtt/data", "/mosquitto/data"),
                ("mqtt/log", "/mosquitto/log"),
            ],
            "zigbee2mqtt": [("zigbee2mqtt", "/app/data")],
            "server": [
                ("authentik/media", "/media"),
                ("authentik/templates", "/templates"),
            ],
            "worker": [
                ("authentik/media", "/media"),
                ("authentik/templates", "/templates"),
                ("authentik/certs", "/certs"),
            ],
            "redis": [("redis", "/data")],
            "pihole": [("pihole", "/etc/pihole")],
            "unbound": [("unbound", "/opt/unbound/etc/unbound")],
            "traefik": [("traefik", "/etc/traefik")],
            "pgadmin": [("pgadmin", "/var/lib/pgadmin")],
            "bitwarden": [
                ("bitwarden/data", "/etc/bitwarden"),
                ("bitwarden/logs", "/var/log/bitwarden"),
            ],
        }[name]
        service["volumes"] = [f"{root}/{src}:{target}" for src, target in mounts]
        for mount in value.get("extra_mounts", []):
            src, target = mount.get("source", ""), mount.get("target", "")
            if (
                not re.fullmatch(re.escape(root) + r"/[A-Za-z0-9_./-]+", src)
                or ".." in src.split("/")
                or ":" in target
                or not target.startswith("/")
                or ".." in target.split("/")
            ):
                raise ValueError(
                    "Extra mounts must come from the captured /srv/homelab/data tree"
                )
            if target in {
                "/var/run/docker.sock",
                "/run/docker.sock",
                "/run/avahi-daemon/socket",
            } or target in [t for _, t in mounts]:
                raise ValueError(
                    "Do not expose host control sockets or override data mounts"
                )
            service["volumes"].append(
                f"{src}:{target}:{'ro' if mount.get('read_only', True) else 'rw'}"
            )
        if name in {"homeassistant", "node_red", "mqtt"}:
            # Existing custom images and helper entrypoints are preserved, not replaced.
            for key in ("command", "entrypoint", "user"):
                if key in value:
                    service[key] = preserved(value[key], key)
        if kind == "identity" and "user" in value:
            service["user"] = preserved(value["user"], "user")
        capabilities = value.get("cap_add", [])
        if capabilities:
            if name != "homeassistant" or capabilities != ["NET_ADMIN"]:
                raise ValueError(
                    "Only the explicitly selected HA mDNS NET_ADMIN capability is supported"
                )
            service["cap_add"] = capabilities
        if name == "homeassistant" and "HOMELAB_HA_IPV4" in value.get(
            "environment", {}
        ):
            if ipaddress.ip_address(
                value["environment"]["HOMELAB_HA_IPV4"]
            ).version != 4 or capabilities != ["NET_ADMIN"]:
                raise ValueError(
                    "The selected mDNS helper needs an explicit IPv4 address and guest network capability"
                )
            if f"{root}/ha-startup:/startup:ro" not in service["volumes"]:
                raise ValueError(
                    "Mount the captured HA startup directory read-only for the mDNS helper"
                )
        result["services"][name] = service
    services = result["services"]
    if kind == "automation" and "node_red_oidc" in cfg:
        oidc = cfg["node_red_oidc"]
        if (
            not isinstance(oidc, dict)
            or set(oidc)
            != {"identity_url", "node_red_url", "client_id", "provider_slug"}
            or not isinstance(oidc["client_id"], str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", oidc["client_id"])
            or not isinstance(oidc["provider_slug"], str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", oidc["provider_slug"])
        ):
            raise ValueError(
                "Preserve the selected native Node-RED OIDC client and provider"
            )
        for name in ("identity_url", "node_red_url"):
            origin = oidc[name]
            if not isinstance(origin, str) or any(
                char.isspace() or ord(char) < 32 or ord(char) == 127 for char in origin
            ):
                raise ValueError("Node-RED OIDC requires literal HTTPS origins")
            parsed = urlsplit(origin)
            if (
                parsed.scheme != "https"
                or not dns_name(parsed.hostname)
                or parsed.port is not None
                or parsed.username
                or parsed.password
                or parsed.path not in ("", "/")
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("Node-RED OIDC requires literal HTTPS origins")
        node = services["node_red"]
        if (
            node.get("command") != ["--settings", "/runtime-settings.js"]
            or f"{root}/node-red/runtime-settings.js:/runtime-settings.js:ro"
            not in node["volumes"]
        ):
            raise ValueError(
                "Native Node-RED OIDC must use the preserved settings wrapper"
            )
        node["environment"].update(
            {
                "NODE_RED_IDENTITY_URL": oidc["identity_url"].rstrip("/"),
                "NODE_RED_EXTERNAL_URL": oidc["node_red_url"].rstrip("/"),
                "NODE_RED_OIDC_CLIENT_ID": oidc["client_id"],
                "NODE_RED_OIDC_PROVIDER": oidc["provider_slug"],
            }
        )
    if kind == "identity":
        env = foundation.identity_environment(cfg)
        for name in ("server", "worker"):
            del services[name]["network_mode"]
            services[name]["command"] = name
            services[name]["environment"].update(
                {k: literal(v) for k, v in env.items()}
            )
            services[name]["depends_on"] = {"redis": {"condition": "service_healthy"}}
        del services["redis"]["network_mode"]
        services["redis"]["command"] = preserved(
            inputs["redis"].get("command", ["redis-server", "--appendonly", "yes"]),
            "command",
        )
        command = services["redis"]["command"]
        if (
            command == []
            or isinstance(command, str)
            and not command.strip()
            or isinstance(command, list)
            and not command[0].strip()
        ):
            raise ValueError(
                "Redis command must not replace the image startup with an empty command"
            )
        services["redis"]["healthcheck"] = {
            "test": ["CMD-SHELL", "redis-cli ping | grep -qx PONG"],
            "start_period": "20s",
            "interval": "30s",
            "retries": 5,
            "timeout": "3s",
        }
        services["server"]["ports"] = ["9000:9000", "9443:9443"]
    if kind == "dns":
        records = dns_records.validate(cfg.get("dns_records", {}))
        if records and "FTLCONF_dns_hosts" in services["pihole"]["environment"]:
            raise ValueError(
                "Keep managed Pi-hole host records writable by the deployment"
            )
        services["pihole"]["environment"].update(
            {"FTLCONF_dhcp_active": "false", "FTLCONF_dns_upstreams": "127.0.0.1#5335"}
        )
        del services["unbound"]["network_mode"]
        services["unbound"]["ports"] = [
            "127.0.0.1:5335:53/tcp",
            "127.0.0.1:5335:53/udp",
        ]
    if kind == "zigbee2mqtt":
        selected = zigbee2mqtt.validate(cfg["zigbee"])
        service = services["zigbee2mqtt"]
        del service["network_mode"]
        # runc in a user namespace binds the OCI device path from the parent LXC.
        # Keep it present and bind the preserved application alias separately.
        device = selected["serial_device"]
        service["devices"] = [f"{device}:{device}:rw"]
        service["volumes"] = [
            {
                "type": "bind",
                "source": root + "/zigbee2mqtt",
                "target": "/app/data",
                "bind": {"create_host_path": False},
            },
            {
                "type": "bind",
                "source": device,
                "target": "/dev/ttyACM0",
                "read_only": False,
                "bind": {"create_host_path": False},
            },
        ]
        service["ports"] = [
            f"{selected['bind_address']}:{selected['frontend_port']}:{selected['frontend_port']}/tcp"
        ]
        service["healthcheck"] = {
            "test": [
                "CMD",
                "node",
                "-e",
                "const h=require('http');const q=h.get('http://127.0.0.1:"
                + str(selected["frontend_port"])
                + "/',r=>process.exit(r.statusCode===200?0:1));q.setTimeout(3000,()=>{q.destroy();process.exit(1)});q.on('error',()=>process.exit(1))",
            ],
            "start_period": "30s",
            "interval": "5s",
            "retries": 30,
            "timeout": "4s",
        }
    if kind == "ingress":
        services["traefik"]["command"] = ["--configFile=/etc/traefik/traefik.yml"]
    if kind == "db-tools":
        address = ipaddress.IPv4Address(required(cfg, "pgadmin_bind_address"))
        if (
            address.is_unspecified
            or address.is_loopback
            or address.is_multicast
            or address.is_link_local
        ):
            raise ValueError(
                "Publish pgAdmin only on the selected backend IPv4 address"
            )
        del services["pgadmin"]["network_mode"]
        services["pgadmin"]["ports"] = [f"{address}:80:80"]
        # A missing capture must fail, rather than initializing a fresh profile.
        services["pgadmin"]["volumes"] = [
            {
                "type": "bind",
                "source": f"{root}/pgadmin",
                "target": "/var/lib/pgadmin",
                "bind": {"create_host_path": False},
            }
        ]
    if kind == "bitwarden":
        return bitwarden.configure(cfg, result)
    return foundation.configure_compose(cfg, result)


def dns_name(host):
    return (
        isinstance(host, str)
        and len(host) <= 253
        and all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in host.split(".")
        )
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    cfg = read_json(args.config)
    artifacts = {"compose.yml": (json.dumps(compose(cfg), indent=2) + "\n").encode()}
    if cfg["kind"] == "dns":
        artifacts["dns-records.json"] = (
            json.dumps(dns_records.validate(cfg.get("dns_records", {})), sort_keys=True)
            + "\n"
        ).encode()
    if "foundation" in cfg or cfg["kind"] == "monitoring":
        manifest = []
        for artifact in (
            monitoring.files(cfg)
            if cfg["kind"] == "monitoring"
            else foundation.files(cfg)
        ):
            artifacts[artifact["path"]] = artifact["content"].encode()
            manifest.append(
                {key: artifact[key] for key in ("path", "uid", "gid", "mode")}
            )
        artifacts["runtime-files.json"] = (
            json.dumps(manifest, indent=2) + "\n"
        ).encode()
    private_directory(args.output, create=not args.output.exists())
    # Check the whole existing output set before any rewrite. Permission/identity
    # drift is a hold, never an instruction to chmod or adopt an existing file.
    for name in artifacts:
        path = args.output / name
        if path.exists() or path.is_symlink():
            regular(path, private=True)
    for name, raw in artifacts.items():
        write_bytes(args.output / name, raw)


if __name__ == "__main__":
    main()
