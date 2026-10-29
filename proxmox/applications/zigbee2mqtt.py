#!/usr/bin/env python3
"""Validate the preserved Zigbee configuration without opening its coordinator."""

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import urllib.request
from urllib.parse import urlsplit


def validate(settings):
    if not isinstance(settings, dict) or set(settings) != {
        "serial_device",
        "bind_address",
        "frontend_port",
        "adapter",
        "mqtt_server",
        "mqtt_base_topic",
    }:
        raise ValueError("Use the current Zigbee endpoint and coordinator contract")
    if (
        not all(
            isinstance(settings[key], str)
            for key in (
                "serial_device",
                "adapter",
                "bind_address",
                "mqtt_server",
                "mqtt_base_topic",
            )
        )
        or not re.fullmatch(
            r"/dev/serial/by-id/usb-[A-Za-z0-9_-]+", settings["serial_device"]
        )
        or not re.fullmatch(r"[a-z][a-z0-9_-]*", settings["adapter"])
        or type(settings["frontend_port"]) is not int
        or not 1 <= settings["frontend_port"] <= 65535
    ):
        raise ValueError("Select one stable coordinator, adapter and frontend port")
    address = ipaddress.IPv4Address(settings["bind_address"])
    endpoint = urlsplit(settings["mqtt_server"])
    if (
        address.is_unspecified
        or address.is_loopback
        or address.is_multicast
        or address.is_link_local
        or endpoint.scheme != "mqtt"
        or not endpoint.hostname
        or endpoint.username
        or endpoint.password
        or endpoint.port != 1883
        or endpoint.path
        or endpoint.query
        or endpoint.fragment
        or not re.fullmatch(
            r"[a-zA-Z0-9][a-zA-Z0-9/_-]{0,127}", settings["mqtt_base_topic"]
        )
    ):
        raise ValueError("Use the preserved MQTT URL, topic and backend listener")
    return settings


def validate_deployment(cfg, stack):
    import network_endpoints

    selected = validate(stack["zigbee"])
    if (
        cfg["guest"].get("serial_device") != {"path": selected["serial_device"]}
        or selected["bind_address"]
        not in network_endpoints.addresses(cfg["guest"])
        or set(stack["services"]) != {"zigbee2mqtt"}
    ):
        raise ValueError("Bind the declared coordinator and listener to this guest")


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 1024 * 1024:
            raise ValueError("Read bounded regular Zigbee configuration files")
        value = stream.read(1024 * 1024 + 1)
    if len(value) > 1024 * 1024:
        raise ValueError("Zigbee configuration grew beyond its bound")
    return value


def byte_array(value, length):
    return (
        isinstance(value, list)
        and len(value) == length
        and all(type(n) is int and 0 <= n <= 255 for n in value)
    )


def configuration(root, settings):
    """Check persistent identity; mutable device databases and counters stay untouched."""
    import yaml

    validate(settings)
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Use the separately prepared Zigbee data directory")
    for name in ("database.db", "coordinator_backup.json"):
        info = (root / name).lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size == 0:
            raise ValueError(
                "Preserve the existing Zigbee database and coordinator backup"
            )
    try:
        value = yaml.safe_load(read(root / "configuration.yaml"))
        if (
            value["serial"]["port"] != "/dev/ttyACM0"
            or value["serial"]["adapter"] != settings["adapter"]
            or value["mqtt"]["server"] != settings["mqtt_server"]
            or value["mqtt"]["base_topic"] != settings["mqtt_base_topic"]
            or value["frontend"]["enabled"] is not True
            or value["frontend"]["port"] != settings["frontend_port"]
        ):
            raise ValueError
        identity = value["advanced"]
        key = identity["network_key"]
        if isinstance(key, str):
            match = re.fullmatch(
                r"!([A-Za-z0-9_][A-Za-z0-9_.-]*\.ya?ml) ([A-Za-z0-9_]+)", key
            )
            if match is None:
                raise ValueError
            key = yaml.safe_load(read(root / match[1]))[match[2]]
        if (
            not byte_array(key, 16)
            or not byte_array(identity["ext_pan_id"], 8)
            or type(identity["pan_id"]) is not int
            or not 1 <= identity["pan_id"] <= 65534
        ):
            raise ValueError
    except (yaml.YAMLError, KeyError, TypeError, ValueError):
        raise ValueError(
            "Preserve the existing Zigbee network and prepare its configuration separately"
        ) from None
    return hashlib.sha256(
        json.dumps(
            {
                "key": key,
                "pan": identity["pan_id"],
                "extended": identity["ext_pan_id"],
                "channel": identity.get("channel", 11),
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()


def check(root, settings, receipt, healthy=False):
    identity = {
        "network_sha256": configuration(root, settings),
        "coordinator": settings["serial_device"],
    }
    if not stat.S_ISCHR(os.stat(settings["serial_device"]).st_mode):
        raise ValueError("The declared coordinator must be a character device")
    receipt = Path(receipt)
    if receipt.exists() or receipt.is_symlink():
        info = receipt.lstat()
        if (
            info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or json.loads(read(receipt)) != identity
        ):
            raise ValueError(
                "Preserve the recorded Zigbee network and coordinator identity"
            )
    else:
        if healthy:
            raise ValueError(
                "Deployment must record the prepared network before starting it"
            )
        fd = os.open(
            receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(fd, "wb") as stream:
            stream.write((json.dumps(identity, sort_keys=True) + "\n").encode())
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(
            receipt.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    if healthy:
        with urllib.request.urlopen(
            f"http://{settings['bind_address']}:{settings['frontend_port']}/", timeout=5
        ) as response:
            if response.status != 200:
                raise ValueError("Zigbee frontend is not healthy")
    return {"healthy": True, "radio_opened": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("validate", "health"))
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument(
        "--identity", type=Path, default=Path("/opt/homelab-app/zigbee-network.json")
    )
    parser.add_argument(
        "--data", type=Path, default=Path("/srv/homelab/data/zigbee2mqtt")
    )
    args = parser.parse_args()
    try:
        print(
            json.dumps(
                check(
                    args.data,
                    json.loads(read(args.settings)),
                    args.identity,
                    args.mode == "health",
                )
            )
        )
    except (OSError, ValueError):
        raise SystemExit(
            "Zigbee verification failed; preserve configuration, coordinator and deployment evidence"
        ) from None


if __name__ == "__main__":
    main()
