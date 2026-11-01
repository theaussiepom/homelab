"""Optional WiNet telemetry beside Zigbee; private options stay outside Compose."""

import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from private_io import read_json, require

RUNTIME = "/opt/homelab-app/runtime/winet-options.json"
FIELDS = {"configuration_file", "inverter_address", "mqtt_server", "mqtt_prefix"}
OPTIONS = {
    "winet_host", "winet_user", "winet_pass", "mqtt_url", "mqtt_prefix",
    "poll_interval", "analytics", "ssl", "site_totals", "additional_winets",
}


def validate(cfg):
    selected = cfg.get("winet")
    if selected is None:
        require("winet" not in cfg.get("services", {}), "Declare WiNet settings with its service")
        return None
    require(cfg.get("kind") == "zigbee2mqtt" and isinstance(selected, dict)
            and set(selected) == FIELDS and "winet" in cfg.get("services", {}),
            "WiNet belongs beside Zigbee with its closed options contract")
    path = selected["configuration_file"]
    require(isinstance(path, str) and Path(path).is_absolute() and ".." not in Path(path).parts,
            "Select one absolute private WiNet options file")
    address = ipaddress.IPv4Address(selected["inverter_address"])
    require(not (address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local),
            "Select the single inverter IPv4 address")
    endpoint = urlsplit(selected["mqtt_server"])
    require(endpoint.scheme == "mqtt" and bool(endpoint.hostname) and endpoint.port == 1883
            and not (endpoint.username or endpoint.password or endpoint.path or endpoint.query or endpoint.fragment),
            "Bind WiNet to the declared credential-free MQTT endpoint")
    require(isinstance(selected["mqtt_prefix"], str)
            and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9/_-]{0,127}", selected["mqtt_prefix"]),
            "Preserve the bounded MQTT discovery prefix")
    service = cfg["services"]["winet"]
    require(not any(service.get(k) for k in ("environment", "extra_mounts"))
            and not any(k in service for k in ("command", "entrypoint", "user")),
            "Use the upstream WiNet entrypoint and private options without overrides")
    return selected


def source_files(cfg):
    selected = validate(cfg)
    return [] if selected is None else [selected["configuration_file"]]


def options(cfg):
    selected = validate(cfg)
    value = read_json(Path(selected["configuration_file"]), private=True)
    require(isinstance(value, dict) and not value.keys() - OPTIONS,
            "Use upstream WiNet JSON options without custom certificate fields")
    require(value.get("winet_host") == selected["inverter_address"]
            and value.get("ssl") is True and value.get("additional_winets", []) == [],
            "Use encrypted transport to the single declared inverter")
    require(all(isinstance(value.get(k), str) and value[k]
                and not any(c in value[k] for c in "\r\n\x00") for k in ("winet_user", "winet_pass")),
            "Preserve explicit private inverter credentials")
    endpoint = urlsplit(value.get("mqtt_url", ""))
    expected = urlsplit(selected["mqtt_server"])
    require((endpoint.scheme, endpoint.hostname, endpoint.port) == (expected.scheme, expected.hostname, expected.port)
            and not (endpoint.path or endpoint.query or endpoint.fragment)
            and value.get("mqtt_prefix") == selected["mqtt_prefix"],
            "Preserve MQTT credentials while binding the selected broker and discovery prefix")
    require(type(value.get("poll_interval")) is int and 1 <= value["poll_interval"] <= 3600
            and all(type(value.get(k)) is bool for k in ("analytics", "site_totals")),
            "Select explicit bounded polling and analytics options")
    return value


def files(cfg):
    # Validate options before publishing any rendered file; never log their values.
    return [{"path": "winet-options.json", "uid": 0, "gid": 0, "mode": "0600",
             "content": json.dumps(options(cfg), sort_keys=True) + "\n"}]


def configure(cfg, document):
    if validate(cfg) is None:
        return document
    service = document["services"]["winet"]
    service["volumes"] = [{"type": "bind", "source": RUNTIME, "target": "/data/options.json",
                           "read_only": True, "bind": {"create_host_path": False}}]
    service["healthcheck"] = {
        "test": ["CMD", "node", "-e", HEALTH],
        "interval": "30s", "timeout": "15s", "retries": 3, "start_period": "30s",
    }
    return document


# Read retained availability through the broker, never open another inverter session.
# Deployment acceptance additionally checks fresh telemetry; retained online alone
# cannot establish that sensor values are current.
HEALTH = """const c=require('./build/src/config').loadConfig();
const slug=require('./build/src/homeassistant').hostSlug(c.winets[0].host);
const topics=new Set(['winet-extractor/'+slug+'/status','winet-extractor/'+slug+'/availability']);
const client=require('mqtt').connect(c.mqttUrl,{reconnectPeriod:0,connectTimeout:5000});
const done=code=>{client.end(true);process.exit(code)};
setTimeout(()=>done(1),10000);
client.on('error',()=>done(1));
client.on('connect',()=>client.subscribe([...topics]));
client.on('message',(topic,payload)=>{if(topics.has(topic)&&payload.toString()==='online')topics.delete(topic);if(!topics.size)done(0)});
"""
