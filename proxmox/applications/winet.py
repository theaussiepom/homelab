"""Optional WiNet telemetry beside Zigbee; private options stay outside Compose."""

import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from private_io import decode_json, require

RUNTIME = "/opt/homelab-app/runtime/winet-options.json"
FIELDS = {"configuration_file", "inverter_address", "mqtt_server", "mqtt_prefix"}
OPTIONS = {
    "winet_host", "winet_user", "winet_pass", "mqtt_url", "mqtt_prefix",
    "poll_interval", "analytics", "ssl", "site_totals", "additional_winets",
}


def validate_settings(selected):
    """Pure declared inverter/MQTT metadata; independent of guest placement."""
    require(isinstance(selected, dict) and set(selected) == FIELDS, "Use the closed WiNet settings contract")
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
    return selected






def _options(value, selected):
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


def options_bytes(raw, selected):
    """Parse only supplied private bytes through the existing options checks."""
    validate_settings(selected)
    require(isinstance(raw, bytes), "Use selected options bytes")
    return _options(decode_json(raw), selected)








# Read retained availability through the broker, never open another inverter session.
# Deployment acceptance additionally checks fresh telemetry; retained online alone
# cannot establish that sensor values are current.
HEALTH = """const c=require('./build/src/config').loadConfig();
const slug=require('./build/src/homeassistant').hostSlug(c.winets[0].host);
const topics=new Set(['winet-extractor/'+slug+'/status','winet-extractor/'+slug+'/availability']);
const latest=new Map([...topics].map(topic=>[topic,'unknown']));
const client=require('mqtt').connect(c.mqttUrl,{reconnectPeriod:0,connectTimeout:5000});
const done=code=>{client.end(true);process.exit(code)};
setTimeout(()=>done(1),10000);
client.on('error',()=>done(1));
client.on('connect',()=>client.subscribe([...topics]));
client.on('message',(topic,payload)=>{if(!latest.has(topic))return;latest.set(topic,payload.toString());if([...latest.values()].every(value=>value==='online'))done(0)});
"""
