"""Bind one retained MQTT probe account without copying unrelated HA credentials."""
import json
from pathlib import Path

from private_io import read_json, require

RUNTIME = "/opt/homelab-app/runtime/mqtt-probe.json"


def validate(cfg):
    selected = cfg.get("mqtt")
    if cfg.get("kind") != "mqtt":
        require(selected is None, "Dedicated MQTT credentials belong to the broker guest")
        return None
    require(isinstance(selected, dict) and set(selected) == {"credential_file"},
            "Select the retained broker probe credential file")
    path = selected["credential_file"]
    require(isinstance(path, str) and Path(path).is_absolute() and ".." not in Path(path).parts,
            "Select one absolute private broker credential file")
    return selected


def source_files(cfg):
    selected = validate(cfg)
    return [] if selected is None else [selected["credential_file"]]


def files(cfg):
    selected = validate(cfg)
    value = read_json(Path(selected["credential_file"]), private=True)
    require(isinstance(value, dict) and set(value) == {"username", "password"}
            and all(isinstance(value[k], str) and 0 < len(value[k].encode()) <= 65535
                    and not any(c in value[k] for c in "\r\n\x00") for k in value),
            "Preserve exactly one retained MQTT account without logging its values")
    return [{"path": "mqtt-probe.json", "uid": 0, "gid": 0, "mode": "0600",
             "content": json.dumps(value, sort_keys=True) + "\n"}]
