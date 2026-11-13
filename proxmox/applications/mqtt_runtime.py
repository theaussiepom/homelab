"""Bind one retained MQTT probe account without copying unrelated HA credentials."""
import json
from pathlib import Path

from private_io import read_json, require

RUNTIME = "/opt/homelab-app/runtime/mqtt-probe.json"








def probe_files(value):
    """Validate only one already supplied retained broker probe record."""
    require(isinstance(value, dict) and set(value) == {"username", "password"}
            and all(isinstance(value[k], str) and 0 < len(value[k].encode()) <= 65535
                    and not any(c in value[k] for c in "\r\n\x00") for k in value),
            "Preserve exactly one retained MQTT account without logging its values")
    return [{"path": "mqtt-probe.json", "uid": 0, "gid": 0, "mode": "0600",
             "content": json.dumps(value, sort_keys=True) + "\n"}]
