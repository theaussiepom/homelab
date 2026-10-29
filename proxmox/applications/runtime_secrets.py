"""Fixed runtime secret bindings; never generate or rotate credentials."""

from pathlib import Path
import re
import json
from private_io import require, regular
from secret_contract import validate_names

PROVIDER = Path("/var/lib/homelab-bootstrap/service-discovery/token.json")


def secret_inputs(name, stack, directory, environment, provider, identity):
    selected = stack["foundation"]["secret_files"]
    bindings = validate_names(name, selected)
    result = {}
    for key, path in selected.items():
        binding = bindings[key]
        filename, variable = binding.filename, binding.environment
        require(
            path == str(directory / filename),
            "Foundation secret path differs from its fixed private destination",
        )
        if variable is None:
            value = json.loads(regular(provider, private=True))
            require(
                isinstance(value, dict)
                and set(value) == {"schema", "identity", "token"}
                and value["schema"] == "homelab-service-discovery-v1"
                and value["identity"] == identity
                and isinstance(value["token"], str)
                and re.fullmatch(
                    re.escape(identity) + r"=[A-Za-z0-9-]+", value["token"]
                )
                and stack["foundation"]["proxmox_token_id"] == identity,
                "Use only the retained declared discovery credential",
            )
            secret = value["token"].split("=", 1)[1]
        else:
            # variable comes only from the fixed mapping above, never Git input.
            secret = environment.get(variable)
        require(
            isinstance(secret, str)
            and 0 < len(secret.encode()) <= 65536
            and secret.strip()
            and not any(char in secret for char in "\r\n\x00"),
            "A required foundation environment secret is missing or invalid",
        )
        result[filename] = secret.encode()
    return result


def prepare_stack(cfg, stack, destination, environment):
    """Bind only the fixed existing secrets required by this selected application."""
    kind = cfg["app"]["kind"]
    extra = {}
    if kind == "automation":
        secret = environment.get("NODE_RED_API_TOKEN")
        require(
            isinstance(secret, str)
            and 0 < len(secret.encode()) <= 65536
            and secret.strip()
            and not any(c in secret for c in "\r\n\x00"),
            "Supply the retained Node-RED runtime token",
        )
        values = stack["services"]["node_red"].setdefault("environment", {})
        require(
            "NODE_RED_API_TOKEN" not in values,
            "Keep runtime token values outside source packets",
        )
        values["NODE_RED_API_TOKEN"] = secret
    elif kind == "bitwarden":
        import bitwarden_runtime

        require(
            stack["services"]["bitwarden"]["environment"] == {},
            "Keep Bitwarden runtime values outside source packets",
        )
        stack["services"]["bitwarden"]["environment"] = bitwarden_runtime.environment(
            cfg, stack
        )
        bitwarden_runtime.validate(cfg, stack)
    elif "foundation" in stack:
        extra = secret_inputs(
            kind,
            stack,
            destination,
            environment,
            PROVIDER,
            stack["foundation"].get("proxmox_token_id", ""),
        )
    return extra
