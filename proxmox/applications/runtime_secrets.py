"""Parse the retained discovery credential supplied by its existing owner."""
import json
import re
from private_io import require


def retained_provider_token(raw, identity):
    """Parse only the exact retained provider record supplied by its owner."""
    value = json.loads(raw)
    require(
        isinstance(value, dict)
        and set(value) == {"schema", "identity", "token"}
        and value["schema"] == "homelab-service-discovery-v1"
        and value["identity"] == identity
        and isinstance(value["token"], str)
        and re.fullmatch(
            re.escape(identity) + r"=[A-Za-z0-9-]+", value["token"]
        ),
        "Use only the retained declared discovery credential",
    )
    return value["token"].split("=", 1)[1]
