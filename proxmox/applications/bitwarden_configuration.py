"""Inspect a concrete private Bitwarden packet without reading runtime inputs or contacting hosts."""

import argparse
import json
from pathlib import Path
import re
import bitwarden_migration as migration


def inspect(value):
    migration.require(
        isinstance(value, dict)
        and set(value) == {"schema", "enabled", "site", "stack", "approved_plan_sha256"}
        and value["schema"] == "homelab-bitwarden-deployment-v1"
        and type(value["enabled"]) is bool,
        "Use the closed Bitwarden deployment packet",
    )
    approval = value["approved_plan_sha256"]
    migration.require(
        approval is None
        or isinstance(approval, str)
        and re.fullmatch("[0-9a-f]{64}", approval),
        "Use an exact saved-plan fingerprint or no deployment approval",
    )
    missing = migration.validate_admission(
        value["site"], value["stack"], runtime=False, ready=False
    )
    migration.require(
        not value["enabled"] or not missing,
        "An enabled packet cannot omit required native migration inputs",
    )
    return {
        "schema": value["schema"],
        "enabled": value["enabled"],
        "ready_for_native_preflight": not missing,
        "missing_inputs": missing,
        "vmid": value["site"]["guest"]["vmid"],
        "public_origin": value["site"]["app"]["bitwarden"]["public_origin"],
        "scope": "source structure only; no native receipt or target verification",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(inspect(migration.read_json(args.config))))
