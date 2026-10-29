"""Ordinary Bitwarden runtime admission; migration receipts are not CD inputs."""

import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit
import private_io as files
import bitwarden


def environment(cfg, stack):
    selected = cfg["app"]["bitwarden"]
    files.require(
        set(selected)
        == {
            "schema",
            "public_origin",
            "issuer",
            "environment_sha256",
            "runtime_env_file",
        }
        and selected["schema"] == "homelab-bitwarden-runtime-v1"
        and Path(selected["runtime_env_file"]).is_absolute(),
        "Use the retained Bitwarden runtime contract",
    )
    raw = files.regular(Path(selected["runtime_env_file"]), private=True)
    files.require(
        hashlib.sha256(raw).hexdigest() == selected["environment_sha256"],
        "Retained Bitwarden runtime input differs",
    )
    value = json.loads(raw)
    files.require(
        isinstance(value, dict)
        and value
        and all(
            isinstance(k, str)
            and isinstance(v, str)
            and not any(c in v for c in "\r\n\x00")
            for k, v in value.items()
        ),
        "Keep the existing runtime strings in the private file",
    )
    settings = stack["bitwarden"]
    files.require(
        value.get("BW_DB_PROVIDER") == "mysql"
        and value.get("BW_DB_SERVER") == settings["database_server"]
        and value.get("BW_DB_DATABASE") == settings["database_name"]
        and value.get("BW_DOMAIN") == urlsplit(selected["public_origin"]).hostname
        and value.get("PUID") == str(settings["data_uid"])
        and value.get("PGID") == str(settings["data_gid"])
        and all(
            value.get(k)
            for k in (
                "BW_DB_USERNAME",
                "BW_DB_PASSWORD",
                "BW_INSTALLATION_ID",
                "BW_INSTALLATION_KEY",
                "globalSettings__identityServer__certificatePassword",
            )
        ),
        "Retain the commissioned endpoint, account and installation identity without conversion",
    )
    bitwarden.validate(stack)
    return value


def validate(cfg, stack):
    expected = environment(cfg, stack)
    files.require(
        stack["services"]["bitwarden"]["environment"] == expected,
        "Runtime settings differ from their retained private authority",
    )
    files.require(
        cfg["app"]["exclusive_writer_confirmed"] is True
        and "capture" not in cfg["app"],
        "Ordinary deployment requires separately prepared data and a retired old writer",
    )
    origin = urlsplit(cfg["app"]["bitwarden"]["public_origin"])
    files.require(
        origin.scheme == "https"
        and origin.hostname
        and not origin.username
        and not origin.password
        and origin.path == ""
        and not origin.query
        and not origin.fragment,
        "Retain the HTTPS origin",
    )
    files.require(
        any(
            route["host"] == origin.hostname
            and route["url"] == "http://" + stack["bitwarden"]["bind_address"] + ":8080"
            for route in cfg["routes"].values()
        ),
        "Retain the selected route",
    )
