"""Ordinary Bitwarden runtime admission; migration receipts are not CD inputs."""

import json
from urllib.parse import urlsplit
import private_io as files
import bitwarden


def _selection(selected):
    files.require(
        set(selected)
        == {
            "schema",
            "public_origin",
            "issuer",
        }
        and selected["schema"] == "homelab-bitwarden-runtime-v2",
        "Use the selected Bitwarden runtime contract",
    )


def environment_bytes(raw, selected, settings):
    """Validate supplied bytes; the protected app payload owns role continuity."""
    _selection(selected)
    files.require(isinstance(raw, bytes), "Use selected runtime bytes")
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
    bitwarden.validate_settings(settings)
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
    return value
