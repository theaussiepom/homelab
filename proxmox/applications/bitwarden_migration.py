"""Bitwarden migration inputs: preserved identity and separately reviewed native receipts."""

import hashlib, ipaddress, json, re
from pathlib import Path
from urllib.parse import urlsplit
import foundation_cd as files

ADMISSION = "homelab-bitwarden-admission-v1"
KEYS = {
    "schema",
    "public_origin",
    "issuer",
    "source_environment_sha256",
    "source_backup_sha256",
    "database_guest",
    "restore_receipt",
    "prerequisites_receipt",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def checksum(value):
    return hashlib.sha256(value).hexdigest()


def environment_hash(value):
    return checksum(encoded(value))


def read_json(path, private=False):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate private JSON field")
            result[key] = value
        return result

    return json.loads(
        files.regular(Path(path), private=private), object_pairs_hook=unique
    )


def nas_receipt(cfg, key):
    require(
        key in ("restore_receipt", "prerequisites_receipt"),
        "Unknown Bitwarden prerequisite",
    )
    return (
        Path(cfg["paths"]["backup_directory"])
        / "bitwarden"
        / (key + "-" + cfg["app"]["bitwarden"]["source_backup_sha256"] + ".json")
    )


def runtime_environment(cfg, stack, source):
    settings = stack["bitwarden"]
    admission = cfg["app"]["bitwarden"]
    require(
        isinstance(source, dict)
        and source
        and all(
            isinstance(key, str)
            and re.fullmatch(
                r"(?:BW_[A-Z0-9_]+|globalSettings[A-Za-z0-9_]+|adminSettings[A-Za-z0-9_]+|PUID|PGID|TZ)",
                key,
            )
            and isinstance(value, str)
            and len(value.encode()) <= 65536
            and not any(c in value for c in "\r\n\x00")
            for key, value in source.items()
        ),
        "Supply the existing effective application environment as private JSON strings",
    )
    require(
        environment_hash(source) == admission["source_environment_sha256"],
        "Existing runtime environment differs; no credential rotation or implicit setting changes",
    )
    required = {
        "BW_DOMAIN",
        "BW_DB_PROVIDER",
        "BW_DB_SERVER",
        "BW_DB_DATABASE",
        "BW_DB_USERNAME",
        "BW_DB_PASSWORD",
        "BW_INSTALLATION_ID",
        "BW_INSTALLATION_KEY",
        "globalSettings__identityServer__certificatePassword",
    }
    require(
        required <= set(source) and all(source[key] for key in required),
        "Preserve installation, database and certificate identity values",
    )
    require(
        source["BW_DB_PROVIDER"] == "mysql"
        and source["BW_DB_DATABASE"] == settings["database_name"]
        and source["BW_DB_SERVER"] == settings["source_database_server"]
        and source["BW_DOMAIN"] == urlsplit(admission["public_origin"]).hostname,
        "Retain the source hostname, mysql provider, schema and selected original database route",
    )
    require(
        source.get("PUID") == str(settings["data_uid"])
        and source.get("PGID") == str(settings["data_gid"]),
        "Retain explicit source UID/GID settings; image defaults must not change restored ownership",
    )
    return dict(source, BW_DB_SERVER=settings["database_server"])


def validate_admission(cfg, stack, runtime=True, ready=True):
    import bitwarden

    bitwarden.validate(stack)
    settings = stack["bitwarden"]
    app = cfg["app"]
    selected = app.get("bitwarden", {})
    require(
        "mariadb-client-core=1:11.8.6-0+deb13u1" in app.get("packages", []),
        "Install the reviewed MariaDB client for the retained-account pre-start query",
    )
    require(
        settings["schema"] == "homelab-bitwarden-migration-v1"
        and isinstance(selected, dict)
        and set(selected) == KEYS
        and selected["schema"] == ADMISSION,
        "Native Bitwarden requires a complete migration admission packet",
    )
    origin = urlsplit(selected["public_origin"])
    require(
        origin.scheme == "https"
        and origin.hostname
        and not origin.username
        and not origin.password
        and origin.path == ""
        and not origin.query
        and not origin.fragment
        and origin.port in (None, 443),
        "Select the retained HTTPS Bitwarden origin",
    )
    require(
        app["kind"] == stack["kind"] == "bitwarden"
        and app["memory_mib"] == stack["guest_memory_mib"]
        and settings["bind_address"]
        in [nic["ipv4"].split("/")[0] for nic in cfg["guest"]["interfaces"]],
        "Bind the Bitwarden listener and resource budget to the selected guest",
    )
    require(
        app.get("discovery_routes")
        == [
            {
                "name": "bitwarden",
                "host": origin.hostname,
                "url": "http://" + settings["bind_address"] + ":8080",
            }
        ],
        "Expose only the retained hostname on this Bitwarden backend; domain cutover is separate",
    )
    require(
        isinstance(selected["issuer"], str)
        and selected["issuer"]
        and not any(c in selected["issuer"] for c in "\r\n\x00"),
        "Retain the observed identity discovery issuer",
    )
    require(
        app.get("health_checks")
        == [
            {
                "name": "Bitwarden alive/config/identity",
                "argv": [
                    "python3",
                    "/opt/homelab-app/bitwarden.py",
                    "--origin",
                    "http://" + settings["bind_address"] + ":8080",
                    "--issuer",
                    selected["issuer"],
                    "--backend",
                ],
                "expect": '"status": "passed"',
            }
        ],
        "Use the fixed bounded unauthenticated health contract",
    )
    missing = []

    def fingerprint(value, label):
        if value is None:
            missing.append(label)
        else:
            require(
                isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value),
                "Invalid migration input fingerprint",
            )

    for key in ("source_environment_sha256", "source_backup_sha256"):
        fingerprint(selected[key], key)
    require(
        type(selected["database_guest"]) is int
        and selected["database_guest"] >= 100
        and selected["database_guest"] != cfg["guest"]["vmid"],
        "Select the existing shared native MariaDB and original input hashes",
    )
    for key in ("restore_receipt", "prerequisites_receipt"):
        row = selected[key]
        require(
            isinstance(row, dict)
            and set(row) == {"path", "sha256"}
            and isinstance(row["path"], str)
            and Path(row["path"]).is_absolute(),
            "Supply exact private prerequisite receipt paths and hashes",
        )
        fingerprint(row["sha256"], key)
    require(
        type(app.get("exclusive_writer_confirmed")) is bool
        and type(app.get("capture", {}).get("coherent")) is bool,
        "State writer fencing and capture coherence explicitly",
    )
    if not app["exclusive_writer_confirmed"]:
        missing.append("old_writer_fence")
    if not app["capture"]["coherent"]:
        missing.append("coherent_filesystem_capture")
    fingerprint(app["capture"].get("sha256"), "capture_sha256")
    require(
        not ready or not missing,
        "The native migration needs complete reviewed inputs, coherent capture and a fenced old writer",
    )
    if not runtime:
        return missing
    network = app.get("network_contract")
    if network is not None:
        require(
            isinstance(network, dict)
            and set(network) == {"path", "sha256", "source_revision"}
            and Path(network["path"]).is_absolute()
            and re.fullmatch("[0-9a-f]{64}", network["sha256"])
            and re.fullmatch("[0-9a-f]{40}", network["source_revision"]),
            "Bind the selected shared network contract and immutable helper source",
        )
        require(
            checksum(files.regular(Path(network["path"]))) == network["sha256"],
            "Shared network contract drifted before the selected native step",
        )
    target = stack["services"]["bitwarden"].get("environment", {})
    source = dict(target, BW_DB_SERVER=settings["source_database_server"])
    require(
        runtime_environment(cfg, stack, source) == target,
        "Only the reviewed database endpoint delta is permitted",
    )
    for key in ("restore_receipt", "prerequisites_receipt"):
        row = selected[key]
        raw = files.regular(Path(row["path"]), private=True)
        require(
            checksum(raw) == row["sha256"]
            and files.regular(nas_receipt(cfg, key), private=True) == raw,
            "A prerequisite receipt or its NAS recovery copy differs",
        )
        receipt = read_json(Path(row["path"]), private=True)
        if key == "restore_receipt":
            expected = {
                "schema": "homelab-bitwarden-db-restore-v2",
                "database_guest": selected["database_guest"],
                "database_server": settings["database_server"],
                "database_name": settings["database_name"],
                "database_client_address": database_client_address(cfg, stack),
                "source_backup_sha256": selected["source_backup_sha256"],
                "capture_sha256": app["capture"]["sha256"],
                "source_environment_sha256": selected["source_environment_sha256"],
                "source_image_id": settings["source_image_id"],
                "writer_fenced": True,
                "checks": {
                    "schema_coverage": "passed",
                    "data_validation": "passed",
                    "retained_account_definition": "passed",
                },
            }
        else:
            expected = {
                "schema": "homelab-bitwarden-prerequisites-v1",
                "node": cfg["site"]["node"],
                "vmid": cfg["guest"]["vmid"],
                "backend_address": settings["bind_address"],
                "public_origin": selected["public_origin"],
                "checks": {
                    "bootstrap_grant": "passed",
                    "discovery_scope": "passed",
                    "ingress_backend_allowance": "passed",
                    "dns_tls_plan": "reviewed",
                },
            }
        require(
            receipt == expected,
            "The reviewed native database or access/route prerequisite does not match this migration",
        )


def database_client_address(cfg, stack):
    server = ipaddress.ip_address(stack["bitwarden"]["database_server"])
    matches = [
        ipaddress.ip_interface(n["ipv4"])
        for n in cfg["guest"]["interfaces"]
        if server in ipaddress.ip_interface(n["ipv4"]).network
    ]
    require(
        len(matches) == 1,
        "Select exactly one guest interface on the native database subnet",
    )
    return str(matches[0].ip)


def database_query_record(cfg, stack):
    """Bind the guest's successful selected-schema query without recording credentials or data."""
    selected = cfg["app"]["bitwarden"]
    settings = stack["bitwarden"]
    return {
        "schema": "homelab-bitwarden-db-query-v1",
        "state": "passed",
        "vmid": cfg["guest"]["vmid"],
        "database_server": settings["database_server"],
        "database_name": settings["database_name"],
        "source_backup_sha256": selected["source_backup_sha256"],
        "source_environment_sha256": selected["source_environment_sha256"],
        "source_image_id": settings["source_image_id"],
        "method": "retained account selected-schema LIMIT 0 query",
    }
