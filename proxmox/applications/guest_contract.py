"""Validate current Debian LXC definitions without reading credentials or targets."""

import json
import network_endpoints
from pathlib import Path
import re
from urllib.parse import urlsplit
import discovery
import foundation
import ingress_routing
from private_io import require

SOURCE = Path(__file__).resolve().parent
_catalogue = json.loads((SOURCE.parents[1] / "blueprints/catalogue.json").read_text())
require(
    _catalogue["schema"] == "homelab-blueprints-v1",
    "Use the current blueprint catalogue",
)
BLUEPRINTS = _catalogue["guests"]
DATABASE_KINDS = {"postgresql", "mariadb", "influxdb"}
SCHEMA = "homelab-guest-deployment-v2"


def phases(cfg):
    selected = BLUEPRINTS[cfg["app"]["kind"]]
    require(
        cfg.get("deployment")
        == {"contract": 2, "capabilities": selected["capabilities"]},
        "Use the current guest preparation contract",
    )
    return ["preparation", *selected["applications"]]


def runtime_images(stack):
    """Expose named images uniformly while application renderers own their inputs."""
    if stack["kind"] == "pegaprox":
        return {"pegaprox": stack}
    return stack["services"]


def archive_inputs(stack):
    """Only verified image archive fields cross into the shared Ansible task."""
    return {
        name: {key: row[key] for key in ("image", "archive", "archive_sha256")}
        for name, row in runtime_images(stack).items()
        if "archive" in row
    }


def data_bind_sources(document):
    """Find preserved guest data binds in the normalized Compose document."""
    result = set()
    for service in document["services"].values():
        for volume in service.get("volumes", []):
            source = (
                volume.partition(":")[0]
                if isinstance(volume, str)
                else volume.get("source", "")
            )
            if source.startswith("/srv/homelab/data/"):
                result.add(source)
    return result


def validate(cfg, stack=None):
    app, guest = cfg["app"], cfg["guest"]
    addresses = network_endpoints.addresses(guest)
    require(
        guest.get("platform", "debian-lxc") == "debian-lxc",
        "Only Debian LXC is implemented",
    )
    allowed = {
        "kind",
        "vmid",
        "hostname",
        "memory_mib",
        "address",
        "mac",
        "packages",
        "stack_config",
        "exclusive_writer_confirmed",
        "health_checks",
        "service_health_checks",
        "repositories",
        "database",
        "frontend_routing",
        "endpoints",
        "node_red_authentication",
        "published_services",
        "service_connections",
        "bitwarden",
        "pegaprox",
        "required_paths",
    }
    require(not app.keys() - allowed, "Use only current application contract fields")
    require(app["kind"] in BLUEPRINTS, "Select a supported application blueprint")
    phases(cfg)
    require(
        {(r["path"], r["type"]) for r in BLUEPRINTS[app["kind"]]["required_paths"]}
        <= {(r["path"], r["type"]) for r in app.get("required_paths", [])},
        "Keep every blueprint data/configuration prerequisite",
    )
    require(
        not {
            "capture",
            "ha_http",
            "new_target",
            "clean_install_confirmed",
            "installation",
        }
        & app.keys(),
        "Installation, configuration conversion and restoration are separate operator work",
    )
    vmid = guest["vmid"]
    require(
        guest.get("started", True) is True,
        "Deployment selects an active guest",
    )
    require(
        type(vmid) is int and vmid >= 100 and vmid not in {900, 4914, 4915, 4920},
        "Preserve protected guest identities",
    )
    require(
        app["vmid"] == vmid
        and app["hostname"] == guest["hostname"]
        and app["memory_mib"] == guest["memory_mib"],
        "Infrastructure and application must select the same guest and budget",
    )
    require(
        any(
            nic["ipv4"] != "manual"
            and str(network_endpoints.interface(nic).ip) == app["address"]
            and nic["mac"].lower() == app["mac"].lower()
            for nic in guest["interfaces"]
        ),
        "Select an assigned interface for application access",
    )
    require(
        set(app["service_health_checks"])
        == set(BLUEPRINTS[app["kind"]]["applications"])
        and all(app["service_health_checks"].values()),
        "Require a health contract for each application",
    )
    require(
        app["packages"]
        and all(
            re.fullmatch(r"[a-z0-9][a-z0-9+.-]*=[0-9][A-Za-z0-9.+:~\-]*", p)
            for p in app["packages"]
        ),
        "Supply exact approved packages",
    )
    discovery.labels(cfg)
    require(
        app["kind"] != "automation"
        or app.get("node_red_authentication") == "authentik-oidc",
        "Node-RED requires its current native Authentik OIDC login",
    )
    if "frontend_routing" in app:
        require(
            app["kind"] in {"ingress", "automation"},
            "Select a multihomed frontend application",
        )
        _, _, _, mac = ingress_routing.validate(app["frontend_routing"])
        require(
            any(
                str(network_endpoints.interface(n)) == app["frontend_routing"]["address"]
                and n["mac"].lower() == mac
                for n in guest["interfaces"]
            ),
            "Routing must match the selected frontend interface",
        )
    require(
        not guest.get("serial_device") or app["kind"] == "zigbee2mqtt",
        "Only the Zigbee blueprint declares a host serial capability",
    )
    host_paths = (
        ("host_device_key", "host_known_hosts") if guest.get("serial_device") else ()
    )
    require(
        all(key in cfg["paths"] for key in host_paths),
        "Declare the registered host-device key and pinned host trust",
    )
    for key in (
        *host_paths,
        "state_root",
        "backup_mount",
        "backup_directory",
        "api_token",
        "ca_file",
        "private_key",
        "known_hosts",
    ):
        require(
            Path(cfg["paths"][key]).is_absolute()
            and ".." not in Path(cfg["paths"][key]).parts,
            "Use absolute private runner paths without traversal",
        )
    require(
        len(
            {
                Path(cfg["paths"][key])
                for key in (
                    "api_token",
                    "private_key",
                    "known_hosts",
                    "ca_file",
                    *host_paths,
                )
            }
        )
        == 4 + len(host_paths),
        "Keep credentials and trust in distinct files",
    )
    mount, backup = Path(cfg["paths"]["backup_mount"]), Path(
        cfg["paths"]["backup_directory"]
    )
    require(
        mount in backup.parents,
        "State recovery copies must be below the declared NAS mount",
    )
    endpoint = urlsplit(cfg["site"]["api_endpoint"])
    require(
        endpoint.scheme == "https"
        and endpoint.hostname
        and endpoint.port == 8006
        and not endpoint.username
        and not endpoint.password
        and not endpoint.query
        and not endpoint.fragment
        and endpoint.path in ("", "/"),
        "Use the credential-free trusted PVE HTTPS endpoint",
    )
    require(
        ("docker" in cfg["deployment"]["capabilities"]) == (stack is not None),
        "Supply exactly the selected runtime stack",
    )
    if app["kind"] in DATABASE_KINDS:
        db = app["database"]
        mode = db.get("account_mode", "fixed")
        require(
            "capture" not in db and mode in {"fixed", "package"},
            "Select the retained database account contract",
        )
        require(
            mode != "package"
            or (
                app["kind"] == "mariadb"
                and db["user"] == db["group"] == "mysql"
                and "uid" not in db
                and "gid" not in db
            ),
            "Package-created identity is only supported for MariaDB",
        )
    if stack is not None:
        require(
            stack["kind"] == app["kind"]
            and stack["guest_memory_mib"] == app["memory_mib"],
            "Bind the stack kind and memory budget",
        )
        selected = foundation.validate(stack)
        if selected and app["kind"] in {"identity", "ingress"}:
            require(
                selected["bind_address"] in addresses,
                "Bind the foundation listener to an assigned interface",
            )
        if selected and app["kind"] == "ingress" and len(guest["interfaces"]) > 1:
            require(
                "frontend_routing" in app
                and ingress_routing.validate(app["frontend_routing"])[0]
                == selected["bind_address"],
                "Require the selected ingress reply-routing contract",
            )
        if app["kind"] == "db-tools":
            require(
                stack["pgadmin_bind_address"] in addresses,
                "Bind pgAdmin to an assigned interface",
            )
        if app["kind"] == "automation":
            address = (
                stack["services"]["homeassistant"]
                .get("environment", {})
                .get("HOMELAB_HA_IPV4")
            )
            require(
                not address or address in addresses,
                "HA discovery must select an assigned address",
            )
        if app["kind"] == "pegaprox":
            import pegaprox

            pegaprox.validate_deployment(cfg, stack)
        if app["kind"] == "zigbee2mqtt":
            import zigbee2mqtt

            zigbee2mqtt.validate_deployment(cfg, stack)
        import render

        document = render.compose(stack)
        require(
            data_bind_sources(document)
            <= {row["path"] for row in app.get("required_paths", [])},
            "Declare every runtime data bind as a prepared path",
        )
    return vmid


def required_network_interfaces(cfg):
    """Use the same ordered ethN names as the OpenTofu guest module."""
    interfaces = cfg["guest"]["interfaces"]
    result = [
        "eth" + str(i) for i, nic in enumerate(interfaces) if nic["ipv4"] != "manual"
    ]
    if not result or len(interfaces) > 16:
        raise ValueError(
            "Select the guest interfaces that require IPv4 before service startup"
        )
    return result
