"""One HTTP route model, rendered as guest discovery notes or file configuration."""

import copy
import ipaddress
from pathlib import PurePosixPath
import re
from urllib.parse import urlsplit

PRIVATE_BACKENDS = tuple(
    ipaddress.IPv4Network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "198.18.0.0/15")
)
DEFAULT_MIDDLEWARES = {"security-headers": {"headers": {"contentTypeNosniff": True}}}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def name(value):
    require(
        isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9-]{0,62}", value),
        "Use a literal routing name",
    )
    return value


def hostname(value):
    require(
        isinstance(value, str)
        and len(value) <= 253
        and "." in value
        and all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
            for part in value.split(".")
        ),
        "Use a literal fully qualified route hostname",
    )
    return value


def origin(value, addresses=None):
    message = "Use a private HTTP(S) backend origin on the selected interface"
    require(
        isinstance(value, str)
        and not any(c.isspace() for c in value)
        and "\\" not in value,
        message,
    )
    try:
        parsed = urlsplit(value)
        ip = ipaddress.IPv4Address(parsed.hostname)
        port = parsed.port
    except (ValueError, TypeError):
        raise ValueError(message) from None
    require(
        parsed.scheme in {"http", "https"}
        and parsed.username is None
        and parsed.password is None
        and parsed.path in {"", "/"}
        and not parsed.query
        and not parsed.fragment
        and (port is None or 1 <= port <= 65535)
        and any(ip in network for network in PRIVATE_BACKENDS)
        and (addresses is None or str(ip) in addresses),
        message,
    )
    return parsed


def validate_routes(routes, addresses=None):
    require(
        isinstance(routes, dict) and len(routes) <= 64, "Use a bounded named routes map"
    )
    hosts = set()
    for key, route in routes.items():
        name(key)
        require(
            isinstance(route, dict)
            and {"host", "url"} <= route.keys()
            and not route.keys()
            - {"host", "url", "aliases", "middlewares", "transport"},
            "Use only the resolved routing contract fields",
        )
        aliases = route.get("aliases", [])
        require(
            isinstance(aliases, list) and len(aliases) <= 8,
            "Use a bounded hostname aliases list",
        )
        selected = [hostname(value) for value in [route["host"], *aliases]]
        require(
            len(set(selected)) == len(selected) and not hosts.intersection(selected),
            "Route hostnames must be globally unique",
        )
        hosts.update(selected)
        backend = origin(route["url"], addresses)
        middleware = route.get("middlewares", ["security-headers"])
        require(
            isinstance(middleware, list) and len(middleware) <= 16,
            "Use an ordered middleware reference list",
        )
        require(
            len({name(value) for value in middleware}) == len(middleware),
            "Middleware references must be unique",
        )
        if "transport" in route:
            name(route["transport"])
            require(
                backend.scheme == "https", "A TLS transport requires an HTTPS backend"
            )
    return hosts


def router(key, route):
    hosts = [route["host"], *route.get("aliases", [])]
    rule = " || ".join(f"Host(`{value}`)" for value in hosts)
    return {
        "rule": "(" + rule + ")" if len(hosts) > 1 else rule,
        "priority": 10,
        "service": key,
        "entryPoints": ["websecure"],
        "tls": {"certResolver": "letsencrypt"},
        "middlewares": [
            value + "@file" for value in route.get("middlewares", ["security-headers"])
        ],
    }


def labels(cfg):
    """Guest Notes contain public route facts, with no application or login policy."""
    require(
        "routing_labels" not in cfg.get("guest", {}),
        "Use typed routes, never arbitrary routing labels",
    )
    routes = cfg.get("routes", {})
    validate_routes(
        routes, {nic["ipv4"].split("/")[0] for nic in cfg["guest"]["interfaces"]}
    )
    result = {}
    for key, route in routes.items():
        selected = router(key, route)
        prefix = f"traefik.http.routers.{key}"
        result.update(
            {
                "traefik.enable": "true",
                f"{prefix}.rule": selected["rule"],
                f"{prefix}.priority": "10",
                f"{prefix}.service": key,
                f"{prefix}.entrypoints": "websecure",
                f"{prefix}.tls": "true",
                f"{prefix}.tls.certresolver": "letsencrypt",
            }
        )
        if selected["middlewares"]:
            result[f"{prefix}.middlewares"] = ",".join(selected["middlewares"])
        service = f"traefik.http.services.{key}.loadbalancer"
        result[f"{service}.server.url"] = route["url"].rstrip("/")
        if "transport" in route:
            result[f"{service}.serverstransport"] = route["transport"] + "@file"
    return result


def ca_path(key):
    return "/etc/ssl/certs/route-" + key + ".pem"


def validate_ingress(settings):
    require(
        isinstance(settings, dict)
        and not settings.keys() - {"routes", "middlewares", "transports"},
        "Use the ingress routing contract",
    )
    validate_routes(settings.get("routes", {}))
    middleware, transports = settings.get("middlewares", {}), settings.get(
        "transports", {}
    )
    require(
        isinstance(middleware, dict) and isinstance(transports, dict),
        "Use named ingress definitions",
    )
    for key, definition in middleware.items():
        name(key)
        require(
            key not in DEFAULT_MIDDLEWARES
            and isinstance(definition, dict)
            and len(definition) == 1
            and all(isinstance(value, dict) for value in definition.values()),
            "Declare one middleware definition; preserve shared defaults",
        )
    for key, definition in transports.items():
        name(key)
        require(
            isinstance(definition, dict)
            and definition
            and not definition.keys() - {"server_name", "ca_file"},
            "Declare verified TLS transport settings",
        )
        if "server_name" in definition:
            hostname(definition["server_name"])
        if "ca_file" in definition:
            path = definition["ca_file"]
            require(
                isinstance(path, str)
                and PurePosixPath(path).is_absolute()
                and ".." not in PurePosixPath(path).parts
                and not any(c.isspace() for c in path),
                "Use an absolute public CA file path",
            )
    for route in settings.get("routes", {}).values():
        references(route, settings)
    return settings


def references(route, settings):
    require(
        set(route.get("middlewares", ["security-headers"]))
        <= DEFAULT_MIDDLEWARES.keys() | settings.get("middlewares", {}).keys(),
        "Select declared middleware references",
    )
    require(
        "transport" not in route
        or route["transport"] in settings.get("transports", {}),
        "Select a declared TLS transport",
    )


def shared(settings):
    """External backends and shared middleware/transports belong to the file provider."""
    validate_ingress(settings)
    http = {
        "middlewares": copy.deepcopy(
            dict(DEFAULT_MIDDLEWARES, **settings.get("middlewares", {}))
        ),
        "routers": {},
        "services": {},
        "serversTransports": {},
    }
    for key, route in settings.get("routes", {}).items():
        http["routers"][key] = router(key, route)
        backend = {"servers": [{"url": route["url"].rstrip("/")}]}
        if "transport" in route:
            backend["serversTransport"] = route["transport"] + "@file"
        http["services"][key] = {"loadBalancer": backend}
    for key, definition in settings.get("transports", {}).items():
        http["serversTransports"][key] = {
            **(
                {"serverName": definition["server_name"]}
                if "server_name" in definition
                else {}
            ),
            **({"rootCAs": [ca_path(key)]} if "ca_file" in definition else {}),
        }
    return {
        "tls": {"options": {"default": {"minVersion": "VersionTLS12"}}},
        "http": http,
    }
