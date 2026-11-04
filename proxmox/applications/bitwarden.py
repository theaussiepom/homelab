#!/usr/bin/env python3
"""Bitwarden Lite rendering and bounded, read-only health checks."""
import argparse
import ipaddress
import json
from urllib.parse import urlsplit
from urllib.request import (
    build_opener,
    HTTPHandler,
    HTTPSHandler,
    HTTPRedirectHandler,
    ProxyHandler,
)

ENDPOINTS = ("/api/alive", "/api/config", "/identity/.well-known/openid-configuration")




def validate_settings(settings):
    """Pure existing image, database and numeric ownership contract."""
    import re

    fields = {
        "schema",
        "bind_address",
        "image_id",
        "database_server",
        "database_provider",
        "database_name",
        "data_uid",
        "data_gid",
    }
    if (
        set(settings) != fields
        or settings["database_provider"] != "mysql"
        or any(
            type(settings.get(key)) is not int or not 1 <= settings[key] <= 2147483647
            for key in ("data_uid", "data_gid")
        )
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", settings.get("image_id", ""))
        or not re.fullmatch(r"[A-Za-z0-9_]+", settings.get("database_name", ""))
        or not all(
            isinstance(settings.get(key), str)
            and settings[key]
            and not any(c in settings[key] for c in "\r\n\x00")
            for key in ("database_server",)
        )
    ):
        raise ValueError(
            "Select the observed image, mysql schema and retained numeric ownership"
        )
    address = ipaddress.IPv4Address(settings["bind_address"])
    database = ipaddress.IPv4Address(settings["database_server"])
    if not all(
        any(
            item in ipaddress.ip_network(net)
            for net in (
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "198.18.0.0/15",
            )
        )
        for item in (address, database)
    ):
        raise ValueError(
            "Use explicit private backend addresses for Bitwarden and shared MariaDB"
        )
    return str(address)




def service_configuration(service, *, selected_image, observed_image, environment, ports, data_sources):
    """Pure renderer; the existing ordinary runtime parser owns private values."""
    if selected_image == 'ghcr.io/bitwarden/lite:latest':
        service['image'] = observed_image
    service.pop('network_mode', None)
    service['environment'] = {key: str(value).replace('$', '$$') for key, value in environment.items()}
    if 'TZ' in environment:
        service['environment']['TZ'] = environment['TZ'].replace('$', '$$')
    service['ports'] = ports
    service['healthcheck'] = {'test': ['CMD-SHELL', 'curl -fsSo /dev/null http://localhost:8080']}
    service['volumes'] = [{'type': 'bind', 'source': data_sources[name], 'target': target,
        'bind': {'create_host_path': False}} for name, target in (
            ('data', '/etc/bitwarden'), ('logs', '/var/log/bitwarden'))]
    return service




def health(fetch, issuer):
    """A passing result proves only these unauthenticated response contracts."""
    observed_version = None
    for path in ENDPOINTS:
        status, body = fetch(path)
        if status != 200 or len(body) > 262144:
            raise ValueError("Bitwarden health response status or size differs")
        if path != "/api/alive":
            try:
                value = json.loads(body)
            except (ValueError, UnicodeError):
                raise ValueError("Bitwarden health response is not JSON") from None
            if not isinstance(value, dict):
                raise ValueError("Bitwarden health JSON must be an object")
            if path == "/api/config":
                observed_version = value.get("version")
                if (
                    not isinstance(observed_version, str)
                    or not observed_version.strip()
                    or len(observed_version) > 128
                    or any(ord(char) < 32 for char in observed_version)
                ):
                    raise ValueError("Bitwarden must report its current API version")
            elif value.get("issuer") != issuer:
                raise ValueError("Bitwarden retained identity issuer differs")
    return {
        "status": "passed",
        "observed_version": observed_version,
        "scope": "unauthenticated alive/config/identity only",
    }


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def reader(origin, backend=False):
    """Use verified HTTPS or an explicitly selected private backend probe."""
    parsed = urlsplit(origin)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
        or (parsed.scheme == "http" and parsed.hostname != "127.0.0.1" and not backend)
    ):
        raise ValueError("Use an HTTPS origin, or 127.0.0.1 HTTP for synthetic tests")
    if backend:
        address = ipaddress.IPv4Address(parsed.hostname)
        if not any(
            address in ipaddress.ip_network(net)
            for net in (
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "198.18.0.0/15",
            )
        ):
            raise ValueError(
                "A backend health probe must use the explicitly selected private IPv4 origin"
            )
    opener = build_opener(ProxyHandler({}), HTTPHandler(), HTTPSHandler(), NoRedirect())

    def fetch(path):
        if path not in ENDPOINTS:
            raise ValueError(
                "Only the three fixed unauthenticated endpoints are allowed"
            )
        with opener.open(origin + path, timeout=8) as response:
            return response.status, response.read(262145)

    return fetch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--backend", action="store_true")
    args = parser.parse_args()
    try:
        result = health(reader(args.origin, args.backend), args.issuer)
    except (ValueError, OSError):
        parser.exit(1, "Bitwarden health contract failed; inspect privately.\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
