"""Pure trusted provider/ACME configuration shared by component callers."""
import ipaddress
import re
from urllib.parse import urlsplit

PLUGIN = "traefik-proxmox-provider"


PLUGIN_ARCHIVE_SHA256 = (
    "9e3b91e0ba79fc27dd2587e8b92db725a424a9c21cb17cfcf07b1ef6e354efd7"
)


def text(value, name):
    if not isinstance(value, str) or not value or any(c in value for c in "\r\n\x00"):
        raise ValueError(f"Invalid foundation {name}")
    return value


def address(value):
    try:
        ip = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        raise ValueError(
            "Foundation bind address must be a selected IPv4 address"
        ) from None
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local:
        raise ValueError("Foundation bind address must be a selected IPv4 address")
    return str(ip)


def origin(value, name):
    value = text(value, name)
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or any(c.isspace() for c in value)
        or "\\" in value
    ):
        raise ValueError(f"Foundation {name} requires a credential-free HTTPS origin")
    try:
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError
    except ValueError:
        raise ValueError(f"Invalid foundation {name} port") from None
    return value.rstrip("/")


def dns_resolvers(value):
    message = "Declare 1-3 unique recursive DNS IPv4 addresses on port 53"
    if not isinstance(value, list) or not 1 <= len(value) <= 3:
        raise ValueError(message)
    result = []
    for resolver in value:
        if not isinstance(resolver, str):
            raise ValueError(message)
        host, separator, port = resolver.rpartition(":")
        try:
            if (
                separator != ":"
                or port != "53"
                or address(host) != host
                or resolver in result
            ):
                raise ValueError(message)
        except ValueError:
            raise ValueError(message) from None
        result.append(resolver)
    return result


def ingress_service(service, *, mount, certs_source, propagation_timeout_seconds=None, route_ca_mounts=()):
    """Pure selected provider/ACME service mounts; source file generation is separate."""
    service['environment'].update(CF_DNS_API_TOKEN_FILE='/run/secrets/cloudflare-dns-token',
                                  SSL_CERT_FILE='/etc/ssl/certs/homelab-pve.pem')
    if propagation_timeout_seconds is not None:
        service['environment']['CLOUDFLARE_PROPAGATION_TIMEOUT'] = str(propagation_timeout_seconds)
    service['volumes'] = [mount('traefik.yml', '/etc/traefik/traefik.yml'),
        mount('shared.yml', '/etc/traefik/shared.yml'),
        mount('pve-ca.pem', '/etc/ssl/certs/homelab-pve.pem'),
        mount('cloudflare-dns-token', '/run/secrets/cloudflare-dns-token'),
        {'type': 'bind', 'source': certs_source, 'target': '/var/traefik/certs',
         'bind': {'create_host_path': False}}, *route_ca_mounts]
    return service


def ingress_static(selected, token):
    """Pure fixed provider/ACME document; caller already selected capabilities."""
    static = {
        "entryPoints": {
            "web": {
                "address": f"{selected['bind_address']}:80",
                "http": {
                    "redirections": {
                        "entryPoint": {"to": "websecure", "scheme": "https"}
                    }
                },
            },
            "websecure": {"address": f"{selected['bind_address']}:443"},
            "health": {"address": "127.0.0.1:8082"},
        },
        "ping": {"entryPoint": "health"},
        "api": {"dashboard": selected.get('dashboard', False)},
        "experimental": {
            "abortOnPluginFailure": True,
            "plugins": {
                PLUGIN: {
                    "moduleName": "github.com/NX211/traefik-proxmox-provider",
                    "version": "v0.7.0",
                    "hash": PLUGIN_ARCHIVE_SHA256,
                }
            },
        },
        "providers": {
            "file": {"filename": "/etc/traefik/shared.yml", "watch": True},
            "plugin": {
                PLUGIN: {
                    "pollInterval": "30s",
                    "apiEndpoint": origin(selected["proxmox_url"], "proxmox_url"),
                    "apiTokenId": selected["proxmox_token_id"],
                    "apiToken": token,
                    "apiLogging": "info",
                    "apiValidateSSL": "true",
                }
            },
        },
        "certificatesResolvers": {
            "letsencrypt": {
                "acme": {
                    "email": selected["acme_email"],
                    "storage": "/var/traefik/certs/acme.json",
                    "dnsChallenge": {
                        "provider": "cloudflare",
                        "resolvers": dns_resolvers(selected["acme_dns_resolvers"]),
                        "propagation": {
                            "disableANSChecks": True,
                            "requireAllRNS": True,
                        },
                    },
                }
            }
        },
        "log": {"level": "INFO"},
        "accessLog": {},
    }
    return static
