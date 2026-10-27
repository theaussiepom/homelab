#!/usr/bin/env python3
"""Preparation-only Bitwarden Lite rendering and bounded, read-only health checks."""
import argparse
import ipaddress
import json
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPHandler, HTTPSHandler, HTTPRedirectHandler, ProxyHandler

ENV_FILE = '/opt/homelab-app/runtime/bitwarden.env'
ENDPOINTS = ('/api/alive', '/api/config', '/identity/.well-known/openid-configuration')


def validate(cfg):
    """Keep credentials in a private runtime input and database restoration outside CD."""
    if set(cfg) - {'kind', 'guest_memory_mib', 'timezone', 'data_root', 'bitwarden', 'services'}:
        raise ValueError('Bitwarden preparation accepts only the declared non-secret preview inputs')
    settings = cfg.get('bitwarden', {})
    fields = {'schema', 'bind_address', 'runtime_env_file', 'database_provider',
              'restore_in_cd', 'deployment_enabled'}
    if (not isinstance(settings, dict) or set(settings) != fields
            or settings['schema'] != 'homelab-bitwarden-preparation-v1'
            or settings['runtime_env_file'] != ENV_FILE
            or settings['database_provider'] != 'mysql'
            or settings['restore_in_cd'] is not False
            or settings['deployment_enabled'] is not False):
        raise ValueError('Use the closed, disabled Bitwarden mysql preparation contract')
    try:
        address = ipaddress.IPv4Address(settings['bind_address'])
    except (ValueError, TypeError):
        raise ValueError('Select a literal private Bitwarden backend IPv4 address') from None
    if not any(address in ipaddress.ip_network(net) for net in
               ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '198.18.0.0/15')):
        raise ValueError('Select a private Bitwarden backend IPv4 address')
    services = cfg.get('services', {})
    if set(services) != {'bitwarden'}:
        raise ValueError('Bitwarden uses one application container and the separate shared MariaDB')
    service = services['bitwarden']
    if (set(service) - {'image', 'memory_mib', 'cpus', 'pids_limit', 'restart'}
            or service.get('image') != 'ghcr.io/bitwarden/lite:latest'
            or service.get('restart', 'no') != 'no'):
        raise ValueError('Use official Lite latest, default startup and the private env file')
    return str(address)


def configure(cfg, document):
    address = validate(cfg)
    service = document['services']['bitwarden']
    del service['network_mode']
    service['env_file'] = [ENV_FILE]
    service['ports'] = [f'{address}:8080:8080']
    # Retain the existing root HTTP readiness probe, suppressing response output.
    service['healthcheck'] = {'test': ['CMD-SHELL', 'curl -fsSo /dev/null http://localhost:8080']}
    service['volumes'] = [
        {'type': 'bind', 'source': f'/srv/homelab/data/bitwarden/{name}',
         'target': target, 'bind': {'create_host_path': False}}
        for name, target in [('data', '/etc/bitwarden'), ('logs', '/var/log/bitwarden')]]
    # Keep the image's default process identity.
    # No absent capture can silently become an empty vault directory.
    return document


def health(fetch, issuer):
    """A passing result proves only these unauthenticated response contracts."""
    observed_version = None
    for path in ENDPOINTS:
        status, body = fetch(path)
        if status != 200 or len(body) > 262144:
            raise ValueError('Bitwarden health response status or size differs')
        if path != '/api/alive':
            try:
                value = json.loads(body)
            except (ValueError, UnicodeError):
                raise ValueError('Bitwarden health response is not JSON') from None
            if not isinstance(value, dict):
                raise ValueError('Bitwarden health JSON must be an object')
            if path == '/api/config':
                observed_version = value.get('version')
                if (not isinstance(observed_version, str) or not observed_version.strip()
                        or len(observed_version) > 128
                        or any(ord(char) < 32 for char in observed_version)):
                    raise ValueError('Bitwarden must report its current API version')
            elif value.get('issuer') != issuer:
                raise ValueError('Bitwarden retained identity issuer differs')
    return {'status': 'passed', 'observed_version': observed_version,
            'scope': 'unauthenticated alive/config/identity only'}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def reader(origin):
    """Use verified HTTPS; plaintext is allowed only for a local synthetic probe."""
    parsed = urlsplit(origin)
    if (parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username
            or parsed.password or parsed.path or parsed.query or parsed.fragment
            or parsed.scheme == 'http' and parsed.hostname != '127.0.0.1'):
        raise ValueError('Use an HTTPS origin, or 127.0.0.1 HTTP for synthetic tests')
    opener = build_opener(ProxyHandler({}), HTTPHandler(), HTTPSHandler(), NoRedirect())
    def fetch(path):
        if path not in ENDPOINTS:
            raise ValueError('Only the three fixed unauthenticated endpoints are allowed')
        with opener.open(origin + path, timeout=8) as response:
            return response.status, response.read(262145)
    return fetch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--origin', required=True)
    parser.add_argument('--issuer', required=True)
    args = parser.parse_args()
    try:
        result = health(reader(args.origin), args.issuer)
    except (ValueError, OSError):
        parser.exit(1, 'Bitwarden health contract failed; inspect privately.\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
