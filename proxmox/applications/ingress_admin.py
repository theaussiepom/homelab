"""Prepare additive internal administration routes offline; never deploy them.

The output is a review artifact, deliberately outside the maintenance executor's
packet schemas. Activation requires a separately reviewed, current-state-bound
maintenance packet through the existing foundation CD path.
"""
import argparse
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

PRIVATE = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))


def require(value, message):
    if not value:
        raise ValueError(message)


def hostname(value):
    require(isinstance(value, str) and len(value) <= 253
            and len(value.split('.')) >= 2
            and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
                    for part in value.split('.')), 'Use literal lowercase DNS names')
    return value


def validate(value):
    require(isinstance(value, dict) and set(value) == {'schema', 'client_networks', 'routes'}
            and value['schema'] == 'homelab-ingress-admin-routes-v1', 'Use the closed admin routes schema')
    ranges = value['client_networks']
    require(isinstance(ranges, list) and 1 <= len(ranges) <= 16, 'Select explicit admin client networks')
    seen = set()
    for item in ranges:
        require(isinstance(item, str), 'Use canonical private IPv4 client CIDRs')
        network = ipaddress.ip_network(item, strict=True)
        require(network.version == 4 and str(network) == item and item not in seen
                and any(network.subnet_of(parent) for parent in PRIVATE),
                'Use unique canonical private IPv4 client CIDRs')
        seen.add(item)
    routes = value['routes']
    require(isinstance(routes, list) and 1 <= len(routes) <= 2, 'Select one or two admin routes')
    names, hosts = set(), set()
    for route in routes:
        require(isinstance(route, dict) and set(route) == {'name', 'host', 'url', 'server_name', 'root_cas'},
                'Select only explicit HTTPS routing and trust inputs')
        name = route['name']
        require(isinstance(name, str) and re.fullmatch('[a-z][a-z0-9-]{0,31}', name)
                and name not in names, 'Use unique admin route names')
        names.add(name)
        host = hostname(route['host']); hostname(route['server_name'])
        require(host not in hosts, 'Duplicate admin hostname')
        hosts.add(host)
        url = route['url']
        require(isinstance(url, str), 'Select an explicit HTTPS backend origin')
        parsed = urlsplit(url)
        require(parsed.scheme == 'https' and not parsed.username and not parsed.password
                and parsed.path == '' and not parsed.query and not parsed.fragment
                and parsed.port is not None and 1 <= parsed.port <= 65535,
                'Select a credential-free HTTPS IPv4 backend and explicit port')
        addr = ipaddress.ip_address(parsed.hostname)
        require(addr.version == 4 and any(addr in parent for parent in PRIVATE)
                and url == f'https://{addr}:{parsed.port}', 'Use an exact private IPv4 backend')
        roots = route['root_cas']
        require(isinstance(roots, list) and len(roots) <= 4, 'Select CA paths or the system trust store')
        paths = set()
        for path in roots:
            require(isinstance(path, str) and re.fullmatch(r'/etc/ssl/certs/[a-zA-Z0-9_-]+\.pem', path)
                    and path not in paths, 'Select already mounted public CA PEM paths')
            paths.add(path)
    return value


def merge(base, settings):
    """Return a copy with new routes, refusing namespace or Host collisions.

    Caller must separately compare Host rules from the discovery provider. This
    file-provider document cannot establish another provider's current routes.
    """
    validate(settings)
    require(isinstance(base, dict) and set(base) <= {'http', 'tls', 'tcp', 'udp'},
            'Supply only the current dynamic shared JSON document')
    result = copy.deepcopy(base)
    http = result.setdefault('http', {})
    require(isinstance(http, dict), 'Invalid shared HTTP configuration')
    for key in ('routers', 'services', 'middlewares', 'serversTransports'):
        require(isinstance(http.setdefault(key, {}), dict), 'Invalid shared HTTP namespace')
        require(all(isinstance(entry, dict) for entry in http[key].values()),
                'Invalid shared HTTP entry')
    require('admin-clients' not in http['middlewares'], 'Existing admin middleware requires review')
    http['middlewares']['admin-clients'] = {'ipAllowList': {'sourceRange': settings['client_networks'][:]}}
    # No ipStrategy or forwarded-header trust: use the directly connected client.
    for route in settings['routes']:
        name = 'admin-' + route['name']
        require(all(name not in http[key] for key in ('routers', 'services', 'serversTransports')),
                'Existing admin namespace requires review')
        require(not any(route['host'] in str(router.get('rule', '')) for router in http['routers'].values()),
                'Existing Host rule requires review')
        http['routers'][name] = {'rule': f"Host(`{route['host']}`)", 'entryPoints': ['websecure'],
                                 'tls': {'certResolver': 'letsencrypt'}, 'service': name,
                                 'middlewares': ['admin-clients']}
        http['services'][name] = {'loadBalancer': {'servers': [{'url': route['url']}],
            'passHostHeader': True, 'serversTransport': name}}
        transport = {'serverName': route['server_name'], 'insecureSkipVerify': False}
        if route['root_cas']:
            transport['rootCAs'] = route['root_cas'][:]
        http['serversTransports'][name] = transport
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--settings', type=Path, required=True)
    parser.add_argument('--shared', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raw = args.shared.read_bytes()
    after = merge(json.loads(raw), json.loads(args.settings.read_text()))
    encoded = (json.dumps(after, indent=2) + '\n').encode()
    proposal = {'schema': 'homelab-ingress-admin-offline-proposal-v1', 'deployable': False,
                'before_sha256': hashlib.sha256(raw).hexdigest(),
                'after_sha256': hashlib.sha256(encoded).hexdigest(), 'shared': after}
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(json.dumps(proposal, indent=2) + '\n')


if __name__ == '__main__':
    main()
