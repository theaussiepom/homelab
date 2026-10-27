"""Typed Proxmox discovery notes and the bounded first-deployment plan policy."""
import ipaddress
import re
from urllib.parse import urlsplit

from plan import check_plan, RESOURCES

PRIVATE_BACKENDS = tuple(ipaddress.IPv4Network(value) for value in
                         ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))


def labels(cfg):
    """Compile only public routing facts; profiles never supply raw Notes labels."""
    if 'routing_labels' in cfg.get('guest', {}):
        raise ValueError('Supply typed discovery_routes, never arbitrary guest routing labels')
    routes = cfg.get('app', {}).get('discovery_routes', [])
    if not isinstance(routes, list) or len(routes) > 16:
        raise ValueError('Discovery routes must be a finite list of at most 16 routes')
    names, hosts, result = set(), set(), {}
    addresses = {nic['ipv4'].split('/')[0] for nic in cfg.get('guest', {}).get('interfaces', [])}
    for route in routes:
        if not isinstance(route, dict) or set(route) != {'name', 'host', 'url'}:
            raise ValueError('Use only name, host and url in a discovery route')
        name, host, url = route['name'], route['host'], route['url']
        if not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', name):
            raise ValueError('Use a literal discovery service name')
        if (not isinstance(host, str) or len(host) > 253 or '.' not in host
                or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                       for label in host.split('.'))):
            raise ValueError('Use a literal fully qualified route hostname')
        if name in names or host in hosts:
            raise ValueError('Discovery names and hostnames must be unique within the guest')
        if not isinstance(url, str) or any(c.isspace() for c in url) or '\\' in url:
            raise ValueError('Use an explicit private backend HTTP origin')
        parsed = urlsplit(url)
        try:
            ip = ipaddress.IPv4Address(parsed.hostname)
            port = parsed.port
        except (ValueError, TypeError):
            raise ValueError('Use an explicit private backend HTTP origin') from None
        if (parsed.scheme != 'http' or parsed.username is not None or parsed.password is not None
                or parsed.path not in ('', '/') or parsed.query or parsed.fragment
                or port is not None and not 1 <= port <= 65535
                or not any(ip in network for network in PRIVATE_BACKENDS)
                or str(ip) not in addresses):
            raise ValueError('The private backend HTTP origin must select an interface on this guest')
        names.add(name); hosts.add(host)
        router, service = f'traefik.http.routers.{name}', f'traefik.http.services.{name}'
        result.update({'traefik.enable': 'true', f'{router}.rule': f'Host(`{host}`)',
                       f'{router}.service': name, f'{router}.entrypoints': 'websecure',
                       f'{router}.tls': 'true', f'{router}.tls.certresolver': 'letsencrypt',
                       f'{router}.middlewares': 'security-headers@file',
                       f'{service}.loadbalancer.server.url': url.rstrip('/')})
    return result


def check_merge_create_plan(value, node, vmid):
    """Admit a merge-triggered *new* guest, never convergence or a continuation.

    The original check_plan remains the guard for reviewed legacy plans. This
    narrower policy adds only automatic admission of the three fresh resources
    selected by an explicit morning merge; it cannot approve an existing guest.
    """
    check_plan(value, node, vmid)
    if not isinstance(node, str) or not node:
        raise ValueError('The selected Proxmox node must be known')
    if (value.get('errored') is True or value.get('complete') is False
            or value.get('applyable') is False or value.get('deferred_changes')
            or value.get('resource_drift')):
        raise ValueError('Automatic creation requires a complete plan without deferred changes or drift')
    for row in value['resource_changes']:
        change = row['change']
        key = RESOURCES[row['address']]
        after = change['after']
        expected_type = row['address'].split('.')[2]
        if (row.get('mode', 'managed') != 'managed' or row.get('type') != expected_type
                or change.get('actions') != ['create'] or change.get('before') is not None
                or row.get('previous_address') is not None or row.get('deposed') is not None
                or 'importing' in change or 'importing' in row
                or change.get('generated_config') is not None):
            raise ValueError('Automatic admission permits only three fresh creates, without import or adoption')
        if type(after.get(key)) is not int or after[key] != vmid or after.get('node_name') != node:
            raise ValueError('Every fresh resource must have the exact known guest and node identity')
        unknown = change.get('after_unknown', {})
        if not isinstance(unknown, dict) or unknown.get(key) or unknown.get('node_name'):
            raise ValueError('Automatic creation cannot defer the selected guest or node identity')
