"""Typed Proxmox discovery notes and the bounded first-deployment plan policy."""
import ipaddress
import re
from urllib.parse import urlsplit

from plan import check_plan, RESOURCES
import foundation

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
        if (not isinstance(route, dict) or not {'name', 'host', 'url'} <= set(route)
                or set(route) - {'name', 'host', 'url', 'login', 'aliases'}):
            raise ValueError('Use only name, host and url plus the optional typed login in a discovery route')
        name, host, url = route['name'], route['host'], route['url']
        if not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', name):
            raise ValueError('Use a literal discovery service name')
        aliases = route.get('aliases', [])
        if not isinstance(aliases, list) or len(aliases) > 8:
            raise ValueError('Route aliases must be a finite list')
        route_hosts = [host, *aliases]
        for selected_host in route_hosts:
            if (not isinstance(selected_host, str) or len(selected_host) > 253 or '.' not in selected_host
                    or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                           for label in selected_host.split('.'))):
                raise ValueError('Use a literal fully qualified route hostname')
        if name in names or len(set(route_hosts)) != len(route_hosts) or hosts.intersection(route_hosts):
            raise ValueError('Discovery names and hostnames must be unique within the guest')
        login, kind = route.get('login', 'own'), cfg.get('app', {}).get('kind')
        if (not isinstance(login, str) or login not in {'own', 'authentik', 'oidc', 'outpost'}
                or login == 'authentik' and (kind != 'automation' or name != 'node-red')
                or login == 'oidc' and (kind != 'automation' or name != 'node-red'
                                       or cfg['app'].get('node_red_authentication') != 'authentik-oidc')
                or login == 'outpost' and (kind != 'identity' or name != 'node-red-outpost')
                or name == 'node-red-outpost' and login != 'outpost'
                or kind == 'automation' and name == 'node-red' and login not in {'authentik', 'oidc'}):
            raise ValueError('Node-RED requires Authentik; only the identity outpost callback bypasses it')
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
        if login == 'outpost' and port != 9000:
            raise ValueError('The embedded outpost callback must use the identity backend on port9000')
        names.add(name); hosts.update(route_hosts)
        router, service = f'traefik.http.routers.{name}', f'traefik.http.services.{name}'
        host_rule = ' || '.join(f'Host(`{selected_host}`)' for selected_host in route_hosts)
        if len(route_hosts) > 1:
            host_rule = '(' + host_rule + ')'
        if login == 'outpost':
            host_rule += ' && PathPrefix(`/outpost.goauthentik.io/`)'
        if login == 'authentik':
            ingress = cfg.get('app', {}).get('ingress_foundation')
            if not isinstance(ingress, dict) or not ingress.get('authentik_url'):
                raise ValueError('Node-RED needs the selected ingress Authentik middleware settings')
            foundation.private_authentik_origin(ingress['authentik_url'])
        middleware = 'security-headers@file' + (',authentik@file' if login == 'authentik' else '')
        result.update({'traefik.enable': 'true', f'{router}.rule': host_rule,
                       f'{router}.priority': '100' if login == 'outpost' else '10',
                       f'{router}.service': name, f'{router}.entrypoints': 'websecure',
                       f'{router}.tls': 'true', f'{router}.tls.certresolver': 'letsencrypt',
                       f'{router}.middlewares': middleware,
                       f'{service}.loadbalancer.server.url': url.rstrip('/')})
    if cfg.get('app', {}).get('kind') == 'automation' and routes and names != {'homeassistant', 'node-red'}:
        raise ValueError('Automation discovery must select HA and the authenticated Node-RED route')
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
