"""Compile explicitly selected guest route checks and their actual prerequisites."""
import copy
import ipaddress

from urllib.parse import urlsplit

from component_errors import at
from component_sources import closed, identifier, require
import component_addresses
import component_auth
import component_connections
import component_monitoring
import component_traffic
import component_types as types
import routed_checks


def check_definition(value):
    require(isinstance(value, dict) and value.get('type') in ('page', 'auth-redirect'),
            'component.route-check')
    closed(value, ('type', 'contains') if value['type'] == 'page' else ('type', 'provider'),
           ('path', 'provider', 'oidc') if value['type'] == 'page' else ('path',))
    if 'oidc' in value:
        require(value['oidc'] is True, 'component.route-check')
    if 'contains' in value:
        types.text(value['contains'])
        require(len(value['contains']) <= 256 and not any(ord(c) < 32 for c in value['contains']),
                'component.route-check')
    component_auth._relative_path(value.get('path', '/'))
    if 'provider' in value:
        reference = value['provider']
        require(isinstance(reference, dict), 'component.reference')
        closed(reference, ('exposure',), ('domain',)) if 'exposure' in reference else closed(reference, ('domain',))
        require(all(identifier(item) for item in reference.values()), 'component.reference')


def guest_definition(value):
    require(isinstance(value, dict) and value.get('mode') in ('inline', 'deferred'),
            'component.route-check-mode')
    deferred = value['mode'] == 'deferred'
    closed(value, ('mode', 'source', 'name') if deferred else ('mode', 'source'))
    selected = closed(value['source'], ('address_group',) if deferred else ('interface',))
    require(all(identifier(item) for item in selected.values()), 'component.reference')
    if deferred:
        from component_workflows import label
        label(value['name'])


def _source(resolver, guest, selected):
    if selected['mode'] == 'deferred':
        values = component_addresses.selected(selected['source']['address_group'], resolver.address_groups)
        require(len(values) == 1, 'component.route-check-source')
        network = ipaddress.IPv4Network(values[0])
        require(network.prefixlen == 32, 'component.route-check-source')
        return str(network.network_address)
    interface = selected['source']['interface']
    require(interface in guest['interfaces'], 'component.reference')
    index = guest['interfaces'][interface]['slot']
    row = guest['provider_interfaces'][index]
    value = row.get('ipv4_endpoint') if row['ipv4'] == 'dhcp' else row['ipv4']
    require(value != 'manual', 'component.route-check-source')
    return str(ipaddress.IPv4Interface(value).ip)


def _flow(resolver, owner, selected, source, target, protocol):
    destination = target['guest']
    if selected['mode'] == 'inline':
        component_traffic.check(resolver.guests, owner, destination, source,
                                target['address'], protocol, target['port'])
    else:
        flow = component_traffic.Flow(source, target['address'], protocol, target['port'])
        guest = resolver.guests[destination]
        require(component_traffic.permits(guest['rules'], 'in', flow,
                component_traffic.nic(guest, target['address'])), 'component.traffic-ingress')


def oidc_check(resolver, exposures, owner, route, settings, row):
    """Compile the public sign-in contract from the same binding as the native client."""
    app = resolver.apps[route['target']['app']]
    require(settings['mode'] == 'deferred' and app['adapter'] == 'pegaprox'
            and 'authentication_resolved' in app, 'component.route-check-oidc')
    auth = app['authentication_resolved']
    client = auth['settings']
    if not client['oidc_enabled']:
        return None, set()
    definition = resolver.policy['authentication'][app['authentication']]
    reference = resolver.site['identity_providers'][definition['provider']]['origin']
    require('exposure' in reference, 'component.route-check-provider')
    provider = exposures.resolved[reference['exposure']]
    require(provider['type'] == 'http' and 'guest' in provider['target']
            and 'resolver' in provider, 'component.route-check-provider')
    ingress = provider['ingress_target']
    dns = [target for target in resolver.endpoints.values() if target.get('app') == provider['resolver']
           and target.get('protocol') == 'udp' and target.get('port') == 53]
    require(len(dns) == 1, 'component.route-check-resolver')
    source = row['source_address']
    _flow(resolver, owner, settings, source, ingress, 'tcp')
    _flow(resolver, owner, settings, source, dns[0], 'udp')
    for key in provider.get('middlewares', []):
        middleware = exposures.middlewares[key]
        if middleware['type'] in ('ip-allow-list', 'cloudflare-source'):
            require(any(ipaddress.IPv4Address(source) in ipaddress.ip_network(value)
                        for value in middleware['ranges']), 'component.route-check-source')
    auth['discovery_check'] = 'deferred'
    return {**row, 'mode': 'oidc', 'path': '/api/auth/oidc/login', 'contains': '',
            'auth_origins': [component_auth._origin(reference, exposures)],
            'oidc': {'issuer': client['oidc_authority'], 'client_id': client['oidc_client_id'],
                     'callback': client['oidc_redirect_uri'], **auth['oidc_endpoints'],
                     'resolver_address': dns[0]['address'], 'ingress_address': ingress['address']}}, {
                         provider['target']['guest'], ingress['guest'], dns[0]['guest']}


def bind(resolver, exposures, dependencies):
    """No route grants, name-based guest cases or implicit deferral decisions."""
    selected = {key: value['route_checks'] for key, value in resolver.guests.items()
                if 'route_checks' in value}
    if not selected:
        require(not any('check' in row for row in exposures.resolved.values()),
                'component.route-check-owner')
        return {}
    result, deferred = {}, {}
    graph = copy.deepcopy(dependencies['guest_dependencies'])
    for owner, settings in selected.items():
        with at('guests', owner, 'route_checks'):
            guest_definition(settings)
            guest = resolver.guests[owner]
            source = _source(resolver, guest, settings)
            routes = {key: row for key, row in exposures.resolved.items() if row['type'] == 'http'
                      and row['target'].get('guest') == owner}
            require(bool(routes), 'component.route-check-owner')
            rows, prerequisites = [], {owner}
            row_needs = []
            for name, route in routes.items():
                with at('exposures', name):
                    ingress = route['ingress_target']
                    require('resolver' in route, 'component.route-check-resolver')
                    resolver_id = route['resolver']
                    endpoints = [row for row in resolver.endpoints.values()
                                 if row.get('app') == resolver_id and row.get('protocol') == 'udp' and row.get('port') == 53]
                    require(len(endpoints) == 1, 'component.route-check-resolver')
                    dns = endpoints[0]
                    require(dns['protocol'] == 'udp' and dns['port'] == 53,
                            'component.route-check-resolver')
                    required = {ingress['guest'], dns['guest']}
                    forward = [exposures.middlewares[key]['target'] for key in route.get('middlewares', [])
                               if exposures.middlewares[key]['type'] == 'forward-auth']
                    check = route.get('check')
                    if check is None:
                        require(len(forward) == 1 and 'app' in forward[0], 'component.route-check')
                        providers = [key for key, row in exposures.resolved.items() if row['type'] == 'http'
                                     and row['target'].get('app') == forward[0]['app']]
                        require(len(providers) == 1, 'component.route-check-provider')
                        check = {'type': 'auth-redirect', 'provider': {'exposure': providers[0]}}
                    check_definition(check)
                    origins = []
                    if 'provider' in check:
                        origins.append(component_auth._origin(check['provider'], exposures))
                        for published in exposures.resolved.values():
                            if published['type'] == 'http' and any(host == check['provider'].get('domain')
                                    for host in [published['domain'], *published.get('aliases', [])]):
                                if 'guest' in published['target']:
                                    required.add(published['target']['guest'])
                        if 'exposure' in check['provider']:
                            provider = exposures.resolved[check['provider']['exposure']]['target']
                            if 'guest' in provider:
                                required.add(provider['guest'])
                    for provider in forward:
                        if 'guest' in provider:
                            required.add(provider['guest'])
                    prerequisites.update(required)
                    dns_source = source if settings['mode'] == 'deferred' else component_monitoring.source_address(guest, dns['address'])
                    _flow(resolver, owner, settings, source, ingress, 'tcp')
                    _flow(resolver, owner, settings, dns_source, dns, 'udp')
                    for key in route.get('middlewares', []):
                        middleware = exposures.middlewares[key]
                        if middleware['type'] in ('ip-allow-list', 'cloudflare-source'):
                            require(any(ipaddress.IPv4Address(source) in ipaddress.ip_network(value)
                                        for value in middleware['ranges']), 'component.route-check-source')
                    route_origins = ['https://' + host + (':' + str(ingress['port']) if ingress['port'] != 443 else '')
                                     for host in route['hosts']]
                    for host in route['hosts']:
                        rows.append({'exposure': name, 'host': host, 'port': ingress['port'],
                            'path': check.get('path', '/'), 'source_address': source,
                            'resolver_address': dns['address'], 'resolver_source': dns_source,
                            'ingress_address': ingress['address'], 'mode': check['type'],
                            'contains': check.get('contains', ''), 'route_origins': route_origins,
                            'auth_origins': origins})
                        row_needs.append(sorted({owner, *required}))
                    if 'oidc' in check:
                        # The native callback belongs to the canonical app origin, including on multi-alias routes.
                        app = resolver.apps[route['target']['app']]
                        require(app.get('origin', {}).get('exposure') == name, 'component.route-check-oidc')
                        primary = next(row for row in rows if row['exposure'] == name
                                       and row['host'] == urlsplit(app['origin_url']).hostname)
                        oidc, needed = oidc_check(resolver, exposures, owner, route, settings, primary)
                        if oidc:
                            rows.append(oidc)
                            prerequisites.update(needed)
                            row_needs.append(sorted({owner, *required, *needed}))
            routed_checks.validate(rows)
            result[owner] = {'mode': settings['mode'], 'rows': rows}
            if settings['mode'] == 'inline':
                graph[owner] = list(dict.fromkeys([*graph[owner], *sorted(prerequisites - {owner})]))
            if settings['mode'] == 'deferred':
                deferred[owner] = {'name': settings['name'], 'needs': sorted(prerequisites)}
                if any(row['mode'] == 'oidc' for row in rows):
                    deferred[owner]['row_needs'] = row_needs
    require(all(row['target'].get('guest') in selected for row in exposures.resolved.values()
                if 'check' in row), 'component.route-check-owner')
    component_connections._acyclic(graph)
    dependencies['guest_dependencies'] = graph
    return {'routed_checks': result, 'deferred_routed_checks': deferred}
