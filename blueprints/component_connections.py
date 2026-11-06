"""Explicit app/stage readiness and account links, separate from value edges."""
import copy
import ipaddress
from component_errors import at
from component_sources import closed, identifier, require
import component_types as types

PRODUCERS = {'dns': {'pihole', 'unbound'}, 'mqtt': {'mqtt'},
             'postgresql': {'postgresql'}, 'mariadb': {'mariadb'}, 'influxdb': {'influxdb'}}
ACCOUNT_TYPES = {'postgresql-admin': ('postgresql', 'server-administration'),
                 'mariadb-admin': ('mariadb', 'server-administration'),
                 'mqtt-client': ('mqtt', 'read-write-all')}


def _acyclic(edges):
    finished = set()

    def visit(node, trail):
        require(node not in trail, 'component.readiness-cycle')
        if node not in finished:
            for target in edges[node]:
                visit(target, trail | {node})
            finished.add(node)
    for node in edges:
        visit(node, set())


def bind(resolver, exposures):
    apps, site, guests = resolver.apps, resolver.site, resolver.guests
    accounts, credential_ids, principals = {}, set(), set()
    for key, value in site['accounts'].items():
        with at('accounts', key):
            closed(value, ('adapter', 'owner', 'target', 'principal', 'credential', 'access', 'lifecycle'))
            require(value['adapter'] in ACCOUNT_TYPES and value['owner'] in apps
                    and value['credential'] in site['secret_sources'] and value['lifecycle'] == 'create-once')
            require(identifier(value['principal']), 'component.account-principal')
            kind, access = ACCOUNT_TYPES[value['adapter']]
            require(value['access'] == access and 'app' in value['target'])
            endpoint = resolver.endpoint(value['target'])
            require(endpoint.get('app') in apps and apps[endpoint['app']]['adapter'] == kind
                    and endpoint.get('protocol') == 'tcp', 'component.account-target')
            principal = (endpoint['app'], value['principal'])
            require(principal not in principals, 'component.account-principal-conflict')
            principals.add(principal)
            credential = site['secret_sources'][value['credential']]
            require(credential['type'] == 'generated' and credential['credential_id'] not in credential_ids,
                    'component.account-credential')
            credential_ids.add(credential['credential_id'])
            if kind == 'postgresql':
                require(value['principal'] not in {'all', 'public', 'none'} and
                        not value['principal'].startswith('pg_'), 'component.account-principal')
            accounts[key] = dict(copy.deepcopy(value), target_endpoint=copy.deepcopy(endpoint),
                                 credential_id=credential['credential_id'])
    app_edges = {name: [] for name in apps}
    guest_edges = {name: [] for name in guests}
    used_accounts = set()
    for app in apps.values():
        app['resolved_connections'] = {}
    for key, value in site['connections'].items():
        with at('connections', key):
            closed(value, ('consumer', 'target', 'source_interface'),
                   ('transport', 'account', 'credential', 'readiness', 'hostname'))
            closed(value['consumer'], ('app', 'connection'))
            consumer = value['consumer']['app']
            require(consumer in apps and identifier(value['consumer']['connection']), 'component.reference')
            app = apps[consumer]
            declarations = resolver.library['app_profiles'][app['profile']].get('connections', {})
            role = value['consumer']['connection']
            require(role in declarations and role not in app['resolved_connections'], 'component.connection-role')
            declaration = declarations[role]
            target = resolver.endpoint(value['target'])
            require('internal' not in target and 'address' in target and 'port' in target,
                    'component.connection-target')
            kind = declaration['type']
            require(target['protocol'] in (('tcp', 'udp') if kind == 'dns' else
                    ('http',) if kind in ('http', 'influxdb') else ('https',) if kind == 'https' else ('tcp',)),
                    'component.connection-target')
            if 'app' in target and kind in PRODUCERS:
                require(apps[target['app']]['adapter'] in PRODUCERS[kind], 'component.connection-target')
            require(value['source_interface'] in app['interfaces'], 'component.connection-source')
            source = app['interfaces'][value['source_interface']]
            if 'app' in target:
                try:
                    address = ipaddress.IPv4Address(target['address'])
                except ipaddress.AddressValueError:
                    require(False, 'component.connection-target-scope')
                if address.is_loopback:
                    require(target.get('guest') == app['guest'] and
                            source.get('scope') == 'guest-loopback', 'component.connection-target-scope')
            require('interface' in source or (source.get('scope') == 'guest-loopback' and
                    target.get('guest') == app['guest'] and target['address'] == '127.0.0.1'),
                    'component.connection-source')
            selected = dict(copy.deepcopy(value), type=kind, target=copy.deepcopy(target),
                            source_address=resolver.role_address(app, value['source_interface']))
            require(not ('account' in value and 'credential' in value), 'component.account-credential')
            if 'account' in value:
                require('interface' in source, 'component.connection-source')
                require(value['account'] in accounts, 'component.reference')
                account = accounts[value['account']]
                require(account['owner'] == consumer and account['target'] == value['target'] and
                        account['adapter'] in declaration.get('accounts', []), 'component.account-binding')
                selected['account'] = copy.deepcopy(account)
                used_accounts.add(value['account'])
            if 'credential' in value:
                credential = closed(value['credential'], ('principal', 'secret'))
                require(('external' in value['target'] or (kind == 'mqtt' and 'app' in target))
                        and identifier(credential['secret'])
                        and credential['secret'] in site['secret_sources'], 'component.account-credential')
                types.text(credential['principal'])
                require(site['secret_sources'][credential['secret']]['type'] in ('file', 'environment'),
                        'component.account-credential')
            if 'transport' in value:
                require(value['transport'] in resolver.policy['transport'], 'component.reference')
            if 'hostname' in value:
                selected['hostname'] = exposures.hostname(value['hostname'], target)
            if 'readiness' in value:
                require(value['readiness'] in declaration.get('readiness', []) and
                        'app' in target and target['app'] != consumer, 'component.readiness')
                producer = target['app']
                app_edges[consumer].append(producer)
                if app['guest'] != apps[producer]['guest']:
                    guest_edges[app['guest']].append(apps[producer]['guest'])
            app['resolved_connections'][role] = selected
    require(used_accounts == set(accounts), 'component.account-binding')
    for name, app in apps.items():
        declarations = resolver.library['app_profiles'][app['profile']].get('connections', {})
        require(all(not row['required'] or role in app['resolved_connections']
                    for role, row in declarations.items()), 'component.connection-required')
    for name, guest in guests.items():
        for requirement in guest.get('readiness', []):
            target = resolver.endpoint(requirement['target'])
            require(target.get('app') in apps and apps[target['app']]['guest'] != name,
                    'component.preparation-readiness')
            guest_edges[name].append(apps[target['app']]['guest'])
    app_edges = {key: list(dict.fromkeys(row)) for key, row in app_edges.items()}
    guest_edges = {key: list(dict.fromkeys(row)) for key, row in guest_edges.items()}
    _acyclic(app_edges)
    _acyclic(guest_edges)
    return {'accounts': accounts, 'app_dependencies': app_edges, 'guest_dependencies': guest_edges}
