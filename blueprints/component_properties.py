"""Inert closed property binding for five independent app adapters.

Source only: no secret contents, target calls, rendering, account creation or
input materialization. Other adapters remain the foundation owner's dispatcher.
"""
import copy
import ipaddress
import re

from component_errors import at
from component_sources import closed, identifier, named, require
import component_types as types
from component_exposures import host

ADAPTERS = {'cloudbeaver', 'bitwarden', 'pegaprox', 'winet', 'node_red'}
FIELDS = {'cloudbeaver': ('server_name', 'recovery_admin', 'heap_mib', 'auth_headers',
                          'connections'),
          'bitwarden': ('issuer', 'database_name', 'data_uid', 'data_gid'),
          'pegaprox': ('trusted_proxy',), 'winet': ('mqtt_prefix',), 'node_red': ()}


def _single(value, maximum=100, *, empty=False):
    require(isinstance(value, str) and (bool(value) or empty) and len(value) <= maximum
            and not any(c in value for c in '\r\n\x00'), 'component.properties')


def _jdbc(value):
    # Reuse the existing closed official-artifact contract without fetching it.
    import cloudbeaver
    try:
        cloudbeaver.jdbc({'managed_connections': {'selected': {'driver': 'mariadb'}}, 'mariadb_jdbc': value})
    except (ValueError, TypeError, KeyError):
        require(False, 'component.properties')


def validate(adapter, properties, *, partial=False):
    require(isinstance(adapter, str) and adapter in ADAPTERS and type(partial) is bool,
            'component.properties')
    optional = ('mariadb_jdbc',) if adapter == 'cloudbeaver' else ()
    fields = FIELDS[adapter]
    closed(properties, () if partial else fields, (*fields, *optional) if partial else optional)
    if adapter == 'cloudbeaver':
        if 'server_name' in properties:
            _single(properties['server_name'])
        if 'recovery_admin' in properties:
            require(isinstance(properties['recovery_admin'], str) and
                    re.fullmatch('[a-z][a-z0-9_-]{2,63}', properties['recovery_admin']), 'component.properties')
        if 'heap_mib' in properties:
            types.integer(properties['heap_mib'], 256, 16384)
        if 'auth_headers' in properties:
            headers = closed(properties['auth_headers'], ('user', 'team'))
            require(all(isinstance(v, str) and re.fullmatch('X-[A-Za-z][A-Za-z0-9-]{0,60}', v)
                        for v in headers.values()) and len({v.lower() for v in headers.values()}) == 2
                    and not {v.lower() for v in headers.values()} & {'x-forwarded-for', 'x-forwarded-proto',
                        'x-forwarded-host', 'x-forwarded-port', 'x-real-ip'}, 'component.properties')
        if 'connections' in properties:
            values = named(properties['connections'])
            require(1 <= len(values) <= 24, 'component.properties')
            for value in values.values():
                closed(value, ('name', 'database'), ('sslmode',))
                _single(value['name'])
                _single(value['database'], 128, empty=True)
                if 'sslmode' in value:
                    require(value['sslmode'] in ('disable', 'prefer', 'require'), 'component.properties')
        if 'mariadb_jdbc' in properties:
            _jdbc(properties['mariadb_jdbc'])
    elif adapter == 'bitwarden':
        if 'issuer' in properties:
            closed(properties['issuer'], ('protocol', 'domain'))
            require(identifier(properties['issuer']['domain']), 'component.reference')
            require(properties['issuer']['protocol'] in ('http', 'https'), 'component.properties')
        if 'database_name' in properties:
            require(isinstance(properties['database_name'], str) and
                    re.fullmatch('[A-Za-z0-9_]+', properties['database_name']), 'component.properties')
        for field in ('data_uid', 'data_gid'):
            if field in properties:
                types.integer(properties[field], 1)
    elif adapter == 'pegaprox' and 'trusted_proxy' in properties:
        closed(properties['trusted_proxy'], ('app', 'interface'))
        require(all(identifier(v) for v in properties['trusted_proxy'].values()), 'component.reference')
    elif adapter == 'winet' and 'mqtt_prefix' in properties:
        require(isinstance(properties['mqtt_prefix'], str) and
                re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9/_-]{0,127}', properties['mqtt_prefix']),
                'component.properties')
    return copy.deepcopy(properties)


def _connection(app, role, kind):
    require(role in app['resolved_connections'], 'component.reference')
    value = app['resolved_connections'][role]
    require(value['type'] == kind, 'component.properties')
    target = value['target']
    types.ip(target['address']) if kind in ('postgresql', 'mariadb') else host(target['address'])
    types.integer(target['port'], 1, 65535)
    return value


def _file(resolver, app, role):
    require(role in app.get('secrets', {}) and app['secrets'][role] in resolver.site['secret_sources'],
            'component.reference')
    value = resolver.site['secret_sources'][app['secrets'][role]]
    require(value['type'] == 'file', 'component.properties')
    types.path(value['path'])
    return value['path']


def _origin(app):
    require(isinstance(app.get('origin_url'), str) and app['origin_url'].startswith('https://'),
            'component.origin')
    # The common exposure binder owns origin validation/ownership, not a second
    # URL parser or app-specific domain copy here.
    return app['origin_url']


def _cloudbeaver(resolver, app, value):
    require(app['lifecycle'] in ('retained', 'fresh'), 'component.lifecycle')
    result = {key: copy.deepcopy(value[key]) for key in
              ('server_name', 'recovery_admin', 'heap_mib', 'auth_headers')}
    result.update(bind_address=resolver.role_address(app, 'web_interface'), public_url=_origin(app),
                  connections={}, managed_connections={})
    for role, metadata in value['connections'].items():
        require(role in app['resolved_connections'], 'component.reference')
        connection = app['resolved_connections'][role]
        kind = connection['type']
        require(kind in ('postgresql', 'mariadb'), 'component.properties')
        connection = _connection(app, role, kind)
        require(connection['target']['port'] == {'postgresql': 5432, 'mariadb': 3306}[kind],
                'component.properties')
        managed = 'account' in connection
        require(('sslmode' in metadata) == (kind == 'postgresql' and not managed), 'component.properties')
        selected = dict(copy.deepcopy(metadata), driver=kind, host=connection['target']['address'],
                        port=connection['target']['port'])
        if managed:
            # Preserve the already resolved owned account for the F native
            # account binder. Never manufacture its owner tuple or credential.
            selected['account'] = copy.deepcopy(connection['account'])
        result['managed_connections' if managed else 'connections'][role] = selected
    require(len(result['connections']) <= 16 and len(result['managed_connections']) <= 8
            and 1 <= len(result['connections']) + len(result['managed_connections']) <= 24,
            'component.properties')
    needs_jdbc = any(row['driver'] == 'mariadb' for row in result['managed_connections'].values())
    require(('mariadb_jdbc' in value) == needs_jdbc, 'component.properties')
    if needs_jdbc:
        result['mariadb_jdbc'] = copy.deepcopy(value['mariadb_jdbc'])
    return result


def _bitwarden(resolver, app, value):
    require(app['lifecycle'] == 'retained', 'component.lifecycle')
    _file(resolver, app, 'runtime_environment')
    database = _connection(app, 'database', 'mariadb')
    require(database['target']['port'] == 3306, 'component.properties')
    domain = value['issuer']['domain']
    require(domain in resolver.site['domains'], 'component.reference')
    issuer = value['issuer']['protocol'] + '://' + host(resolver.site['domains'][domain])
    public = _origin(app)
    runtime = {'schema': 'homelab-bitwarden-runtime-v2', 'public_origin': public, 'issuer': issuer}
    settings = {'schema': 'homelab-bitwarden-runtime-v2',
        'bind_address': resolver.role_address(app, 'web_interface'),
        'database_server': database['target']['address'], 'database_provider': 'mysql',
        'database_name': value['database_name'], 'data_uid': value['data_uid'], 'data_gid': value['data_gid']}
    return {'runtime': runtime, 'settings': settings}


def _pegaprox(resolver, app, value):
    selected = value['trusted_proxy']
    require(selected['app'] in resolver.apps, 'component.reference')
    producer = resolver.apps[selected['app']]
    require(producer['adapter'] == 'traefik' and selected['interface'] in producer['interfaces']
            and 'interface' in producer['interfaces'][selected['interface']], 'component.properties')
    address = resolver.role_address(producer, selected['interface'])
    types.ip(address)
    source = ipaddress.IPv4Address(address)
    require(source.is_private and not (source.is_unspecified or source.is_loopback or source.is_link_local
            or source.is_multicast) and address != resolver.role_address(app, 'web_interface'), 'component.properties')
    return {'trusted_proxy': address + '/32', 'database_key_source': _file(resolver, app, 'database_key')}


def _winet(resolver, app, value):
    broker = _connection(app, 'broker', 'mqtt')
    inverter = _connection(app, 'inverter', 'https')
    require(broker['target']['port'] == 1883 and inverter['target']['port'] == 443,
            'component.properties')
    types.ip(inverter['target']['address'])
    address = ipaddress.IPv4Address(inverter['target']['address'])
    require(not (address.is_unspecified or address.is_loopback or address.is_link_local
            or address.is_multicast), 'component.properties')
    hostname = broker.get('hostname', broker['target']['address'])
    host(hostname)
    return {'mqtt_prefix': value['mqtt_prefix'],
            'mqtt_server': 'mqtt://' + hostname + ':1883',
            'inverter_address': inverter['target']['address'],
            'configuration_file': _file(resolver, app, 'options')}


HANDLERS = {'cloudbeaver': _cloudbeaver, 'bitwarden': _bitwarden,
            'pegaprox': _pegaprox, 'winet': _winet, 'node_red': lambda r, a, v: {}}


def bind(resolver):
    result = {}
    for app_id, app in resolver.apps.items():
        if app['adapter'] not in ADAPTERS:
            continue
        with at('apps', app_id, 'properties'):
            value = validate(app['adapter'], app['properties'])
            result[app_id] = HANDLERS[app['adapter']](resolver, app, value)
    return result
