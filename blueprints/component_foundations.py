"""Closed application capabilities that bind named, already validated components."""
import copy
import ipaddress
import re
from uuid import UUID
from urllib.parse import urlsplit

from component_errors import at
from component_sources import closed, identifier, require
import component_types as types

OWNED = {'renovate', 'homeassistant', 'unbound', 'pihole', 'authentik', 'traefik', 'mqtt',
         'mqtt_explorer', 'zabbix', 'music_assistant', 'postgresql', 'mariadb',
         'influxdb', 'zigbee2mqtt'}


def _line(value, maximum=4096, *, empty=False):
    require(isinstance(value, str) and (empty or value) and len(value) <= maximum
            and not any(c in value for c in '\r\n\x00'), 'component.property')
    return value


def _sql(value):
    require(isinstance(value, str) and re.fullmatch('[a-z][a-z0-9_]{0,62}', value)
            and value not in {'postgres', 'template0', 'template1'}, 'component.database')
    return value


def _digest(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'component.digest')


def physical(value):
    closed(value, ('app', 'interface'))
    require(all(identifier(row) for row in value.values()), 'component.reference')


def _database(value):
    closed(value, ('name', 'user'))
    for row in value.values():
        _sql(row)


def validate(adapter, value, *, partial=False):
    """Component unit boundary; references and required runtime bindings follow."""
    require(adapter in OWNED, 'component.adapter')
    if adapter == 'renovate':
        import component_renovate
        component_renovate.validate(value, partial=partial)
    elif adapter == 'unbound':
        closed(value, (), ('publish_port',))
        if 'publish_port' in value:
            types.integer(value['publish_port'], 1, 65535)
    elif adapter == 'homeassistant':
        closed(value, (), ('mdns',))
        if 'mdns' in value:
            closed(value['mdns'], ('interface', 'startup'))
            require(all(identifier(row) for row in value['mdns'].values()), 'component.reference')
    elif adapter == 'mqtt':
        closed(value, (), ('password_file',))
        if 'password_file' in value:
            require(isinstance(value['password_file'], str) and
                    re.fullmatch('/mosquitto/config/[A-Za-z0-9_.-]{1,100}', value['password_file'])
                    and value['password_file'].rsplit('/', 1)[1] not in ('.', '..'), 'component.property')
    elif adapter == 'mqtt_explorer':
        closed(value, () if partial else ('connection_name',), ('connection_name',) if partial else ())
        if 'connection_name' in value:
            _line(value['connection_name'], 100)
    elif adapter == 'authentik':
        closed(value, () if partial else ('database',), ('database', 'smtp', 'callbacks') if partial else ('smtp', 'callbacks'))
        if 'database' in value:
            _database(value['database'])
        if 'smtp' in value:
            row = closed(value['smtp'], ('host', 'port', 'use_tls', 'use_ssl', 'from', 'username'), ('timeout',))
            for key in ('host', 'from'):
                _line(row[key], 253)
            _line(row['username'], 256, empty=True)
            types.integer(row['port'], 1, 65535)
            require(type(row['use_tls']) is bool and type(row['use_ssl']) is bool
                    and not (row['use_tls'] and row['use_ssl']), 'component.property')
            if 'timeout' in row:
                types.integer(row['timeout'], 1, 300)
        if 'callbacks' in value:
            closed(value['callbacks'], ('evidence',))
            require(identifier(value['callbacks']['evidence']), 'component.reference')
    elif adapter == 'zabbix':
        closed(value, () if partial else ('database',), ('database',) if partial else ())
        if 'database' in value:
            _database(value['database'])
    elif adapter == 'postgresql':
        closed(value, (), ('client_access', 'application_database'))
        if 'application_database' in value:
            closed(value['application_database'], ('app',))
            require(identifier(value['application_database']['app']), 'component.reference')
        require(isinstance(value.get('client_access', []), list) and len(value.get('client_access', [])) <= 128,
                'component.database-access')
        for row in value.get('client_access', []):
            closed(row, ('source', 'database', 'user', 'method'))
            physical(row['source'])
            require(row['database'] == 'all' and row['user'] == 'all'
                    and row['method'] == 'scram-sha-256', 'component.database-access')
    elif adapter == 'zigbee2mqtt':
        closed(value, () if partial else ('adapter', 'mqtt_base_topic'),
               ('adapter', 'mqtt_base_topic', 'watchdog') if partial else ('watchdog',))
        if 'watchdog' in value:
            require(value['watchdog'] == 'default', 'component.property')
        if 'adapter' in value:
            require(isinstance(value['adapter'], str) and re.fullmatch('[a-z][a-z0-9_-]{0,62}', value['adapter']),
                    'component.property')
        if 'mqtt_base_topic' in value:
            require(isinstance(value['mqtt_base_topic'], str) and
                    re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9/_-]{0,127}', value['mqtt_base_topic']),
                    'component.property')
    elif adapter == 'traefik':
        closed(value, (), ('dashboard', 'provider', 'acme'))
        require(type(value.get('dashboard', False)) is bool, 'component.property')
        if 'provider' in value:
            row = closed(value['provider'], ('context', 'token_id'), ('discovery',))
            require(identifier(row['context']), 'component.reference')
            require(isinstance(row['token_id'], str) and
                    re.fullmatch(r'[^\s!]+@[^\s!]+![A-Za-z0-9_.-]+', row['token_id']), 'component.property')
            if 'discovery' in row:
                discovery = closed(row['discovery'], ('local_directory', 'mirror_directory', 'owner_sha256', 'guests'))
                for key in ('local_directory', 'mirror_directory'):
                    types.path(discovery[key])
                    require(discovery[key].endswith('/service-discovery'), 'component.property')
                require(discovery['local_directory'] != discovery['mirror_directory'], 'component.property')
                _digest(discovery['owner_sha256'])
                types.strings(discovery['guests'], ids=True)
                require(1 <= len(discovery['guests']) <= 32, 'component.property')
        if 'acme' in value:
            row = closed(value['acme'], ('email', 'resolvers'), ('propagation_timeout_seconds',))
            require(isinstance(row['email'], str) and re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', row['email']),
                    'component.property')
            require(isinstance(row['resolvers'], list) and 1 <= len(row['resolvers']) <= 3, 'component.property')
            for ref in row['resolvers']:
                types.endpoint(ref)
            if 'propagation_timeout_seconds' in row:
                types.integer(row['propagation_timeout_seconds'], 120, 2100)
    else:
        closed(value)


def _address(resolver, ref):
    physical(ref)
    require(ref['app'] in resolver.apps, 'component.reference')
    app = resolver.apps[ref['app']]
    require(ref['interface'] in app['interfaces'] and 'interface' in app['interfaces'][ref['interface']],
            'component.physical-role')
    value = resolver.role_address(app, ref['interface'])
    types.ip(value)
    selected = ipaddress.IPv4Address(value)
    require(not (selected.is_unspecified or selected.is_loopback or selected.is_multicast or selected.is_link_local),
            'component.physical-role')
    return value


def _callback_records(values):
    require(isinstance(values, list) and 1 <= len(values) <= 8, 'component.callback-evidence')
    seen = set()
    for row in values:
        closed(row, ('provider_id', 'application_id', 'client_id_sha256', 'provider_metadata_sha256',
                     'application_metadata_sha256', 'policy_metadata_sha256', 'existing_redirects', 'additions'))
        types.integer(row['provider_id'], 1)
        require(row['provider_id'] not in seen, 'component.callback-evidence')
        seen.add(row['provider_id'])
        try:
            require(isinstance(row['application_id'], str) and str(UUID(row['application_id'])) == row['application_id'],
                    'component.callback-evidence')
        except (ValueError, AttributeError):
            require(False, 'component.callback-evidence')
        for key in ('client_id_sha256', 'provider_metadata_sha256', 'application_metadata_sha256', 'policy_metadata_sha256'):
            _digest(row[key])
        require(isinstance(row['existing_redirects'], list) and 1 <= len(row['existing_redirects']) <= 20
                and isinstance(row['additions'], list) and 1 <= len(row['additions']) <= 4,
                'component.callback-evidence')
        urls = []
        for value in row['existing_redirects']:
            closed(value, ('matching_mode', 'url'))
            require(value['matching_mode'] == 'strict', 'component.callback-evidence')
            urls.append(value['url'])
        for index, url in enumerate([*urls, *row['additions']]):
            _line(url, 2048)
            parsed = urlsplit(url)
            require(parsed.scheme == 'https' and parsed.hostname and not parsed.username and not parsed.password
                    and not parsed.query and not parsed.fragment and '\\' not in url
                    and '?' not in url and '#' not in url
                    and not any(c.isspace() for c in url)
                    and (index < len(urls) or parsed.path == '/oauth2/callback'), 'component.callback-evidence')
            try:
                require(parsed.port is None or 1 <= parsed.port <= 65535, 'component.callback-evidence')
            except ValueError:
                require(False, 'component.callback-evidence')
        require(len(set([*urls, *row['additions']])) == len(urls) + len(row['additions']), 'component.callback-evidence')
    return copy.deepcopy(values)


def bind(resolver):
    for app_id, app in resolver.apps.items():
        if app['adapter'] not in OWNED:
            continue
        with at('apps', app_id, 'properties'):
            adapter, props = app['adapter'], app['properties']
            validate(adapter, props)
            values = {}
            if adapter == 'pihole':
                values['dns_records'] = copy.deepcopy(getattr(resolver, 'exposure_values', {}).get(
                    'dns_records', {}).get(app_id, {}))
            if adapter in ('authentik', 'zabbix'):
                database = app['resolved_connections'].get('database')
                require(database is not None and database['type'] == 'postgresql'
                        and database['target']['port'] == 5432, 'component.database-binding')
                values['database'] = dict(props['database'], host=database['target']['address'], port=5432)
                import component_monitoring
                owned_monitoring = adapter == 'zabbix' and component_monitoring.server(resolver) == app_id
                required = {'secret_key', 'postgresql_password'} if adapter == 'authentik' else (
                    set() if owned_monitoring else {'database_password'})
                require(required <= set(app['secret_bindings']), 'component.secret-required')
                if owned_monitoring:
                    require('database_password' not in app['secret_bindings'], 'component.secret-conflict')
                    values['database_credential'] = {'type': 'monitoring-owned', 'server': app_id}
                if 'callbacks' in props:
                    key = props['callbacks']['evidence']
                    require(key in resolver.site['evidence'] and
                            resolver.site['evidence'][key]['type'] == 'identity-callbacks', 'component.callback-evidence')
                    values['allowed_callback_additions'] = _callback_records(resolver.site['evidence'][key]['document'])
            if adapter == 'postgresql':
                values['client_access'] = []
                seen = set()
                for row in props.get('client_access', []):
                    address = _address(resolver, row['source'])
                    require(address not in seen, 'component.database-access')
                    seen.add(address)
                    values['client_access'].append(dict(source_address=address, **{k: row[k] for k in ('database', 'user', 'method')}))
            if adapter == 'mqtt':
                require('probe' in app['secret_bindings'] and app['secret_bindings']['probe']['type'] == 'file',
                        'component.secret-required')
                values['probe_credential_file'] = app['secret_bindings']['probe']['path']
            if adapter == 'mqtt_explorer':
                require('origin_url' in app and 'outpost' in app['resolved_connections'], 'component.authentication-required')
                outpost = app['resolved_connections']['outpost']
                target = outpost['target']
                require(outpost['type'] == 'http' and target['protocol'] == 'http' and target['port'] == 9000,
                        'component.authentication')
                require('app' not in target or resolver.apps[target['app']]['adapter'] == 'authentik',
                        'component.authentication')
                values['authentik_outpost_url'] = 'http://' + target['address'] + ':9000'
                broker = app['resolved_connections'].get('broker')
                require(broker is not None and broker['type'] == 'mqtt' and broker['target']['port'] == 1883
                        and 'hostname' in broker and ('account' in broker or 'credential' in broker),
                        'component.broker-binding')
                values['broker'] = copy.deepcopy(broker)
                if 'account' in broker:
                    producer = resolver.apps[broker['target']['app']]
                    require('password_file' in producer['properties'], 'component.broker-binding')
                    values['broker']['password_file'] = producer['properties']['password_file']
                    values['broker']['image'] = producer['software_selection']['images']['mqtt']['image']
            if adapter == 'zigbee2mqtt':
                require(app['lifecycle'] == 'retained', 'component.initialization-unsupported')
                require('coordinator' in app.get('devices', {}), 'component.device-required')
                serial = resolver.site['devices'][app['devices']['coordinator']]
                broker = app['resolved_connections'].get('broker')
                require(broker is not None and broker['type'] == 'mqtt' and broker['target']['port'] == 1883,
                        'component.broker-binding')
                target = resolver.endpoint({'app': app_id, 'endpoint': 'web_endpoint'})
                require(target['protocol'] == 'http', 'component.reference')
                hostname = broker.get('hostname', broker['target']['address'])
                values.update(serial_device=serial['path'], bind_address=target['address'],
                              frontend_port=target['port'], adapter=props['adapter'],
                              mqtt_base_topic=props['mqtt_base_topic'], mqtt_server='mqtt://' + hostname + ':1883')
            if adapter == 'traefik':
                require('provider' in props and 'acme' in props, 'component.foundation-required')
                require({'cloudflare_dns_token', 'proxmox_token'} <= set(app['secret_bindings']), 'component.secret-required')
                provider = props['provider']
                require(provider['context'] == resolver.guests[app['guest']]['context'], 'component.reference')
                context = resolver.site['contexts'][provider['context']]
                target = resolver.endpoint(context['api_endpoint'])
                values['provider'] = {'url': 'https://' + target['address'] + ':8006',
                    'token_id': provider['token_id'], 'ca_file': context['trust']['ca_file']}
                if 'discovery' in provider:
                    scope = copy.deepcopy(provider['discovery'])
                    require(all(key in resolver.guests and resolver.guests[key]['context'] == provider['context']
                                for key in scope['guests']), 'component.reference')
                    scope['guests'] = [resolver.guests[key]['identity']['vmid'] for key in scope['guests']]
                    values['provider']['discovery'] = scope
                values['acme'] = copy.deepcopy(props['acme'])
                addresses = []
                for ref in props['acme']['resolvers']:
                    endpoint = resolver.endpoint(ref)
                    require(endpoint.get('protocol') in ('udp', 'tcp') and endpoint.get('port') == 53,
                            'component.dns-endpoint')
                    types.ip(endpoint.get('address'))
                    address = endpoint['address'] + ':53'
                    require(address not in addresses, 'component.dns-endpoint')
                    addresses.append(address)
                values['acme']['resolvers'] = addresses
                values['route_ca_files'] = {}
                routes = getattr(resolver, 'exposure_values', {}).get('routes', {}).get(app_id, {})
                middleware = getattr(resolver, 'exposure_values', {}).get('middlewares', {})
                cloudflare = any(middleware[key]['type'] == 'cloudflare-source'
                                 for row in routes.values() for key in row.get('middlewares', []))
                if cloudflare:
                    require('cloudflare_origin_token' in app['secret_bindings'], 'component.secret-required')
                    values['cloudflare'] = True
                require(all(resolver.policy['tls'][row['tls']]['resolver'] == 'letsencrypt'
                            for row in routes.values()), 'component.tls-resolver-unsupported')
                transports = getattr(resolver, 'authentication_values', {}).get('transports', {})
                for key in sorted({row['transport'] for row in routes.values() if 'transport' in row}):
                    require(key in transports, 'component.reference')
                    if 'ca_file' in transports[key]:
                        values['route_ca_files'][key] = {
                            'source': transports[key]['ca_file'], 'filename': 'route-' + key + '.pem'}
                    if 'certificate' in transports[key]:
                        values.setdefault('route_ca_certificates', {})[key] = {
                            'certificate': transports[key]['certificate'],
                            'filename': 'route-' + key + '.pem'}
            app['settings'] = values
