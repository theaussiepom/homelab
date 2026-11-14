"""Render independent component applications into their actual Compose projects.

Only framework-owned adapter handlers emit service configuration. This consumes
engine input, never a user-supplied Compose overlay or a fixed guest-kind bundle.
"""
import copy
import ipaddress
import json
import re
from pathlib import PurePosixPath
import music_assistant as music
import unbound_startup
import winet as winet_runtime
import zigbee2mqtt as zigbee_runtime
import component_native
import bitwarden
import pegaprox
import foundation
import discovery
import cloudbeaver as community
import mqtt_explorer as explorer
import monitoring
from container_policy import restart_policy
from application_contract import runtime_files,ordered_services
from private_io import require

SCHEMA = 'homelab-component-runtime-v1'


def _name(value):
    require(isinstance(value, str) and re.fullmatch('[a-z0-9][a-z0-9_-]{0,127}', value),
            'Use a stable component runtime name')
    return value


def _positive(value):
    require(type(value) in (int, float) and value > 0, 'Use positive component container resources')
    return value


def _mount_path(value):
    require(isinstance(value, str) and value.startswith('/') and not value.startswith('//')
            and PurePosixPath(value).as_posix() == value and
            not any(part in ('.', '..') for part in value.split('/'))
            and not any(char in value for char in '$:\\')
            and not any(ord(char) < 32 or ord(char) == 127 for char in value),
            'Use literal confined component bind paths without interpolation')
    return value


def _validate_mounts(service):
    for mount in service.get('volumes', []):
        if isinstance(mount, str):
            fields = mount.split(':')
            require(len(fields) in (2, 3) and (len(fields) == 2 or fields[2] in ('ro', 'rw')),
                    'Use a declared component bind mount')
            _mount_path(fields[0]); _mount_path(fields[1])
        else:
            require(isinstance(mount, dict) and mount.get('type') == 'bind',
                    'Use a declared component bind mount')
            _mount_path(mount['source']); _mount_path(mount['target'])


def _image(selected, adapter):
    value = selected.get('image')
    if value == 'ghcr.io/koush/scrypted:latest':
        require(adapter == 'scrypted', 'Keep the declared latest image policy')
        return value, 'always'
    if value == 'ghcr.io/music-assistant/server:latest':
        require(adapter == 'music_assistant', 'Keep the declared latest image policy')
        return value, 'always'
    if isinstance(value, str) and re.fullmatch('sha256:[0-9a-f]{64}', value):
        require(isinstance(selected.get('archive'), str) and selected['archive'].startswith('/')
                and isinstance(selected.get('archive_sha256'), str)
                and re.fullmatch('[0-9a-f]{64}', selected['archive_sha256']),
                'Retain the selected image archive identity')
        return value, 'never'
    require(isinstance(value, str) and re.fullmatch('[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}', value),
            'Use the declared immutable component image')
    return value, 'missing'


def _service(app, service, guest):
    require(service in app['containers'] and service in app['software_selection']['images'],
            'Resolve every owned container image and resource requirement')
    settings = app['containers'][service]
    image, pull = _image(app['software_selection']['images'][service], app['adapter'])
    result = {'image': image, 'pull_policy': pull, 'restart': restart_policy({}),
              'mem_limit': str(_positive(settings.get('memory_mib'))) + 'm',
              'cpus': _positive(settings.get('cpu_limit')), 'pids_limit': _positive(settings.get('pids_limit')),
              'stop_grace_period': '60s',
              'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}},
              'environment': {'TZ': guest['timezone'].replace('$', '$$')}, 'volumes': []}
    for key in ('read_only', 'user', 'cap_drop', 'cap_add', 'tmpfs'):
        if key in settings:
            result[key] = copy.deepcopy(settings[key])
    if settings.get('no_new_privileges'):
        result['security_opt'] = ['no-new-privileges:true']
    return result


def _mounts(app, allowed, *, explicit_modes=()):
    result = []
    selected_paths = app.get('storage_paths', {})
    require(set(selected_paths) <= set(allowed), 'Mount only selected adapter storage roles')
    # Named source maps are canonicalized in packets. Ordering is the adapter's
    # runtime contract, never incidental YAML/JSON dictionary insertion order.
    for role in allowed:
        if role not in selected_paths:
            continue
        selected = selected_paths[role]
        require(selected['target'] == allowed[role], 'Mount only selected adapter storage roles')
        source = selected['source']
        _mount_path(source)
        _mount_path(selected['target'])
        result.append(source + ':' + selected['target'] + (
            ':ro' if selected['read_only'] else ':rw' if role in explicit_modes else ''))
    return result


def _ports(app, service):
    result = []
    listeners = [row for row in app['listeners'].values() if row['service'] == service and 'publish' in row]
    for listener in sorted(listeners, key=lambda row: (row['publish']['port'], row['port'], row['protocol'],
                                                       row['publication_address'])):
        address = listener['publication_address']
        require(isinstance(address, str) and str(ipaddress.IPv4Address(address)) == address,
                'Publish only the resolved component IPv4 address')
        require(listener['protocol'] in ('tcp', 'udp') and type(listener['port']) is int
                and 1 <= listener['port'] <= 65535 and type(listener['publish']['port']) is int
                and 1 <= listener['publish']['port'] <= 65535, 'Use the bounded component listener')
        selected = f"{address}:{listener['publish']['port']}:{listener['port']}/{listener['protocol']}"
        if selected not in result:
            result.append(selected)
    return result


def _aliases(app):
    """Only declared saved names follow their explicitly selected endpoints."""
    result, folded = {}, {}
    for connection in app.get('resolved_connections', {}).values():
        if 'hostname' not in connection:
            continue
        name, address = connection['hostname'], connection['target']['address']
        require(isinstance(name, str) and 0 < len(name) <= 253 and all(
                re.fullmatch('[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?', label)
                for label in name.split('.'))
                and isinstance(address, str) and str(ipaddress.IPv4Address(address)) == address,
                'Derive only the selected endpoint hostname alias')
        key = name.lower()
        require(key not in folded or folded[key] == address, 'Saved endpoint hostname aliases conflict')
        folded[key] = address
        result[name] = address
    return result


def _homeassistant(app, guest):
    service = _service(app, 'homeassistant', guest)
    service['network_mode'] = 'host'
    service['volumes'] = _mounts(app, {'config': '/config', 'startup': '/startup',
        'media': '/media', 'community': '/hacsfiles'}, explicit_modes=('startup', 'media', 'community'))
    aliases = _aliases(app)
    if aliases:
        service['extra_hosts'] = aliases
    props = app.get('properties', {})
    require(set(props) <= {'mdns'}, 'Use only supported Home Assistant properties')
    if 'mdns' in props:
        selected = props['mdns']
        require(app['lifecycle'] == 'retained' and set(selected) == {'interface', 'startup'}
                and selected['interface'] in app['role_addresses']
                and selected['startup'] in app['storage_paths']
                and app['storage_paths'][selected['startup']]['target'] == '/startup'
                and app['storage_paths'][selected['startup']]['read_only'] is True
                and service.get('cap_add') == ['NET_ADMIN'],
                'Bind the retained mDNS capability to its exact role and startup mount')
        service['environment']['HOMELAB_HA_IPV4'] = app['role_addresses'][selected['interface']]
        service['entrypoint'] = ['/bin/sh', '-c', '/startup/mdns-route.sh && exec /init']
        service['command'] = None
    else:
        require(not service.get('cap_add') and 'startup' not in app.get('storage_paths', {}),
                'Plain Home Assistant does not select the retained mDNS capability')
    return {'homeassistant': service}


def _mqtt(app, guest):
    service = _service(app, 'mqtt', guest)
    service['network_mode'] = 'host'
    service['volumes'] = _mounts(app, {'config': '/mosquitto/config',
        'data': '/mosquitto/data', 'log': '/mosquitto/log'})
    require(set(app.get('storage_paths', {})) == {'config', 'data', 'log'},
            'Bind the broker config, data and log roles explicitly')
    return {'mqtt': service}


def _runtime_mount(app, filename, target):
    require(filename in runtime_files(app), 'Mount only a selected owned runtime leaf')
    root = app['identity']['runtime_directory']
    require(root == '/opt/homelab-app/runtime' or
            re.fullmatch('/opt/homelab-app/runtime/[a-z0-9_-]+(?:/[a-z0-9_-]+)*', root),
            'Use the owned application runtime directory')
    source = _mount_path(root + '/' + filename)
    _mount_path(target)
    return {'type': 'bind', 'source': source, 'target': target,
            'read_only': True, 'bind': {'create_host_path': False}}


def _authentik(app, guest):
    require({'secret_key', 'postgresql_password'} <= set(app['secret_bindings']),
            'Bind the existing Authentik runtime secret roles')
    settings = app['settings']['database']
    env = {'AUTHENTIK_SECRET_KEY': 'file:///run/secrets/authentik-secret-key',
        'AUTHENTIK_POSTGRESQL__HOST': settings['host'],
        'AUTHENTIK_POSTGRESQL__USER': settings['user'],
        'AUTHENTIK_POSTGRESQL__NAME': settings['name'],
        'AUTHENTIK_POSTGRESQL__PASSWORD': 'file:///run/secrets/postgresql-password',
        'AUTHENTIK_REDIS__HOST': app['identity']['services']['redis']}
    smtp = app['properties'].get('smtp')
    if smtp:
        keys = {'host': 'HOST', 'port': 'PORT', 'use_tls': 'USE_TLS', 'use_ssl': 'USE_SSL',
                'from': 'FROM', 'username': 'USERNAME', 'timeout': 'TIMEOUT'}
        for key, value in smtp.items():
            env['AUTHENTIK_EMAIL__' + keys[key]] = str(value).lower() if type(value) is bool else str(value)
    if 'smtp_password' in app['secret_bindings']:
        env['AUTHENTIK_EMAIL__PASSWORD'] = 'file:///run/secrets/smtp-password'
    result = {}
    allowed = {'media': '/media', 'templates': '/templates', 'certs': '/certs', 'redis': '/data'}
    require(set(app.get('storage_paths', {})) == set(allowed), 'Bind Authentik persistent storage roles')
    for name in ('server', 'worker', 'redis'):
        service = _service(app, name, guest)
        roles = ('redis',) if name == 'redis' else ('media', 'templates', 'certs') if name == 'worker' else ('media', 'templates')
        selected = dict(app, storage_paths={key: app['storage_paths'][key] for key in roles})
        service['volumes'] = _mounts(selected, {key: allowed[key] for key in roles})
        if name == 'redis':
            service['command'] = ['--save', '60', '1', '--loglevel', 'warning']
            service['healthcheck'] = {'test': ['CMD-SHELL', 'redis-cli ping | grep -qx PONG'],
                'start_period': '20s', 'interval': '30s', 'retries': 5, 'timeout': '3s'}
        else:
            service['user'] = app['containers'][name].get('user', '1000')
            require(service['user'] in ('1000', '1000:1000'), 'Retain Authentik application UID/GID')
            service['command'] = name
            service['environment'].update({key: value.replace('$', '$$') for key, value in env.items()})
            service['depends_on'] = {app['identity']['services']['redis']: {'condition': 'service_healthy'}}
            names = {'secret_key': 'authentik-secret-key', 'postgresql_password': 'postgresql-password',
                     'smtp_password': 'smtp-password'}
            service['volumes'] += [_runtime_mount(app, names[key], '/run/secrets/' + names[key])
                                   for key in app['secret_bindings']]
        if name == 'server':
            service['ports'] = [port.removesuffix('/tcp') for port in _ports(app, name)]
        result[name] = service
    return result


def _unbound(app, guest):
    service = _service(app, 'unbound', guest)
    require(app['lifecycle'] != 'retained' or 'config' in app.get('storage_paths', {}),
            'Retain the explicit existing Unbound configuration binding')
    require(app['lifecycle'] != 'fresh' or not app.get('storage_paths'),
            'Fresh Unbound uses packaged config; an empty bind is not initialization')
    service['volumes'] = _mounts(app, {'config': '/opt/unbound/etc/unbound',
        'dev': '/opt/unbound/etc/unbound/dev', 'var': '/opt/unbound/etc/unbound/var',
        'control_key': '/opt/unbound/etc/unbound/unbound_control.key',
        'control_cert': '/opt/unbound/etc/unbound/unbound_control.pem',
        'server_key': '/opt/unbound/etc/unbound/unbound_server.key',
        'server_cert': '/opt/unbound/etc/unbound/unbound_server.pem'},
        explicit_modes=('dev', 'var', 'control_key', 'control_cert', 'server_key', 'server_cert'))
    service['ports'] = _ports(app, 'unbound')
    if app['lifecycle'] == 'fresh':
        service['entrypoint'] = unbound_startup.command(app['containers']['unbound']['memory_mib'],
                                                      app['containers']['unbound']['cpu_limit'])
        service['command'] = []
    return {'unbound': service}


def _pihole(app, guest):
    service = _service(app, 'pihole', guest)
    service['network_mode'] = 'host'
    service['volumes'] = _mounts(app, {'config': '/etc/pihole', 'database': '/ftl-db'},
                                explicit_modes=('database',))
    upstreams = [row['target'] for row in app.get('resolved_connections', {}).values() if row['type'] == 'dns']
    require(len(upstreams) == 1, 'Select one explicit managed or external Pi-hole upstream')
    upstream = upstreams[0]
    require(upstream['protocol'] in ('tcp', 'udp'), 'Select an explicit DNS upstream')
    service['environment'].update(FTLCONF_dhcp_active='false',
        FTLCONF_dns_upstreams=upstream['address'] + '#' + str(upstream['port']))
    if 'web_interface' in app.get('role_addresses', {}):
        address = foundation.address(app['role_addresses']['web_interface'])
        listener = app['listeners'].get('web_listener', {})
        require(listener.get('service') == 'pihole' and listener.get('namespace') == 'host'
                and listener.get('interface') == 'web_interface' and listener.get('bind') == 'interface'
                and listener.get('protocol') == 'tcp' and listener.get('port') == 80
                and listener.get('actual_bind') == address and 'publish' not in listener,
                'Bind Pi-hole web only to its selected web role')
        service['environment']['FTLCONF_webserver_port'] = address + ':80'
    return {'pihole': service}


def _scrypted(app, guest):
    require(not app.get('devices') and not app.get('properties', {}).get('devices'),
            'Scrypted software qualification has no graphics-device passthrough')
    require(set(app.get('storage_paths', {})) == {'data', 'recordings'},
            'Preserve both Scrypted state and recording bindings')
    sources = [PurePosixPath(_mount_path(app['storage_paths'][role]['source']))
               for role in ('data', 'recordings')]
    require(all(str(path) != '/' for path in sources) and sources[0] != sources[1]
            and sources[0] not in sources[1].parents and sources[1] not in sources[0].parents,
            'Keep Scrypted configuration and recordings in separate nonroot directories')
    for role, target in (('data', '/server/volume'), ('recordings', '/nvr')):
        row = app['storage_paths'][role]
        require(row['target'] == target and row['kind'] == 'directory'
                and row['read_only'] is False, 'Preserve writable Scrypted container paths')
    service = _service(app, 'scrypted', guest)
    require(service['image'] == 'ghcr.io/koush/scrypted:latest',
            'Preserve the selected unpinned Scrypted image')
    require(set(app['containers']['scrypted']) == {'memory_mib', 'cpu_limit', 'pids_limit', 'user'}
            and app['containers']['scrypted']['user'] == '0:0',
            'Preserve the Scrypted process identity and bounded resources')
    service.update(network_mode='host', user='0:0', restart='no',
                   memswap_limit=service['mem_limit'],
                   hostname=_name(app['identity']['runtime_id']),
                   container_name=_name(app['identity']['runtime_id']))
    service['environment'].update(SCRYPTED_NVR_VOLUME='/nvr', SCRYPTED_DOCKER_AVAHI='true',
                                  SCRYPTED_INSECURE_PORT='80', SCRYPTED_SECURE_PORT='443')
    # Retain /init and the upstream server command. Only the settings guard
    # runs first; it loads Level, never an NVR/plugin or graphics module.
    service['command'] = ['/bin/sh', '-ec',
        'node /opt/homelab-app/scrypted-datastore.js verify; '
        'ulimit -c 0; exec npm --prefix /server exec scrypted-serve']
    service['volumes'] = [
        {'type': 'bind', 'source': _mount_path(app['storage_paths'][role]['source']),
         'target': target, 'read_only': False, 'bind': {'create_host_path': False}}
        for role, target in (('data', '/server/volume'), ('recordings', '/nvr'))]
    service['volumes'].append({'type': 'bind',
        'source': '/opt/homelab-app/scrypted-datastore.js',
        'target': '/opt/homelab-app/scrypted-datastore.js', 'read_only': True,
        'bind': {'create_host_path': False}})
    return {'scrypted': service}


def _music_assistant(app, guest):
    """Render Music listeners while retaining the selected provider identity."""
    require(app['lifecycle'] == 'retained',
            'Fresh Music Assistant commissioning is not implemented')
    require(not app.get('properties'), 'Use only supported Music Assistant properties')
    selected = music.address(app.get('role_addresses', {}).get('web_interface'))
    stream = music.address(app['role_addresses'].get('stream_interface', selected))
    require(set(app.get('storage_paths', {})) == {'data'},
            'Bind only the existing Music Assistant data role')
    storage = app['storage_paths']['data']
    require(storage['target'] == '/data' and storage['kind'] == 'directory'
            and storage['read_only'] is False,
            'Keep the Music Assistant owned writable data mount')
    root = music.data_path(storage['source'])
    settings = app['containers']['music_assistant']
    require(set(settings) == {'memory_mib', 'cpu_limit', 'pids_limit'},
            'Retain the upstream Music Assistant process and security identity')
    listeners = app['listeners']
    require(len(listeners) == 2 and all(
        row['service'] == 'music_assistant' and row['namespace'] == 'host'
        and row['interface'] == ('stream_interface' if row['port'] == 8097 and 'stream_interface' in app['role_addresses'] else 'web_interface')
        and row['bind'] == 'interface' and row['protocol'] == 'tcp'
        and row['actual_bind'] == (stream if row['port'] == 8097 else selected)
        and 'publish' not in row for row in listeners.values())
        and {row['port'] for row in listeners.values()} == {8095, 8097},
        'Preserve the declared Music Assistant UI and player listeners')
    service = _service(app, 'music_assistant', guest)
    service['network_mode'] = 'host'
    options = {'stream_address': stream} if 'stream_interface' in app['role_addresses'] else {}
    music.configure_service(service, selected, data_root=root, **options)
    return {'music_assistant': service}



def _cloudbeaver(app, guest):
    require(isinstance(app.get('authentication_resolved'), dict)
            and app['authentication_resolved'].get('version') == 1,
            'Bind the selected CloudBeaver OIDC authentication capability')
    value = app['settings']
    require(len(value.get('connections', {})) + len(value.get('managed_connections', {})) > 0,
            'Select at least one explicit Community datasource')
    require(set(app.get('storage_paths', {})) == {'workspace'}, 'Bind the owned Community workspace')
    storage = app['storage_paths']['workspace']
    require(storage['kind'] == 'directory' and storage['read_only'] is False,
            'Keep the Community workspace writable and private')
    _mounts(app, {'workspace': '/opt/cloudbeaver/workspace'})
    floor = {'cloudbeaver': {'user': '8978:8978', 'cap_drop': ['ALL'], 'no_new_privileges': True},
             'auth_gateway': {'user': '65532:65532', 'cap_drop': ['ALL'], 'no_new_privileges': True, 'read_only': True}}
    for name, settings in app['containers'].items():
        require(name in floor and set(settings) <= {'memory_mib', 'cpu_limit', 'pids_limit', *floor[name]}
                and all(key not in settings or settings[key] == expected for key, expected in floor[name].items()),
                'Retain the Community process identities and privilege boundary')
    require(type(value['heap_mib']) is int
            and app['containers']['cloudbeaver']['memory_mib'] >= value['heap_mib'] + 512
            and app['containers']['auth_gateway']['memory_mib'] >= 128,
            'Reserve JVM native and gateway memory')
    require(all(row['service'] in {'cloudbeaver', 'auth_gateway'} and row['protocol'] == 'tcp'
                and row['namespace'] == 'app-network'
                and row['port'] == {'cloudbeaver': 8978, 'auth_gateway': 4180}[row['service']]
                for row in app['listeners'].values()), 'Keep the Community and gateway internal listeners')
    require(not _ports(app, 'cloudbeaver'), 'Do not publish the Community backend')
    ports = [row.removesuffix('/tcp') for row in _ports(app, 'auth_gateway')]
    require(len(ports) == 1, 'Publish only the owned authentication gateway')
    services = {name: _service(app, name, guest) for name in ('cloudbeaver', 'auth_gateway')}
    return community.service_configuration(value, services,
        mount=lambda name, target: _runtime_mount(app, name, target), workspace=storage['source'],
        server_service=_name(app['identity']['services']['cloudbeaver']), ports=ports)


def _mqtt_explorer(app, guest):
    require(isinstance(app.get('origin_url'), str) and app['origin_url'].startswith('https://')
            and isinstance(app.get('settings'), dict) and 'authentik_outpost_url' in app['settings'],
            'Require the selected authenticated HTTPS Explorer front door')
    broker = app['settings']['broker']
    require(broker.get('type') == 'mqtt' and broker['target']['port'] == 1883
            and 'hostname' in broker and ('account' in broker or 'credential' in broker),
            'Bind the explicitly selected saved broker connection and credential owner')
    require(set(app.get('storage_paths', {})) == {'data'}, 'Bind only the Explorer data role')
    storage = app['storage_paths']['data']
    require(storage['kind'] == 'directory' and storage['read_only'] is False,
            'Keep the owned Explorer profile data writable')
    _mounts(app, {'data': '/app/data'})
    for name, settings in app['containers'].items():
        user = {'mqtt_explorer': '1001:1001', 'explorer_gateway': '65532:65532'}.get(name)
        fixed = {'user': user, 'read_only': True, 'cap_drop': ['ALL'], 'no_new_privileges': True}
        require(user is not None and set(settings) <= {'memory_mib', 'cpu_limit', 'pids_limit', *fixed}
                and all(key not in settings or settings[key] == expected for key, expected in fixed.items()),
                'Keep the Explorer process identities and privilege boundary')
    require(all(row['service'] in {'mqtt_explorer', 'explorer_gateway'} and row['protocol'] == 'tcp'
                and row['namespace'] == 'app-network'
                and row['port'] == {'mqtt_explorer': 3000, 'explorer_gateway': 4180}[row['service']]
                for row in app['listeners'].values()), 'Keep the Explorer and gateway internal listeners')
    require(not _ports(app, 'mqtt_explorer'), 'Do not publish the unauthenticated Explorer backend')
    ports = [row.removesuffix('/tcp') for row in _ports(app, 'explorer_gateway')]
    require(len(ports) == 1, 'Publish only the owned authenticated Explorer gateway')
    value = {'public_url': app['origin_url'], 'broker_address': broker['target']['address'],
             'broker_connection': {'hostname': broker['hostname']}}
    services = {name: _service(app, name, guest) for name in ('mqtt_explorer', 'explorer_gateway')}
    return explorer.service_configuration(value, services,
        mount=lambda name, target: _runtime_mount(app, name, target), data_path=storage['source'],
        explorer_service=_name(app['identity']['services']['mqtt_explorer']), ports=ports)


def _zabbix(app, guest):
    settings = app['settings']
    database = settings['database']
    require(database['name'] not in {'postgres', 'template0', 'template1'}
            and database['user'] not in {'postgres', 'template0', 'template1'},
            'Select the owned monitoring database and role')
    owned = settings.get('database_credential')
    require((isinstance(owned, dict) and owned == {'type': 'monitoring-owned', 'server': app['id']}
             and 'database_password' not in app.get('secret_bindings', {}))
            or owned is None and 'database_password' in app.get('secret_bindings', {}),
            'Bind only the selected owned monitoring database credential')
    require(not app.get('storage_paths'), 'Monitoring runtime files are separately owned inputs')
    for name, selected in app['containers'].items():
        require(name in {'zabbix_server', 'zabbix_web'}
                and set(selected) == {'memory_mib', 'cpu_limit', 'pids_limit'},
                'Retain the monitoring image process and user defaults')
        require(app['software_selection']['images'][name]['image'] == monitoring.VERSIONS[name],
                'Use the tested matching monitoring images')
    require(all(row['service'] in {'zabbix_server', 'zabbix_web'} and row['protocol'] == 'tcp'
                and row['namespace'] == 'app-network'
                and row['port'] == {'zabbix_server': 10051, 'zabbix_web': 8080}[row['service']]
                for row in app['listeners'].values()), 'Preserve the monitoring server and web listeners')
    server_ports = [row.removesuffix('/tcp') for row in _ports(app, 'zabbix_server')]
    web_ports = [row.removesuffix('/tcp') for row in _ports(app, 'zabbix_web')]
    require(len(server_ports) == 1 and len(web_ports) >= 1, 'Publish the declared monitoring listeners')
    value = {'postgresql_host': database['host'], 'postgresql_database': database['name'],
             'postgresql_user': database['user']}
    if 'authentication_resolved' in app:
        value['saml'] = app['authentication_resolved']
    services = {name: _service(app, name, guest) for name in ('zabbix_server', 'zabbix_web')}
    return monitoring.service_configuration(value, services,
        mount=lambda name, target: _runtime_mount(app, name, target), timezone=guest['timezone'],
        server_service=_name(app['identity']['services']['zabbix_server']),
        server_ports=server_ports, web_ports=web_ports)


def _node_red(app, guest):
    """Render Node-RED without replacing its retained authentication wrappers."""
    require(not app.get('properties'), 'Use only supported Node-RED properties')
    service = _service(app, 'node_red', guest)
    require(len(app['listeners']) == 1 and all(row['service'] == 'node_red'
            and row['namespace'] == 'host' and row['protocol'] == 'tcp'
            and row['port'] == 1880 and row['bind'] in ('wildcard','interface') and 'publish' not in row
            for row in app['listeners'].values()), 'Keep the declared Node-RED native listener')
    service['network_mode'] = 'host'
    storage = app.get('storage_paths', {})
    retained = app['lifecycle'] == 'retained'
    require(retained or app['lifecycle'] == 'fresh', 'Select a supported Node-RED lifecycle')
    if next(iter(app['listeners'].values()))['bind'] == 'interface':
        require(retained, 'A bound Node-RED listener requires its retained settings wrapper')
        selected = music.address(app['role_addresses']['web_interface'])
        listener = next(iter(app['listeners'].values()))
        require(listener.get('interface') == 'web_interface' and listener.get('actual_bind') == selected,
                'Bind Node-RED only to its selected web role')
        service['environment']['NODE_RED_WEB_ADDRESS'] = selected
    if retained:
        require(set(storage) == {'data', 'config', 'settings', 'healthcheck'}
                and storage['settings']['read_only'] is True and storage['healthcheck']['read_only'] is True,
                'Retain the existing Node-RED settings and health wrappers')
        selected = app.get('authentication_resolved', {})
        require(set(selected) == {'identity_url', 'node_red_url', 'client_id', 'provider_slug'},
                'Retain the selected Node-RED OIDC metadata and existing strategy')
        require(service.get('user', 'node-red') == 'node-red', 'Keep the retained Node-RED process identity')
        service['user'] = 'node-red'
        service['entrypoint'] = ['./entrypoint.sh']
        service['command'] = ['--settings', '/runtime-settings.js']
        service['environment']['FLOWS'] = '/config/flows.json'
        mapping = {'identity_url': 'NODE_RED_IDENTITY_URL', 'node_red_url': 'NODE_RED_EXTERNAL_URL',
                   'client_id': 'NODE_RED_OIDC_CLIENT_ID', 'provider_slug': 'NODE_RED_OIDC_PROVIDER'}
        service['environment'].update({variable: selected[key].replace('$', '$$') for key, variable in mapping.items()})
    else:
        require(set(storage) == {'data'} and not app.get('authentication_resolved'),
                'Fresh public Node-RED does not select a retained strategy or wrapper')
    # The role map has no mount-order semantics. Retain the adapter's existing
    # order even after canonical runtime JSON sorts object keys.
    selected_storage = dict(app, storage_paths={role: storage[role]
        for role in ('data', 'config', 'settings', 'healthcheck') if role in storage})
    service['volumes'] = _mounts(selected_storage, {'data': '/data', 'config': '/config',
                                      'settings': '/runtime-settings.js', 'healthcheck': '/healthcheck.js'})
    aliases = _aliases(app)
    if aliases:
        service['extra_hosts'] = aliases
    # Existing per-phase NODE_RED_API_TOKEN is bound only by the private input
    # stage. Neither source rendering nor this handler reads/injects its value.
    return {'node_red': service}


def _winet(app, guest):
    require(set(app.get('properties', {})) == {'mqtt_prefix'}, 'Select only the WiNet discovery prefix')
    require(set(app['settings']) == {'configuration_file', 'inverter_address', 'mqtt_server', 'mqtt_prefix'}
            and app['settings']['mqtt_prefix'] == app['properties']['mqtt_prefix'],
            'Resolve the existing WiNet options and named endpoints')
    require(not app.get('storage_paths') and not app['listeners'],
            'WiNet uses its existing protected options input, not extra mounts or listeners')
    service = _service(app, 'winet', guest)
    require(not any(key in service for key in ('command', 'entrypoint', 'user', 'cap_add')),
            'Use the upstream WiNet process and identity')
    service['network_mode'] = 'host'
    service['volumes'] = [_runtime_mount(app, 'winet-options.json', '/data/options.json')]
    service['healthcheck'] = {'test': ['CMD', 'node', '-e', winet_runtime.HEALTH],
        'interval': '30s', 'timeout': '15s', 'retries': 3, 'start_period': '30s'}
    aliases = _aliases(app)
    if aliases:
        service['extra_hosts'] = aliases
    return {'winet': service}


def _zigbee2mqtt(app, guest):
    require(app['lifecycle'] == 'retained', 'Fresh Zigbee commissioning is not implemented')
    selected = zigbee_runtime.validate(app['settings'])
    require(set(app.get('storage_paths', {})) == {'data'}, 'Select the retained Zigbee data role')
    data = app['storage_paths']['data']
    require(data['target'] == '/app/data' and data['kind'] == 'directory' and data['read_only'] is False,
            'Keep the existing writable Zigbee data directory')
    mounts = _mounts(app, {'data': '/app/data'})
    require(mounts == [data['source'] + ':/app/data'], 'Keep the exact Zigbee data mount')
    service = _service(app, 'zigbee2mqtt', guest)
    if 'watchdog' in app.get('properties', {}):
        require(app['properties']['watchdog'] == 'default', 'Use only the default Zigbee watchdog')
        service['environment']['Z2M_WATCHDOG'] = 'default'
    require(not any(key in service for key in ('command', 'entrypoint', 'user', 'cap_add')),
            'Keep the upstream Zigbee process and coordinator configuration')
    require(len(app['listeners']) == 1 and all(row['service'] == 'zigbee2mqtt'
            and row['namespace'] == 'app-network' and row['protocol'] == 'tcp'
            and row['port'] == selected['frontend_port'] and row['bind'] == 'wildcard'
            for row in app['listeners'].values()), 'Bind the actual retained Zigbee frontend listener')
    ports = _ports(app, 'zigbee2mqtt')
    require(ports == [selected['bind_address'] + ':' + str(selected['frontend_port']) + ':'
                     + str(selected['frontend_port']) + '/tcp'], 'Publish the selected Zigbee backend only')
    device = selected['serial_device']
    service['devices'] = [device + ':' + device + ':rw']
    service['volumes'] = [{'type': 'bind', 'source': data['source'], 'target': '/app/data',
                          'bind': {'create_host_path': False}},
                         {'type': 'bind', 'source': device, 'target': '/dev/ttyACM0', 'read_only': False,
                          'bind': {'create_host_path': False}}]
    service['ports'] = ports
    service['healthcheck'] = {'test': ['CMD', 'node', '-e',
        "const h=require('http');const q=h.get('http://127.0.0.1:" + str(selected['frontend_port'])
        + "/',r=>process.exit(r.statusCode===200?0:1));q.setTimeout(3000,()=>{q.destroy();process.exit(1)});q.on('error',()=>process.exit(1))"],
        'start_period': '30s', 'interval': '5s', 'retries': 30, 'timeout': '4s'}
    aliases = _aliases(app)
    if aliases:
        service['extra_hosts'] = aliases
    return {'zigbee2mqtt': service}



def _bitwarden(app, guest):
    require(app['lifecycle'] == 'retained', 'Fresh Bitwarden commissioning is not implemented')
    value = app['settings']['settings']
    bitwarden.validate_settings(value)
    require(set(app['containers']) == {'bitwarden'} and
            set(app['containers']['bitwarden']) == {'memory_mib', 'cpu_limit', 'pids_limit'},
            'Retain the Bitwarden image process and user defaults')
    selected = app['software_selection']['images']['bitwarden']
    image = selected['image']
    require(isinstance(image, str) and
            re.fullmatch(r'ghcr\.io/bitwarden/lite(?::[A-Za-z0-9_.-]+)?@sha256:[0-9a-f]{64}', image)
            and not {'archive', 'archive_sha256'} & set(selected),
            'Select the immutable official Bitwarden image')
    require(set(app.get('storage_paths', {})) == {'data', 'logs'}, 'Bind the retained vault data and logs')
    require(all(row['kind'] == 'directory' and row['read_only'] is False
                for row in app['storage_paths'].values()), 'Keep the retained vault data directories writable')
    _mounts(app, {'data': '/etc/bitwarden', 'logs': '/var/log/bitwarden'})
    require(all(row['service'] == 'bitwarden' and row['namespace'] == 'app-network'
                and row['port'] == 8080 and row['protocol'] == 'tcp'
                for row in app['listeners'].values()), 'Keep the actual Bitwarden backend listener')
    ports = [row.removesuffix('/tcp') for row in _ports(app, 'bitwarden')]
    require(len(ports) == 1, 'Publish the declared Bitwarden backend')
    environment = app.get('private_environment', {})
    require(isinstance(environment, dict) and (bool(environment) or 'private_environment' not in app)
            and all(isinstance(key, str) and isinstance(item, str)
                    and not any(c in item for c in '\r\n\x00') for key, item in environment.items()),
            'Use only the admitted internal Bitwarden runtime environment')
    service = _service(app, 'bitwarden', guest)
    bitwarden.service_configuration(service, environment=environment, ports=ports,
        data_sources={key: row['source'] for key, row in app['storage_paths'].items()})
    return {'bitwarden': service}


def _pegaprox(app, guest):
    require('database_key' in app.get('secret_bindings', {}), 'Bind the selected existing PegaProx database key')
    settings = app['containers']['pegaprox']
    floor = {'read_only': True, 'cap_drop': ['ALL'], 'no_new_privileges': True,
             'tmpfs': ['/tmp:rw,nosuid,nodev,size=64m']}
    require(set(app['containers']) == {'pegaprox'} and
            set(settings) <= {'memory_mib', 'cpu_limit', 'pids_limit', *floor}
            and all(key not in settings or settings[key] == value for key, value in floor.items()),
            'Retain the PegaProx filesystem and privilege boundary')
    memory = pegaprox.positive(settings['memory_mib'], 'container_memory_mib', 1024)
    budget = pegaprox.positive(guest['memory_mib'], 'guest_memory_mib', 2048)
    cpus = pegaprox.positive(settings['cpu_limit'], 'cpus')
    pids = pegaprox.positive(settings['pids_limit'], 'pids_limit')
    require(type(memory) is int and type(budget) is int and type(pids) is int
            and cpus <= 2 and pids <= 512 and memory + 512 <= budget
            and guest['os_reserve_mib'] >= 512, 'Retain the bounded PegaProx resource and OS reserve policy')
    image = app['software_selection']['images']['pegaprox']['image']
    require(isinstance(image, str) and re.fullmatch(
        r'ghcr\.io/pegaprox/pegaprox(?::[A-Za-z0-9_.-]+)?@sha256:[0-9a-f]{64}', image),
        'Use the official pinned PegaProx image')
    require(set(app.get('storage_paths', {})) == {'config', 'logs'}, 'Bind the owned PegaProx configuration and logs')
    require(all(row['kind'] == 'directory' and row['read_only'] is False
                for row in app['storage_paths'].values()), 'Keep the owned PegaProx data directories writable')
    _mounts(app, {'config': '/app/config', 'logs': '/app/logs'})
    address=ipaddress.IPv4Address(app['role_addresses']['web_interface'])
    require(not (address.is_unspecified or address.is_loopback or address.is_multicast
                 or address.is_link_local or address.is_reserved)
            and (address.is_private or address in ipaddress.IPv4Network('198.18.0.0/15')),
            'Select a management IPv4 address, never a wildcard or public listener')
    require(all(row['service'] == 'pegaprox' and row['namespace'] == 'app-network'
                and row['port'] == 5000 and row['protocol'] == 'tcp'
                for row in app['listeners'].values()), 'Preserve the PegaProx internal HTTP listener')
    ports = _ports(app, 'pegaprox')
    require(len(ports) == 1 and any(row.get('publication_address')==str(address)
                and row.get('publish',{}).get('scope')=='guest-interface'
                and row['publish']['port']==5000 for row in app['listeners'].values()),
            'Publish the declared PegaProx management listener')
    proxy = app['settings']['trusted_proxy']
    try:
        selected = ipaddress.IPv4Network(proxy, strict=True)
    except (TypeError, ValueError):
        raise ValueError('Bind the selected PegaProx trusted ingress /32') from None
    require(str(selected) == proxy and selected.prefixlen == 32
            and any(selected.subnet_of(network) for network in pegaprox.PRIVATE_BACKENDS)
            and str(selected.network_address) != app['role_addresses']['web_interface'],
            'Bind the exact distinct selected trusted ingress source')
    service = _service(app, 'pegaprox', guest)
    pegaprox.service_configuration(service, trusted_proxy=proxy,
        mount=lambda name, target: _runtime_mount(app, name, target), ports=ports,
        data_sources={key: row['source'] for key, row in app['storage_paths'].items()})
    return {'pegaprox': service}


def _traefik(app, guest):
    settings = app['settings']
    require({'provider', 'acme'} <= set(settings) and
            {'cloudflare_dns_token', 'proxmox_token'} <= set(app.get('secret_bindings', {})),
            'Bind the selected Traefik provider and ACME capabilities')
    require(set(app['containers']) == {'traefik'} and
            set(app['containers']['traefik']) == {'memory_mib', 'cpu_limit', 'pids_limit'},
            'Retain the Traefik image process and user defaults')
    require(set(app.get('storage_paths', {})) == {'certs'}, 'Bind the selected Traefik certificate store')
    storage = app['storage_paths']['certs']
    require(storage['kind'] == 'directory' and storage['read_only'] is False,
            'Keep the selected certificate store writable')
    _mounts(app, {'certs': '/var/traefik/certs'})
    require(all(row['service'] == 'traefik' and row['namespace'] == 'host'
                and row['protocol'] == 'tcp' and row['port'] in (80, 443)
                for row in app['listeners'].values()) and not _ports(app, 'traefik'),
            'Keep Traefik on its declared host HTTP and HTTPS listeners')
    timeout = settings['acme'].get('propagation_timeout_seconds')
    require(timeout is None or type(timeout) is int and 120 <= timeout <= 2100,
            'Preserve the bounded selected ACME propagation timeout')
    route_mounts = []
    rows = settings.get('route_ca_files', {})
    certificates = settings.get('route_ca_certificates', {})
    require(isinstance(rows, dict) and isinstance(certificates, dict)
            and len(rows) + len(certificates) <= 64 and not set(rows) & set(certificates),
            'Bind finite disjoint resolved route trust files')
    for key, selected in {**rows, **certificates}.items():
        fields = {'certificate', 'filename'} if key in certificates else {'source', 'filename'}
        require(isinstance(key, str) and re.fullmatch('[a-z][a-z0-9_-]{0,62}', key)
                and isinstance(selected, dict) and set(selected) == fields
                and selected['filename'] == 'route-' + key + '.pem',
                'Use only the selected route CA filename')
        route_mounts.append(_runtime_mount(app, selected['filename'], discovery.ca_path(key)))
    service = _service(app, 'traefik', guest)
    service['network_mode'] = 'host'
    service['command'] = ['--configFile=/etc/traefik/traefik.yml']
    foundation.ingress_service(service, mount=lambda name, target: _runtime_mount(app, name, target),
        certs_source=storage['source'], propagation_timeout_seconds=timeout, route_ca_mounts=route_mounts)
    if settings.get('cloudflare'):
        service['volumes'].append(_runtime_mount(app, 'cloudflare-origin-token', '/run/secrets/cloudflare-origin-token'))
        for leaf, target in (('cloudflare.go', 'cloudflare.go'), ('cloudflare-go.mod', 'go.mod'),
                             ('cloudflare-LICENSE', 'LICENSE'), ('cloudflare-manifest.yml', '.traefik.yml')):
            service['volumes'].append(_runtime_mount(app, leaf,
                '/plugins-local/src/github.com/theaussiepom/homelab-cloudflare/' + target))
    return {'traefik': service}


def _renovate(app, guest):
    import renovate
    require(app['lifecycle'] in ('fresh', 'retained') and not app['listeners'],
            'Run Mend CE scheduled scans without a published listener')
    settings = app['containers']['renovate']
    require(settings.get('user') == '12021:12021' and settings.get('cap_drop') == ['ALL']
            and settings.get('no_new_privileges') is True and settings.get('read_only') is True
            and not settings.get('cap_add'),
            'Preserve the unprivileged Mend CE runtime')
    service = _service(app, 'renovate', guest)
    require(service['image'].startswith('ghcr.io/mend/renovate-ce:'), 'Select the Mend CE server image')
    require(set(app['storage_paths']) == {'scratch', 'cache'}, 'Bind both writable Mend CE cache paths')
    service['volumes'] = _mounts(app, {'scratch': '/tmp', 'cache': '/opt/containerbase'})
    service['environment'].update(renovate.environment(app))
    return {'renovate': service}


HANDLERS = {'renovate': _renovate, 'unbound': _unbound, 'pihole': _pihole, 'music_assistant': _music_assistant, 'scrypted': _scrypted, 'homeassistant': _homeassistant, 'mqtt': _mqtt, 'authentik': _authentik, 'cloudbeaver': _cloudbeaver, 'mqtt_explorer': _mqtt_explorer, 'zabbix': _zabbix, 'node_red': _node_red, 'winet': _winet, 'zigbee2mqtt': _zigbee2mqtt,
            'bitwarden': _bitwarden, 'pegaprox': _pegaprox, 'traefik': _traefik}


def compositions(cfg):
    """One actual service graph per explicitly owned project, any guest ID."""
    require(isinstance(cfg, dict) and set(cfg) == {'schema', 'guest', 'applications'}
            and cfg['schema'] == SCHEMA and isinstance(cfg['applications'], dict),
            'Use the resolved component runtime contract')
    guest = cfg['guest']
    require(isinstance(guest, dict) and isinstance(guest.get('timezone'), str),
            'Resolve component guest runtime context')
    result, total = {}, 0
    for app in cfg['applications'].values():
        if app.get('adapter') in ('postgresql', 'mariadb', 'influxdb'):
            require(set(app.get('native_requirements', {})) == {'memory_mib'} and
                    type(app['native_requirements']['memory_mib']) is int
                    and app['native_requirements']['memory_mib'] > 0,
                    'Keep an explicit native application reservation')
            total += app['native_requirements']['memory_mib']
            continue
        require(app.get('adapter') in HANDLERS, 'Component adapter runtime is not yet implemented')
        project = _name(app['project_name'])
        document = result.setdefault(project, {'name': project, 'services': {}})
        for profile_id, value in HANDLERS[app['adapter']](app, guest).items():
            service_id = _name(app['identity']['services'][profile_id])
            require(service_id not in document['services'], 'Component services collide in the selected project')
            total += app['containers'][profile_id]['memory_mib']
            if 'network_mode' not in value:
                networks = app['identity']['networks']
                require(len(networks) == 1, 'Select the owned component private network')
                network = _name(next(iter(networks.values())))
                if network != 'default':
                    value['networks'] = [network]
                    document.setdefault('networks', {})[network] = {}
            _validate_mounts(value)
            document['services'][service_id] = value
    require(total + max(256, guest['os_reserve_mib']) <= guest['memory_mib'],
            'Leave the declared OS reserve outside component container limits')
    return result


def artifacts(cfg):
    documents = compositions(cfg)
    manifest, result = {}, {}
    for project, document in documents.items():
        files = {app.get('project_file', 'compose-' + project + '.yml')
                 for app in cfg['applications'].values() if app.get('project_name') == project}
        require(len(files) == 1, 'Bind one file identity to each Compose project')
        filename = next(iter(files))
        require(isinstance(filename, str) and re.fullmatch('[a-z][a-z0-9_-]{0,62}\\.ya?ml', filename)
                and filename not in result, 'Keep distinct confined Compose file identities')
        result[filename] = (json.dumps(document, indent=2) + '\n').encode()
        manifest[project] = {'file': filename, 'applications': {
            name: ordered_services(app)
            for name, app in cfg['applications'].items() if app.get('project_name') == project}}
    result['component-projects.json'] = (json.dumps(manifest, indent=2) + '\n').encode()
    rendered_native = {app_id: component_native.render(
        app, clients=app.get('settings', {}).get('client_access', ()))
        for app_id, app in cfg['applications'].items()
        if app.get('adapter') in ('postgresql', 'mariadb', 'influxdb')}
    component_native.namespace(rendered_native)
    native = {}
    for app_id, selected in rendered_native.items():
        app = cfg['applications'][app_id]
        if app['adapter'] == 'postgresql':
            import database_hba
            original = selected['files']['pg_hba.conf']
            if 'monitoring_hba_source' in app:
                original = database_hba.monitoring(original, app['monitoring_hba_source'])
            selected['files']['pg_hba.conf'] = database_hba.administrators(
                original, app.get('database_administrators', {}))
        rename = {key: 'native-' + _name(app_id) + '-' + key for key in selected['files']}
        for key, value in selected['files'].items():
            require(rename[key] not in result, 'Native component artifacts collide')
            result[rename[key]] = value.encode()
        for row in selected['identity']['config_files']:
            row['source'] = '${inputs}/' + rename[row['source'].removeprefix('${inputs}/')]
        native[app_id] = {key: selected[key] for key in ('services', 'identity')}
    if native:
        result['component-native.json'] = (json.dumps(native, indent=2) + '\n').encode()
    return result
