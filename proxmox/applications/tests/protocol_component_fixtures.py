"""Synthetic protocol inputs for retained CI fixtures, not a source adapter.

Each constructor supplies one explicit supported component descriptor.  The real
renderer and pure file builder remain the only service/runtime constructors.
No private source or reusable-stack checkout is read here.
"""
import copy
import json
from pathlib import Path

import component_foundation_files
import component_proxy_files
import component_runtime
import dns_records


def _listener(service, port, address=None, published=None):
    result = {'service': service, 'port': port, 'protocol': 'tcp',
              'namespace': 'app-network', 'interface': 'private_interface',
              'bind': 'wildcard', 'actual_bind': '0.0.0.0'}
    if address is not None:
        result.update(publication_address=address,
                      publish={'port': port if published is None else published,
                               'scope': 'guest-interface', 'interface': 'web_interface'})
    return result


def _directory(source, target):
    return {'source': source, 'target': target, 'kind': 'directory', 'read_only': False}


def _app(adapter, project, services, network='default'):
    return {'id': adapter, 'adapter': adapter, 'lifecycle': 'retained',
            'project_name': project, 'project_file': 'compose.yml',
            'identity': {'runtime_directory': '/opt/homelab-app/runtime',
                         'services': {name: name for name in services},
                         'networks': {network: network}},
            'containers': {name: {'memory_mib': memory, 'cpu_limit': 1, 'pids_limit': 128}
                           for name, memory in services.items()},
            'software_selection': {'images': {}}, 'settings': {},
            'properties': {}, 'resolved_connections': {}, 'role_addresses': {},
            'storage_paths': {}, 'listeners': {}}


def document(app, *, memory_mib=2048):
    """Use the actual component renderer and the fixture's original OS budget."""
    return component_runtime.compositions({
        'schema': component_runtime.SCHEMA,
        'guest': {'timezone': 'Etc/UTC', 'memory_mib': memory_mib, 'os_reserve_mib': 256},
        'applications': {app['id']: app}})[app['project_name']]


def cloudbeaver_app(selected, value, *, image, gateway_image):
    app = _app('cloudbeaver', 'homelab-db-tools',
               {'cloudbeaver': 1536, 'auth_gateway': 128}, 'database_tools')
    # These are the former synthetic protocol inputs, not consumer defaults.
    settings = {'bind_address': '198.18.30.32', 'public_url': 'https://db.example.invalid',
                'server_name': 'Database Tools', 'recovery_admin': 'local-recovery',
                'heap_mib': 1024, 'auth_headers': {'user': 'X-User', 'team': 'X-Team'},
                'connections': {
                    'postgresql': {'name': 'PostgreSQL', 'driver': 'postgresql',
                                   'database': 'postgres', 'sslmode': 'prefer',
                                   'host': '198.18.31.23', 'port': 5432},
                    'mariadb': {'name': 'MariaDB', 'driver': 'mariadb', 'database': '',
                                'host': '198.18.32.24', 'port': 3306}}}
    settings.update(copy.deepcopy(value), recovery_admin='local-recovery')
    app['settings'] = settings
    app['authentication_resolved'] = dict(copy.deepcopy(selected), version=1)
    app['software_selection']['images'] = {'cloudbeaver': {'image': image},
                                          'auth_gateway': {'image': gateway_image}}
    app['storage_paths'] = {'workspace': _directory('/srv/homelab/data/cloudbeaver',
                                                   '/opt/cloudbeaver/workspace')}
    app['listeners'] = {'web_listener': _listener('auth_gateway', 4180, settings['bind_address'], 80),
                        'community_listener': _listener('cloudbeaver', 8978)}
    return app


def cloudbeaver_files(app, secret):
    return component_proxy_files.files(app, secrets={'client_secret': secret},
                                       records={}, public_ca=None)


def bitwarden_app(*, image):
    app = _app('bitwarden', 'homelab-bitwarden', {'bitwarden': 1536})
    app['containers']['bitwarden']['pids_limit'] = 256
    app['software_selection']['images']['bitwarden'] = {'image': image}
    app['settings'] = {'settings': {
        'schema': 'homelab-bitwarden-runtime-v2', 'bind_address': '198.18.30.35',
        'database_server': '198.18.32.24',
        'database_provider': 'mysql', 'database_name': 'bitwarden_fixture',
        'data_uid': 1000, 'data_gid': 1000}}
    app['storage_paths'] = {name: _directory('/srv/homelab/data/bitwarden/' + name, target)
                            for name, target in [('data', '/etc/bitwarden'),
                                                  ('logs', '/var/log/bitwarden')]}
    app['listeners'] = {'web_listener': _listener('bitwarden', 8080, '198.18.30.35')}
    return app


def zabbix_app(*, database_host, images):
    app = _app('zabbix', 'homelab-monitoring', {'zabbix_server': 768, 'zabbix_web': 512})
    app['software_selection']['images'] = {
        name: {'image': images[name]} for name in ('zabbix_server', 'zabbix_web')}
    app['settings'] = {'database': {'host': database_host, 'name': 'zabbix', 'user': 'zabbix'},
                       'database_credential': {'type': 'monitoring-owned', 'server': app['id']}}
    app['listeners'] = {'server_listener': _listener('zabbix_server', 10051, '198.18.30.50'),
                        'web_listener': _listener('zabbix_web', 8080, '198.18.30.50'),
                        'local-web_listener': _listener('zabbix_web', 8080, '127.0.0.1', 8081)}
    return app


def authentik_app(*, image, redis_image):
    app = _app('authentik', 'homelab-identity', {'server': 768, 'worker': 768, 'redis': 128})
    for name in ('server', 'worker'):
        app['containers'][name]['user'] = '1000:1000'
    app['software_selection']['images'] = {name: {'image': redis_image if name == 'redis' else image}
                                          for name in app['containers']}
    app['settings'] = {'database': {'host': 'postgres', 'name': 'authentik', 'user': 'authentik'}}
    app['properties'] = {'smtp': {'host': 'smtp.example.invalid', 'from': 'sso@example.invalid', 'use_tls': True}}
    roles = ('secret_key', 'postgresql_password', 'smtp_password')
    app['secret_bindings'] = {role: {'type': 'file', 'path': '/synthetic/'+role+'.secret'} for role in roles}
    app['input_sources'] = copy.deepcopy(app['secret_bindings'])
    app['storage_paths'] = {role: _directory('/srv/homelab/data/'+source, target) for role, source, target in (
        ('media', 'authentik/media', '/media'), ('templates', 'authentik/templates', '/templates'),
        ('certs', 'authentik/certs', '/certs'), ('redis', 'redis', '/data'))}
    app['listeners'] = {'web_listener': _listener('server', 9000, '198.18.30.20')}
    return app


def authentik_files(app):
    # Existing fixture data only. The selected pure builder opens no private path.
    rows = component_foundation_files.files(app, secrets={
        role: ('synthetic-$'+role).encode() for role in app['input_sources']})
    return [dict(row, content=row['content'].decode('utf-8') if isinstance(row['content'], bytes)
                 else row['content']) for row in rows]


def dns_apps(*, image, records):
    pihole = _app('pihole', 'homelab-dns', {'pihole': 256})
    pihole['software_selection']['images'] = {'pihole': {'image': image}}
    pihole['settings'] = {'dns_records': dns_records.validate(copy.deepcopy(records))}
    pihole['storage_paths'] = {'config': _directory('/srv/homelab/data/pihole', '/etc/pihole')}
    pihole['resolved_connections'] = {'upstream': {'type': 'dns', 'target': {
        'protocol': 'udp', 'address': '127.0.0.1', 'port': 5335}}}
    unbound = _app('unbound', 'homelab-dns', {'unbound': 256})
    # The DNS reconciliation fixture starts ONLY Pi-hole. Its unstarted peer's
    # image selection is preserved verbatim, rather than choosing a new image.
    unbound['software_selection']['images'] = {'unbound': {'image': image}}
    unbound['storage_paths'] = {'config': _directory('/srv/homelab/data/unbound', '/opt/unbound/etc/unbound')}
    unbound['listeners'] = {protocol+'_listener': dict(_listener('unbound', 53, '127.0.0.1', 5335), protocol=protocol)
                            for protocol in ('tcp', 'udp')}
    return {'pihole': pihole, 'unbound': unbound}


def dns_document(*, image, records):
    return component_runtime.compositions({'schema': component_runtime.SCHEMA,
        'guest': {'timezone': 'Etc/UTC', 'memory_mib': 1024, 'os_reserve_mib': 256},
        'applications': dns_apps(image=image, records=records)})['homelab-dns']


def zigbee_app(*, image):
    app = _app('zigbee2mqtt', 'homelab-zigbee2mqtt', {'zigbee2mqtt': 256})
    app['software_selection']['images'] = {'zigbee2mqtt': {'image': image}}
    app['settings'] = {'serial_device': '/dev/serial/by-id/usb-fixture', 'bind_address': '198.18.30.22',
                       'frontend_port': 8099, 'adapter': 'ember', 'mqtt_server': 'mqtt://broker.mqtt:1883',
                       'mqtt_base_topic': 'home'}
    app['storage_paths'] = {'data': _directory('/srv/homelab/data/zigbee2mqtt', '/app/data')}
    app['listeners'] = {'web_listener': _listener('zigbee2mqtt', 8099, '198.18.30.22')}
    return app


def structural_runtime():
    """Explicit independent app placement, including several projects per guest."""
    image = 'example.invalid/service@sha256:'+'1'*64
    apps = dns_apps(image=image, records={})
    apps['authentik'] = authentik_app(image=image, redis_image=image)
    apps['cloudbeaver'] = cloudbeaver_app(
        {'oauth_name': 'Fixture SSO', 'oauth_client_id': 'fixture-client',
         'oidc_issuer': 'https://sso.example.invalid/oidc/', 'user_claim': 'preferred_username'},
        {'public_url': 'https://db.example.invalid'}, image=image, gateway_image=image)
    apps['zigbee2mqtt'] = zigbee_app(image=image)
    # The source-owned public Node descriptor retains its wrapper/auth/flow
    # structure. It does not import the retiring fixed catalogue or private site.
    node = copy.deepcopy(json.loads(Path(__file__).with_name('public-synthetic-retained-services.json').read_text())['cases']['node_red']['app'])
    node.update(id='node_red', project_name='homelab-automation', project_file='compose.yml')
    apps['node_red'] = node
    home = _app('homeassistant', 'homelab-automation', {'homeassistant': 256})
    home['software_selection']['images'] = {'homeassistant': {'image': image}}
    home['storage_paths'] = {'config': _directory('/srv/homelab/data/homeassistant/config', '/config')}
    apps['homeassistant'] = home
    broker = _app('mqtt', 'homelab-automation', {'mqtt': 256})
    broker['software_selection']['images'] = {'mqtt': {'image': image}}
    broker['storage_paths'] = {role: _directory('/srv/homelab/data/mqtt/'+role, '/mosquitto/'+role)
                              for role in ('config', 'data', 'log')}
    apps['mqtt'] = broker
    proxy = _app('traefik', 'homelab-ingress', {'traefik': 256})
    proxy['software_selection']['images'] = {'traefik': {'image': image}}
    proxy['secret_bindings'] = {role: {'type': 'file', 'path': '/synthetic/'+role}
                                for role in ('cloudflare_dns_token', 'proxmox_token')}
    proxy['settings'] = {'provider': {'url': 'https://198.18.25.10:8006'}, 'acme': {}, 'route_ca_files': {}}
    proxy['storage_paths'] = {'certs': _directory('/srv/homelab/data/traefik/certs', '/var/traefik/certs')}
    proxy['listeners'] = {str(port)+'_listener': dict(_listener('traefik', port), namespace='host',
        interface='frontend', bind='interface', actual_bind='198.18.40.33') for port in (80, 443)}
    apps['traefik'] = proxy
    return {'schema': component_runtime.SCHEMA,
            'guest': {'timezone': 'Etc/UTC', 'memory_mib': 8192, 'os_reserve_mib': 256},
            'applications': apps}


def structural_documents():
    return component_runtime.compositions(structural_runtime())


def influx_web_listeners(roles):
    """Use one current InfluxDB network fixture in unit and hosted Linux checks."""
    return {
        name: {'service': 'influxdb', 'namespace': 'host', 'interface': role,
               'bind': 'interface', 'protocol': 'tcp', 'port': 8086,
               'actual_bind': roles[role]}
        for name, role in (('web_listener', 'web_interface'),
                           ('backend_listener', 'service_interface'))}
