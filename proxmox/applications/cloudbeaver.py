"""Validated Community database-tools inputs and privately generated runtime files."""
import base64
import hashlib
import hmac
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from private_io import require

WORKSPACE = '/srv/homelab/data/cloudbeaver'
HEADERS = ('X-User', 'X-Team', 'X-Role', 'X-Role-TE', 'X-First-name', 'X-Last-name',
           'X-Full-name', 'X-Forwarded-User', 'X-Forwarded-Email', 'X-Forwarded-Groups')
DRIVERS = {'postgresql': ('postgresql', 'postgres-jdbc', 5432),
           'mariadb': ('mysql', 'mariaDB', 3306)}


def selected(cfg):
    """Legacy database-tools inputs retain their existing pgAdmin implementation."""
    variant = cfg.get('variant', 'pgadmin')
    require(cfg.get('kind') == 'db-tools' or 'variant' not in cfg,
            'Application variants belong only to database tools')
    if cfg.get('kind') == 'db-tools':
        require(isinstance(variant, str) and variant in {'pgadmin', 'cloudbeaver'}, 'Select pgadmin or cloudbeaver')
    return cfg.get('kind') == 'db-tools' and variant == 'cloudbeaver'


def https(value, *, issuer=False):
    require(isinstance(value, str) and len(value) <= 2048 and not any(c.isspace() for c in value)
            and '\\' not in value, 'Use a literal credential-free HTTPS URL')
    try:
        url = urlsplit(value)
    except ValueError:
        raise ValueError('Use a literal credential-free HTTPS URL') from None
    require(url.scheme == 'https' and url.hostname and '.' in url.hostname and not url.username
            and not url.password and not url.query and not url.fragment
            and (issuer or url.path in {'', '/'}), 'Use a literal credential-free HTTPS URL')
    try:
        require(url.port is None or 1 <= url.port <= 65535, 'Use a valid HTTPS port')
    except ValueError:
        raise ValueError('Use a valid HTTPS port') from None
    return value if issuer else value.rstrip('/')


def validate(cfg):
    if not selected(cfg):
        require('cloudbeaver' not in cfg, 'CloudBeaver settings require its explicit variant')
        return None
    value = cfg.get('cloudbeaver')
    require(isinstance(value, dict) and set(value) == {'bind_address', 'public_url', 'server_name',
            'recovery_admin', 'heap_mib', 'auth_headers', 'connections', 'retained_pgadmin_image'},
            'Use the closed CloudBeaver Community configuration')
    try:
        address = ipaddress.IPv4Address(value['bind_address'])
    except (ValueError, TypeError):
        raise ValueError('Publish only on the selected private guest address') from None
    require(address.is_private and not (address.is_loopback or address.is_link_local or address.is_multicast
            or address.is_unspecified), 'Publish only on the selected private guest address')
    https(value['public_url'])
    require(isinstance(value['server_name'], str) and 1 <= len(value['server_name']) <= 100
            and not any(c in value['server_name'] for c in '\r\n\x00'), 'Use a bounded server display name')
    require(isinstance(value['recovery_admin'], str) and re.fullmatch('[a-z][a-z0-9_-]{2,63}', value['recovery_admin']),
            'Use a literal application recovery administrator name')
    require(type(value['heap_mib']) is int and 256 <= value['heap_mib'] <= 16384,
            'Select a bounded explicit JVM heap')
    headers = value['auth_headers']
    require(isinstance(headers, dict) and set(headers) == {'user', 'team'} and
            all(isinstance(v, str) and re.fullmatch('X-[A-Za-z][A-Za-z0-9-]{0,60}', v) for v in headers.values())
            and len({v.lower() for v in headers.values()}) == 2
            and not {v.lower() for v in headers.values()} & {'x-forwarded-for', 'x-forwarded-proto',
                'x-forwarded-host', 'x-forwarded-port', 'x-real-ip'}, 'Use distinct identity headers, never routing headers')
    require(isinstance(value['retained_pgadmin_image'], str) and re.fullmatch(r'(?:[A-Za-z0-9._:/-]+@)?sha256:[0-9a-f]{64}', value['retained_pgadmin_image']),
            'Bind the exact retained pgAdmin image before its managed retirement')
    connections = value['connections']
    require(isinstance(connections, dict) and 1 <= len(connections) <= 16, 'Declare finite metadata-only connections')
    for name, connection in connections.items():
        require(isinstance(name, str) and re.fullmatch('[a-z][a-z0-9_-]{0,62}', name) and isinstance(connection, dict)
                and isinstance(connection.get('driver'), str) and connection['driver'] in DRIVERS, 'Select a supported named database connection')
        expected = {'name', 'driver', 'database'} | ({'sslmode'} if connection['driver'] == 'postgresql' else set())
        require(set(connection) in (expected, expected | {'host', 'port'})
                and isinstance(connection['name'], str) and 1 <= len(connection['name']) <= 100
                and isinstance(connection['database'], str) and len(connection['database']) <= 128
                and not any(c in connection['name'] + connection['database'] for c in '\r\n\x00'),
                'Connection metadata never contains shared usernames, passwords or keys')
        if connection['driver'] == 'postgresql':
            require(isinstance(connection['sslmode'], str) and connection['sslmode'] in {'disable', 'prefer', 'require'}, 'Select explicit supported PostgreSQL SSL mode')
        if 'host' in connection:
            ipaddress.IPv4Address(connection['host'])
            require(connection['port'] == DRIVERS[connection['driver']][2], 'Bind the selected database engine listener')
    services = cfg.get('services')
    require(isinstance(services, dict) and set(services) == {'cloudbeaver', 'auth_gateway'}, 'Use only CloudBeaver and its OIDC gateway')
    for service in services.values():
        require(isinstance(service, dict) and not service.get('environment') and not any(k in service for k in ('user', 'command', 'entrypoint',
                'extra_mounts', 'cap_add', 'privileged', 'network_mode', 'ports', 'security_opt')),
                'CloudBeaver and gateway runtime placement and identity are generated')
    require(all(type(s.get('memory_mib')) is int for s in services.values())
            and services['cloudbeaver']['memory_mib'] >= value['heap_mib'] + 512
            and services['auth_gateway']['memory_mib'] >= 128, 'Reserve JVM native and gateway memory')
    return value


def foundation(cfg, selected):
    """Validate explicit OIDC inputs without provider-specific URL construction."""
    require(set(selected) == {'version', 'oidc_issuer', 'oauth_client_id', 'oauth_name', 'user_claim', 'secret_files'}
            and selected['version'] == 1, 'Use the closed CloudBeaver OIDC foundation configuration')
    https(selected['oidc_issuer'], issuer=True)
    require(all(isinstance(selected[k], str) and 1 <= len(selected[k]) <= 256 and
            not any(c in selected[k] for c in '\r\n\x00') for k in ('oauth_client_id', 'oauth_name'))
            and isinstance(selected['user_claim'], str) and selected['user_claim'] in {'sub', 'preferred_username', 'email'}, 'Select a verified OIDC identity claim')
    return selected


def derive(secret, purpose):
    """Separate application recovery and cookie keys without another secret copy."""
    require(isinstance(secret, bytes) and 32 <= len(secret) <= 65536 and secret.strip()
            and not any(c in secret for c in (b'\r', b'\n', b'\x00')), 'Use the retained high-entropy OAuth client secret')
    return hmac.new(secret, b'cloudbeaver-community-v1:' + purpose.encode(), hashlib.sha256).digest()


def connection_document(value):
    result = {}
    for name, connection in value['connections'].items():
        provider, driver, port = DRIVERS[connection['driver']]
        require('host' in connection and connection['port'] == port, 'Resolve database connections before rendering')
        properties = {'sslmode': connection['sslmode']} if connection['driver'] == 'postgresql' else {}
        result[name] = {'provider': provider, 'driver': driver, 'name': connection['name'],
            'configuration': {'host': connection['host'], 'port': str(port), 'database': connection['database'],
                              'configurationType': 'MANUAL', 'type': 'dev', 'properties': properties},
            'save-password': False, 'show-system-objects': False}
    return {'folders': {}, 'connections': result}


def configuration(value):
    """The Community server trusts headers only on its unpublished Compose bridge."""
    return {'server': {'serverPort': 8978, 'forceHttps': True, 'serverName': value['server_name'], 'contentRoot': 'web',
            'driversLocation': 'drivers', 'rootURI': '/', 'serviceURI': '/api/',
            'database': {'driver': 'h2_embedded_v2', 'url': 'jdbc:h2:${workspace}/.data/cb.h2v2.dat',
                         'initialDataConfiguration': 'conf/initial-data.conf'}},
        'app': {'forwardProxy': True, 'anonymousAccessEnabled': False, 'defaultUserTeam': 'user',
            'supportsCustomConnections': True, 'publicCredentialsSaveEnabled': False,
            'adminCredentialsSaveEnabled': False, 'grantConnectionsAccessToAnonymousTeam': False,
            'enabledAuthProviders': ['local', 'reverseProxy'], 'redirectOnFederatedAuth': True,
            'authConfigurations': [{'id': 'reverseProxy', 'provider': 'reverseProxy',
                'displayName': 'Verified sign-in', 'disabled': False, 'parameters': {
                    'user-header': value['auth_headers']['user'], 'team-header': value['auth_headers']['team'],
                    'team-delimiter': ',', 'auto-user-provisioning': True}}]}}


def gateway(value, selected, secret):
    headers = {name.lower(): name for name in (*HEADERS, *value['auth_headers'].values())}
    injections = []
    for name in headers.values():
        values = []
        if name.lower() == value['auth_headers']['user'].lower():
            values = [{'claimSource': {'claim': {'sub': 'user', 'preferred_username': 'preferred_username', 'email': 'email'}[selected['user_claim']], 'prefix': 'oidc.'}}]
        elif name.lower() == value['auth_headers']['team'].lower():
            values = [{'secretSource': {'value': 'user'}}]
        injections.append({'name': name, 'preserveRequestValue': False, 'values': values})
    alpha = {'upstreamConfig': {'upstreams': [{'id': 'community', 'path': '/',
                'uri': 'http://cloudbeaver:8978', 'proxyWebSockets': True, 'passHostHeader': True}]},
        'injectRequestHeaders': injections, 'injectResponseHeaders': [],
        'server': {'bindAddress': '0.0.0.0:4180'},
        'providers': [{'id': 'identity', 'provider': 'oidc', 'name': selected['oauth_name'],
            'clientID': selected['oauth_client_id'], 'clientSecret': secret.decode(),
            'scope': 'openid email profile', 'code_challenge_method': 'S256',
            'oidcConfig': {'issuerURL': selected['oidc_issuer'], 'insecureSkipNonce': False}}]}
    options = {'redirect_url': value['public_url'].rstrip('/') + '/oauth2/callback',
        'cookie_secret': base64.urlsafe_b64encode(derive(secret, 'session-cookie')).decode(),
        'cookie_name': '__Host-cloudbeaver', 'cookie_secure': True, 'cookie_httponly': True,
        'cookie_samesite': 'lax', 'cookie_path': '/', 'email_domains': ['*'],
        'reverse_proxy': True, 'skip_provider_button': True,
        'request_logging': False, 'auth_logging': False, 'standard_logging': True}
    return alpha, '\n'.join(k + ' = ' + json.dumps(v) for k, v in options.items()) + '\n'


def files(cfg, secret):
    value = validate(cfg)
    selected = foundation(cfg, cfg['foundation'])
    alpha, options = gateway(value, selected, secret)
    encoded_name = value['server_name'].encode('utf-16-be').hex()
    properties_name = ''.join('\\u' + encoded_name[i:i+4] for i in range(0, len(encoded_name), 4))
    auto = ('CB_SERVER_NAME=' + properties_name + '\n'
        + 'CB_ADMIN_NAME=' + value['recovery_admin'] + '\nCB_ADMIN_PASSWORD='
        + base64.urlsafe_b64encode(derive(secret, 'local-recovery')).decode() + 'aA1!\n')
    public = dict(value, workspace=WORKSPACE, project='homelab-db-tools')
    rows = [('CloudBeaverHealth.java', Path(__file__).with_name('CloudBeaverHealth.java').read_text(), 8978),
            ('cloudbeaver.conf', json.dumps(configuration(value)), 8978),
            ('cloudbeaver.auto.conf', auto, 8978),
            ('cloudbeaver-connections.json', json.dumps(connection_document(value)), 8978),
            ('cloudbeaver-permissions.json', json.dumps({name: ['user'] for name in value['connections']}), 8978),
            ('oauth2-alpha.json', json.dumps(alpha), 65532), ('oauth2.cfg', options, 65532),
            ('cloudbeaver-public.json', json.dumps(public), 0)]
    return [{'path': name, 'content': content + '\n', 'uid': uid, 'gid': uid, 'mode': '0400'}
            for name, content, uid in rows]


def configure(cfg, result):
    value = validate(cfg)
    def mount(name, target):
        return {'type': 'bind', 'source': '/opt/homelab-app/runtime/' + name, 'target': target,
                'read_only': True, 'bind': {'create_host_path': False}}
    services = result['services']
    result['networks'] = {'database_tools': {}}
    for name, service in services.items():
        service.pop('network_mode')
        service['networks'] = ['database_tools']
        service['cap_drop'] = ['ALL']
        service['security_opt'] = ['no-new-privileges:true']
    server = services['cloudbeaver']
    server['user'] = '8978:8978'
    server['environment'] = {'JAVA_OPTS': '-Xms128m -Xmx' + str(value['heap_mib'])
        + 'm -XX:MaxMetaspaceSize=256m -XX:ReservedCodeCacheSize=64m'}
    server['volumes'] = [{'type': 'bind', 'source': WORKSPACE, 'target': '/opt/cloudbeaver/workspace',
                          'bind': {'create_host_path': False}},
        mount('cloudbeaver.conf', '/opt/cloudbeaver/conf/cloudbeaver.conf'),
        mount('cloudbeaver.auto.conf', '/opt/cloudbeaver/conf/.cloudbeaver.auto.conf'),
        mount('cloudbeaver-connections.json', '/opt/cloudbeaver/conf/initial-data-sources.conf')]
    server['volumes'].append(mount('CloudBeaverHealth.java', '/opt/cloudbeaver/conf/CloudBeaverHealth.java'))
    server['healthcheck'] = {'test': ['CMD', 'java', '-Xms8m', '-Xmx64m', '-Xss512k', '-XX:MaxMetaspaceSize=64m', '-XX:ReservedCodeCacheSize=16m', '-XX:ActiveProcessorCount=1', '-XX:CICompilerCount=2', '-XX:+UseSerialGC',
        '/opt/cloudbeaver/conf/CloudBeaverHealth.java'],
        'start_period': '60s', 'interval': '10s', 'timeout': '8s', 'retries': 18}
    proxy = services['auth_gateway']
    proxy['user'] = '65532:65532'
    proxy['read_only'] = True
    proxy['environment'] = {'GOMEMLIMIT': '96MiB'}
    proxy['ports'] = [value['bind_address'] + ':80:4180']
    proxy['volumes'] = [mount('oauth2-alpha.json', '/etc/oauth2-proxy/alpha.json'),
                        mount('oauth2.cfg', '/etc/oauth2-proxy/oauth2.cfg')]
    proxy['command'] = ['--config=/etc/oauth2-proxy/oauth2.cfg', '--alpha-config=/etc/oauth2-proxy/alpha.json']
    proxy['depends_on'] = {'cloudbeaver': {'condition': 'service_healthy'}}
    return result
