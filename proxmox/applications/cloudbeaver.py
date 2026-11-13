"""Validated Community database-tools inputs and privately generated runtime files."""
import base64
import hashlib
import hmac
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


def jdbc(value):
    """One official pinned driver, with an explicit image compatibility path."""
    needed = any(item['driver'] == 'mariadb' for item in value.get('managed_connections', {}).values())
    require(('mariadb_jdbc' in value) == needed, 'Bind the fixed MariaDB JDBC artifact only for managed MariaDB connections')
    if not needed:
        return None
    artifact = value['mariadb_jdbc']
    require(isinstance(artifact, dict) and set(artifact) == {'version', 'sha256', 'image_filename'}
            and isinstance(artifact['version'], str) and re.fullmatch(r'3\.5\.[0-9]{1,3}', artifact['version'])
            and int(artifact['version'].split('.')[2]) >= 11
            and isinstance(artifact['sha256'], str) and re.fullmatch('[0-9a-f]{64}', artifact['sha256'])
            and isinstance(artifact['image_filename'], str) and artifact['image_filename'] in {
                'mariadb-java-client-'+artifact['version']+'.jar', 'mariadb-java-client-3.5.10.jar'},
            'Use the closed fixed vendor JDBC artifact and a declared image filename')
    filename = 'mariadb-java-client-'+artifact['version']+'.jar'
    return dict(artifact, url='https://repo.maven.apache.org/maven2/org/mariadb/jdbc/mariadb-java-client/'
                +artifact['version']+'/'+filename, source='/opt/homelab-app/runtime/'+filename,
                target='/opt/cloudbeaver/drivers/mariadb/'+artifact['image_filename'])










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
    result = {'server': {'serverPort': 8978, 'forceHttps': True, 'serverName': value['server_name'], 'contentRoot': 'web',
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
    if value.get('managed_connections'):
        result['app'].update(adminCredentialsSaveEnabled=True, secretManagerEnabled=True)
    return result


def gateway(value, selected, secret, *, server_service='cloudbeaver'):
    require(isinstance(server_service, str) and re.fullmatch('[a-z0-9][a-z0-9_-]{0,127}', server_service),
            'Use the exact owned Community service name')
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
                'uri': 'http://' + server_service + ':8978', 'proxyWebSockets': True, 'passHostHeader': True}]},
        'injectRequestHeaders': injections, 'injectResponseHeaders': [],
        'server': {'bindAddress': '0.0.0.0:4180'},
        'providers': [{'id': 'identity', 'provider': 'oidc', 'name': selected['oauth_name'],
            'clientID': selected['oauth_client_id'], 'clientSecret': secret.decode(),
            'scope': 'openid email profile', 'code_challenge_method': 'S256',
            'oidcConfig': {'issuerURL': selected['oidc_issuer'], 'insecureSkipNonce': False}}]}
    if 'oidc_endpoints' in selected:
        endpoints = selected['oidc_endpoints']
        provider = alpha['providers'][0]
        provider.update(loginURL=endpoints['authorization_url'], redeemURL=endpoints['token_url'],
                        profileURL=endpoints['userinfo_url'])
        provider['oidcConfig'].update(skipDiscovery=True, jwksURL=endpoints['jwks_url'],
                                     enabledSigningAlgs=list(endpoints['signing_algorithms']))
    options = {'redirect_url': value['public_url'].rstrip('/') + '/oauth2/callback',
        'cookie_secret': base64.urlsafe_b64encode(derive(secret, 'session-cookie')).decode(),
        'cookie_name': '__Host-cloudbeaver', 'cookie_secure': True, 'cookie_httponly': True,
        'cookie_samesite': 'lax', 'cookie_path': '/', 'email_domains': ['*'],
        'reverse_proxy': True, 'skip_provider_button': True,
        'request_logging': False, 'auth_logging': False, 'standard_logging': True}
    return alpha, '\n'.join(k + ' = ' + json.dumps(v) for k, v in options.items()) + '\n'




def service_configuration(value, services, *, mount, workspace=WORKSPACE,
                          server_service='cloudbeaver', ports=None):
    """Pure service transformation for the selected component renderer."""
    require(isinstance(server_service, str) and re.fullmatch('[a-z0-9][a-z0-9_-]{0,127}', server_service),
            'Use the exact owned Community service name')
    for name, service in services.items():
        service.pop('network_mode', None)
        service['cap_drop'] = ['ALL']
        service['security_opt'] = ['no-new-privileges:true']
    server = services['cloudbeaver']
    server['user'] = '8978:8978'
    server['environment'] = {'JAVA_OPTS': '-Xms128m -Xmx' + str(value['heap_mib'])
        + 'm -XX:MaxMetaspaceSize=256m -XX:ReservedCodeCacheSize=64m'}
    server['volumes'] = [{'type': 'bind', 'source': workspace, 'target': '/opt/cloudbeaver/workspace',
                          'bind': {'create_host_path': False}},
        mount('cloudbeaver.conf', '/opt/cloudbeaver/conf/cloudbeaver.conf'),
        mount('cloudbeaver.auto.conf', '/opt/cloudbeaver/conf/.cloudbeaver.auto.conf'),
        mount('cloudbeaver-connections.json', '/opt/cloudbeaver/conf/initial-data-sources.conf')]
    server['volumes'].append(mount('CloudBeaverHealth.java', '/opt/cloudbeaver/conf/CloudBeaverHealth.java'))
    if value.get('managed_connections'):
        server['volumes'].append(mount('CloudBeaverDatabaseHealth.java', '/opt/cloudbeaver/conf/CloudBeaverDatabaseHealth.java'))
    if jdbc(value) is not None:
        artifact = jdbc(value)
        server['volumes'].append(mount(Path(artifact['source']).name, artifact['target']))
    server['healthcheck'] = {'test': ['CMD', '/opt/java/openjdk/bin/java', '-Xms8m', '-Xmx64m', '-Xss512k', '-XX:MaxMetaspaceSize=64m', '-XX:ReservedCodeCacheSize=16m', '-XX:ActiveProcessorCount=1', '-XX:CICompilerCount=2', '-XX:+UseSerialGC',
        '/opt/cloudbeaver/conf/CloudBeaverHealth.java'] + (['--postgresql'] if any(item['driver'] == 'postgresql'
            for item in value.get('managed_connections', {}).values()) else []) + ([artifact['version'], artifact['sha256'], artifact['image_filename']]
            if jdbc(value) is not None else []),
        'start_period': '60s', 'interval': '10s', 'timeout': '8s', 'retries': 18}
    proxy = services['auth_gateway']
    proxy['user'] = '65532:65532'
    proxy['read_only'] = True
    proxy['environment'] = {'GOMEMLIMIT': '96MiB'}
    proxy['ports'] = ports if ports is not None else [value['bind_address'] + ':80:4180']
    proxy['volumes'] = [mount('oauth2-alpha.json', '/etc/oauth2-proxy/alpha.json'),
                        mount('oauth2.cfg', '/etc/oauth2-proxy/oauth2.cfg')]
    proxy['command'] = ['--config=/etc/oauth2-proxy/oauth2.cfg', '--alpha-config=/etc/oauth2-proxy/alpha.json']
    proxy['depends_on'] = {server_service: {'condition': 'service_healthy'}}
    return services
