"""Small file contracts for Authentik, pgAdmin and discovered Traefik routes.

Inputs hold non-secret settings and paths to private controller files. Only this
renderer reads those files; Compose contains references, never their contents.
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit

RUNTIME = '/opt/homelab-app/runtime'
PLUGIN = 'traefik-proxmox-provider'
# SHA256 of the catalog ZIP, independently matched to tested commit e35cce5.
# Traefik3.7.1 compares plain archive hex, not a normalized tree or sha256: URI.
PLUGIN_ARCHIVE_SHA256 = '9e3b91e0ba79fc27dd2587e8b92db725a424a9c21cb17cfcf07b1ef6e354efd7'
AUTH_ENV = {'AUTHENTIK_EMAIL__HOST', 'AUTHENTIK_EMAIL__PORT', 'AUTHENTIK_EMAIL__USE_TLS',
            'AUTHENTIK_EMAIL__USE_SSL', 'AUTHENTIK_EMAIL__FROM', 'AUTHENTIK_EMAIL__TIMEOUT',
            'AUTHENTIK_EMAIL__USERNAME', 'AUTHENTIK_HOST'}
SCHEMAS = {
    'identity': ({'bind_address', 'postgresql_host', 'postgresql_user', 'postgresql_database'},
                 set(), {'secret_key', 'postgresql_password'}, {'smtp_password'}),
    'db-tools': ({'public_url', 'identity_url', 'oauth_client_id', 'oauth_name'},
                 {'oauth_display_name', 'provider_slug'}, {'oauth_client_secret'}, set()),
    'ingress': ({'bind_address', 'proxmox_url', 'proxmox_token_id', 'acme_email', 'pve_ca_file',
                 'acme_dns_resolvers'},
                set(), {'proxmox_token', 'cloudflare_dns_token'}, set()),
}


def text(value, name):
    if not isinstance(value, str) or not value or any(c in value for c in '\r\n\x00'):
        raise ValueError(f'Invalid foundation {name}')
    return value


def address(value):
    try:
        ip = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        raise ValueError('Foundation bind address must be a selected IPv4 address') from None
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local:
        raise ValueError('Foundation bind address must be a selected IPv4 address')
    return str(ip)


def origin(value, name):
    value = text(value, name)
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ('', '/') or parsed.query or parsed.fragment
            or any(c.isspace() for c in value) or '\\' in value):
        raise ValueError(f'Foundation {name} requires a credential-free HTTPS origin')
    try:
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError
    except ValueError:
        raise ValueError(f'Invalid foundation {name} port') from None
    return value.rstrip('/')


def file_path(value):
    value = text(value, 'source file path')
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Foundation source files require absolute paths without traversal')
    return value


def dns_resolvers(value):
    message = 'Declare 1-3 unique recursive DNS IPv4 addresses on port 53'
    if not isinstance(value, list) or not 1 <= len(value) <= 3:
        raise ValueError(message)
    result = []
    for resolver in value:
        if not isinstance(resolver, str):
            raise ValueError(message)
        host, separator, port = resolver.rpartition(':')
        try:
            if separator != ':' or port != '53' or address(host) != host or resolver in result:
                raise ValueError(message)
        except ValueError:
            raise ValueError(message) from None
        result.append(resolver)
    return result


def validate(cfg):
    if 'foundation' not in cfg:
        return None
    kind, selected = cfg.get('kind'), cfg['foundation']
    if kind not in SCHEMAS or not isinstance(selected, dict):
        raise ValueError('Foundation configuration belongs only to identity, db-tools or ingress')
    required, optional, secret_required, secret_optional = SCHEMAS[kind]
    if (type(selected.get('version')) is not int or selected['version'] != 1
            or not required <= selected.keys()
            or set(selected) - required - optional - {'version', 'secret_files'}):
        raise ValueError('Use the closed foundation version 1 configuration')
    secrets = selected.get('secret_files')
    if (not isinstance(secrets, dict) or not secret_required <= secrets.keys()
            or set(secrets) - secret_required - secret_optional):
        raise ValueError('Supply only the selected foundation secret file references')
    for path in secrets.values():
        file_path(path)
    for name in (required | (optional & selected.keys())) - {'acme_dns_resolvers'}:
        text(selected[name], name)
    services = cfg.get('services', {})
    if kind == 'identity':
        address(selected['bind_address'])
        if any(name in cfg for name in ('authentik_secret_key', 'postgresql_password')):
            raise ValueError('Foundation identity uses secret files instead of inline credentials')
        for name in ('server', 'worker'):
            service = services.get(name, {})
            if service.get('user', '1000:1000') not in ('1000', '1000:1000'):
                raise ValueError('Foundation Authentik uses the selected UID/GID 1000')
            if set(service.get('environment', {})) - AUTH_ENV or service.get('extra_mounts'):
                raise ValueError('Foundation Authentik accepts only selected non-secret environment settings')
    elif kind == 'db-tools':
        origin(selected['public_url'], 'public_url')
        origin(selected['identity_url'], 'identity_url')
        if not re.fullmatch(r'[A-Za-z0-9_-]+', selected.get('provider_slug', 'pgadmin4')):
            raise ValueError('Use a literal OAuth provider slug')
        if services.get('pgadmin', {}).get('environment') or services.get('pgadmin', {}).get('extra_mounts'):
            raise ValueError('Foundation pgAdmin uses generated config_local.py instead of inline overrides')
        if services.get('pgadmin', {}).get('user', '5050:5050') not in ('5050', '5050:5050'):
            raise ValueError('Foundation pgAdmin uses the selected UID/GID 5050')
    else:
        address(selected['bind_address'])
        dns_resolvers(selected['acme_dns_resolvers'])
        origin(selected['proxmox_url'], 'proxmox_url')
        file_path(selected['pve_ca_file'])
        if not re.fullmatch(r'[^\s!]+@[^\s!]+![A-Za-z0-9_.-]+', selected['proxmox_token_id']):
            raise ValueError('Use an explicit Proxmox API token identity')
        if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', selected['acme_email']):
            raise ValueError('Use the selected ACME notification email')
        if services.get('traefik', {}).get('environment') or services.get('traefik', {}).get('extra_mounts'):
            raise ValueError('Foundation Traefik uses only its generated provider and TLS configuration')
    return selected


def source_files(cfg):
    selected = validate(cfg)
    if selected is None:
        return []
    result = list(selected['secret_files'].values())
    if cfg['kind'] == 'ingress':
        result.append(selected['pve_ca_file'])
    return sorted(set(result))


def read_private(path, certificate=False):
    # No symlink, device, world-readable secret or accidental empty GH secret.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
            raise ValueError('Foundation input must be a bounded regular file')
        if not certificate and stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError('Foundation secret source files must be private to their owner')
        value = stream.read(65537)
    if certificate:
        if '-----BEGIN CERTIFICATE-----' not in value or 'PRIVATE KEY' in value:
            raise ValueError('The Proxmox trust input must contain public CA certificates only')
        return value
    value = value.removesuffix('\n')
    return text(value, 'secret file contents')


def identity_environment(cfg):
    selected = validate(cfg)
    env = {'AUTHENTIK_SECRET_KEY': 'file:///run/secrets/authentik-secret-key',
           'AUTHENTIK_POSTGRESQL__HOST': selected['postgresql_host'],
           'AUTHENTIK_POSTGRESQL__USER': selected['postgresql_user'],
           'AUTHENTIK_POSTGRESQL__NAME': selected['postgresql_database'],
           'AUTHENTIK_POSTGRESQL__PASSWORD': 'file:///run/secrets/postgresql-password',
           'AUTHENTIK_REDIS__HOST': 'redis'}
    if 'smtp_password' in selected['secret_files']:
        env['AUTHENTIK_EMAIL__PASSWORD'] = 'file:///run/secrets/smtp-password'
    return env


def mount(name, target):
    return {'type': 'bind', 'source': f'{RUNTIME}/{name}', 'target': target,
            'read_only': True, 'bind': {'create_host_path': False}}


def configure_compose(cfg, result):
    selected = validate(cfg)
    if selected is None:
        return result
    services, kind = result['services'], cfg['kind']
    if kind == 'identity':
        for name in ('server', 'worker'):
            service = services[name]
            service['user'] = cfg['services'][name].get('user', '1000')
            for key, target in [('secret_key', 'authentik-secret-key'), ('postgresql_password', 'postgresql-password'),
                                ('smtp_password', 'smtp-password')]:
                if key in selected['secret_files']:
                    service['volumes'].append(mount(target, f'/run/secrets/{target}'))
        # The frontend proxy connects over the isolated backend, not management.
        services['server']['ports'] = [f"{selected['bind_address']}:9000:9000"]
    elif kind == 'db-tools':
        service = services['pgadmin']
        service['user'] = cfg['services']['pgadmin'].get('user', '5050')
        service['environment'].update({'PGADMIN_LISTEN_ADDRESS': '0.0.0.0', 'PGADMIN_LISTEN_PORT': '80'})
        service['volumes'] += [mount('pgadmin-config.py', '/pgadmin4/config_local.py'),
                               mount('oauth-client-secret', '/run/secrets/oauth-client-secret')]
    else:
        service = services['traefik']
        service['environment'].update({'CF_DNS_API_TOKEN_FILE': '/run/secrets/cloudflare-dns-token',
                                       'SSL_CERT_FILE': '/etc/ssl/certs/homelab-pve.pem'})
        service['volumes'] = [mount('traefik.yml', '/etc/traefik/traefik.yml'),
                               mount('shared.yml', '/etc/traefik/shared.yml'),
                               mount('pve-ca.pem', '/etc/ssl/certs/homelab-pve.pem'),
                               mount('cloudflare-dns-token', '/run/secrets/cloudflare-dns-token'),
                               {'type': 'bind', 'source': '/srv/homelab/data/traefik/certs',
                                'target': '/var/traefik/certs', 'bind': {'create_host_path': False}}]
    return result


def files(cfg):
    selected = validate(cfg)
    if selected is None:
        return []
    values = {key: read_private(path) for key, path in selected['secret_files'].items()}
    artifacts = []
    def add(name, content, uid=0, gid=None, mode='0400'):
        artifacts.append({'path': name, 'content': content, 'uid': uid,
                          'gid': uid if gid is None else gid, 'mode': mode})
    if cfg['kind'] == 'identity':
        for key, name in [('secret_key', 'authentik-secret-key'), ('postgresql_password', 'postgresql-password'),
                          ('smtp_password', 'smtp-password')]:
            if key in values:
                add(name, values[key], 1000)
    elif cfg['kind'] == 'db-tools':
        identity = origin(selected['identity_url'], 'identity_url')
        slug = selected.get('provider_slug', 'pgadmin4')
        provider = {'OAUTH2_NAME': selected['oauth_name'],
                    'OAUTH2_DISPLAY_NAME': selected.get('oauth_display_name', selected['oauth_name']),
                    'OAUTH2_CLIENT_ID': selected['oauth_client_id'], 'OAUTH2_SCOPE': 'openid email profile',
                    'OAUTH2_USERNAME_CLAIM': 'preferred_username', 'OAUTH2_SSL_CERT_VERIFICATION': True,
                    'OAUTH2_TOKEN_URL': identity + '/application/o/token/',
                    'OAUTH2_AUTHORIZATION_URL': identity + '/application/o/authorize/',
                    'OAUTH2_API_BASE_URL': identity + '/',
                    'OAUTH2_USERINFO_ENDPOINT': identity + '/application/o/userinfo/',
                    'OAUTH2_SERVER_METADATA_URL': identity + f'/application/o/{slug}/.well-known/openid-configuration',
                    'OAUTH2_LOGOUT_URL': identity + f'/application/o/{slug}/end-session/'}
        config = ('# Generated from non-secret site settings; preserve the captured pgAdmin profile.\n'
                  'from pathlib import Path\nSERVER_MODE = True\nAUTHENTICATION_SOURCES = ["oauth2"]\n'
                  'PROXY_X_HOST_COUNT = 1\nPROXY_X_PROTO_COUNT = 1\nPROXY_X_FOR_COUNT = 1\n'
                  'PREFERRED_URL_SCHEME = "https"\nOAUTH2_AUTO_CREATE_USER = True\n'
                  f'OAUTH2_CONFIG = [{provider!r}]\n'
                  'OAUTH2_CONFIG[0]["OAUTH2_CLIENT_SECRET"] = '
                  'Path("/run/secrets/oauth-client-secret").read_text()\n')
        add('pgadmin-config.py', config, 5050)
        add('oauth-client-secret', values['oauth_client_secret'], 5050)
    else:
        static = {'entryPoints': {
                    'web': {'address': f"{selected['bind_address']}:80", 'http': {'redirections': {'entryPoint': {'to': 'websecure', 'scheme': 'https'}}}},
                    'websecure': {'address': f"{selected['bind_address']}:443"},
                    'health': {'address': '127.0.0.1:8082'}},
                  'ping': {'entryPoint': 'health'},
                  'api': {'dashboard': False},
                  'experimental': {'abortOnPluginFailure': True, 'plugins': {PLUGIN: {
                      'moduleName': 'github.com/NX211/traefik-proxmox-provider',
                      'version': 'v0.7.0', 'hash': PLUGIN_ARCHIVE_SHA256}}},
                  'providers': {'file': {'filename': '/etc/traefik/shared.yml', 'watch': True},
                    'plugin': {PLUGIN: {'pollInterval': '30s', 'apiEndpoint': origin(selected['proxmox_url'], 'proxmox_url'),
                        'apiTokenId': selected['proxmox_token_id'], 'apiToken': values['proxmox_token'],
                        'apiLogging': 'info', 'apiValidateSSL': 'true'}}},
                  'certificatesResolvers': {'letsencrypt': {'acme': {'email': selected['acme_email'],
                      'storage': '/var/traefik/certs/acme.json', 'dnsChallenge': {
                          'provider': 'cloudflare', 'resolvers': dns_resolvers(selected['acme_dns_resolvers']),
                          'propagation': {'disableANSChecks': True, 'requireAllRNS': True}}}}},
                  'log': {'level': 'INFO'}, 'accessLog': {}}
        shared = {'tls': {'options': {'default': {'minVersion': 'VersionTLS12'}}},
                  'http': {'middlewares': {'security-headers': {'headers': {'contentTypeNosniff': True}}}}}
        add('traefik.yml', json.dumps(static, indent=2) + '\n')
        add('shared.yml', json.dumps(shared, indent=2) + '\n')
        add('pve-ca.pem', read_private(selected['pve_ca_file'], certificate=True))
        add('cloudflare-dns-token', values['cloudflare_dns_token'])
    return artifacts
