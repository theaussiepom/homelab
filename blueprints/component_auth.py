"""Closed source-only authentication/trust bindings; inert framework proposal.

No secret path is opened, IdP is contacted, policy is mutated or runtime account
is created. Existing app adapters retain their cryptographic/login behavior.
"""
import copy
import re
import ssl
from urllib.parse import urlsplit

from component_errors import at
from component_sources import closed, identifier, require
import component_types as types

ALGORITHMS = {'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512',
              'ES256', 'ES384', 'ES512', 'EdDSA'}
ENDPOINTS = ('authorization', 'token', 'userinfo', 'jwks')
AUTH_ADAPTERS = {'cloudbeaver-oidc': 'cloudbeaver',
                 'node-red-retained-oidc': 'node_red', 'zabbix-saml': 'zabbix'}


def _host(value):
    require(isinstance(value, str) and 0 < len(value) <= 253 and
            all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', part)
                for part in value.split('.')), 'component.hostname')
    return value


def _https_origin(value):
    types.text(value)
    require(not any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value)
            and not any(c in value for c in ('\\', '?', '#')), 'component.authentication')
    try:
        parsed = urlsplit(value)
        require(parsed.scheme == 'https' and parsed.hostname and not parsed.username
                and not parsed.password and parsed.path in ('', '/')
                and (parsed.port is None or 1 <= parsed.port <= 65535), 'component.authentication')
        _host(parsed.hostname)
    except ValueError:
        require(False, 'component.authentication')
    return value.rstrip('/')


def _origin(reference, exposures):
    require(isinstance(reference, dict), 'component.reference')
    if 'exposure' in reference:
        closed(reference, ('exposure',), ('domain',))
        require(identifier(reference['exposure']) and reference['exposure'] in exposures.resolved,
                'component.reference')
        selected = exposures.resolved[reference['exposure']]
        require(selected['type'] == 'http', 'component.authentication')
        domain = reference.get('domain', selected['domain'])
        require(domain in [selected['domain'], *selected.get('aliases', [])], 'component.reference')
        port = selected['ingress_target']['port']
        types.integer(port, 1, 65535)
    else:
        closed(reference, ('domain',))
        domain, port = reference['domain'], 443
    require(identifier(domain) and domain in exposures.domains, 'component.reference')
    host = _host(exposures.domains[domain])
    return _https_origin('https://' + host + (':' + str(port) if port != 443 else ''))


def _relative_path(value):
    types.text(value)
    require(value.startswith('/') and not value.startswith('//')
            and not any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value)
            and not any(c in value for c in ('?', '#', '\\', '%'))
            and not any(part in ('.', '..') for part in value.split('/')),
            'component.authentication')
    return value


def certificate(value, code='component.authentication'):
    require(isinstance(value, str) and value and '\x00' not in value, code)
    require(len(value.encode()) <= 65536 and value.count('-----BEGIN CERTIFICATE-----') == 1
            and value.count('-----END CERTIFICATE-----') == 1
            and value.strip().startswith('-----BEGIN CERTIFICATE-----')
            and value.strip().endswith('-----END CERTIFICATE-----')
            and 'PRIVATE KEY' not in value, code)
    try:
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=value)
    except ssl.SSLError:
        require(False, code)
    return value


def providers(resolver, exposures):
    result = {}
    for key, value in resolver.site['identity_providers'].items():
        with at('identity_providers', key):
            require(isinstance(value, dict), 'component.authentication')
            if value.get('type') == 'oidc':
                closed(value, ('type', 'origin', 'issuer_path', 'endpoints', 'signing_algorithms'))
                origin = _origin(value['origin'], exposures)
                closed(value['endpoints'], ENDPOINTS)
                issuer = origin + _relative_path(value['issuer_path'])
                urls = {name + '_url': origin + _relative_path(value['endpoints'][name])
                        for name in ENDPOINTS}
                algorithms = value['signing_algorithms']
                require(isinstance(algorithms, list) and bool(algorithms)
                        and all(isinstance(row, str) and row in ALGORITHMS for row in algorithms)
                        and len(set(algorithms)) == len(algorithms), 'component.authentication')
                result[key] = {'type': 'oidc', 'origin': origin, 'issuer': issuer,
                               'endpoints': dict(urls, signing_algorithms=list(algorithms))}
            elif value.get('type') == 'retained-node-red-oidc':
                closed(value, ('type', 'origin', 'provider_slug'))
                require(isinstance(value['provider_slug'], str) and
                        re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', value['provider_slug']),
                        'component.authentication')
                origin = _origin(value['origin'], exposures)
                require(urlsplit(origin).port is None, 'component.authentication')
                result[key] = {'type': value['type'], 'origin': origin,
                               'provider_slug': value['provider_slug']}
            else:
                closed(value, ('type', 'signing_certificate'))
                require(value['type'] == 'saml', 'component.authentication')
                result[key] = {'type': 'saml',
                               'signing_certificate': certificate(value['signing_certificate'])}
    return result


def transports(resolver, exposures):
    result = {}
    for key, value in resolver.policy['transport'].items():
        with at('policies', 'transport', key):
            closed(value, ('type',), ('context', 'server_name', 'certificate'))
            require(value['type'] == 'tls' and set(value) != {'type'}, 'component.transport')
            require(not ('context' in value and 'certificate' in value), 'component.transport')
            selected = {}
            if 'context' in value:
                require(identifier(value['context']) and value['context'] in resolver.site['contexts'],
                        'component.reference')
                ca_file = resolver.site['contexts'][value['context']]['trust']['ca_file']
                types.path(ca_file)
                selected['ca_file'] = ca_file
            if 'certificate' in value:
                selected['certificate'] = certificate(value['certificate'], 'component.transport')
            if 'server_name' in value:
                closed(value['server_name'], ('domain',))
                domain = value['server_name']['domain']
                require(identifier(domain) and domain in exposures.domains, 'component.reference')
                selected['server_name'] = _host(exposures.domains[domain])
            result[key] = selected
    return result


def _node_red(provider, selected, app):
    """Retain the existing settings wrapper; never provision a second secret."""
    require(provider['type'] == 'retained-node-red-oidc' and urlsplit(provider['origin']).port is None
            and urlsplit(app['origin_url']).port is None, 'component.authentication')
    require(re.fullmatch(r'[A-Za-z0-9_-]{1,256}', selected['client_id']) is not None,
            'component.authentication')
    return {'identity_url': provider['origin'], 'node_red_url': app['origin_url'],
            'client_id': selected['client_id'], 'provider_slug': provider['provider_slug']}


def authentication(resolver, selected_providers):
    requirements = resolver.library['authentication_profiles']
    for key, requirement in requirements.items():
        with at('authentication_profiles', key):
            closed(requirement, ('type', 'required'))
            require(requirement['type'] in AUTH_ADAPTERS and type(requirement['required']) is bool,
                    'component.authentication')
    definitions = resolver.policy['authentication']
    result = {}
    for key, app in resolver.apps.items():
        require(app['profile'] in resolver.library['app_profiles'], 'component.reference')
        profile = resolver.library['app_profiles'][app['profile']]
        requirement = None
        if 'authentication' in profile:
            require(profile['authentication'] in requirements, 'component.reference')
            requirement = requirements[profile['authentication']]
            require(not requirement['required'] or 'authentication' in app, 'component.authentication-required')
        if 'authentication' not in app:
            continue
        with at('apps', key, 'authentication'):
            reference = app['authentication']
            require(identifier(reference) and reference in definitions, 'component.reference')
            value = definitions[reference]
            require(isinstance(value, dict) and value.get('type') in AUTH_ADAPTERS
                    and app['adapter'] == AUTH_ADAPTERS[value['type']], 'component.authentication')
            require(requirement is None or value['type'] == requirement['type'], 'component.authentication')
            cloud = value['type'] == 'cloudbeaver-oidc'
            saml = value['type'] == 'zabbix-saml'
            closed(value, ('type', 'provider', 'default_login') if saml else
                   ('type', 'provider', 'client_id', 'client_secret', 'display_name', 'user_claim')
                   if cloud else ('type', 'provider', 'client_id'))
            require(identifier(value['provider']) and value['provider'] in selected_providers,
                    'component.reference')
            provider = selected_providers[value['provider']]
            require('origin_url' in app and _https_origin(app['origin_url']) == app['origin_url'],
                    'component.authentication')
            if saml:
                require(provider['type'] == 'saml' and value['default_login'] in ('zabbix', 'saml'),
                        'component.authentication')
                selected = {'public_url': app['origin_url'], 'default_login': value['default_login'],
                            'idp_signing_certificate': provider['signing_certificate']}
            else:
                require(provider['type'] == ('oidc' if cloud else 'retained-node-red-oidc'),
                        'component.authentication')
                types.text(value['client_id'])
                require(len(value['client_id']) <= 256 and
                        not any(c in value['client_id'] for c in '\r\n'), 'component.authentication')
                if cloud:
                    secret = value['client_secret']
                    require(identifier(secret) and secret in resolver.site['secret_sources']
                            and resolver.site['secret_sources'][secret]['type'] in ('file', 'environment'),
                            'component.authentication')
                    types.text(value['display_name'])
                    require(len(value['display_name']) <= 256
                            and not any(c in value['display_name'] for c in '\r\n')
                            and value['user_claim'] in ('sub', 'preferred_username', 'email'),
                            'component.authentication')
                    selected = {'version': 1, 'oidc_issuer': provider['issuer'],
                                'oauth_client_id': value['client_id'], 'oauth_name': value['display_name'],
                                'user_claim': value['user_claim'],
                                'oidc_endpoints': copy.deepcopy(provider['endpoints']),
                                'client_secret': secret}
                else:
                    selected = _node_red(provider, value, app)
            result[key] = selected
    return result


def canonical_home_middlewares(resolver, exposures):
    """Return only the fixed temporary canonical-root redirect renderer shape."""
    result = {}
    for key, value in resolver.policy['middlewares'].items():
        if not isinstance(value, dict) or value.get('type') != 'canonical-home-redirect':
            continue
        with at('policies', 'middlewares', key):
            closed(value, ('type', 'app'))
            require(identifier(value['app']) and value['app'] in resolver.apps, 'component.reference')
            app = resolver.apps[value['app']]
            require('origin' in app and 'origin_url' in app and
                    _https_origin(app['origin_url']) == app['origin_url'], 'component.origin')
            canonical = exposures.resolved[app['origin']['exposure']]
            require(canonical['type'] == 'http' and canonical['target'].get('app') == value['app']
                    and key not in canonical.get('middlewares', []), 'component.origin')
            routes = [row for row in exposures.resolved.values() if key in row.get('middlewares', [])]
            require(bool(routes), 'component.middleware')
            for row in routes:
                require(row['type'] == 'http' and row['target'] == canonical['target']
                        and row['ingress_target'] == canonical['ingress_target']
                        and row['middlewares'] == [*canonical.get('middlewares', []), key]
                        and not set(row['hosts']) & set(canonical['hosts']), 'component.origin')
            result[key] = {'redirectRegex': {'regex': '^https://[^/]+/(.*)',
                           'replacement': app['origin_url'] + '/', 'permanent': False}}
    return result


def bind(resolver, exposures):
    selected = providers(resolver, exposures)
    return {'identity_providers': selected,
            'authentication': authentication(resolver, selected),
            'transports': transports(resolver, exposures),
            'canonical_middlewares': canonical_home_middlewares(resolver, exposures)}
