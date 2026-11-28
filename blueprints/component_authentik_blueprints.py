"""Resolve app-owned registration intent into native Authentik v1 blueprints."""
import hashlib
import re
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

import yaml

from component_errors import at
from component_sources import closed, identifier, require
from routed_checks import OIDC_CALLBACKS
from identity_callbacks import canonical
from component_input_secrets import BLUEPRINT_SECRET_ROLES

FORWARD_SCOPE_MAPPINGS = ('goauthentik.io/providers/proxy/scope-proxy',
                         *('goauthentik.io/providers/oauth2/scope-' + scope
                           for scope in ('openid', 'email', 'profile', 'entitlements')))


@dataclass(frozen=True)
class Reference:
    tag: str
    value: object


class BlueprintDumper(yaml.SafeDumper):
    """Emit Authentik lookup tags without interpreting authored YAML as code."""


def represent_reference(dumper, reference):
    if isinstance(reference.value, list):
        return dumper.represent_sequence(reference.tag, reference.value, flow_style=True)
    return dumper.represent_scalar(reference.tag, reference.value)


BlueprintDumper.add_representer(Reference, represent_reference)


def find(model, field, value):
    return Reference('!Find', [model, [field, value]])


def render_forward_auth(spec):
    """Manage one proxy registration. The admission group and outpost are existing objects."""
    retained = spec.get('retained_application', {})
    provider = {'model': 'authentik_providers_proxy.proxyprovider', 'id': 'provider',
                'identifiers': {'name': spec['provider_name']}, 'attrs': {
                    'mode': 'forward_single', 'external_host': spec['origin'],
                    'internal_host': '', 'skip_path_regex': '', 'cookie_domain': '',
                    'basic_auth_enabled': False, 'intercept_header_auth': True, 'authentication_flow': None,
                    'jwt_federation_providers': [], 'jwt_federation_sources': [],
                    'authorization_flow': find('authentik_flows.flow', 'slug', spec['authorization_flow']),
                    'invalidation_flow': find('authentik_flows.flow', 'slug', spec['invalidation_flow']),
                    'property_mappings': [find('authentik_providers_oauth2.scopemapping', 'managed', scope)
                                          for scope in spec['scope_mappings']]}}
    app = {'model': 'authentik_core.application', 'id': 'application',
           'identifiers': {'slug': spec['slug']}, 'attrs': {'name': spec['app_name'],
               'provider': Reference('!KeyOf', 'provider'), 'policy_engine_mode': retained.get('policy_engine_mode', 'all'),
               'meta_launch_url': retained.get('launch_url', spec['origin'] + '/')}}
    binding = {'model': 'authentik_policies.policybinding',
               'identifiers': {'target': Reference('!KeyOf', 'application'),
                               'group': find('authentik_core.group', 'name', spec['admission_group'])},
               'attrs': {'order': 0, 'enabled': True, 'negate': False, 'failure_result': False}}
    return yaml.dump({'version': 1, 'metadata': {'name': 'homelab-forward-' + spec['slug'],
                      'labels': {'blueprints.goauthentik.io/instantiate': 'false'}},
                      'entries': [provider, app, binding]}, Dumper=BlueprintDumper, sort_keys=False)


def retained_node_red_registration(source, app, owner, resolver, exposures):
    """Adopt one existing client and only callbacks on explicitly selected aliases of this route."""
    require(app['lifecycle'] == 'retained', 'component.lifecycle')
    fields = ('slug', 'provider_name', 'admission_group', 'signing_key', 'authentication_flow',
              'authorization_flow', 'invalidation_flow', 'policy_engine_mode', 'launch_url',
              'callback_aliases', 'client_secret', 'secret_slot')
    closed(source, fields)
    for name in ('provider_name', 'admission_group', 'signing_key', 'authorization_flow', 'invalidation_flow'):
        label(source[name])
    if source['authentication_flow'] is not None:
        label(source['authentication_flow'])
    client = app['authentication_resolved']
    require(source['slug'] == client['provider_slug'] and re.fullmatch('[a-z0-9]+(?:-[a-z0-9]+)*', source['slug'])
            and source['policy_engine_mode'] in ('any', 'all')
            and source['launch_url'] in ('', app['origin_url'] + '/'), 'component.authentication')
    secret = source['client_secret']
    require(identifier(secret) and secret in resolver.site['secret_sources'] and
            resolver.site['secret_sources'][secret]['type'] in ('file', 'environment'), 'component.secret-source')
    aliases = source['callback_aliases']
    route = exposures.resolved[app['origin']['exposure']]
    require(isinstance(aliases, list) and all(identifier(item) and item in route.get('aliases', [])
            for item in aliases) and len(set(aliases)) == len(aliases), 'component.authentication')
    path = OIDC_CALLBACKS['/auth/strategy']
    additional = ['https://' + exposures.domains[item] + path for item in aliases]
    callback = app['origin_url'] + path
    require(callback not in additional and len(set(additional)) == len(additional), 'component.authentication')
    spec = {key: source[key] for key in fields if key not in ('client_secret', 'secret_slot', 'callback_aliases')}
    return {**spec, 'app': app['id'], 'guest': app['guest'], 'identity': owner,
            'app_name': app['display_name'], 'client_id': client['client_id'], 'callback': callback,
            'additional_callbacks': additional, 'secret_source': secret, 'retained': True}


def label(value):
    require(isinstance(value, str) and 0 < len(value) <= 150 and value == value.strip()
            and not any(ord(c) < 32 or ord(c) == 127 for c in value), 'component.authentication')


def registration(source, app, owner, app_id):
    closed(source, ('slug', 'provider_name', 'admission_group', 'signing_key',
                    'authentication_flow', 'authorization_flow', 'invalidation_flow'), ('secret_slot',))
    source = {key: value for key, value in source.items() if key != 'secret_slot'}
    require(isinstance(source['slug'], str) and re.fullmatch('[a-z0-9]+(?:-[a-z0-9]+)*', source['slug'])
            and len(source['slug']) <= 63, 'component.authentication')
    for value in source.values():
        label(value)
    client = app['authentication_resolved']
    settings = client['settings']
    slug = source['slug']
    issuer = urlsplit(settings['oidc_authority'])
    require(issuer.path == '/application/o/' + slug + '/', 'component.authentication')
    return {**source, 'app': app_id, 'guest': app['guest'], 'identity': owner,
            'app_name': app['display_name'], 'client_id': settings['oidc_client_id'],
            'callback': settings['oidc_redirect_uri'], 'launch_url': app['origin_url'] + '/',
            'secret_source': client['client_secret']}


def render(spec):
    slug = spec['slug']
    group = {'model': 'authentik_core.group', 'id': 'admission-group',
             'identifiers': {'name': spec['admission_group']}}
    provider = {'model': 'authentik_providers_oauth2.oauth2provider', 'id': 'provider',
                'identifiers': {'client_id': spec['client_id']}, 'attrs': {
                    'name': spec['provider_name'], 'client_type': 'confidential',
                    'client_secret': Reference('!File', '/run/secrets/oidc-' + slug),
                    'issuer_mode': 'per_provider', 'sub_mode': 'hashed_user_id',
                    'signing_key': find('authentik_crypto.certificatekeypair', 'name', spec['signing_key']),
                    'redirect_uris': [{'matching_mode': 'strict', 'redirect_uri_type': 'authorization', 'url': url}
                                      for url in [*spec.get('additional_callbacks', []), spec['callback']]],
                    'include_claims_in_id_token': True,
                    'property_mappings': [find('authentik_providers_oauth2.scopemapping', 'managed',
                         'goauthentik.io/providers/oauth2/scope-' + scope) for scope in ('openid', 'profile', 'email')],
                    **{key: find('authentik_flows.flow', 'slug', spec[key]) if spec[key] is not None else None
                       for key in ('authentication_flow', 'authorization_flow', 'invalidation_flow')}}}
    application = {'model': 'authentik_core.application', 'id': 'application',
                   'identifiers': {'slug': slug}, 'attrs': {'name': spec['app_name'],
                       'provider': Reference('!KeyOf', 'provider'), 'policy_engine_mode': spec.get('policy_engine_mode', 'all'),
                       'meta_launch_url': spec['launch_url']}}
    binding = {'model': 'authentik_policies.policybinding', 'identifiers': {
                   'target': Reference('!KeyOf', 'application'), 'group': Reference('!KeyOf', 'admission-group')},
               'attrs': {'order': 0, 'enabled': True, 'negate': False, 'failure_result': False}}
    entries = [provider, application, binding]
    if spec.get('retained'):
        binding['identifiers']['group'] = find('authentik_core.group', 'name', spec['admission_group'])
    else:
        entries.insert(0, group)
    return yaml.dump({'version': 1, 'metadata': {'name': 'homelab-oidc-' + slug,
            'labels': {'blueprints.goauthentik.io/instantiate': 'false'}},
            'entries': entries}, Dumper=BlueprintDumper, sort_keys=False)


def require_worker(owner):
    images = owner['software_selection']['images']
    worker = images['worker']['image']
    version = re.fullmatch(r'[^@]+:(\d+)\.(\d+)\.(\d+)@sha256:[0-9a-f]{64}', worker)
    require(worker == images['server']['image'] and version and
            tuple(map(int, version.groups())) >= (2026, 8, 6), 'component.image-binding')


def bind_forward(resolver, exposures, app):
    required = ('middleware', 'slug', 'provider_name', 'admission_group', 'outpost',
                'authorization_flow', 'invalidation_flow')
    source = closed(app['forward_auth'], required, ('retained_application',))
    for key in required:
        label(source[key])
    slug = source['slug']
    require(re.fullmatch('[a-z0-9]+(?:-[a-z0-9]+)*', slug) and len(slug) <= 63
            and source['outpost'] == 'embedded', 'component.authentication')
    middleware = exposures.middlewares.get(source['middleware'], {})
    owner = middleware.get('target', {}).get('app')
    require(middleware.get('type') == 'forward-auth' and owner in resolver.apps
            and resolver.apps[owner]['adapter'] == 'authentik', 'component.authentication')
    require_worker(resolver.apps[owner])
    selected = exposures.resolved.get(app.get('origin', {}).get('exposure'), {})
    require(selected.get('type') == 'http' and selected['target'].get('app') == app['id']
            and selected.get('middlewares', []).count(source['middleware']) == 1
            and len(selected['hosts']) == 1 and app.get('origin_url') == 'https://' + selected['hosts'][0],
            'component.authentication')
    name = app['display_name']
    if 'retained_application' in source:
        require(app['lifecycle'] == 'retained', 'component.lifecycle')
        retained = closed(source['retained_application'], ('name', 'policy_engine_mode', 'launch_url'))
        name = retained['name']
        label(name)
        require(retained['policy_engine_mode'] in ('any', 'all') and
                retained['launch_url'] in ('', app['origin_url'] + '/'), 'component.authentication')
    if app.get('authentication_resolved', {}).get('type') == 'forward-auth':
        declared = source['middleware']
        require(app['settings']['auth_headers'] == {'user': 'X-authentik-username', 'team': 'X-Team'},
                'component.authentication')
        network = set(app['identity']['networks'].values())
        for peer in resolver.apps.values():
            if (peer['id'] != app['id'] and peer['guest'] == app['guest']
                    and peer['identity'].get('project') == app['identity']['project']):
                require(network.isdisjoint(peer['identity']['networks'].values()), 'component.authentication')
        target = selected['target']
        routes = [row for row in exposures.resolved.values()
                  if row['target'].get('app') == app['id'] or
                  (row['type'] == 'http' and row['target'].get('address') == target['address']
                   and row['target'].get('port') == target['port'])]
        for route in routes:
            chain = route.get('middlewares', [])
            require(route is selected and len(chain) >= 2 and chain[-2] == declared
                    and exposures.middlewares[chain[-1]]['type'] == 'cloudbeaver-headers',
                    'component.authentication')
    settings = resolver.apps[owner]['settings']
    registrations = settings.setdefault('forward_blueprints', {})
    spec = {**source, 'app': app['id'], 'guest': app['guest'], 'type': 'forward_single',
            'origin': app['origin_url'], 'app_name': name, 'scope_mappings': list(FORWARD_SCOPE_MAPPINGS)}
    other = settings.get('oidc_blueprints', {})
    require(not any(item['slug'] == slug or item['provider_name'] == spec['provider_name']
                    or item.get('origin') == spec['origin'] for item in (*registrations.values(), *other.values())),
            'component.authentication')
    registrations[slug] = {**spec, 'blueprint': render_forward_auth(spec)}


def bind_saml(source, app, owner, settings):
    """Adopt the existing confidential IdP key by reference to the SP's pinned public certificate."""
    required = ('slug', 'application_name', 'provider_name', 'issuer', 'signing_key', 'admission_group',
                'authentication_flow', 'authorization_flow', 'invalidation_flow', 'policy_engine_mode',
                'session_minutes', 'attribute_mappings')
    closed(source, required)
    require(app['lifecycle'] == 'retained', 'component.lifecycle')
    for name in ('application_name', 'provider_name', 'issuer', 'signing_key', 'admission_group',
                 'authorization_flow', 'invalidation_flow'):
        label(source[name])
    if source['authentication_flow'] is not None:
        label(source['authentication_flow'])
    slug = source['slug']
    require(isinstance(slug, str) and re.fullmatch('[a-z0-9]+(?:-[a-z0-9]+)*', slug) and len(slug) <= 63,
            'component.authentication')
    require(source['policy_engine_mode'] in ('all', 'any') and type(source['session_minutes']) is int
            and 0 < source['session_minutes'] <= 525600, 'component.authentication')
    mappings = source['attribute_mappings']
    supported = ('email', 'groups', 'name', 'upn', 'uid', 'username', 'ms-windowsaccountname')
    require(isinstance(mappings, list) and all(item in supported for item in mappings)
            and len(set(mappings)) == len(mappings) and {'username', 'groups'} <= set(mappings),
            'component.authentication')
    certificate = app['authentication_resolved']['idp_signing_certificate'].strip()
    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).hexdigest()
    origin = app['origin_url']
    attributes = {
        'acs_url': origin + '/index_sso.php?acs', 'audience': origin + '/', 'issuer_override': source['issuer'],
        'sp_binding': 'post', 'sign_assertion': True, 'sign_response': False,
        'digest_algorithm': 'http://www.w3.org/2001/04/xmlenc#sha256',
        'signature_algorithm': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        'session_valid_not_on_or_after': 'minutes=' + str(source['session_minutes']),
        'assertion_valid_not_before': 'minutes=-5', 'assertion_valid_not_on_or_after': 'minutes=5',
        'default_name_id_policy': 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        'default_relay_state': '', 'sls_url': '', 'sls_binding': 'redirect', 'logout_method': 'frontchannel_iframe',
        'sign_logout_request': False, 'sign_logout_response': False,
    }
    flows = {key: source[key] for key in ('authentication_flow', 'authorization_flow', 'invalidation_flow')}
    references = {key: find('authentik_flows.flow', 'slug', val) if val else None for key, val in flows.items()}
    mapping_ids = ['goauthentik.io/providers/saml/' + name for name in sorted(mappings)]
    provider = {'model': 'authentik_providers_saml.samlprovider', 'id': 'provider',
                'identifiers': {'name': source['provider_name']}, 'attrs': {
                    **attributes, **references, 'signing_kp': find('authentik_crypto.certificatekeypair', 'name', source['signing_key']),
                    'property_mappings': [find('authentik_providers_saml.samlpropertymapping', 'managed', key) for key in mapping_ids]}}
    application = {'model': 'authentik_core.application', 'id': 'application', 'identifiers': {'slug': slug},
                   'attrs': {'name': source['application_name'], 'provider': Reference('!KeyOf', 'provider'),
                             'policy_engine_mode': source['policy_engine_mode'], 'meta_launch_url': ''}}
    binding = {'model': 'authentik_policies.policybinding', 'identifiers': {
        'target': Reference('!KeyOf', 'application'), 'group': find('authentik_core.group', 'name', source['admission_group'])},
        'attrs': {'order': 0, 'enabled': True, 'negate': False, 'failure_result': False}}
    spec = {key: source[key] for key in ('slug', 'application_name', 'provider_name', 'signing_key', 'admission_group',
                                         'policy_engine_mode')}
    spec.update(type='saml', app=app['id'], guest=app['guest'], identity=owner, attributes=attributes,
                flows=flows, mappings=mapping_ids, certificate_sha256=fingerprint)
    spec['blueprint'] = yaml.dump({'version': 1, 'metadata': {'name': 'homelab-saml-' + slug,
        'labels': {'blueprints.goauthentik.io/instantiate': 'false'}}, 'entries': [provider, application, binding]},
        Dumper=BlueprintDumper, sort_keys=False)
    current = settings.setdefault('saml_blueprints', {})
    require(slug not in current and all(old['provider_name'] != spec['provider_name'] and
            old['attributes']['acs_url'] != attributes['acs_url'] for old in current.values()), 'component.authentication')
    current[slug] = spec


def bind(resolver, exposures):
    owned = {}
    for app_id, app in sorted(resolver.apps.items()):
        if 'authentication' not in app:
            continue
        policy = resolver.policy['authentication'][app['authentication']]
        if 'registration' not in policy:
            continue
        with at('apps', app_id, 'authentication'):
            provider = resolver.site['identity_providers'][policy['provider']]
            reference = provider.get('origin', {}).get('exposure')
            require(reference in exposures.resolved, 'component.route-check-provider')
            owner = exposures.resolved[reference]['target'].get('app')
            require(owner in resolver.apps and resolver.apps[owner]['adapter'] == 'authentik',
                    'component.authentication')
            require_worker(resolver.apps[owner])
            source = policy['registration']
            if app['adapter'] == 'zabbix':
                require(provider['type'] == 'saml', 'component.authentication')
                bind_saml(source, app, owner, resolver.apps[owner]['settings'])
                continue
            if app['adapter'] == 'node_red':
                require(provider['type'] == 'oidc', 'component.authentication')
                spec = retained_node_red_registration(source, app, owner, resolver, exposures)
            else:
                spec = registration(source, app, owner, app_id)
            settings = resolver.apps[owner]['settings']
            configs = settings.setdefault('oidc_blueprints', {})
            slug = spec['slug']
            require(slug not in configs and (owner, spec['client_id']) not in owned
                    and all(item['provider_name'] != spec['provider_name'] for item in configs.values()),
                    'component.authentication')
            owned[owner, spec['client_id']] = app_id
            client_hash = canonical(spec['client_id'])
            require(all(row['client_id_sha256'] != client_hash for row in settings.get('allowed_callback_additions', [])),
                    'component.authentication')
            require(len(configs) < len(BLUEPRINT_SECRET_ROLES), 'component.secret-role')
            occupied = {row['secret_role'] for row in configs.values()}
            if 'secret_slot' in source:
                slot = source['secret_slot']
                require(type(slot) is int and 1 <= slot <= len(BLUEPRINT_SECRET_ROLES), 'component.secret-role')
                role = BLUEPRINT_SECRET_ROLES[slot - 1]
                require(role not in occupied, 'component.secret-role')
            else:
                role = next(role for role in BLUEPRINT_SECRET_ROLES if role not in occupied)
            configs[slug] = {**spec, 'secret_role': role, 'blueprint': render(spec)}
    for app_id, app in sorted(resolver.apps.items()):
        if 'forward_auth' in app:
            with at('apps', app_id, 'forward_auth'):
                bind_forward(resolver, exposures, app)
    for owner in resolver.apps.values():
        settings = owner.get('settings', {})
        for slug, saml in settings.get('saml_blueprints', {}).items():
            others = (*settings.get('oidc_blueprints', {}).values(), *settings.get('forward_blueprints', {}).values())
            require(all(other['slug'] != slug and other['provider_name'] != saml['provider_name'] for other in others),
                    'component.authentication')
