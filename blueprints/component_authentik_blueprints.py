"""Resolve app-owned registration intent into native Authentik v1 blueprints."""
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import yaml

from component_errors import at
from component_sources import closed, require
from identity_callbacks import canonical
from component_input_secrets import BLUEPRINT_SECRET_ROLES


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


def registration(source, app, owner, app_id):
    closed(source, ('slug', 'provider_name', 'admission_group', 'signing_key',
                    'authentication_flow', 'authorization_flow', 'invalidation_flow'))
    require(isinstance(source['slug'], str) and re.fullmatch('[a-z0-9]+(?:-[a-z0-9]+)*', source['slug'])
            and len(source['slug']) <= 63, 'component.authentication')
    for value in source.values():
        require(isinstance(value, str) and 0 < len(value) <= 150 and value == value.strip()
                and not any(ord(c) < 32 or ord(c) == 127 for c in value), 'component.authentication')
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
                    'redirect_uris': [{'matching_mode': 'strict', 'redirect_uri_type': 'authorization', 'url': spec['callback']}],
                    'include_claims_in_id_token': True,
                    'property_mappings': [find('authentik_providers_oauth2.scopemapping', 'managed',
                         'goauthentik.io/providers/oauth2/scope-' + scope) for scope in ('openid', 'profile', 'email')],
                    **{key: find('authentik_flows.flow', 'slug', spec[key])
                       for key in ('authentication_flow', 'authorization_flow', 'invalidation_flow')}}}
    application = {'model': 'authentik_core.application', 'id': 'application',
                   'identifiers': {'slug': slug}, 'attrs': {'name': spec['app_name'],
                       'provider': Reference('!KeyOf', 'provider'), 'policy_engine_mode': 'all',
                       'meta_launch_url': spec['launch_url']}}
    binding = {'model': 'authentik_policies.policybinding', 'identifiers': {
                   'target': Reference('!KeyOf', 'application'), 'group': Reference('!KeyOf', 'admission-group')},
               'attrs': {'order': 0, 'enabled': True, 'negate': False, 'failure_result': False}}
    return yaml.dump({'version': 1, 'metadata': {'name': 'homelab-oidc-' + slug,
            'labels': {'blueprints.goauthentik.io/instantiate': 'false'}},
            'entries': [group, provider, application, binding]}, Dumper=BlueprintDumper, sort_keys=False)


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
            reference = provider['origin'].get('exposure')
            require(reference in exposures.resolved, 'component.route-check-provider')
            owner = exposures.resolved[reference]['target'].get('app')
            require(owner in resolver.apps and resolver.apps[owner]['adapter'] == 'authentik',
                    'component.authentication')
            images = resolver.apps[owner]['software_selection']['images']
            worker = images['worker']['image']
            version = re.fullmatch(r'[^@]+:(\d+)\.(\d+)\.(\d+)@sha256:[0-9a-f]{64}', worker)
            require(worker == images['server']['image'] and version
                    and tuple(map(int, version.groups())) >= (2026, 8, 6), 'component.image-binding')
            spec = registration(policy['registration'], app, owner, app_id)
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
            configs[slug] = {**spec, 'secret_role': BLUEPRINT_SECRET_ROLES[len(configs)], 'blueprint': render(spec)}
