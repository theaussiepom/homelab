"""Pure finite foundation files from selected raw inputs and resolved metadata.

No authored/private paths, custody records or API endpoints are opened here.
The owning caller verifies discovery custody before supplying the token record.
"""
import copy
import json
import re
from pathlib import Path

import discovery
import foundation
import runtime_secrets
import identity_callbacks
from private_io import require

AUTH_FILES = {'secret_key': 'authentik-secret-key',
              'postgresql_password': 'postgresql-password', 'smtp_password': 'smtp-password'}
AUTH_HEADERS = ['X-authentik-' + name for name in ('username', 'groups', 'entitlements',
    'email', 'name', 'uid', 'jwt', 'meta-jwks', 'meta-outpost', 'meta-provider', 'meta-app', 'meta-version')]
PLAN_FIELDS = {'routes', 'middlewares', 'transports', 'canonical_middlewares'}


def _row(name, content, uid=0):
    return {'path': name, 'content': content, 'uid': uid, 'gid': uid, 'mode': '0400'}


def _scalar(raw):
    require(isinstance(raw, bytes) and 0 < len(raw) <= 65536,
            'Supply bounded selected scalar bytes')
    try:
        value = raw.decode('utf-8')
    except UnicodeError:
        raise ValueError('Supply UTF-8 selected scalar bytes') from None
    require(value.strip() and not any(char in value for char in '\r\n\x00'),
            'Supply one unchanged selected scalar value')
    return value


def _certificate(raw):
    require(isinstance(raw, bytes) and 0 < len(raw) <= 65536,
            'Supply the selected bounded public CA bytes')
    try:
        value = raw.decode('utf-8')
    except UnicodeError:
        raise ValueError('Supply UTF-8 public CA bytes') from None
    require('-----BEGIN CERTIFICATE-----' in value and 'PRIVATE KEY' not in value,
            'Supply only the selected public trust certificates')
    return raw


def _backend(target):
    require(isinstance(target, dict) and target.get('protocol') in ('http', 'https')
            and 'address' in target and type(target.get('port')) is int,
            'Bind an already resolved HTTP backend')
    result = target['protocol'] + '://' + target['address'] + ':' + str(target['port'])
    discovery.origin(result)
    return result


def routing(app, plan):
    """Project only this ingress's typed routes through the existing renderer."""
    require(isinstance(plan, dict) and set(plan) == PLAN_FIELDS
            and all(isinstance(value, dict) for value in plan.values()),
            'Supply the exact compiler-owned ingress projections')
    require(isinstance(app.get('id'), str), 'Select the owned ingress identity')
    middleware = {}
    canonical = set()
    for key, row in plan['middlewares'].items():
        discovery.name(key)
        require(isinstance(row, dict), 'Supply a resolved middleware declaration')
        kind = row.get('type')
        if kind == 'default-headers':
            require(set(row) == {'type'}, 'Preserve the fixed header middleware')
            if key != 'security-headers':
                middleware[key] = copy.deepcopy(discovery.DEFAULT_MIDDLEWARES['security-headers'])
        elif kind == 'ip-allow-list':
            require(set(row) == {'type', 'ranges'} and isinstance(row['ranges'], list)
                    and bool(row['ranges']), 'Preserve resolved client ranges')
            middleware[key] = {'ipAllowList': {'sourceRange': copy.deepcopy(row['ranges'])}}
        elif kind == 'forward-auth':
            require(set(row) == {'type', 'endpoint', 'target'}, 'Use only resolved forward authentication')
            middleware[key] = {'forwardAuth': {'address': _backend(row['target']) + discovery.AUTHENTIK_AUTH_PATH,
                'trustForwardHeader': True, 'authResponseHeaders': list(AUTH_HEADERS)}}
        elif kind == 'cloudflare-source':
            require(set(row) == {'type', 'ranges', 'origin_header'}, 'Use the resolved Cloudflare source policy')
            if any(key in route.get('middlewares', []) for route in plan['routes'].values()):
                middleware[key] = {'plugin': {'cloudflare-source': {
                    'internalCIDRs': copy.deepcopy(row['ranges']), 'originHeader': row['origin_header']}}}
        else:
            require(kind == 'canonical-home-redirect' and set(row) == {'type', 'app'}
                    and key in plan['canonical_middlewares'], 'Preserve the fixed canonical-home redirect')
            canonical.add(key)
            value = plan['canonical_middlewares'][key]
            require(isinstance(value, dict) and set(value) == {'redirectRegex'} and
                    isinstance(value['redirectRegex'], dict) and
                    set(value['redirectRegex']) == {'regex', 'replacement', 'permanent'} and
                    value['redirectRegex']['regex'] == '^https://[^/]+/(.*)' and
                    value['redirectRegex']['permanent'] is False,
                    'Preserve only the compiler-validated temporary canonical-home redirect')
            foundation.origin(value['redirectRegex']['replacement'], 'canonical home')
            middleware[key] = copy.deepcopy(value)
    require(canonical == set(plan['canonical_middlewares']), 'Refuse unused canonical projections')
    routes, callbacks, used_transports = {}, {}, set()
    for key, row in plan['routes'].items():
        discovery.name(key)
        require(isinstance(row, dict) and row.get('type') == 'http' and
                row.get('ingress_target', {}).get('app') == app['id'] and
                isinstance(row.get('hosts'), list) and row['hosts'],
                'Select only this ingress resolved HTTP routes')
        hosts = row['hosts']; selected = {'host': hosts[0], 'middlewares': list(row.get('middlewares', []))}
        require(set(selected['middlewares']) <= set(plan['middlewares']), 'Select defined middleware references')
        if len(hosts) > 1:
            selected['aliases'] = hosts[1:]
        auth = [name for name in selected['middlewares'] if plan['middlewares'][name]['type'] == 'forward-auth']
        require(len(auth) <= 1, 'Select one forward authentication boundary')
        if auth:
            selected['authentik_forward_auth'] = auth[0]
        target = row['target']
        if target.get('internal'):
            require(target['internal'] == 'dashboard' and target.get('app') == app['id'] and auth,
                    'Expose only the authenticated owned dashboard')
            selected['service'] = 'api@internal'
        else:
            selected['url'] = _backend(target)
        if 'transport' in row:
            selected['transport'] = row['transport']; used_transports.add(row['transport'])
        if 'app' not in target or target.get('internal'):
            routes[key] = selected
        elif auth:
            # Ordinary managed routes stay in their guest Notes. Only their
            # unauthenticated outpost callback belongs to the file provider.
            callbacks[key] = discovery.callback_fields(selected)
    require(used_transports <= set(plan['transports']), 'Select resolved backend trust')
    transports = {key: copy.deepcopy(value) for key, value in plan['transports'].items() if key in used_transports}
    result = {'routes': routes, 'middlewares': middleware, 'transports': transports,
              'authentik_callbacks': callbacks}
    discovery.validate_ingress(result)
    return result


def files(app, *, secrets, public_ca=None, route_cas=None, route_plan=None):
    require(isinstance(app, dict) and app.get('adapter') in ('authentik', 'traefik')
            and isinstance(secrets, dict) and isinstance(app.get('input_sources'), dict)
            and set(secrets) == set(app['input_sources']),
            'Supply exactly the selected foundation input roles')
    if app['adapter'] == 'authentik':
        require({'secret_key', 'postgresql_password'} <= set(secrets) <= set(AUTH_FILES)
                and public_ca is None and route_cas is None and route_plan is None,
                'Supply only this Authentik selected scalar roles')
        for raw in secrets.values():
            _scalar(raw)
        rows = [_row(AUTH_FILES[key], value, 1000) for key, value in secrets.items()]
        callbacks = app.get('settings', {}).get('allowed_callback_additions')
        if callbacks is not None:
            identity_callbacks.validate(callbacks)
            rows.append({'path':'identity-callbacks.json','content':json.dumps(callbacks),
                         'uid':0,'gid':0,'mode':'0600'})
        return rows
    cloudflare = app['settings'].get('cloudflare', False)
    require(set(secrets) == {'cloudflare_dns_token', 'proxmox_token'} |
            ({'cloudflare_origin_token'} if cloudflare else set())
            and isinstance(route_cas, dict), 'Supply only selected provider, DNS and public trust inputs')
    require(app['input_sources']['proxmox_token'].get('type') == 'file',
            'Read the retained provider record through its selected owner')
    settings = app['settings']; provider = settings['provider']; acme = settings['acme']
    require(isinstance(secrets['proxmox_token'], bytes) and 0 < len(secrets['proxmox_token']) <= 65536,
            'Supply the bounded retained provider record')
    token = runtime_secrets.retained_provider_token(secrets['proxmox_token'], provider['token_id'])
    _scalar(secrets['cloudflare_dns_token'])
    route_files = settings.get('route_ca_files', {})
    require(set(route_cas) == set(route_files), 'Supply exactly selected route trust bytes')
    selected = {'bind_address': app['role_addresses']['frontend'], 'proxmox_url': provider['url'],
        'proxmox_token_id': provider['token_id'], 'acme_email': acme['email'],
        'acme_dns_resolvers': acme['resolvers'], 'dashboard': app['properties'].get('dashboard', False)}
    foundation.address(selected['bind_address']); foundation.origin(selected['proxmox_url'], 'provider')
    foundation.dns_resolvers(selected['acme_dns_resolvers'])
    shared = routing(app, route_plan)
    if cloudflare:
        selected['cloudflare'] = True
        _scalar(secrets['cloudflare_origin_token'])
        require(16 <= len(secrets['cloudflare_origin_token']) <= 4096, 'Supply the retained bounded origin token')
        gates = [row['plugin']['cloudflare-source'] for row in shared['middlewares'].values()
                 if 'cloudflare-source' in row.get('plugin', {})]
        require(bool(gates), 'Select an explicit Cloudflare source middleware')
    expected_ca = {key for key, value in shared['transports'].items() if 'ca_file' in value}
    require(expected_ca == set(route_files), 'Retain exactly the selected route CA mounts')
    rows = [_row('traefik.yml', json.dumps(foundation.ingress_static(selected, token), indent=2)+'\n'),
            _row('shared.yml', json.dumps(discovery.shared(shared), indent=2)+'\n')]
    for key, row in route_files.items():
        discovery.name(key)
        require(isinstance(row, dict) and set(row) == {'source', 'filename'}
                and row['filename'] == 'route-'+key+'.pem'
                and row['source'] == shared['transports'][key]['ca_file'],
                'Preserve the selected route trust binding')
        rows.append(_row(row['filename'], _certificate(route_cas[key])))
    rows += [_row('pve-ca.pem', _certificate(public_ca)),
             _row('cloudflare-dns-token', secrets['cloudflare_dns_token'])]
    if cloudflare:
        rows.append(_row('cloudflare-origin-token', secrets['cloudflare_origin_token']))
        for leaf, name in (('cloudflare.go', 'cloudflare.go'), ('cloudflare-go.mod', 'go.mod'),
                           ('cloudflare-LICENSE', 'LICENSE'), ('cloudflare-manifest.yml', '.traefik.yml')):
            rows.append(_row(leaf, (Path(__file__).with_name('traefik_cloudflare') / name).read_bytes()))
    return rows
