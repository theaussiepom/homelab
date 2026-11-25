"""Bounded loopback settings API client, executed inside the selected PegaProx service."""
import json
import sys
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler

ERROR = 'PegaProx OIDC reconciliation failed'
FIXED = {'oidc_provider': 'generic', 'oidc_scopes': 'openid profile email',
         'oidc_default_role': 'viewer', 'oidc_auto_create_users': True,
         'oidc_admin_group_id': '', 'oidc_user_group_id': '', 'oidc_viewer_group_id': '',
         'oidc_skip_jwt_verification': False, 'oidc_skip_ssl_verify': False, 'oidc_audiences': ''}
VARIABLE = {'oidc_enabled', 'oidc_client_id', 'oidc_authority', 'oidc_redirect_uri',
            'oidc_username_claim', 'oidc_button_text', 'oidc_group_mappings', 'oidc_allow_private_ip'}
ENDPOINTS = {'authorization_url': 'authorization_endpoint', 'token_url': 'token_endpoint',
             'userinfo_url': 'userinfo_endpoint', 'jwks_url': 'jwks_uri'}
ALGORITHMS = {'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512',
              'ES256', 'ES384', 'ES512', 'EdDSA'}


def need(condition):
    if not condition:
        raise ValueError(ERROR)


def scalar(value):
    need(isinstance(value, str) and 0 < len(value.encode()) <= 65536 and value == value.strip()
         and not any(ord(c) < 32 or ord(c) == 127 for c in value))
    return value


def https(value):
    parsed = urlsplit(scalar(value))
    need(parsed.scheme == 'https' and parsed.hostname and not parsed.username
         and not parsed.password and not parsed.query and not parsed.fragment
         and '\\' not in value)
    return parsed


def validate(value):
    need(isinstance(value, dict) and set(value) - {'discovery_check'} ==
         {'settings', 'oidc_endpoints', 'client_secret', 'management_token'})
    need(value.get('discovery_check', 'local') in ('local', 'deferred'))
    settings = value['settings']
    need(isinstance(settings, dict) and set(settings) == set(FIXED) | VARIABLE)
    need(all(type(settings[k]) is type(v) and settings[k] == v for k, v in FIXED.items()))
    need(type(settings['oidc_enabled']) is bool and type(settings['oidc_allow_private_ip']) is bool)
    for field in ('oidc_client_id', 'oidc_button_text'):
        need(len(scalar(settings[field])) <= 256)
    need(settings['oidc_username_claim'] in ('preferred_username', 'email', 'upn'))
    authority = https(settings['oidc_authority'])
    need(https(settings['oidc_redirect_uri']).path == '/oidc/callback')
    groups = settings['oidc_group_mappings']
    need(isinstance(groups, list) and 0 < len(groups) <= 32)
    seen = set()
    for group in groups:
        need(isinstance(group, dict) and set(group) == {'group_id', 'role'})
        name = scalar(group['group_id'])
        need(len(name) <= 256 and name.casefold() not in seen and group['role'] in ('admin', 'user', 'viewer'))
        seen.add(name.casefold())
    endpoints = value['oidc_endpoints']
    need(isinstance(endpoints, dict) and set(endpoints) == set(ENDPOINTS) | {'signing_algorithms'})
    for name in ENDPOINTS:
        need(https(endpoints[name]).netloc == authority.netloc)
    algorithms = endpoints['signing_algorithms']
    need(isinstance(algorithms, list) and bool(algorithms)
         and all(isinstance(row, str) and row in ALGORITHMS for row in algorithms)
         and len(set(algorithms)) == len(algorithms))
    need(scalar(value['client_secret']) != '********')
    need(scalar(value['management_token']).startswith('pgx_')
         and value['management_token'] != value['client_secret'])
    return value


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise ValueError(ERROR)


def request(url, *, token=None, data=None, public=False):
    headers = {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    message = Request(url, headers=headers, data=None if data is None else json.dumps(data).encode())
    opener = build_opener(ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(message, timeout=20)
    except HTTPError as error:
        response = error
    with response:
        need(response.code == 200 or public and response.code == 401)
        raw = response.read(1048577)
        need(len(raw) <= 1048576)
        result = json.loads(raw)
        need(isinstance(result, dict))
        return result


def reconcile(value, *, applied=False):
    validate(value)
    settings = value['settings']
    if settings['oidc_enabled'] and value.get('discovery_check') != 'deferred':
        discovery = request(settings['oidc_authority'].rstrip('/') + '/.well-known/openid-configuration')
        need(discovery.get('issuer') == settings['oidc_authority'])
        need(all(discovery.get(field) == value['oidc_endpoints'][key] for key, field in ENDPOINTS.items()))
        need(set(value['oidc_endpoints']['signing_algorithms']) <=
             set(discovery.get('id_token_signing_alg_values_supported', [])))
    url = 'http://127.0.0.1:5000/api/settings/server'
    token = value['management_token']
    current = request(url, token=token)
    updates = {key: item for key, item in settings.items() if current.get(key) != item
               or type(current.get(key)) is not type(item)}
    if not applied or not current.get('oidc_client_secret'):
        updates['oidc_client_secret'] = value['client_secret']
    if updates:
        need(request(url, token=token, data=updates).get('success') is True)
        current = request(url, token=token)
    need(all(current.get(key) == item and type(current.get(key)) is type(item)
             for key, item in settings.items()) and current.get('oidc_client_secret') == '********')
    public = request('http://127.0.0.1:5000/api/auth/check', public=True)
    need(public.get('initialized') is True and public.get('authenticated') is False
         and public.get('oidc_enabled') is settings['oidc_enabled'])
    return {'changed': bool(updates)}


def main():
    try:
        value = json.load(sys.stdin)
        need(isinstance(value, dict) and set(value) == {'configuration', 'applied'}
             and type(value['applied']) is bool)
        print(json.dumps(reconcile(value['configuration'], applied=value['applied'])))
    except Exception:
        print(ERROR, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
