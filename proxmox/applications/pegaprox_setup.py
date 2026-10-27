#!/usr/bin/env python3
"""Bootstrap one fresh local account over container loopback; never print secrets."""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess

# This code is sent to Python's argv, while credentials travel only on stdin.
# Certificate bypass is confined to the generated self-signed loopback endpoint;
# it is never used for the browser, Proxmox, an IdP or a supplied URL.
CONTAINER_CODE = r'''
import json, ssl, sys
from urllib.error import HTTPError
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler, ProxyHandler
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise RuntimeError('Unexpected local redirect')
opener = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl._create_unverified_context()), NoRedirect())
mode = sys.argv[1]
def require(condition, message='Local setup verification failed'):
    if not condition: raise RuntimeError(message)
def call(path, data=None, token=None):
    headers = {'X-Requested-With': 'XMLHttpRequest', 'Origin': 'https://127.0.0.1:5000'}
    if token: headers['X-Session-ID'] = token
    if data is not None: headers['Content-Type'] = 'application/json'
    req = Request('https://127.0.0.1:5000' + path, headers=headers,
                  data=None if data is None else json.dumps(data).encode())
    try: response = opener.open(req, timeout=8)
    except HTTPError as error: response = error
    with response:
        raw = response.read(1048577)
        if len(raw) > 1048576: raise RuntimeError('Oversized local response')
        return response.code, json.loads(raw)
require(call('/api/health') == (200, {'status': 'ok', 'version': '1.4.1'}))
status, state = call('/api/auth/check')
require(status == 401 and state.get('authenticated') is False)
if mode == 'bootstrap':
    require(state.get('initialized') is False, 'Existing account/configuration; no bootstrap replay')
    require(not state.get('oidc_enabled') and (not state.get('ldap_enabled')))
    value = json.load(sys.stdin)
    code, created = call('/api/auth/setup', value)
    require(code == 200 and created.get('success') is True)
    code, login = call('/api/auth/login', value)
    require(code == 200 and login.get('success') is True)
    token = login['session_id']
    try:
        code, checked = call('/api/auth/check', token=token)
        require(code == 200 and checked['authenticated'] is True)
        require(checked['user']['username'] == value['username'] and checked['user']['role'] == 'admin')
    finally:
        require(call('/api/auth/logout', {}, token)[0] == 200)
    require(call('/api/auth/check')[1].get('initialized') is True)
elif mode == 'verify':
    require(state.get('initialized') is True)
else: raise RuntimeError('Unknown mode')
print('PegaProx verification passed')
'''


def password(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError('Expected an owned private bootstrap file')
        value = stream.read(129)
    if not 8 <= len(value) <= 128 or any(c in value for c in (b'\r', b'\n', b'\x00')):
        raise ValueError('Invalid bootstrap file')
    return value.decode()


def invoke(command, mode, username=None, secret=None):
    payload = '' if mode == 'verify' else json.dumps({'username': username, 'password': secret})
    result = subprocess.run([*command, 'python3', '-c', CONTAINER_CODE, mode], input=payload,
                            text=True, capture_output=True, timeout=90, check=False)
    if result.returncode != 0 or result.stdout.strip() != 'PegaProx verification passed':
        raise ValueError('PegaProx local bootstrap/verification failed; preserve the hold')
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['bootstrap', 'verify'])
    parser.add_argument('--password-file', type=Path)
    parser.add_argument('--username')
    args = parser.parse_args()
    try:
        if args.mode == 'bootstrap' and (args.password_file is None or not args.username):
            raise ValueError('Missing bootstrap inputs')
        value = password(args.password_file) if args.mode == 'bootstrap' else None
        print(invoke(['docker', 'compose', '-f', '/opt/homelab-app/compose.yml', 'exec', '-T', 'pegaprox'],
                     args.mode, args.username, value))
    except Exception:
        raise SystemExit('PegaProx local setup held; inspect private evidence. No password reset or replay.') from None


if __name__ == '__main__':
    main()
