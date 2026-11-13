#!/usr/bin/env python3
"""Read-only loopback health and closed-setup verification for PegaProx."""
import argparse
import re
import subprocess

CONTAINER_CODE = r"""
import json, sys, time
from urllib.error import HTTPError
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise RuntimeError('Unexpected local redirect')
def require(condition, message='Local setup verification failed'):
    if not condition: raise RuntimeError(message)
def call(path):
    headers = {'X-Requested-With': 'XMLHttpRequest', 'Origin': 'http://127.0.0.1:5000'}
    req = Request('http://127.0.0.1:5000' + path, headers=headers)
    opener = build_opener(ProxyHandler({}), NoRedirect())
    try: response = opener.open(req, timeout=4 if path == '/api/health' else 8)
    except HTTPError as error: response = error
    with response:
        raw = response.read(1048577)
        if len(raw) > 1048576: raise RuntimeError('Oversized local response')
        return response.code, json.loads(raw)
deadline = time.monotonic() + 65
while True:
    try:
        status, body = call('/api/health')
        if status == 200 and isinstance(body, dict) and body.get('status') == 'ok' and isinstance(body.get('version'), str) and body['version']: break
    except (OSError, ValueError, RuntimeError):
        pass
    if time.monotonic() >= deadline:
        raise RuntimeError('PegaProx did not become ready')
    time.sleep(2)
status, state = call('/api/auth/check')
require(status == 401 and isinstance(state, dict) and state.get('authenticated') is False)
require(state.get('initialized') is True)
print('PegaProx verification passed')
"""


def verify(command):
    result = subprocess.run(
        [*command, "python3", "-c", CONTAINER_CODE],
        text=True,
        capture_output=True,
        timeout=90,
        check=False,
    )
    if (
        result.returncode != 0
        or result.stdout.strip() != "PegaProx verification passed"
    ):
        raise ValueError("PegaProx verification failed; preserve the deployment hold")
    return result.stdout.strip()


def command(compose_file='/opt/homelab-app/compose.yml', service='pegaprox'):
    if not (isinstance(compose_file,str) and re.fullmatch(
            r'/opt/homelab-app/[a-z][a-z0-9_-]{0,62}\.ya?ml',compose_file)
            and isinstance(service,str) and re.fullmatch('[a-z0-9][a-z0-9_-]{0,127}',service)):
        raise ValueError('Select the declared PegaProx project file and owned service')
    return ['docker','compose','-f',compose_file,'exec','-T',service]


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose-file',default='/opt/homelab-app/compose.yml')
    parser.add_argument('--service',default='pegaprox')
    args=parser.parse_args()
    try:
        print(verify(command(args.compose_file,args.service)))
    except Exception:
        raise SystemExit(
            "PegaProx health contract failed; inspect private evidence."
        ) from None
