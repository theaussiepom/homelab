#!/usr/bin/env python3
"""Read-only loopback health and closed-setup verification for PegaProx."""
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


if __name__ == "__main__":
    try:
        print(
            verify(
                [
                    "docker",
                    "compose",
                    "-f",
                    "/opt/homelab-app/compose.yml",
                    "exec",
                    "-T",
                    "pegaprox",
                ]
            )
        )
    except Exception:
        raise SystemExit(
            "PegaProx health contract failed; inspect private evidence."
        ) from None
