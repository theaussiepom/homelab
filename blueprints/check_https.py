#!/usr/bin/env python3
"""Read-only HTTPS acceptance for the exposures assigned to one guest job."""
import argparse
import http.client
import json
from pathlib import Path
import ssl
import time
from urllib.parse import urljoin, urlsplit

import compile as compiler
import component_https

MAX_BODY = 1024 * 1024
TIMEOUT = 10
ATTEMPTS = 6
REDIRECTS = {301, 302, 303, 307, 308}


def request(url):
    parsed = urlsplit(url)
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443,
        timeout=TIMEOUT, context=ssl.create_default_context())
    try:
        connection.request('GET', parsed.path + ('?' + parsed.query if parsed.query else ''),
                           headers={'User-Agent': 'homelab-https-check', 'Accept-Encoding': 'identity'})
        response = connection.getresponse()
        return response.status, response.getheader('Location'), response.read(MAX_BODY + 1)
    finally:
        connection.close()


def probe(check):
    url, seen, authenticated_route = check['url'], set(), False
    for _ in range(6):
        parsed = urlsplit(url)
        if not parsed.hostname:
            raise ValueError('HTTPS destination has no hostname')
        selected = component_https.origin(parsed.hostname, parsed.port or 443)
        if (parsed.scheme != 'https' or parsed.username is not None or parsed.password is not None
                or selected not in check['origins'] or url in seen
                or any(ord(c) < 32 or ord(c) == 127 for c in url) or '\\' in url):
            raise ValueError('unsafe or cyclic HTTPS redirect')
        seen.add(url)
        authenticated_route |= selected in check['auth_origins']
        status, location, body = request(url)
        if status in REDIRECTS:
            if not location:
                raise ValueError('redirect has no destination')
            url = urljoin(url, location)
            continue
        if status != 200 or not body or len(body) > MAX_BODY:
            raise ValueError('HTTPS endpoint did not return a bounded successful page')
        if check['require_auth'] and not authenticated_route:
            raise ValueError('protected endpoint did not reach its declared identity provider')
        # A login page replaces the requested resource until authentication.
        if check['contains'] and not authenticated_route and check['contains'].encode() not in body:
            raise ValueError('HTTPS endpoint response did not match its declared content')
        return
    raise ValueError('too many HTTPS redirects')


def verify(checks):
    # Retry only read-only GETs, with a finite bound shared by all endpoints.
    pending = list(checks)
    for attempt in range(ATTEMPTS):
        failed = []
        for check in pending:
            try:
                probe(check)
            except (OSError, ValueError, http.client.HTTPException):
                failed.append(check)
        pending = failed
        if not pending:
            return
        if attempt + 1 < ATTEMPTS:
            time.sleep(5)
    # URLs, responses and authentication redirect query strings stay out of logs.
    raise ValueError('HTTPS checks failed for exposures: ' + ', '.join(sorted({c['exposure'] for c in pending})))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stack', type=Path, required=True)
    parser.add_argument('--site-root', type=Path, required=True)
    parser.add_argument('--guest', required=True)
    parser.add_argument('--disabled', default='[]')
    args = parser.parse_args()
    plan = compiler.resolve_plan(args.stack, compiler.site_path(args.site_root),
                                 compiler.parse_disabled(args.disabled), admit=True)
    _, assignments = component_https.checks(plan.resolved, plan.site, plan.library)
    compiler.require(args.guest in plan.resolved['enabled'], 'Select an enabled guest')
    selected = assignments[args.guest]
    verify(selected)
    print(json.dumps({'https_checks': 'passed', 'endpoints': len(selected)}))


if __name__ == '__main__':
    main()
