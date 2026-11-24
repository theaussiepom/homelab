"""Read-only FQDN checks through declared DNS, hostname-verified TLS and HTTP."""
import codecs
from concurrent.futures import as_completed
import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
from urllib.parse import parse_qs, urljoin, urlsplit

import dns_records

INPUT_LIMIT = 1024 * 1024
BODY_INSPECTION_LIMIT = 1024 * 1024
MAX_ENDPOINTS = 256
CONCURRENCY = 8
VERIFY_SECONDS = 600


class RouteFailure(ValueError):
    """Only fixed internal codes and numeric status escape to diagnostics."""
    def __init__(self, stage, cause, status=None):
        super().__init__('Routed endpoint ' + stage + ' ' + cause)
        self.details = {'stage': stage, 'cause': cause}
        if status is not None:
            self.details['http_status'] = status


class VerificationFailure(ValueError):
    def __init__(self, diagnostic):
        super().__init__('Routed endpoint verification failed')
        self.diagnostic = diagnostic


def expect(value, stage, cause, status=None):
    if not value:
        raise RouteFailure(stage, cause, status)


def failure(stage, error):
    for kind, cause in ((TimeoutError, 'timeout'), (ssl.SSLCertVerificationError, 'certificate'),
                        (ssl.SSLError, 'tls_error'), (ConnectionRefusedError, 'refused'),
                        (OSError, 'io_error'), (http.client.HTTPException, 'protocol_error')):
        if isinstance(error, kind):
            return RouteFailure(stage, cause)
    return RouteFailure(stage, 'invalid_response')


def require(value):
    if not value:
        raise ValueError('Invalid routed endpoint verification')


def ipv4(value):
    require(isinstance(value, str) and str(ipaddress.IPv4Address(value)) == value)
    return value


def hostname(value):
    require(isinstance(value, str) and len(value) <= 253 and '.' in value and
            all(re.fullmatch('[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', part) for part in value.split('.')))
    return value


def origin(value):
    require(isinstance(value, str) and len(value) <= 2048 and not any(c.isspace() for c in value))
    parsed = urlsplit(value)
    require(parsed.scheme == 'https' and parsed.hostname and not parsed.username and not parsed.password
            and parsed.path in ('', '/') and not parsed.query and not parsed.fragment
            and (parsed.port is None or 1 <= parsed.port <= 65535))
    hostname(parsed.hostname)
    return value.rstrip('/')


OIDC_ENDPOINTS = {'authorization_url': 'authorization_endpoint', 'token_url': 'token_endpoint',
                  'userinfo_url': 'userinfo_endpoint', 'jwks_url': 'jwks_uri'}
OIDC_ALGORITHMS = {'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512',
                   'ES256', 'ES384', 'ES512', 'EdDSA'}


def oidc_contract(row, selected):
    data = row['oidc']
    require(isinstance(data, dict) and set(data) == set(OIDC_ENDPOINTS) | {'issuer', 'callback',
            'client_id', 'signing_algorithms', 'resolver_address', 'ingress_address'})
    require(row['path'] == '/api/auth/oidc/login' and len(row['auth_origins']) == 1)
    require(data['callback'] == selected + '/oidc/callback')
    for name in ('issuer', *OIDC_ENDPOINTS):
        value = data[name]
        require(isinstance(value, str) and len(value) <= 2048
                and not any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value)
                and not any(c in value for c in ('?', '#', '%', chr(92))))
        url = urlsplit(value)
        require(url.scheme == 'https' and 'https://' + url.netloc == row['auth_origins'][0]
                and url.path.startswith('/') and not any(p in ('.', '..') for p in url.path.split('/')))
    require(isinstance(data['client_id'], str) and 0 < len(data['client_id']) <= 256
            and not any(ord(c) < 32 or ord(c) == 127 for c in data['client_id']))
    algs = data['signing_algorithms']
    require(isinstance(algs, list) and algs and all(isinstance(x, str) and x in OIDC_ALGORITHMS for x in algs)
            and len(algs) == len(set(algs)))
    ipv4(data['resolver_address'])
    ipv4(data['ingress_address'])


def validate(rows):
    require(isinstance(rows, list) and 1 <= len(rows) <= MAX_ENDPOINTS)
    seen = set()
    for row in rows:
        require(isinstance(row, dict) and set(row) - ({'oidc'} if row.get('mode') == 'oidc' else set()) == {'exposure', 'host', 'port', 'path', 'source_address',
            'resolver_address', 'resolver_source', 'ingress_address', 'mode', 'contains', 'route_origins', 'auth_origins'})
        require(isinstance(row['exposure'], str) and re.fullmatch('[a-z][a-z0-9_-]{0,62}', row['exposure']))
        hostname(row['host'])
        require(type(row['port']) is int and 1 <= row['port'] <= 65535)
        require(isinstance(row['path'], str) and row['path'].startswith('/') and not row['path'].startswith('//')
                and len(row['path']) <= 1024 and not any(c in row['path'] for c in '?%#\\')
                and not any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in row['path'])
                and not any(part in ('.', '..') for part in row['path'].split('/')))
        for field in ('source_address', 'resolver_address', 'resolver_source', 'ingress_address'):
            ipv4(row[field])
        require(row['mode'] in ('page', 'auth-redirect', 'oidc') and isinstance(row['contains'], str)
                and len(row['contains']) <= 256 and not any(ord(c) < 32 or ord(c) == 127 for c in row['contains'])
                and bool(row['contains']) == (row['mode'] == 'page'))
        for field in ('route_origins', 'auth_origins'):
            require(isinstance(row[field], list) and len(row[field]) <= 32
                    and all(isinstance(value, str) for value in row[field])
                    and len(set(row[field])) == len(row[field]))
            for value in row[field]:
                require(origin(value) == value)
        require(row['route_origins'] and (row['mode'] != 'auth-redirect' or row['auth_origins']))
        selected = 'https://' + row['host'] + (':'+str(row['port']) if row['port'] != 443 else '')
        key = (selected, row['mode'] == 'oidc')
        require(selected in row['route_origins'] and key not in seen)
        if row['mode'] == 'oidc':
            require('oidc' in row)
            oidc_contract(row, selected)
        seen.add(key)
    return rows


def fetch(row, url, deadline):
    parsed = urlsplit(url)
    selected = origin('https://' + parsed.netloc)
    expect(selected in row['route_origins'], 'redirect', 'foreign_origin')
    # Query the declared resolver directly. A public/fallback resolver cannot
    # hide a missing internal record, including on an externally bootstrapped ingress.
    stage = 'dns'
    try:
        dns_records.probe(parsed.hostname, row['ingress_address'], server=row['resolver_address'], source=row['resolver_source'])
        remaining = deadline - time.monotonic()
        expect(remaining > 0, 'connect', 'deadline_exhausted')
        stage = 'tls'
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        require(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED)
        stage = 'connect'
        raw = socket.create_connection((row['ingress_address'], parsed.port or 443), timeout=min(10, remaining),
                                       source_address=(row['source_address'], 0))
        connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, context=context,
                                                timeout=min(10, remaining))
        try:
            # The address came from a successful real DNS answer above. Keep the
            # FQDN for both SNI/certificate verification and the HTTP Host header.
            stage = 'tls'
            connection.sock = context.wrap_socket(raw, server_hostname=parsed.hostname)
            path = parsed.path or '/'
            if parsed.query:
                path += '?' + parsed.query
            stage = 'http'
            accept = 'text/html' if row['mode'] == 'auth-redirect' else 'text/html,application/json'
            connection.request('GET', path, headers={'User-Agent':'HomeLab-route-check/1','Accept':accept})
            response = connection.getresponse()
            body = response.read(BODY_INSPECTION_LIMIT+1)
            if row['mode'] == 'oidc':
                expect(len(body) <= BODY_INSPECTION_LIMIT, 'oidc', 'response_too_large')
            # One sentinel byte distinguishes EOF from a truncated prefix. Do
            # not turn a valid UTF-8 character cut at the budget into U+FFFD.
            decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
            text = decoder.decode(body[:BODY_INSPECTION_LIMIT], final=len(body) <= BODY_INSPECTION_LIMIT)
            return response.status, response.getheader('Location'), text
        finally:
            connection.close()
            raw.close()
    except RouteFailure:
        raise
    except (ValueError, OSError, http.client.HTTPException) as error:
        raise failure(stage, error) from None


def check_oidc(row, login_url, deadline):
    data = row['oidc']
    provider = {**row, 'route_origins': row['auth_origins'],
                'resolver_address': data['resolver_address'], 'ingress_address': data['ingress_address']}
    status, _, body = fetch(provider, data['issuer'].rstrip('/') + '/.well-known/openid-configuration', deadline)
    expect(status == 200, 'discovery', 'unexpected_status', status)
    try:
        document = json.loads(body)
    except (ValueError, RecursionError):
        raise RouteFailure('discovery', 'invalid_document') from None
    expect(isinstance(document, dict) and document.get('issuer') == data['issuer'],
           'discovery', 'issuer_mismatch')
    expect(all(document.get(field) == data[key] for key, field in OIDC_ENDPOINTS.items()),
           'discovery', 'endpoint_mismatch')
    algorithms = document.get('id_token_signing_alg_values_supported')
    expect(isinstance(algorithms, list) and all(alg in algorithms for alg in data['signing_algorithms']),
           'discovery', 'signing_algorithm_mismatch')
    status, location, _ = fetch(row, login_url, deadline)
    expect(status == 302, 'oidc', 'expected_redirect', status)
    expect(isinstance(location, str) and 0 < len(location) <= 8192 and '#' not in location
           and not any(c.isspace() or ord(c) < 32 or ord(c) == 127 or c == chr(92) for c in location),
           'oidc', 'invalid_redirect')
    endpoint, _, query = location.partition('?')
    expect(endpoint == data['authorization_url'], 'oidc', 'authorization_endpoint_mismatch')
    try:
        params = parse_qs(query, keep_blank_values=True, strict_parsing=True, max_num_fields=64)
    except ValueError:
        raise RouteFailure('oidc', 'invalid_redirect') from None
    expect(params.get('client_id') == [data['client_id']], 'oidc', 'client_id_mismatch')
    expect(params.get('redirect_uri') == [data['callback']], 'oidc', 'callback_mismatch')


def check(row, deadline):
    url = 'https://' + row['host'] + (':'+str(row['port']) if row['port'] != 443 else '') + row['path']
    if row['mode'] == 'oidc':
        return check_oidc(row, url, deadline)
    visited = set()
    for _ in range(8):
        expect(url not in visited, 'redirect', 'loop')
        visited.add(url)
        status, location, body = fetch(row, url, deadline)
        if status in (301,302,303,307,308):
            expect(isinstance(location, str) and 0 < len(location) <= 8192 and not any(c in location for c in '\r\n\\'),
                   'redirect', 'invalid_target', status)
            try:
                target = urljoin(url, location)
                parsed = urlsplit(target)
                target_origin = origin('https://' + parsed.netloc) if parsed.scheme == 'https' else None
            except ValueError:
                raise RouteFailure('redirect', 'invalid_target', status) from None
            expect(target_origin is not None and not parsed.username and not parsed.password,
                   'redirect', 'invalid_target', status)
            if row['mode'] == 'auth-redirect' and target_origin in row['auth_origins']:
                return
            expect(target_origin in row['route_origins'], 'redirect', 'foreign_origin', status)
            url = target
            continue
        expect(row['mode'] == 'page', 'expectation', 'auth_redirect_missing', status)
        expect(status == 200, 'expectation', 'unexpected_status', status)
        expect(row['contains'].casefold() in body.casefold(), 'expectation', 'marker_missing', status)
        return
    raise RouteFailure('redirect', 'limit')


def probe(row, deadline):
    """Retry one unchanged endpoint contract without exporting exception values."""
    attempts = 0
    while True:
        attempts += 1
        try:
            check(row, deadline)
            return {'status': 'passed', 'attempts': attempts}
        except (ValueError, OSError, http.client.HTTPException) as error:
            permanent = (row['mode'] == 'oidc' and isinstance(error, RouteFailure)
                         and error.details['stage'] in ('oidc', 'discovery')
                         and error.details.get('http_status', 200) < 500)
            if permanent or time.monotonic()+2 >= deadline:
                details = error if isinstance(error, RouteFailure) else failure('verification', error)
                return {'status': 'failed', 'attempts': attempts, **details.details}
            time.sleep(2)


def verify(rows):
    validate(rows)
    deadline = time.monotonic() + VERIFY_SECONDS
    for index, row in enumerate(rows):
        result = probe(row, deadline)
        if result['status'] != 'passed':
            raise VerificationFailure({'endpoint': index, 'exposure': row['exposure'], **result})
    return {'status':'passed','routed_endpoints':len(rows),'credentialed_login':False}


def parallel(rows, executor, *, blocked=None):
    """Collect every alias result; one failed probe never cancels another."""
    validate(rows)
    def selected(row):
        return probe(row, time.monotonic() + VERIFY_SECONDS)
    blocked = {} if blocked is None else blocked
    require(all(type(index) is int and 0 <= index < len(rows) and detail.get('status') == 'blocked'
                for index, detail in blocked.items()))
    pending = {executor.submit(selected, row): index for index, row in enumerate(rows) if index not in blocked}
    results = [({'endpoint': index, 'exposure': row['exposure'], **blocked[index]} if index in blocked else None)
               for index, row in enumerate(rows)]
    for future in as_completed(pending):
        index = pending[future]
        try:
            result = future.result()
            require(isinstance(result, dict) and result.get('status') in ('passed', 'failed'))
        except Exception:
            result = {'status': 'failed', 'attempts': 0, 'stage': 'verification', 'cause': 'internal_error'}
        results[index] = {'endpoint': index, 'exposure': rows[index]['exposure'], **result}
    require(all(result is not None for result in results))
    return {'status': 'passed' if all(row['status'] == 'passed' for row in results) else 'failed',
            'routed_endpoints': len(rows), 'credentialed_login': False, 'endpoints': results}


def main():
    try:
        require(len(sys.argv) == 2 and len(sys.argv[1]) <= INPUT_LIMIT)
        print(json.dumps(verify(json.loads(sys.argv[1]))))
    except VerificationFailure as error:
        print(json.dumps(error.diagnostic), file=sys.stderr)
        raise SystemExit('Routed endpoint verification failed; preserve its private evidence') from None
    except Exception:
        raise SystemExit('Routed endpoint verification failed; preserve its private evidence') from None


if __name__ == '__main__':
    main()
