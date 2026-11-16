"""Read-only FQDN checks through declared DNS, hostname-verified TLS and HTTP."""
import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
from urllib.parse import urljoin, urlsplit

import dns_records

LIMIT = 1024 * 1024


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


def validate(rows):
    require(isinstance(rows, list) and 1 <= len(rows) <= 256)
    seen = set()
    for row in rows:
        require(isinstance(row, dict) and set(row) == {'exposure', 'host', 'port', 'path', 'source_address',
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
        require(row['mode'] in ('page', 'auth-redirect') and isinstance(row['contains'], str)
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
        require(selected in row['route_origins'] and selected not in seen)
        seen.add(selected)
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
            connection.request('GET', path, headers={'User-Agent':'HomeLab-route-check/1','Accept':'text/html,application/json'})
            response = connection.getresponse()
            body = response.read(LIMIT+1)
            expect(len(body) <= LIMIT, 'http', 'response_too_large', response.status)
            return response.status, response.getheader('Location'), body.decode('utf-8', errors='replace')
        finally:
            connection.close()
            raw.close()
    except RouteFailure:
        raise
    except (ValueError, OSError, http.client.HTTPException) as error:
        raise failure(stage, error) from None


def check(row, deadline):
    url = 'https://' + row['host'] + (':'+str(row['port']) if row['port'] != 443 else '') + row['path']
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


def verify(rows):
    validate(rows)
    deadline = time.monotonic() + 600
    for index, row in enumerate(rows):
        attempts = 0
        while True:
            attempts += 1
            try:
                check(row, deadline)
                break
            except (ValueError, OSError, http.client.HTTPException) as error:
                if time.monotonic()+2 >= deadline:
                    details = error if isinstance(error, RouteFailure) else failure('verification', error)
                    raise VerificationFailure({'status': 'failed', 'endpoint': index,
                        'exposure': row['exposure'], 'attempts': attempts, **details.details}) from None
                time.sleep(2)
    return {'status':'passed','routed_endpoints':len(rows),'credentialed_login':False}


def main():
    try:
        require(len(sys.argv) == 2 and len(sys.argv[1]) <= LIMIT)
        print(json.dumps(verify(json.loads(sys.argv[1]))))
    except VerificationFailure as error:
        print(json.dumps(error.diagnostic), file=sys.stderr)
        raise SystemExit('Routed endpoint verification failed; preserve its private evidence') from None
    except Exception:
        raise SystemExit('Routed endpoint verification failed; preserve its private evidence') from None


if __name__ == '__main__':
    main()
