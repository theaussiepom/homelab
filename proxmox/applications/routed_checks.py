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
    require(selected in row['route_origins'])
    # Query the declared resolver directly. A public/fallback resolver cannot
    # hide a missing internal record, including on an externally bootstrapped ingress.
    dns_records.probe(parsed.hostname, row['ingress_address'], server=row['resolver_address'], source=row['resolver_source'])
    remaining = deadline - time.monotonic()
    require(remaining > 0)
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    require(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED)
    raw = socket.create_connection((row['ingress_address'], parsed.port or 443), timeout=min(10, remaining),
                                   source_address=(row['source_address'], 0))
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, context=context,
                                            timeout=min(10, remaining))
    try:
        # The address came from a successful real DNS answer above. Keep the
        # FQDN for both SNI/certificate verification and the HTTP Host header.
        connection.sock = context.wrap_socket(raw, server_hostname=parsed.hostname)
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query
        connection.request('GET', path, headers={'User-Agent':'HomeLab-route-check/1','Accept':'text/html,application/json'})
        response = connection.getresponse()
        body = response.read(LIMIT+1)
        require(len(body) <= LIMIT)
        return response.status, response.getheader('Location'), body.decode('utf-8', errors='replace')
    finally:
        connection.close()
        raw.close()


def check(row, deadline):
    url = 'https://' + row['host'] + (':'+str(row['port']) if row['port'] != 443 else '') + row['path']
    visited = set()
    for _ in range(8):
        require(url not in visited)
        visited.add(url)
        status, location, body = fetch(row, url, deadline)
        if status in (301,302,303,307,308):
            require(isinstance(location, str) and 0 < len(location) <= 8192 and not any(c in location for c in '\r\n\\'))
            target = urljoin(url, location)
            parsed = urlsplit(target)
            target_origin = origin('https://' + parsed.netloc) if parsed.scheme == 'https' else None
            require(target_origin is not None and not parsed.username and not parsed.password)
            if row['mode'] == 'auth-redirect' and target_origin in row['auth_origins']:
                return
            require(target_origin in row['route_origins'])
            url = target
            continue
        require(row['mode'] == 'page' and status == 200 and row['contains'].casefold() in body.casefold())
        return
    raise ValueError('Routed endpoint redirect limit exceeded')


def verify(rows):
    validate(rows)
    deadline = time.monotonic() + 600
    for row in rows:
        while True:
            try:
                check(row, deadline)
                break
            except (ValueError, OSError, http.client.HTTPException):
                require(time.monotonic()+2 < deadline)
                time.sleep(2)
    return {'status':'passed','routed_endpoints':len(rows),'credentialed_login':False}


def main():
    try:
        require(len(sys.argv) == 2 and len(sys.argv[1]) <= LIMIT)
        print(json.dumps(verify(json.loads(sys.argv[1]))))
    except Exception:
        raise SystemExit('Routed endpoint verification failed; preserve its private evidence') from None


if __name__ == '__main__':
    main()
