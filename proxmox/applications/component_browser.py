"""Install only the admitted Influx objects in Traefik's watched shared file."""
import argparse
import hashlib
import http.client
import json
import os
import re
from pathlib import Path
import ssl
import socket
import stat
import time
from urllib.parse import urlsplit

import component_image as shared
from ingress_browser import candidate, packet, require

CONFIG = Path('/opt/homelab-app/runtime/shared.yml')
STATIC = Path('/opt/homelab-app/runtime/traefik.yml')
STATE = Path('/var/lib/homelab-browser-routes')


def read_config(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) in (0o400, 0o600) and info.st_size <= 1024*1024,
                'Expected a private installed ingress configuration')
        return stream.read(1024*1024+1)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def guard(settings):
    identity = json.loads(shared.read(shared.IDENTITY))
    require(identity.get('vmid') == settings['vmid'] and identity.get('kind') == 'ingress', 'Wrong installed guest')
    compose_raw, static_raw = shared.read(shared.COMPOSE), read_config(STATIC)
    require(digest(compose_raw) == settings['compose_sha256'] and digest(static_raw) == settings['runtime_sha256'],
            'Installed Compose or static configuration drifted')
    compose, static = json.loads(compose_raw), json.loads(static_raw)
    require(compose.get('name') == 'homelab-ingress' and set(compose.get('services', {})) == {'traefik'}
            and compose['services']['traefik']['image'] == settings['image']
            and all(any(isinstance(m, dict) and m.get('source') == str(src) and m.get('target') == dest
                        and m.get('read_only') is True for m in compose['services']['traefik'].get('volumes', []))
                    for src, dest in [(CONFIG, '/etc/traefik/shared.yml'), (STATIC, '/etc/traefik/traefik.yml')]),
            'Expected the unchanged ingress image and existing read-only file mounts')
    require(static.get('providers', {}).get('file') == {'filename': '/etc/traefik/shared.yml', 'watch': True}
            and static.get('entryPoints', {}).get('websecure', {}).get('address') == settings['route']['frontend_address'] + ':443'
            and 'letsencrypt' in static.get('certificatesResolvers', {})
            and not static['entryPoints']['websecure'].get('forwardedHeaders', {}).get('insecure')
            and not static['entryPoints']['websecure'].get('forwardedHeaders', {}).get('trustedIPs'),
            'The existing watched-file, TLS or direct-browser trust policy differs')
    ids = shared.command(['docker', 'compose', '-f', str(shared.COMPOSE), 'ps', '-q', 'traefik']).decode().split()
    require(len(ids) == 1 and re.fullmatch('[0-9a-f]{12,64}', ids[0]), 'Expected one existing Traefik container')
    row = json.loads(shared.command(['docker', 'inspect', '--format', '{{json .}}', ids[0]]))
    require(row['State']['Running'] is True and row['Config']['Image'] == settings['image'], 'Running ingress image differs')
    return compose_raw, static_raw, (ids[0], row['State']['StartedAt'])


def backend_ready(route):
    """Check only health/setup and the exact source address, never user data."""
    rows = json.loads(shared.command(['ip', '-json', 'address', 'show']))
    addresses = {n.get('local') for row in rows for n in row.get('addr_info', []) if n.get('family') == 'inet'}
    require(route['proxy_address'] in addresses, 'The approved Influx client address is not attached')
    backend = urlsplit(route['backend'])
    for path in ('/health', '/api/v2/setup'):
        conn = http.client.HTTPConnection(backend.hostname, backend.port, timeout=5,
                                          source_address=(route['proxy_address'], 0))
        try:
            conn.request('GET', path)
            reply = conn.getresponse(); body = reply.read(65537)
            require(reply.status == 200 and len(body) <= 65536, 'Influx readiness did not pass')
            value = json.loads(body)
            require(value.get('status') == 'pass' if path == '/health' else value.get('allowed') is False,
                    'Influx health/setup state differs')
        finally:
            conn.close()


def route_ready(route):
    """A TLS-verified anonymous redirect is a bounded load check, not login acceptance."""
    issuer = urlsplit(route['issuer']).hostname
    for attempt in range(30):
        try:
            conn = http.client.HTTPSConnection(route['host'], timeout=3)
            try:
                # Pin the actual selected ingress frontend while verifying the
                # browser hostname's certificate; DNS may still name the old proxy.
                raw = socket.create_connection((route['frontend_address'], 443), timeout=3)
                try:
                    conn.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=route['host'])
                except BaseException:
                    raw.close()
                    raise
                conn.request('GET', '/')
                reply = conn.getresponse(); location = urlsplit(reply.getheader('Location', ''))
                if (reply.status in (302, 303) and location.scheme == 'https'
                        and location.username is None and location.password is None
                        and location.port in (None, 443)
                        and (location.hostname == issuer or location.hostname == route['host']
                             and location.path.startswith('/outpost.goauthentik.io/'))):
                    return
            finally:
                conn.close()
        except (OSError, http.client.HTTPException):
            pass
        if attempt != 29: time.sleep(2)
    raise ValueError('The TLS-verified browser authentication redirect did not become ready')


def run(selected, verify_only=False):
    settings = packet(selected)
    require(os.geteuid() == 0, 'Use the selected guest maintenance playbook')
    original_runtime = guard(settings)
    compose_before, static_before, _ = original_runtime
    STATE.mkdir(mode=0o700, exist_ok=True)
    info = STATE.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
            'Expected the private route evidence directory')
    operation = STATE / 'influx-browser-v1'
    encoded = (json.dumps(settings, sort_keys=True, indent=2) + '\n').encode()
    if verify_only:
        info = operation.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
                'Expected the original private route operation directory')
        require(shared.read(operation / 'settings.json') == encoded
                and shared.read(operation / 'complete.json') == b'{"status":"passed"}\n'
                and not (operation / 'HOLD.json').exists() and not (operation / 'HOLD.json').is_symlink(),
                'The completed browser overlay differs or is held')
        original = shared.read(operation / 'shared-before.json')
        require(digest(original) == settings['shared_before_sha256']
                and read_config(CONFIG) == candidate(original, settings['route']), 'The maintained route drifted')
        backend_ready(settings['route']); route_ready(settings['route'])
        require(guard(settings) == original_runtime, 'Ingress restarted or changed during verification')
        return {'status': 'passed', 'changed': False, 'browser_login_verified': False}
    # A changed source revision cannot create another attempt for this route.
    operation.mkdir(mode=0o700)
    original = read_config(CONFIG)
    require(digest(original) == settings['shared_before_sha256'], 'Watched configuration drifted')
    updated = candidate(original, settings['route'])
    require(digest(updated) == settings['shared_after_sha256'], 'Reviewed route candidate differs')
    shared.save(operation / 'settings.json', encoded)
    shared.save(operation / 'shared-before.json', original)
    shared.save(operation / 'HOLD.json', b'{"automatic_retry":false}\n')
    backend_ready(settings['route'])
    # Keep the existing bind-mounted inode and exact owner/group/mode. Renaming
    # a replacement file would leave a single-file Docker bind on the old inode.
    with os.fdopen(os.open(CONFIG, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as anchor:
        info = os.fstat(anchor.fileno()); mode = stat.S_IMODE(info.st_mode)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and mode in (0o400, 0o600) and anchor.read() == original, 'Watched file changed before activation')
        os.fchmod(anchor.fileno(), 0o600)
        try:
            with os.fdopen(os.open(CONFIG, os.O_RDWR | os.O_NOFOLLOW), 'r+b') as stream:
                current = os.fstat(stream.fileno())
                require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino) and stream.read() == original,
                        'Watched file identity changed during admission')
                stream.seek(0); stream.write(updated); stream.truncate(); stream.flush(); os.fsync(stream.fileno())
        finally:
            os.fchmod(anchor.fileno(), mode); os.fsync(anchor.fileno())
    require(read_config(CONFIG) == updated and shared.read(shared.COMPOSE) == compose_before
            and read_config(STATIC) == static_before, 'Route/static/Compose readback differs')
    route_ready(settings['route'])
    require(guard(settings) == original_runtime, 'Ingress restarted or changed during activation')
    shared.save(operation / 'complete.json', b'{"status":"passed"}\n')
    (operation / 'HOLD.json').unlink(); shared.sync(operation)
    return {'status': 'passed', 'changed': True, 'browser_login_verified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--settings', type=Path, required=True)
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(run(json.loads(shared.read(args.settings)), args.verify_only)))
    except Exception:
        raise SystemExit('Ingress browser route held; preserve original evidence. No automatic retry.') from None
