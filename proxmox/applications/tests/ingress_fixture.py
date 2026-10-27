"""Exercise pinned Traefik routes with synthetic backends, never live services.

No published ports, credentials, production data or external container network.
The tools image is the existing CI source-tools image, not a deployment image.
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid

IMAGE = 'traefik@sha256:1336e85aaed293bd63d005086e0dd013b04078b26aaeb1c18b26a2f928af7e65'


def serve():
    class Backend(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.server.server_port == 9000 and self.path == '/outpost.goauthentik.io/auth/traefik':
                if self.headers.get('Cookie') == 'fixture_session=ok':
                    self.send_response(200)
                    self.send_header('X-authentik-username', 'fixture-user')
                else:
                    self.send_response(302)
                    locations = {
                        'flows.example.invalid': 'https://auth.example.invalid/login?host=flows.example.invalid',
                        'flows.alias.invalid': 'https://auth.example.invalid/login?host=flows.alias.invalid'}
                    self.send_header('Location', locations.get(self.headers.get('X-Forwarded-Host'),
                                     'https://auth.example.invalid/login?host=missing'))
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({'backend': self.server.server_port, 'path': self.path,
                                        'host': self.headers.get('Host'),
                                        'proto': self.headers.get('X-Forwarded-Proto'),
                                        'user': self.headers.get('X-authentik-username')}).encode())

        def log_message(self, *args):
            pass

    for port in (8123, 1880, 9000, 8080):
        server = ThreadingHTTPServer(('127.0.0.1', port), Backend)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Event().wait()


def request(host, path, headers=None):
    # Traefik's generated default cert is deliberately used only in this fixture.
    connection = http.client.HTTPSConnection('127.0.0.1', 8443, timeout=3,
                                              context=ssl._create_unverified_context())
    try:
        connection.request('GET', path, headers={'Host': host, **(headers or {})})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def check():
    for attempt in range(60):
        try:
            if request('ha.example.invalid', '/')[0] == 200:
                break
        except (OSError, ssl.SSLError):
            pass
        if attempt == 59:
            raise RuntimeError('Synthetic ingress startup exceeded its bound')
        time.sleep(0.5)
    count = 0
    for domain in ('example.invalid', 'alias.invalid'):
        for prefix, port, path in [('ha', 8123, '/auth/authorize'),
                                   ('auth', 9000, '/application/o/pgadmin4/.well-known/openid-configuration'),
                                   ('pgadmin', 8080, '/oauth2/authorize?code=synthetic'),
                                   ('flows', 9000, '/outpost.goauthentik.io/callback?code=synthetic')]:
            host = f'{prefix}.{domain}'
            status, headers, body = request(host, path)
            assert status == 200, (host, path, status)
            assert json.loads(body) == {'backend': port, 'path': path, 'host': host,
                                        'proto': 'https', 'user': None}
            if prefix == 'pgadmin':
                assert headers['X-Fixture-Policy'] == 'synthetic-only'
            count += 1
        host = f'flows.{domain}'
        status, headers, _ = request(host, '/', {'X-Forwarded-Host': 'spoof.invalid',
                                                'X-Forwarded-Proto': 'http'})
        assert status == 302, status
        assert headers['Location'] == 'https://auth.example.invalid/login?host=' + host
        count += 1
        status, _, body = request(host, '/editor', {'Cookie': 'fixture_session=ok',
                                                   'X-authentik-username': 'spoofed-user'})
        assert status == 200, status
        assert json.loads(body) == {'backend': 1880, 'path': '/editor', 'host': host,
                                    'proto': 'https', 'user': 'fixture-user'}
        count += 1
    assert request('unrouted.example.invalid', '/')[0] == 404
    print(f'Ingress fixture passed: {count + 1} HTTPS route/header checks; real login remains unverified')


def docker(*args, **kwargs):
    return subprocess.run(['docker', *args], check=True, timeout=180, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tools-image', default='homelab-app-test')
    args = parser.parse_args()
    from test_ingress import ingress_fixture, render
    cfg = ingress_fixture()
    del cfg['ingress_cert_resolver']  # No ACME network or credentials in a fixture.
    for name, port in [('homeassistant', 8123), ('node_red', 1880), ('identity', 9000), ('pgadmin', 8080)]:
        cfg[f'{name}_url'] = f'http://127.0.0.1:{port}'
    routes = render.ingress(cfg)
    # Stand in for the existing non-authentication middleware definition.
    routes['http']['middlewares']['chain-lan-unsafe'] = {'headers': {'customResponseHeaders': {
        'X-Fixture-Policy': 'synthetic-only'}}}
    names = []
    with tempfile.TemporaryDirectory(prefix='homelab-ingress-fixture-') as tmp:
        root = Path(tmp)
        (root / 'routes.yml').write_text(json.dumps(routes))
        try:
            for side in ('backends', 'proxy'):
                name = 'homelab-ingress-fixture-' + side + '-' + uuid.uuid4().hex[:10]
                names.append(name)
                # Match the 0700 temporary directory owner without DAC capabilities.
                common = ['run', '-d', '--rm', '--platform', 'linux/amd64', '--read-only',
                          '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                          '--user', f'{os.getuid()}:{os.getgid()}',
                          '--cpus', '1', '--memory', '256m', '--name', name,
                          '--tmpfs', '/tmp:rw,nosuid,nodev,size=16m']
                if side == 'backends':
                    docker(*common, '--network', 'none', '--entrypoint', 'python3',
                           '-v', f'{Path(__file__).resolve()}:/fixture.py:ro', args.tools_image,
                           '/fixture.py', 'serve', stdout=subprocess.DEVNULL)
                else:
                    docker(*common, '--network', 'container:' + names[0],
                           '-v', f'{root}:/fixture:ro', IMAGE,
                           '--entrypoints.https.address=:8443', '--providers.file.filename=/fixture/routes.yml',
                           '--global.checknewversion=false', '--global.sendanonymoususage=false',
                           stdout=subprocess.DEVNULL)
            docker('exec', names[0], 'python3', '/fixture.py', 'check')
        except Exception:
            if len(names) == 2:
                subprocess.run(['docker', 'logs', '--tail', '50', names[1]], check=False)
            raise
        finally:
            for name in reversed(names):
                subprocess.run(['docker', 'rm', '-f', name], check=False, stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    if sys.argv[1:] == ['serve']:
        serve()
    elif sys.argv[1:] == ['check']:
        check()
    else:
        main()
