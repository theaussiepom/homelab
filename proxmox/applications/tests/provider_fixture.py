"""Run pinned Traefik and its unmodified Proxmox plugin against synthetic HTTPS.

Only loopback inside a Docker network namespace is used: no published ports,
Docker socket mounts, live PVE access, real tokens, or application data. Fetch
the pinned upstream source before running this fixture; --plugin-source accepts
its checkout or extracted archive and verifies all source bytes before use.
"""
import argparse
import hashlib
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

IMAGE = 'traefik@sha256:6b9cbca6fac42ab0075f5437d8dc1685cfd188626d8d515839ea94f8b6271c42'
MODULE = 'github.com/NX211/traefik-proxmox-provider'
PLUGIN_COMMIT = 'e35cce5af139328b8e424836a0b32638ed777016'
PLUGIN_TREE_SHA256 = 'b1154d92f81ef7c1b85b2f572735839b82c352f4e1fc5da8d398301e63bfc247'
TOKEN = 'PVEAPIToken=fixture@pve!discovery=synthetic-not-a-secret'
SERVICES = {211: ('authentik', 'sso.example.invalid', 9000),
            202: ('pgadmin', 'pgadmin.example.invalid', 8080)}


def source_digest(root):
    digest = hashlib.sha256()
    files = sorted(path for path in root.rglob('*')
                   if '.git' not in path.relative_to(root).parts and path.is_file())
    if any(path.is_symlink() for path in files):
        raise ValueError('Plugin fixture source must not contain symlinks')
    for path in files:
        digest.update(path.relative_to(root).as_posix().encode() + b'\0')
        digest.update(path.read_bytes() + b'\0')
    return digest.hexdigest()


def notes(name, host, port):
    # v0.7.0 splits colon-containing lines before considering equals syntax.
    # Colon form is therefore essential for explicit http:// backend URLs.
    return '\n'.join([
        'Synthetic service, discovered exclusively from Proxmox Notes.',
        'traefik.enable: true',
        f'traefik.http.routers.{name}.rule: Host(`{host}`)',
        f'traefik.http.routers.{name}.entrypoints: https',
        f'traefik.http.routers.{name}.tls: true',
        f'traefik.http.routers.{name}.service: {name}',
        f'traefik.http.routers.{name}.middlewares: fixture-policy@file',
        f'traefik.http.services.{name}.loadbalancer.server.url: http://127.0.0.1:{port}',
    ])


def serve():
    calls = []
    lock = threading.Lock()

    class Backend(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({'backend': self.server.server_port,
                                        'path': self.path, 'host': self.headers.get('Host'),
                                        'proto': self.headers.get('X-Forwarded-Proto'),
                                        'user': self.headers.get('X-authentik-username')}).encode())

        def log_message(self, *args):
            pass

    class PVE(BaseHTTPRequestHandler):
        def send_json(self, status, payload):
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(payload).encode())

        def do_GET(self):
            if self.path == '/fixture/requests':
                with lock:
                    return self.send_json(200, list(calls))
            with lock:
                calls.append({'method': self.command, 'path': self.path,
                              'authorized': self.headers.get('Authorization') == TOKEN})
            if self.headers.get('Authorization') != TOKEN:
                return self.send_json(401, {'error': 'Synthetic token required'})
            data = {
                '/api2/json/version': {'release': 'fixture-only'},
                '/api2/json/nodes': [{'node': 'fixture'}],
                '/api2/json/nodes/fixture/qemu': [],
                '/api2/json/nodes/fixture/lxc': [
                    {'vmid': vmid, 'name': value[0], 'status': 'running'}
                    for vmid, value in SERVICES.items()
                ] + [{'vmid': 213, 'name': 'stopped', 'status': 'stopped'},
                     {'vmid': 214, 'name': 'disabled', 'status': 'running'}],
                '/api2/json/nodes/fixture/lxc/214/config': {'description': 'traefik.enable: false'},
            }
            for vmid, value in SERVICES.items():
                data[f'/api2/json/nodes/fixture/lxc/{vmid}/config'] = {'description': notes(*value)}
            if self.path in data:
                return self.send_json(200, {'data': data[self.path]})
            # The pinned plugin asks a QEMU-agent endpoint even for LXCs. Deny
            # it: passing routes must use the declared backend URL, not discovery.
            return self.send_json(404, {'error': 'No such synthetic API endpoint'})

        def reject_mutation(self):
            with lock:
                calls.append({'method': self.command, 'path': self.path, 'authorized': False})
            self.send_json(405, {'error': 'Read-only fixture'})

        do_POST = do_PUT = do_DELETE = do_PATCH = reject_mutation

        def log_message(self, *args):
            pass

    for port in (9000, 8080):
        server = ThreadingHTTPServer(('127.0.0.1', port), Backend)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    api = ThreadingHTTPServer(('127.0.0.1', 8006), PVE)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('/fixture/server.pem', '/fixture/server.key')
    api.socket = context.wrap_socket(api.socket, server_side=True)
    threading.Thread(target=api.serve_forever, daemon=True).start()
    threading.Event().wait()


def request(host, path):
    context = ssl.create_default_context(cafile='/fixture/ca.pem')
    conn = http.client.HTTPSConnection('127.0.0.1', 8443, timeout=3, context=context)
    try:
        conn.request('GET', path, headers={'Host': host})
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()


def api_calls():
    conn = http.client.HTTPSConnection('127.0.0.1', 8006, timeout=3,
                                      context=ssl.create_default_context(cafile='/fixture/ca.pem'))
    try:
        conn.request('GET', '/fixture/requests')
        response = conn.getresponse()
        assert response.status == 200, response.status
        return json.loads(response.read())
    finally:
        conn.close()


def check():
    for attempt in range(90):
        try:
            if request('sso.example.invalid', '/ready')[0] == 200:
                break
        except (OSError, ssl.SSLError):
            pass
        if attempt == 89:
            raise RuntimeError('Synthetic provider startup exceeded 45 seconds')
        time.sleep(0.5)
    for name, host, port in SERVICES.values():
        paths = ['/']
        if name == 'authentik':
            paths += ['/application/o/pgadmin4/.well-known/openid-configuration',
                      '/outpost.goauthentik.io/callback?code=synthetic']
        else:
            paths += ['/oauth2/authorize?code=synthetic']
        for path in paths:
            status, headers, body = request(host, path)
            assert status == 200, (host, path, status)
            assert json.loads(body) == {'backend': port, 'path': path, 'host': host,
                                        'proto': 'https', 'user': None}
            assert headers.get('X-Fixture-Policy') == 'notes-discovery'
            assert headers.get('Strict-Transport-Security') == 'max-age=31536000'
            assert 'Location' not in headers, 'Self-authentication routes must not redirect in a loop'
    for host in ('unrouted.example.invalid', 'stopped.example.invalid', 'disabled.example.invalid'):
        assert request(host, '/')[0] == 404, host
    calls = api_calls()
    assert calls and all(call['method'] == 'GET' and call['authorized'] for call in calls), calls
    paths = {call['path'] for call in calls}
    for vmid in SERVICES:
        assert f'/api2/json/nodes/fixture/lxc/{vmid}/config' in paths
        assert f'/api2/json/nodes/fixture/qemu/{vmid}/agent/network-get-interfaces' in paths
    assert '/api2/json/nodes/fixture/lxc/213/config' not in paths
    print('Provider fixture passed: pinned plugin discovers two LXC Notes routes; '
          'explicit backends, HTTPS trust, shared headers and OAuth paths verified. '
          'Native PVE and real login remain unverified.')


def docker(*args, **kwargs):
    return subprocess.run(['docker', *args], check=True, timeout=180, **kwargs)


def certificate_files(root):
    def openssl(*args):
        subprocess.run(['openssl', *args], check=True, timeout=20,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    (root / 'ca.cnf').write_text('[req]\ndistinguished_name=dn\nx509_extensions=ca\n'
                                 '[dn]\n[ca]\nbasicConstraints=critical,CA:true\n'
                                 'keyUsage=critical,keyCertSign,cRLSign\n'
                                 'subjectKeyIdentifier=hash\n')
    for name in ('ca', 'wrong-ca'):
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', f'/CN=Homelab synthetic provider {name}',
                '-config', str(root / 'ca.cnf'),
                '-keyout', str(root / f'{name}.key'), '-out', str(root / f'{name}.pem'))
    openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=127.0.0.1',
            '-keyout', str(root / 'server.key'), '-out', str(root / 'server.csr'))
    (root / 'server.ext').write_text('subjectAltName=IP:127.0.0.1,DNS:sso.example.invalid\n'
                                    'extendedKeyUsage=serverAuth\n')
    openssl('x509', '-req', '-in', str(root / 'server.csr'), '-CA', str(root / 'ca.pem'),
            '-CAkey', str(root / 'ca.key'), '-CAcreateserial', '-days', '1',
            '-extfile', str(root / 'server.ext'), '-out', str(root / 'server.pem'))
    for path in root.iterdir():
        path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tools-image', default='homelab-app-test')
    parser.add_argument('--plugin-source', type=Path, required=True,
                        help=f'Unmodified source at {MODULE}@{PLUGIN_COMMIT}')
    args = parser.parse_args()
    plugin_source = args.plugin_source.resolve(strict=True)
    if source_digest(plugin_source) != PLUGIN_TREE_SHA256:
        raise ValueError('Plugin source differs from the pinned v0.7.0 source tree')
    names = []
    with tempfile.TemporaryDirectory(prefix='homelab-provider-fixture-') as tmp:
        root = Path(tmp)
        certificate_files(root)
        dynamic = {'http': {'middlewares': {'fixture-policy': {'headers': {
            'customResponseHeaders': {'X-Fixture-Policy': 'notes-discovery'},
            'stsSeconds': 31536000}}}},
            'tls': {'stores': {'default': {'defaultCertificate': {
                'certFile': '/fixture/server.pem', 'keyFile': '/fixture/server.key'}}}}}
        (root / 'dynamic.json').write_text(json.dumps(dynamic))
        static = {'entryPoints': {'https': {'address': ':8443'}},
                  'global': {'checkNewVersion': False, 'sendAnonymousUsage': False},
                  'experimental': {'localPlugins': {'proxmox': {'moduleName': MODULE}}},
                  'providers': {'file': {'filename': '/fixture/dynamic.json'}, 'plugin': {
                      'proxmox': {'pollInterval': '5s', 'apiEndpoint': 'https://127.0.0.1:8006',
                                  'apiTokenId': 'fixture@pve!discovery',
                                  'apiToken': 'synthetic-not-a-secret',
                                  'apiLogging': 'info', 'apiValidateSSL': 'true'}}}}
        (root / 'static.json').write_text(json.dumps(static))
        try:
            backend_name = 'homelab-provider-backends-' + uuid.uuid4().hex[:10]
            names.append(backend_name)
            common = ['run', '-d', '--platform', 'linux/amd64', '--read-only',
                      '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                      '--user', f'{os.getuid()}:{os.getgid()}', '--cpus', '1', '--memory', '384m',
                      '--tmpfs', '/tmp:rw,nosuid,nodev,size=32m', '-v', f'{root}:/fixture:ro']
            docker(*common, '--name', backend_name, '--network', 'none',
                   '--entrypoint', 'python3', '-v', f'{Path(__file__).resolve()}:/fixture.py:ro',
                   args.tools_image, '/fixture.py', 'serve', stdout=subprocess.DEVNULL)
            # A deliberately unrelated CA must prevent the real provider from
            # reading even /version. This checks the plugin's TLS setting, not
            # just Python's certificate validation.
            for trusted in (False, True):
                proxy_name = 'homelab-provider-proxy-' + uuid.uuid4().hex[:10]
                names.append(proxy_name)
                ca = 'ca.pem' if trusted else 'wrong-ca.pem'
                docker(*common, '--name', proxy_name, '--network', 'container:' + backend_name,
                       '-e', f'SSL_CERT_FILE=/fixture/{ca}', '-e', 'SSL_CERT_DIR=/fixture/no-certs',
                       '-v', f'{plugin_source}:/plugins-local/src/{MODULE}:ro',
                       IMAGE, '--configFile=/fixture/static.json', stdout=subprocess.DEVNULL)
                if trusted:
                    docker('exec', backend_name, 'python3', '/fixture.py', 'check')
                else:
                    for attempt in range(90):
                        result = docker('logs', proxy_name, capture_output=True, text=True)
                        if 'certificate signed by unknown authority' in result.stdout + result.stderr:
                            break
                        if attempt == 89:
                            raise RuntimeError('Provider did not reject the untrusted PVE certificate within 45 seconds')
                        time.sleep(0.5)
                    docker('exec', backend_name, 'python3', '/fixture.py', 'check-untrusted')
                    print('Provider rejected the unrelated PVE CA with TLS verification enabled.')
                docker('rm', '-f', proxy_name, stdout=subprocess.DEVNULL)
                names.remove(proxy_name)
        except Exception:
            for name in names:
                subprocess.run(['docker', 'logs', '--tail', '60', name], check=False, timeout=20)
            raise
        finally:
            for name in reversed(names):
                subprocess.run(['docker', 'rm', '-f', name], check=False, timeout=30,
                               stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    if sys.argv[1:] == ['serve']:
        serve()
    elif sys.argv[1:] == ['check']:
        check()
    elif sys.argv[1:] == ['check-untrusted']:
        assert not api_calls(), 'The untrusted plugin must not reach the API'
    else:
        main()
