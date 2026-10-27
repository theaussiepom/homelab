"""Pinned Traefik: synthetic HTTPS trust, Host/redirects, WSS and client ACLs.

Runs only disposable containers sharing an isolated network namespace. No host
ports, production addresses, sessions, credentials or application data.
"""
import base64
import argparse
from email.parser import BytesParser
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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

from ingress_fixture import IMAGE, docker, request


def serve():
    class Backend(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/redirect':
                if self.headers.get('Host') != 'admin.example.invalid':
                    self.send_error(400); return
                self.send_response(302)
                self.send_header('Location', 'https://admin.example.invalid/login')
                self.end_headers()
                return
            if self.headers.get('Upgrade', '').lower() == 'websocket':
                if self.headers.get('Origin') != 'https://admin.example.invalid':
                    self.send_error(403); return
                key = self.headers['Sec-WebSocket-Key']
                accept = base64.b64encode(hashlib.sha1(
                    (key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
                self.send_response(101)
                self.send_header('Upgrade', 'websocket')
                self.send_header('Connection', 'Upgrade')
                self.send_header('Sec-WebSocket-Accept', accept)
                self.send_header('X-Fixture-Origin', 'https://admin.example.invalid')
                self.end_headers()
                self.wfile.write(b'\x81\x02ok'); self.wfile.flush()
                return
            self.send_response(200); self.end_headers()
            self.wfile.write(json.dumps({'host': self.headers.get('Host'), 'path': self.path,
                'proto': self.headers.get('X-Forwarded-Proto'),
                'sni': getattr(self.connection, 'fixture_sni', None)}).encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 9443), Backend)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain('/fixture/backend.pem', '/fixture/backend.key')
    context.set_servername_callback(lambda sock, name, ctx: setattr(sock, 'fixture_sni', name))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def check():
    for attempt in range(60):
        try:
            if request('admin.example.invalid', '/')[0] == 200:
                break
        except (OSError, ssl.SSLError):
            pass
        if attempt == 59:
            raise RuntimeError('Synthetic admin ingress did not start')
        time.sleep(0.5)
    status, _, body = request('admin.example.invalid', '/api/test?value=kept')
    assert status == 200
    assert json.loads(body) == {'host': 'admin.example.invalid', 'path': '/api/test?value=kept',
                                'proto': 'https', 'sni': 'backend.example.invalid'}
    status, headers, _ = request('admin.example.invalid', '/redirect')
    assert status == 302 and headers['Location'] == 'https://admin.example.invalid/login'
    for name in ('wrong-sni', 'wrong-ca'):
        assert request(name + '.example.invalid', '/')[0] in (500, 502)
    assert request('denied.example.invalid', '/', {'X-Forwarded-For': '10.15.0.5'})[0] == 403
    assert request('unknown.example.invalid', '/')[0] == 404
    # Read the actual upgrade response and first frame on the same connection.
    import socket
    with socket.create_connection(('127.0.0.1', 8443), timeout=4) as raw:
        # Only the synthetic frontend's generated default certificate is untrusted.
        with ssl._create_unverified_context().wrap_socket(raw, server_hostname='admin.example.invalid') as stream:
            sample_nonce = base64.b64encode(b'the sample nonce')
            stream.sendall(b'GET /console?fixture=1 HTTP/1.1\r\nHost: admin.example.invalid\r\n'
                b'Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n'
                b'Sec-WebSocket-Key: ' + sample_nonce + b'\r\nOrigin: https://admin.example.invalid\r\n\r\n')
            received = b''
            while b'\r\n\r\n' not in received:
                chunk = stream.recv(4096)
                assert chunk, received
                received += chunk
            head, frame = received.split(b'\r\n\r\n', 1)
            status_line, header_bytes = head.split(b'\r\n', 1)
            parsed = BytesParser().parsebytes(header_bytes + b'\r\n\r\n')
            assert status_line.split()[1] == b'101', status_line
            assert parsed['X-Fixture-Origin'] == 'https://admin.example.invalid'
            assert parsed['Sec-WebSocket-Accept'] == 's3pPLMBiTxaQ9kYGzzhZRbK+xOo='
            while len(frame) < 4:
                chunk = stream.recv(4 - len(frame))
                assert chunk, frame
                frame += chunk
            assert frame[:4] == b'\x81\x02ok', frame
    print('Admin ingress fixture passed: verified backend CA/SNI, wrong trust refusal, '
          'Host/path/redirect, client ACL/spoof refusal and WebSocket 101/frame; native login unverified')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tools-image', default='homelab-app-test')
    args = parser.parse_args()
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import ingress_admin
    names = []
    with tempfile.TemporaryDirectory(prefix='homelab-admin-fixture-') as temp:
        root = Path(temp)
        for name in ('backend', 'wrong-ca'):
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-keyout', str(root/(name+'.key')), '-out', str(root/(name+'.pem')),
                '-subj', '/CN=backend.example.invalid', '-addext', 'subjectAltName=DNS:backend.example.invalid'],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        settings = {'schema': 'homelab-ingress-admin-routes-v1', 'client_networks': ['10.15.0.0/24'],
                    'routes': [{'name': 'test', 'host': 'admin.example.invalid',
                                'url': 'https://10.25.0.10:8006', 'server_name': 'backend.example.invalid',
                                'root_cas': ['/etc/ssl/certs/fixture.pem']}]}
        routes = ingress_admin.merge({}, settings)
        # Only fixture networking/trust paths change to the shared isolated loopback.
        http = routes['http']
        http['middlewares']['admin-clients']['ipAllowList']['sourceRange'] = ['127.0.0.1/32']
        http['services']['admin-test']['loadBalancer']['servers'] = [{'url': 'https://127.0.0.1:9443'}]
        http['serversTransports']['admin-test']['rootCAs'] = ['/fixture/backend.pem']
        for name in ('wrong-sni', 'wrong-ca', 'denied'):
            import copy
            router = copy.deepcopy(http['routers']['admin-test'])
            router['rule'] = f'Host(`{name}.example.invalid`)'
            if name == 'denied':
                router['middlewares'] = ['deny-fixture']
                http['middlewares']['deny-fixture'] = {'ipAllowList': {'sourceRange': ['10.15.0.0/24']}}
            else:
                router['service'] = name
                service = copy.deepcopy(http['services']['admin-test'])
                service['loadBalancer']['serversTransport'] = name
                http['services'][name] = service
                transport = copy.deepcopy(http['serversTransports']['admin-test'])
                if name == 'wrong-sni': transport['serverName'] = 'wrong.example.invalid'
                else: transport['rootCAs'] = ['/fixture/wrong-ca.pem']
                http['serversTransports'][name] = transport
            http['routers'][name] = router
        for router in http['routers'].values():
            router['entryPoints'] = ['https']; router['tls'] = {}
        (root/'routes.yml').write_text(json.dumps(routes))
        try:
            for side in ('backend', 'proxy'):
                name = 'homelab-admin-fixture-' + side + '-' + uuid.uuid4().hex[:10]
                names.append(name)
                common = ['run', '-d', '--rm', '--platform', 'linux/amd64', '--read-only', '--cap-drop', 'ALL',
                          '--security-opt', 'no-new-privileges', '--user', f'{os.getuid()}:{os.getgid()}',
                          '--cpus', '1', '--memory', '256m', '--name', name,
                          '--tmpfs', '/tmp:rw,nosuid,nodev,size=16m', '-v', f'{root}:/fixture:ro']
                if side == 'backend':
                    docker(*common, '--network', 'none', '--entrypoint', 'python3',
                        '-v', f'{Path(__file__).resolve()}:/ingress_admin_fixture.py:ro',
                        '-v', f'{Path(__file__).with_name("ingress_fixture.py").resolve()}:/ingress_fixture.py:ro',
                        args.tools_image, '/ingress_admin_fixture.py', 'serve', stdout=subprocess.DEVNULL)
                else:
                    docker(*common, '--network', 'container:' + names[0], IMAGE,
                        '--entrypoints.https.address=:8443', '--providers.file.filename=/fixture/routes.yml',
                        '--global.checknewversion=false', '--global.sendanonymoususage=false', stdout=subprocess.DEVNULL)
            docker('exec', names[0], 'python3', '/ingress_admin_fixture.py', 'check')
        except Exception:
            if len(names) == 2: subprocess.run(['docker', 'logs', '--tail', '30', names[1]], check=False)
            raise
        finally:
            for name in reversed(names):
                subprocess.run(['docker', 'rm', '-f', name], check=False, stdout=subprocess.DEVNULL, timeout=30)


if __name__ == '__main__':
    if sys.argv[1:] == ['serve']: serve()
    elif sys.argv[1:] == ['check']: check()
    else: main()
