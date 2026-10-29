"""Pinned Traefik: live watched-file reload, source gate, SSO and native headers.

Only synthetic loopback transports; no published port or external network.
"""
import argparse
import http.client
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

IMAGE = 'traefik@sha256:1336e85aaed293bd63d005086e0dd013b04078b26aaeb1c18b26a2f928af7e65'
HOST = 'influx.example.invalid'


def serve():
    class Backend(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.server.server_port == 9000 and self.path == '/outpost.goauthentik.io/auth/traefik':
                if 'sso=ok' not in self.headers.get('Cookie', ''):
                    self.send_response(302)
                    self.send_header('Location', 'https://sso.example.invalid/application/o/authorize/')
                elif 'sso=denied' in self.headers.get('Cookie', ''):
                    self.send_response(403)
                else:
                    self.send_response(200)
                    self.send_header('X-authentik-username', 'fixture-user')
                    self.send_header('Authorization', 'must-not-replace-native-token')
                self.end_headers(); return
            self.send_response(200)
            if self.path == '/api/v2/signin': self.send_header('Set-Cookie', 'native=ok; Path=/; HttpOnly')
            self.end_headers()
            self.wfile.write(json.dumps({'backend': self.server.server_port, 'path': self.path,
                'host': self.headers.get('Host'), 'proto': self.headers.get('X-Forwarded-Proto'),
                'authorization': self.headers.get('Authorization'), 'cookie': self.headers.get('Cookie')}).encode())

        def log_message(self, *args): pass

    for port in (8086, 9000):
        server = ThreadingHTTPServer(('127.0.0.1', port), Backend)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Event().wait()


def request(path, headers=None, host=HOST, peer='127.0.0.1'):
    conn = http.client.HTTPSConnection('127.0.0.1', 8443, timeout=3,
        source_address=(peer, 0), context=ssl._create_unverified_context())
    try:
        conn.request('GET', path, headers={'Host': host, **(headers or {})})
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally: conn.close()


def wait_for(expected, path="/", host=HOST):
    """Wait for a specific router response, rather than an unloaded default 404."""
    for n in range(40):
        try:
            if request(path, host=host)[0] == expected: return
        except (OSError, http.client.HTTPException): pass
        if n != 39: time.sleep(0.5)
    raise RuntimeError('Synthetic file-provider load exceeded its bound')


def check(stage):
    """Check existing routing before adding and verifying the watched overlay."""
    if stage == 'before':
        wait_for(200, path='/existing', host='other.example.invalid')
        assert request('/')[0] == 404
        assert request('/existing', host='other.example.invalid')[0] == 200
        return
    wait_for(302)
    assert request('/')[1]['Location'] == 'https://sso.example.invalid/application/o/authorize/'
    # The direct socket peer decides the local gate, regardless of spoofed headers.
    for headers in ({}, {'X-Forwarded-For': '127.0.0.1', 'CF-Connecting-IP': '127.0.0.1'}):
        assert request('/', headers, peer='127.0.0.2')[0] == 403
    status, _, body = request('/outpost.goauthentik.io/callback?code=synthetic')
    assert status == 200 and json.loads(body)['backend'] == 9000
    status, headers, body = request('/api/v2/signin', {'Cookie': 'sso=ok', 'Authorization': 'Basic synthetic-only'})
    assert status == 200 and headers['Set-Cookie'] == 'native=ok; Path=/; HttpOnly'
    assert json.loads(body)['authorization'] == 'Basic synthetic-only'
    status, headers, body = request('/api/v2/query?org=synthetic', {
        'Cookie': 'sso=ok; native=ok', 'Authorization': 'Token synthetic-only'})
    value = json.loads(body)
    assert status == 200 and value['backend'] == 8086 and value['host'] == HOST and value['proto'] == 'https'
    assert value['path'] == '/api/v2/query?org=synthetic' and value['authorization'] == 'Token synthetic-only'
    assert value['cookie'] == 'sso=ok; native=ok'
    assert headers['X-Content-Type-Options'] == 'nosniff'
    assert "'unsafe-eval'" in headers['Content-Security-Policy']
    assert request('/', {'Cookie': 'sso=ok; sso=denied'})[0] == 403
    assert request('/existing', host='other.example.invalid')[0] == 200
    print('Influx browser fixture passed: watched reload without restart, source allow/deny, callback, SSO and native header/cookie separation')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tools-image', default='homelab-app-test')
    args = parser.parse_args()
    from ingress_fixture import docker
    from test_ingress_browser import browser, settings
    names = []
    with tempfile.TemporaryDirectory(prefix='influx-browser-fixture-') as temp:
        root = Path(temp)
        original = {'http': {'routers': {'other': {'rule': 'Host(`other.example.invalid`)',
            'entryPoints': ['websecure'], 'tls': {}, 'service': 'other'}},
            'services': {'other': {'loadBalancer': {'servers': [{'url': 'http://127.0.0.1:8086'}]}}}}}
        path = root/'shared.yml'; path.write_text(json.dumps(original)); before_inode = path.stat().st_ino
        wanted = browser.merge(original, settings())
        # Adapt only the isolated loopback transport; production validation and
        # route-policy construction above use the actual private-address contract.
        http = wanted['http']
        http['middlewares']['influx-local']['ipAllowList']['sourceRange'] = ['127.0.0.1/32']
        http['middlewares']['influx-authentik']['forwardAuth']['address'] = 'http://127.0.0.1:9000/outpost.goauthentik.io/auth/traefik'
        for name, port in [('influx-private', 8086), ('influx-identity', 9000)]:
            http['services'][name]['loadBalancer']['servers'][0]['url'] = f'http://127.0.0.1:{port}'
        for name in ('influx-browser', 'influx-outpost'): http['routers'][name]['tls'] = {}
        try:
            for side in ('backends', 'proxy'):
                name = 'homelab-influx-browser-' + side + '-' + uuid.uuid4().hex[:10]; names.append(name)
                common = ['run','-d','--rm','--platform','linux/amd64','--read-only','--cap-drop','ALL',
                    '--security-opt','no-new-privileges','--user',f'{os.getuid()}:{os.getgid()}',
                    '--cpus','1','--memory','256m','--name',name,'--tmpfs','/tmp:rw,nosuid,nodev,size=16m']
                if side == 'backends':
                    docker(*common,'--network','none','--entrypoint','python3',
                        '-v',f'{Path(__file__).resolve()}:/fixture.py:ro',args.tools_image,'/fixture.py','serve',stdout=subprocess.DEVNULL)
                else:
                    docker(*common,'--network','container:'+names[0],'-v',f'{root}:/fixture:ro',IMAGE,
                        '--entrypoints.websecure.address=:8443','--providers.file.filename=/fixture/shared.yml',
                        '--global.checknewversion=false','--global.sendanonymoususage=false',stdout=subprocess.DEVNULL)
            docker('exec',names[0],'python3','/fixture.py','before')
            identity = subprocess.check_output(['docker','inspect','--format','{{.State.StartedAt}}',names[1]])
            # Write the watched inode, as the maintenance helper does. No restart.
            with path.open('w') as stream: json.dump(wanted, stream); stream.flush(); os.fsync(stream.fileno())
            assert path.stat().st_ino == before_inode
            docker('exec',names[0],'python3','/fixture.py','after')
            assert subprocess.check_output(['docker','inspect','--format','{{.State.StartedAt}}',names[1]]) == identity
        except Exception:
            if len(names) == 2: subprocess.run(['docker','logs','--tail','30',names[1]],check=False)
            raise
        finally:
            for name in reversed(names): subprocess.run(['docker','rm','-f',name],check=False,stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    if sys.argv[1:] == ['serve']: serve()
    elif sys.argv[1:] in (['before'], ['after']): check(sys.argv[1])
    else: main()
