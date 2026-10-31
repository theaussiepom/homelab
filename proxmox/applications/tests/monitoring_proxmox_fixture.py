"""Exercise real Proxmox HTTP status polling with synthetic TLS and responses."""
import json
from pathlib import Path
import subprocess
import time

SERVER = '''import http.server,json,ssl,threading
from pathlib import Path
root=Path('/fixture')
good=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);good.load_cert_chain(root/'good.crt',root/'good.key')
bad=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);bad.load_cert_chain(root/'wrong.crt',root/'wrong.key')
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  mode=(root/'status').read_text();status=int(mode) if mode.isdigit() else 200
  if self.headers.get('Authorization')!='PVEAPIToken=fixture@pve!monitoring=synthetic-token':status=401
  if self.path=='/redirect-target':status=200
  data=[{'type':'node','node':'fixture'},{'type':'lxc','vmid':216}] if self.path.endswith('/cluster/resources') else {'version':'fixture'}
  body=json.dumps({'data':data}).encode()
  self.send_response(status)
  if status==302:self.send_header('Location','https://pve:8006/redirect-target')
  self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers()
  self.wfile.write(body)
 def log_message(self,*args):pass
def serve(port,context):
 server=http.server.ThreadingHTTPServer(('0.0.0.0',port),Handler);server.socket=context.wrap_socket(server.socket,server_side=True);server.serve_forever()
threading.Thread(target=serve,args=(8007,bad),daemon=True).start()
serve(8006,good)
'''


def add(services, root, image='homelab-app-test'):
    directory = root / 'pve-tls'
    directory.mkdir(mode=0o700)
    for name in ('good', 'wrong'):
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(directory / (name + '.key')),
                        '-out', str(directory / (name + '.crt')), '-days', '1',
                        '-subj', '/CN=pve', '-addext', 'subjectAltName=DNS:pve'],
                       check=True, capture_output=True)
        (directory / (name + '.key')).chmod(0o600)
        (directory / (name + '.crt')).chmod(0o644)
    (directory / 'status').write_text('200')
    (directory / 'server.py').write_text(SERVER)
    services['pve'] = {'image': image, 'platform': 'linux/amd64', 'pull_policy': 'never',
                       'entrypoint': ['python3', '-I', '-S', '-B', '/fixture/server.py'],
                       'volumes': [str(directory) + ':/fixture:ro']}
    server = services['zabbix_server']
    server.setdefault('volumes', []).append(
        str(directory / 'good.crt') + ':/var/lib/zabbix/ssl/ssl_ca/proxmox-ca.pem:ro')
    ca_hash = subprocess.check_output(
        ['openssl', 'x509', '-in', str(directory / 'good.crt'), '-noout', '-subject_hash'],
        text=True).strip()
    server['volumes'].append(str(directory / 'good.crt') +
                             ':/var/lib/zabbix/ssl/ssl_ca/' + ca_hash + '.0:ro')
    server['environment']['ZBX_SSLCALOCATION'] = '/var/lib/zabbix/ssl/ssl_ca'
    # Faster cache refresh is confined to this disposable test instance.
    server['environment']['ZBX_CACHEUPDATEFREQUENCY'] = '1'
    return directory


def check(api, hostid, directory):
    rows = api('item.get', {'hostids': [hostid],
                           'filter': {'key_': 'proxmox.api.available'},
                           'output': ['itemid', 'type', 'verify_peer', 'verify_host',
                                      'follow_redirects', 'retrieve_mode', 'status_codes']})
    assert len(rows) == 1
    row = rows[0]
    assert all(row[k] == v for k, v in {'type': '19', 'verify_peer': '1', 'verify_host': '1',
                                       'follow_redirects': '0', 'retrieve_mode': '1',
                                       'status_codes': '100-599'}.items()), row
    # Poll frequency alone is reduced for the test, not the production recipe.
    api('item.update', {'itemid': row['itemid'], 'delay': '1s'})
    host = api('host.get', {'hostids': [hostid], 'output': ['hostid'],
                           'selectMacros': ['hostmacroid', 'macro']})[0]
    port = next(m['hostmacroid'] for m in host['macros'] if m['macro'] == '{$PVE.URL.PORT}')
    results = []
    for mode, expected in [('200', '200'), ('401', '401'), ('503', '503'),
                           ('302', '302'), ('wrong-ca', '520'), ('200', '200')]:
        (directory / 'status').write_text(mode)
        # A separate TLS endpoint prevents an already authenticated session
        # from being resumed when testing an untrusted replacement certificate.
        api('usermacro.update', {'hostmacroid': port, 'value': '8007' if mode == 'wrong-ca' else '8006'})
        deadline = time.monotonic() + 100
        while True:
            sample = api('item.get', {'itemids': [row['itemid']],
                                     'output': ['state', 'lastclock', 'lastvalue']})[0]
            if sample['state'] == '0' and int(sample['lastclock']) > 0 and sample['lastvalue'] == expected:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError('Proxmox synthetic status did not match ' + mode +
                                   '; observed state=' + sample['state'] +
                                   ', value=' + sample['lastvalue'][:20])
            time.sleep(1)
        results.append({'input': mode, 'status': int(expected)})
    return results
