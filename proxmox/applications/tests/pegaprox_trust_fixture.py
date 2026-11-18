#!/usr/bin/env python3
"""Stock-image startup and real TLS checks using only disposable invented state."""
from datetime import datetime, timedelta, timezone
import ipaddress
import json
from pathlib import Path
import subprocess
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parent)]
import component_runtime
from component_pegaprox_fixture import descriptor, guest
import pegaprox_health
import pegaprox_oidc_fixture as oidc
import pegaprox_runtime_fixture as runtime
import pegaprox_trust

TRUST_VOLUMES = []

PROBE = r'''
import json, os, ssl, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import requests
environment = dict(item.split('=', 1) for item in Path('/proc/1/environ').read_text().split('\0') if '=' in item)
for key in ('SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE'):
 assert environment[key] == '/tmp/homelab-pegaprox-ca.pem'
 os.environ[key] = environment[key]
assert b'/app/pegaprox_multi_cluster.py' in Path('/proc/1/cmdline').read_bytes()
base = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
base.load_verify_locations(cafile='/etc/ssl/certs/ca-certificates.crt')
combined = ssl.create_default_context()
assert set(base.get_ca_certs(binary_form=True)) < set(combined.get_ca_certs(binary_form=True))
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200); self.end_headers(); self.wfile.write(b'fixture-tls-passed')
 def log_message(self, *args): pass
server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('/run/homelab/server.pem', '/run/homelab/server.key')
server.socket = context.wrap_socket(server.socket, server_side=True)
thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
try:
 session = requests.Session(); session.trust_env = False
 session.verify = ssl.get_default_verify_paths().cafile
 url = 'https://127.0.0.1:' + str(server.server_port)
 assert session.get(url, timeout=5).text == 'fixture-tls-passed'
 for address, verify in [(url, '/etc/ssl/certs/ca-certificates.crt'),
                         ('https://localhost:' + str(server.server_port), session.verify)]:
  try: session.get(address, verify=verify, timeout=5)
  except requests.exceptions.SSLError: pass
  else: raise AssertionError('Untrusted authority or wrong hostname was accepted')
finally:
 server.shutdown(); server.server_close(); thread.join(timeout=5)
print('stock-startup-public-roots-provider-ca-and-tls-refusals-passed')
'''


def public_fixture():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Synthetic Proxmox CA')])
    now = datetime.now(timezone.utc)
    def builder(subject, public):
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(name).public_key(public)
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=30)))
    ca = (builder(name, key.public_key()).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
    server_key = ec.generate_private_key(ec.SECP256R1())
    server = (builder(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Synthetic server')]), server_key.public_key())
              .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False)
              .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
    return {'proxmox-ca.pem': ca.decode(), 'server.pem': server.decode(),
            'server.key': server_key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
            'pegaprox-trust.py': Path(pegaprox_trust.__file__).read_text()}


def check(name, account):
    run = runtime.run
    volume = name + '-provider-trust'
    previous = json.loads(run('inspect', name))[0]
    network, endpoint = next(iter(previous['NetworkSettings']['Networks'].items()))
    app = descriptor(endpoint['IPAddress'], image=oidc.IMAGE)
    app['settings']['proxmox_ca_source'] = '/synthetic/context-ca.pem'
    service = component_runtime._pegaprox(app, guest())['pegaprox']
    run('volume', 'create', volume)
    try:
        write = "import json,os,pathlib,sys; values=json.load(sys.stdin); root=pathlib.Path('/fixture'); [( (root/name).write_text(value), (root/name).chmod(0o400), os.chown(root/name,999,999)) for name,value in values.items()]"
        result = subprocess.run(['docker','run','--rm','--pull=never','--platform','linux/amd64',
            '--network','none','--user','0','--read-only','--cap-drop','ALL','--cap-add','CHOWN',
            '--security-opt','no-new-privileges','-i','-v',volume+':/fixture','--entrypoint','python3',
            oidc.IMAGE,'-c',write],input=json.dumps(public_fixture()),capture_output=True,text=True,timeout=60)
        assert result.returncode == 0, 'Synthetic trust input preparation failed'
        run('stop', '--time', '20', name); run('rm', name)
        arguments = ['run','-d','--name',name,'--pull=never','--platform','linux/amd64',
            '--network',network,'--ip',endpoint['IPAddress'],'--read-only','--cap-drop','ALL',
            '--security-opt','no-new-privileges','--cpus',str(service['cpus']),
            '--memory',service['mem_limit'],'--pids-limit',str(service['pids_limit']),
            '--tmpfs',service['tmpfs'][0],'--restart',service['restart'],'--stop-timeout','60']
        for value in previous['Config']['Env']: arguments += ['-e', value]
        for value in previous['HostConfig']['Binds']: arguments += ['-v', value]
        # Named test volume avoids dependence on Docker host/client filesystem sharing.
        arguments += ['-v',volume+':/run/homelab:ro','--entrypoint',service['entrypoint'][0],
                      oidc.IMAGE,*service['entrypoint'][1:]]
        run(*arguments)
        for restart in (False, True):
            if restart: run('restart', '--time', '20', name)
            pegaprox_health.verify(['docker','exec','-i',name])
            assert run('exec',name,'python3','-c',PROBE) == 'stock-startup-public-roots-provider-ca-and-tls-refusals-passed'
        oidc.check(name, account)
        print(json.dumps({'stock_runtime_tls': True, 'untrusted_ca_refused': True,
                          'wrong_hostname_refused': True, 'image_roots_retained': True,
                          'trust_restart_passed': True}))
    finally:
        # The outer fixture still verifies the retained account and database after this callback.
        TRUST_VOLUMES.append(volume)


if __name__ == '__main__':
    try:
        runtime.main(image=oidc.IMAGE, after_start=check)
    finally:
        for volume in TRUST_VOLUMES: runtime.run('volume', 'rm', volume)
