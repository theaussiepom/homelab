#!/usr/bin/env python3
"""Pinned-image TLS-to-HTTP replacement using invented state and no host ports."""
import ipaddress
import json
from pathlib import Path
import subprocess
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pegaprox
import pegaprox_health

IMAGE = "ghcr.io/pegaprox/pegaprox@sha256:8d295a524a52f0b923616a3eb415ff6422fe62beba5bb441f35c75d8985f1add"
# Construct historical TLS state only in a fresh disposable fixture volume.
SYNTHETIC_SETUP_CODE = "\nimport json, ssl, sys, time\nfrom urllib.error import HTTPError\nfrom urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler, ProxyHandler\nclass NoRedirect(HTTPRedirectHandler):\n    def redirect_request(self, *args):\n        raise RuntimeError('Unexpected local redirect')\nmode = sys.argv[1]\ndef require(condition, message='Local setup verification failed'):\n    if not condition: raise RuntimeError(message)\ndef call(path, data=None, token=None):\n    headers = {'X-Requested-With': 'XMLHttpRequest', 'Origin': 'https://127.0.0.1:5000'}\n    if token: headers['X-Session-ID'] = token\n    if data is not None: headers['Content-Type'] = 'application/json'\n    req = Request('https://127.0.0.1:5000' + path, headers=headers,\n                  data=None if data is None else json.dumps(data).encode())\n    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n    context.check_hostname = False\n    context.verify_mode = ssl.CERT_REQUIRED\n    context.load_verify_locations(cafile='/app/config/ssl/cert.pem')\n    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), NoRedirect())\n    try: response = opener.open(req, timeout=4 if path == '/api/health' else 8)\n    except HTTPError as error: response = error\n    with response:\n        raw = response.read(1048577)\n        if len(raw) > 1048576: raise RuntimeError('Oversized local response')\n        return response.code, json.loads(raw)\ndeadline = time.monotonic() + 65\nwhile True:\n    try:\n        if call('/api/health') == (200, {'status': 'ok', 'version': '1.4.1'}): break\n    except (OSError, ValueError, RuntimeError):\n        pass\n    if time.monotonic() >= deadline:\n        raise RuntimeError('PegaProx did not become ready')\n    time.sleep(2)\nstatus, state = call('/api/auth/check')\nrequire(status == 401 and state.get('authenticated') is False)\nif mode == 'bootstrap':\n    require(state.get('initialized') is False, 'Existing account/configuration; no bootstrap replay')\n    require(not state.get('oidc_enabled') and (not state.get('ldap_enabled')))\n    value = json.load(sys.stdin)\n    code, created = call('/api/auth/setup', value)\n    require(code == 200 and created.get('success') is True)\n    code, login = call('/api/auth/login', value)\n    require(code == 200 and login.get('success') is True)\n    token = login['session_id']\n    try:\n        code, checked = call('/api/auth/check', token=token)\n        require(code == 200 and checked['authenticated'] is True)\n        require(checked['user']['username'] == value['username'] and checked['user']['role'] == 'admin')\n    finally:\n        require(call('/api/auth/logout', {}, token)[0] == 200)\n    require(call('/api/auth/check')[1].get('initialized') is True)\nelif mode == 'verify':\n    require(state.get('initialized') is True)\nelse: raise RuntimeError('Unknown mode')\nprint('PegaProx verification passed')\n"

# Non-loopback clients matter: PegaProx always trusts its own loopback address.
PROXY_CLIENT_CODE = r"""
import json, sys
from http.cookies import SimpleCookie
from urllib.error import HTTPError
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler
value = json.load(sys.stdin)
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args): raise RuntimeError('Unexpected redirect')
opener = build_opener(ProxyHandler({}), NoRedirect())
def call(path, data, headers):
    req = Request('http://' + value['backend'] + ':5000' + path,
                  data=None if data is None else json.dumps(data).encode(),
                  headers={'Content-Type':'application/json', **headers})
    try: response = opener.open(req, timeout=8)
    except HTTPError as error: response = error
    with response:
        raw = response.read(1048577)
        assert len(raw) <= 1048576
        return response.code, raw, response.headers
headers = {'X-Forwarded-Proto':'https', 'X-Forwarded-Host':'pega.fixture.invalid',
           'Origin':'https://pega.fixture.invalid'}
code, raw, response_headers = call('/api/auth/login', value['account'], headers)
body = json.loads(raw)
assert code == 200 and body.get('success') is True
cookie = SimpleCookie()
for item in response_headers.get_all('Set-Cookie', []): cookie.load(item)
assert cookie, 'No login cookie'
assert all(bool(item['secure']) == value['trusted'] for item in cookie.values())
assert all(item['httponly'] and item['samesite'].lower() == 'strict' for item in cookie.values())
token = body['session_id']
code, raw, _ = call('/api/auth/check', None, {'X-Session-ID':token})
checked = json.loads(raw)
assert code == 200 and checked['authenticated'] is True
assert checked['user']['username'] == value['account']['username']
assert checked['user']['role'] == 'admin'
try:
    # This nonexistent POST has no mutation handler but does pass the real CSRF gate.
    # Login/check/logout are exempt and cannot establish Origin enforcement.
    headers['X-Session-ID'] = token
    code, raw, _ = call('/api/fixture-origin-probe', {}, headers)
    if value['trusted']:
        assert code in (404, 405), (code, 'Trusted forwarding rejected')
    else:
        assert code == 403 and 'csrf' in raw.decode().lower()
    headers['Origin'] = 'https://foreign.fixture.invalid'
    code, raw, _ = call('/api/fixture-origin-probe', {}, headers)
    assert code == 403 and 'csrf' in raw.decode().lower()
    headers['X-Requested-With'] = 'XMLHttpRequest'
    code, raw, _ = call('/api/fixture-origin-probe', {}, headers)
    assert code == 403 and 'csrf' in raw.decode().lower()
finally:
    assert call('/api/auth/logout', {}, {'X-Session-ID':token})[0] == 200
print('proxy-account-cookie-origin-passed')
"""


def run(*args):
    try:
        return subprocess.check_output(['docker', *args], text=True, stderr=subprocess.PIPE, timeout=90).strip()
    except subprocess.CalledProcessError as error:
        # This fixture owns only invented disposable state; preserve bounded CLI diagnostics.
        print((error.stderr or 'Docker fixture command failed')[:2048], file=sys.stderr)
        raise


def main():
    name = 'pegaprox-fixture-' + uuid.uuid4().hex[:12]
    network = name + '-internal'
    volumes = [name + '-' + suffix for suffix in ('config', 'logs', 'key')]
    account = {'username':'practice-admin', 'password':'Aa11Aa11Aa11'}
    clients_owned = [name+'-trusted',name+'-untrusted']
    created_volumes = []
    created_network = False
    outcome = {'image':IMAGE, 'native_verified':False, 'network':'disposable-internal', 'published_ports':[]}
    try:
        # Static client IPs require an explicitly configured subnet on hosted Docker.
        # Select one small synthetic block; Docker refuses any collision without retry.
        subnet = ipaddress.IPv4Network((int(ipaddress.IPv4Address('198.18.0.0'))
                                       + (int(name[-4:], 16) % 16384) * 8, 29))
        run('network', 'create', '--internal', '--subnet', str(subnet), network)
        created_network = True
        net = json.loads(run('network', 'inspect', network))[0]
        assert net['Internal'] is True
        assert ipaddress.IPv4Network(net['IPAM']['Config'][0]['Subnet']) == subnet
        backend, proxy, stranger = [str(subnet.network_address + n) for n in (2, 3, 4)]
        runtime = {'kind':'pegaprox', 'image':IMAGE, 'bind_address':backend, 'trusted_proxy':proxy+'/32',
                   'guest_memory_mib':2048, 'container_memory_mib':1024, 'cpus':1, 'pids_limit':256}
        preview = pegaprox.compose(runtime)['services']['pegaprox']
        assert preview['ports'] == [backend+':5000:5000/tcp']
        bounded = ['--pull=never', '--platform','linux/amd64', '--network',network, '--read-only',
                   '--cap-drop','ALL', '--security-opt','no-new-privileges',
                   '--cpus',str(preview['cpus']), '--memory',preview['mem_limit'],
                   '--pids-limit',str(preview['pids_limit']), '--tmpfs',preview['tmpfs'][0]]
        for volume in volumes:
            run('volume','create',volume)
            created_volumes.append(volume)
        run('run','--rm',*bounded,'-v',volumes[2]+':/app/config','--entrypoint','python3',IMAGE,
            '-c',"import base64,os,pathlib; p=pathlib.Path('/app/config/pegaprox-db-key'); p.write_bytes(base64.urlsafe_b64encode(os.urandom(32))); p.chmod(0o600)")
        def start(environment):
            env = [arg for key,value in environment.items() for arg in ('-e', key+'='+value)]
            return run('run','-d','--name',name,*bounded,'--ip',backend,'--restart',preview['restart'],
                       '--stop-timeout','60','--log-opt','max-size=10m','--log-opt','max-file=3',*env,
                       '-v',volumes[0]+':/app/config','-v',volumes[1]+':/app/logs',
                       '-v',volumes[2]+':/run/secrets:ro',IMAGE)
        proxy_keys = {'PEGAPROX_BEHIND_PROXY','PEGAPROX_HOST','PEGAPROX_TRUSTED_PROXIES'}
        prior_env = {k:v for k,v in preview['environment'].items() if k not in proxy_keys}
        old_id = start(prior_env)
        command = ['docker','exec','-i',name]
        initial = subprocess.run([*command,'python3','-c',SYNTHETIC_SETUP_CODE,'bootstrap'],
                                 input=json.dumps(account),capture_output=True,text=True,timeout=90,check=True)
        assert initial.stdout.strip() == 'PegaProx verification passed'
        old = json.loads(run('inspect',name))[0]
        state = "import hashlib,json,pathlib; from pegaprox.core.keystore import load_master_key; k=load_master_key(); assert k.source=='env:PEGAPROX_KEY_FILE'; p=pathlib.Path('/app/config/pegaprox.db'); assert p.is_file() and p.read_bytes()[:16]!=b'SQLite format 3\\x00'; assert not pathlib.Path('/app/config/secret.key').exists(); print(json.dumps({'key_hash':hashlib.sha256(pathlib.Path('/run/secrets/pegaprox-db-key').read_bytes()).hexdigest(),'source':k.source}))"
        before = json.loads(run('exec',name,'python3','-c',state))
        db_write = "import json; from pegaprox.core import dbcrypto; c=dbcrypto.connect('/app/config/pegaprox.db'); c.execute('INSERT OR REPLACE INTO server_settings(key,value) VALUES (?,?)',('fixture.restart.marker',json.dumps('invented-state'))); c.execute('INSERT OR REPLACE INTO server_settings(key,value) VALUES (?,?)',('reverse_proxy_enabled',json.dumps(False))); c.commit(); c.close()"
        db_read = "import json; from pegaprox.core import dbcrypto; c=dbcrypto.connect('/app/config/pegaprox.db'); row=c.execute('SELECT value FROM server_settings WHERE key=?',('fixture.restart.marker',)).fetchone(); assert row and json.loads(row[0])=='invented-state'; setting=c.execute('SELECT value FROM server_settings WHERE key=?',('reverse_proxy_enabled',)).fetchone(); assert setting and json.loads(setting[0]) is False; c.close(); print('database-row-passed')"
        run('exec',name,'python3','-c',db_write)
        run('exec',name,'python3','-c',"from pathlib import Path; Path('/app/config/fixture-marker').write_text('invented-state')")
        # Compose-equivalent replacement: same image/state/policy, only the three env additions.
        run('stop','--time','20',name)
        run('rm',name)
        new_id = start(preview['environment'])
        assert new_id != old_id
        pegaprox_health.verify(command)
        current = json.loads(run('inspect',name))[0]
        assert current['Image'] == old['Image']
        for field in ('User','Image','Entrypoint','Cmd'):
            assert current['Config'][field] == old['Config'][field]
        for field in ('ReadonlyRootfs','CapDrop','SecurityOpt','Memory','NanoCpus','PidsLimit',
                      'RestartPolicy','LogConfig','PortBindings','NetworkMode','Tmpfs','Binds'):
            assert current['HostConfig'][field] == old['HostConfig'][field]
        assert current['HostConfig']['ReadonlyRootfs'] is True
        assert current['HostConfig']['CapDrop'] == ['ALL']
        assert not current['HostConfig']['PortBindings']
        assert current['Config']['User'] and current['Config']['User'] != 'root'
        assert set(current['Config']['Env']) - set(old['Config']['Env']) == {
            key+'='+preview['environment'][key] for key in proxy_keys}
        assert not (set(old['Config']['Env']) - set(current['Config']['Env']))
        def retained():
            assert json.loads(run('exec',name,'python3','-c',state)) == before
            assert run('exec',name,'python3','-c',db_read) == 'database-row-passed'
            run('exec',name,'python3','-c',"from pathlib import Path; assert Path('/app/config/fixture-marker').read_text()=='invented-state'")
        def clients():
            for address,trusted,client_name in ((proxy,True,clients_owned[0]),(stranger,False,clients_owned[1])):
                result = subprocess.run(['docker','run','--rm','--name',client_name,'-i',*bounded,'--ip',address,
                                         '--entrypoint','python3',IMAGE,'-c',PROXY_CLIENT_CODE],
                                        input=json.dumps({'backend':backend,'trusted':trusted,'account':account}),
                                        capture_output=True,text=True,timeout=90,check=True)
                assert result.stdout.strip() == 'proxy-account-cookie-origin-passed'
        retained()
        clients()
        outcome['retained_tls_to_http_replacement'] = True
        run('restart','--time','20',name)
        pegaprox_health.verify(command)
        retained()
        clients()
        outcome.update(nonroot_user=current['Config']['User'],read_only_root=True,
                       encrypted_db=True,separate_key=True,restart_persistence=True,
                       retained_account_login=True,trusted_proxy_secure_cookies=True,
                       untrusted_forwarding_ignored=True,foreign_origins_refused=True,
                       passwordless_cd_verification=True)
    finally:
        subprocess.run(['docker','rm','-f',name,*clients_owned],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        for volume in created_volumes: run('volume','rm',volume)
        if created_network: run('network','rm',network)
        outcome['disposable_resources_removed'] = True
        print(json.dumps(outcome,indent=2))


if __name__ == '__main__':
    main()
