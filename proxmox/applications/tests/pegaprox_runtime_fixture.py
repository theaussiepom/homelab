#!/usr/bin/env python3
"""Test only the pinned image with invented state, no network and no host ports."""
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pegaprox
import pegaprox_health


IMAGE = "ghcr.io/pegaprox/pegaprox@sha256:8d295a524a52f0b923616a3eb415ff6422fe62beba5bb441f35c75d8985f1add"
# Test-only initial account in a fresh isolated volume; ordinary CD has no bootstrap path.
SYNTHETIC_SETUP_CODE = "\nimport json, ssl, sys, time\nfrom urllib.error import HTTPError\nfrom urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler, ProxyHandler\nclass NoRedirect(HTTPRedirectHandler):\n    def redirect_request(self, *args):\n        raise RuntimeError('Unexpected local redirect')\nmode = sys.argv[1]\ndef require(condition, message='Local setup verification failed'):\n    if not condition: raise RuntimeError(message)\ndef call(path, data=None, token=None):\n    headers = {'X-Requested-With': 'XMLHttpRequest', 'Origin': 'https://127.0.0.1:5000'}\n    if token: headers['X-Session-ID'] = token\n    if data is not None: headers['Content-Type'] = 'application/json'\n    req = Request('https://127.0.0.1:5000' + path, headers=headers,\n                  data=None if data is None else json.dumps(data).encode())\n    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n    context.check_hostname = False\n    context.verify_mode = ssl.CERT_REQUIRED\n    context.load_verify_locations(cafile='/app/config/ssl/cert.pem')\n    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), NoRedirect())\n    try: response = opener.open(req, timeout=4 if path == '/api/health' else 8)\n    except HTTPError as error: response = error\n    with response:\n        raw = response.read(1048577)\n        if len(raw) > 1048576: raise RuntimeError('Oversized local response')\n        return response.code, json.loads(raw)\ndeadline = time.monotonic() + 65\nwhile True:\n    try:\n        if call('/api/health') == (200, {'status': 'ok', 'version': '1.4.1'}): break\n    except (OSError, ValueError, RuntimeError):\n        pass\n    if time.monotonic() >= deadline:\n        raise RuntimeError('PegaProx did not become ready')\n    time.sleep(2)\nstatus, state = call('/api/auth/check')\nrequire(status == 401 and state.get('authenticated') is False)\nif mode == 'bootstrap':\n    require(state.get('initialized') is False, 'Existing account/configuration; no bootstrap replay')\n    require(not state.get('oidc_enabled') and (not state.get('ldap_enabled')))\n    value = json.load(sys.stdin)\n    code, created = call('/api/auth/setup', value)\n    require(code == 200 and created.get('success') is True)\n    code, login = call('/api/auth/login', value)\n    require(code == 200 and login.get('success') is True)\n    token = login['session_id']\n    try:\n        code, checked = call('/api/auth/check', token=token)\n        require(code == 200 and checked['authenticated'] is True)\n        require(checked['user']['username'] == value['username'] and checked['user']['role'] == 'admin')\n    finally:\n        require(call('/api/auth/logout', {}, token)[0] == 200)\n    require(call('/api/auth/check')[1].get('initialized') is True)\nelif mode == 'verify':\n    require(state.get('initialized') is True)\nelse: raise RuntimeError('Unknown mode')\nprint('PegaProx verification passed')\n"

def run(*args):
    return subprocess.check_output(['docker', *args], text=True, stderr=subprocess.PIPE, timeout=90).strip()


def main():
    name = 'pegaprox-fixture-' + uuid.uuid4().hex[:12]
    volumes = [name + '-' + suffix for suffix in ('config', 'logs', 'key')]
    runtime = {'kind': 'pegaprox', 'image': IMAGE, 'bind_address': '198.18.25.34',
               'guest_memory_mib': 2048, 'container_memory_mib': 1024, 'cpus': 1, 'pids_limit': 256}
    preview = pegaprox.compose(runtime)['services']['pegaprox']
    assert preview.pop('ports') == ['198.18.25.34:5000:5000/tcp']
    bounded = ['--pull=never', '--platform', 'linux/amd64', '--network', 'none', '--read-only',
               '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
               '--cpus', str(preview['cpus']), '--memory', preview['mem_limit'],
               '--pids-limit', str(preview['pids_limit']), '--tmpfs', preview['tmpfs'][0]]
    image = IMAGE
    outcome = {'image': image, 'native_verified': False, 'network': 'none', 'published_ports': []}
    try:
        for volume in volumes:
            run('volume', 'create', volume)
        # Mount at the image-owned config path for Docker's initial ownership copy.
        run('run', '--rm', *bounded, '-v', volumes[2] + ':/app/config', '--entrypoint', 'python3', image,
            '-c', "import base64,os,pathlib; p=pathlib.Path('/app/config/pegaprox-db-key'); p.write_bytes(base64.urlsafe_b64encode(os.urandom(32))); p.chmod(0o600)")
        env = [arg for key, value in preview['environment'].items()
               for arg in ('-e', key + '=' + (value if key != 'PEGAPROX_KEY_FILE' else '/run/secrets/pegaprox-db-key'))]
        run('run', '-d', '--name', name, *bounded, *env,
            '-v', volumes[0] + ':/app/config', '-v', volumes[1] + ':/app/logs',
            '-v', volumes[2] + ':/run/secrets:ro', image)
        command = ['docker', 'exec', '-i', name]
        initial = subprocess.run([*command, 'python3', '-c', SYNTHETIC_SETUP_CODE, 'bootstrap'],
                                 input=json.dumps({'username': 'practice-admin', 'password': 'Aa11Aa11Aa11'}),
                                 capture_output=True, text=True, timeout=90, check=True)
        assert initial.stdout.strip() == 'PegaProx verification passed'
        pegaprox_health.verify(command)
        outcome['fresh_synthetic_setup_then_current_runtime_verification'] = True
        inspect = json.loads(run('inspect', name))[0]
        assert inspect['HostConfig']['NetworkMode'] == 'none'
        assert not inspect['HostConfig']['PortBindings']
        assert inspect['Config']['User'] and inspect['Config']['User'] != 'root'
        # The separate supplied key is used; encrypted data must not begin with SQLite's magic.
        state = "import hashlib,json,pathlib; from pegaprox.core.keystore import load_master_key; k=load_master_key(); assert k.source=='env:PEGAPROX_KEY_FILE'; p=pathlib.Path('/app/config/pegaprox.db'); assert p.is_file() and p.read_bytes()[:16]!=b'SQLite format 3\\x00'; assert not pathlib.Path('/app/config/secret.key').exists(); print(json.dumps({'key_hash':hashlib.sha256(pathlib.Path('/run/secrets/pegaprox-db-key').read_bytes()).hexdigest(),'source':k.source}))"
        before = json.loads(run('exec', name, 'python3', '-c', state))
        db_write = "import json; from pegaprox.core import dbcrypto; c=dbcrypto.connect('/app/config/pegaprox.db'); c.execute('INSERT OR REPLACE INTO server_settings(key,value) VALUES (?,?)',('fixture.restart.marker',json.dumps('invented-state'))); c.commit(); c.close()"
        db_read = "import json; from pegaprox.core import dbcrypto; c=dbcrypto.connect('/app/config/pegaprox.db'); row=c.execute('SELECT value FROM server_settings WHERE key=?',('fixture.restart.marker',)).fetchone(); assert row and json.loads(row[0])=='invented-state'; c.close(); print('database-row-passed')"
        run('exec', name, 'python3', '-c', db_write)
        assert run('exec', name, 'python3', '-c', db_read) == 'database-row-passed'
        run('exec', name, 'python3', '-c', "from pathlib import Path; Path('/app/config/fixture-marker').write_text('invented-state')")
        run('restart', '--time', '20', name)
        pegaprox_health.verify(command)
        outcome['passwordless_cd_verification_after_restart'] = True
        after = json.loads(run('exec', name, 'python3', '-c', state))
        assert before == after
        assert run('exec', name, 'python3', '-c', db_read) == 'database-row-passed'
        outcome['encrypted_database_row_persisted'] = True
        run('exec', name, 'python3', '-c', "from pathlib import Path; assert Path('/app/config/fixture-marker').read_text()=='invented-state'")
        outcome.update(nonroot_user=inspect['Config']['User'], read_only_root=True,
                       encrypted_db=True, separate_key=True, restart_persistence=True)
    finally:
        subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        for volume in volumes:
            run('volume', 'rm', volume)
        outcome['disposable_resources_removed'] = True
        print(json.dumps(outcome, indent=2))


if __name__ == '__main__':
    main()
