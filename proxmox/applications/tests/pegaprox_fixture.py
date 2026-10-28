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
import pegaprox_setup


def run(*args):
    return subprocess.check_output(['docker', *args], text=True, stderr=subprocess.PIPE, timeout=90).strip()


def main():
    name = 'pegaprox-fixture-' + uuid.uuid4().hex[:12]
    volumes = [name + '-' + suffix for suffix in ('config', 'logs', 'key')]
    cfg = json.loads((Path(__file__).resolve().parents[1] / 'examples/pegaprox.preparation.example.json').read_text())
    runtime = {key: value for key, value in cfg.items() if key not in {'enabled', 'deployable'}}
    preview = pegaprox.bootstrap_compose(runtime)['services']['pegaprox']
    assert not preview.get('ports')
    bounded = ['--pull=never', '--platform', 'linux/amd64', '--network', 'none', '--read-only',
               '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
               '--cpus', str(preview['cpus']), '--memory', preview['mem_limit'],
               '--pids-limit', str(preview['pids_limit']), '--tmpfs', preview['tmpfs'][0]]
    image = pegaprox.IMAGE
    outcome = {'image': image, 'native_verified': False, 'network': 'none', 'published_ports': []}
    try:
        for volume in volumes:
            run('volume', 'create', volume)
        # Mount at the image-owned config path for Docker's initial ownership copy.
        run('run', '--rm', *bounded, '-v', volumes[2] + ':/app/config', '--entrypoint', 'python3', image,
            '-c', "import base64,os,pathlib; p=pathlib.Path('/app/config/db-key'); p.write_bytes(base64.urlsafe_b64encode(os.urandom(32))); p.chmod(0o600)")
        env = [arg for key, value in preview['environment'].items()
               for arg in ('-e', key + '=' + (value if key != 'PEGAPROX_KEY_FILE' else '/run/secrets/db-key'))]
        run('run', '-d', '--name', name, *bounded, *env,
            '-v', volumes[0] + ':/app/config', '-v', volumes[1] + ':/app/logs',
            '-v', volumes[2] + ':/run/secrets:ro', image)
        probe = "import json,ssl,urllib.request; r=urllib.request.urlopen('https://127.0.0.1:5000/api/health',context=ssl._create_unverified_context(),timeout=4); assert r.status==200; print(r.read().decode())"

        def healthy():
            deadline = time.monotonic() + 150
            while time.monotonic() < deadline:
                try:
                    value = json.loads(run('exec', name, 'python3', '-c', probe))
                    return value
                except (subprocess.CalledProcessError, json.JSONDecodeError):
                    time.sleep(2)
            raise RuntimeError('Pinned image did not become healthy within 150 seconds')

        outcome['health'] = healthy()
        assert outcome['health'] == {'status': 'ok', 'version': '1.4.1'}
        command = ['docker', 'exec', '-i', name]
        pegaprox_setup.invoke(command, 'bootstrap', 'practice-admin', 'Synthetic-fixture-123')
        try:
            pegaprox_setup.invoke(command, 'bootstrap', 'practice-admin', 'Changed-fixture-456')
        except ValueError:
            outcome['bootstrap_replay_refused'] = True
        else:
            raise AssertionError('Existing account must never be reset by bootstrap')
        pegaprox_setup.invoke(command, 'verify')
        outcome['initial_admin_login'] = True
        inspect = json.loads(run('inspect', name))[0]
        assert inspect['HostConfig']['NetworkMode'] == 'none'
        assert not inspect['HostConfig']['PortBindings']
        assert inspect['Config']['User'] and inspect['Config']['User'] != 'root'
        # The separate supplied key is used; encrypted data must not begin with SQLite's magic.
        state = "import hashlib,json,pathlib; from pegaprox.core.keystore import load_master_key; k=load_master_key(); assert k.source=='env:PEGAPROX_KEY_FILE'; p=pathlib.Path('/app/config/pegaprox.db'); assert p.is_file() and p.read_bytes()[:16]!=b'SQLite format 3\\x00'; assert not pathlib.Path('/app/config/secret.key').exists(); print(json.dumps({'key_hash':hashlib.sha256(pathlib.Path('/run/secrets/db-key').read_bytes()).hexdigest(),'source':k.source}))"
        before = json.loads(run('exec', name, 'python3', '-c', state))
        db_write = "import json; from pegaprox.core import dbcrypto; c=dbcrypto.connect('/app/config/pegaprox.db'); c.execute('INSERT OR REPLACE INTO server_settings(key,value) VALUES (?,?)',('fixture.restart.marker',json.dumps('invented-state'))); c.commit(); c.close()"
        db_read = "import json; from pegaprox.core import dbcrypto; c=dbcrypto.connect('/app/config/pegaprox.db'); row=c.execute('SELECT value FROM server_settings WHERE key=?',('fixture.restart.marker',)).fetchone(); assert row and json.loads(row[0])=='invented-state'; c.close(); print('database-row-passed')"
        run('exec', name, 'python3', '-c', db_write)
        assert run('exec', name, 'python3', '-c', db_read) == 'database-row-passed'
        run('exec', name, 'python3', '-c', "from pathlib import Path; Path('/app/config/fixture-marker').write_text('invented-state')")
        run('restart', '--time', '20', name)
        healthy()
        pegaprox_setup.invoke(command, 'verify')
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
