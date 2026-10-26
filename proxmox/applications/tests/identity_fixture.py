"""Start pinned Authentik2025.2.1 against disposable PostgreSQL16 and Redis.

Only synthetic empty data and fixture credentials are used. Rendered commands,
file:// settings and Redis dependency stay intact; host paths are translated
to disposable volumes and the host port publication is removed. One internal
Docker network has no published ports or Internet route. Native migration and
household authentication remain outside this fixture.
"""
import argparse
from datetime import datetime
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

AUTH = 'ghcr.io/goauthentik/server@sha256:dc07e81b4462a1dad9c6720f4c73993e37d7cb2d2f94a306187318704d112e71'
REDIS = 'redis@sha256:6cbef353e480a8a6e7f10ec545f13d7d3fa85a212cdcc5ffaf5a1c818b9d3798'
POSTGRES = 'postgres@sha256:38471f330eb885e04de130b768d6db4e10469e2311879c7e5c699f6d2d8a1c74'


def check():
    deadline = time.monotonic() + 240
    for endpoint in ('/-/health/live/', '/-/health/ready/'):
        while True:
            try:
                conn = http.client.HTTPConnection('server', 9000, timeout=3)
                try:
                    conn.request('GET', endpoint)
                    response = conn.getresponse()
                    body = response.read()
                    if response.status == 200:
                        break
                finally:
                    conn.close()
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError('Synthetic Authentik health endpoints did not become ready within 240 seconds')
            time.sleep(1)
    print('Pinned Authentik server live/ready endpoints passed against synthetic PostgreSQL16 and Redis.')


def docker(*args, timeout=180, **kwargs):
    return subprocess.run(['docker', *args], check=True, timeout=timeout, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tools-image', default='homelab-app-test')
    args = parser.parse_args()
    from test_foundation import fixture, render
    project = 'homelab-identity-fixture-' + uuid.uuid4().hex[:10]
    client_name = project + '-health-client'
    with tempfile.TemporaryDirectory(prefix=project + '-') as tmp:
        root = Path(tmp)
        cfg = fixture(root, 'identity')
        cfg['foundation'].update(postgresql_host='postgres', postgresql_user='authentik',
                                 postgresql_database='authentik')
        for name in ('server', 'worker'):
            cfg['services'][name].update(image=AUTH, memory_mib=768, cpus=1,
                                         user='1000:1000', pids_limit=128)
        cfg['services']['redis'].update(image=REDIS, memory_mib=128, cpus=1)
        document = render.compose(cfg)
        document.pop('name', None)
        document['networks'] = {'default': {'internal': True}}
        document['volumes'] = {name: {} for name in ('secrets', 'media', 'templates', 'certs', 'redis')}
        runtime_files = render.foundation_files(cfg)
        for artifact in runtime_files:
            (root / artifact['path']).write_text(artifact['content'])
        (root / 'runtime-files.json').write_text(json.dumps(runtime_files))
        # All files here are synthetic. A seed job installs the real app-facing
        # copies with UID/GID1000 and mode0400 into the private secrets volume.
        root.chmod(0o755)
        for path in root.iterdir():
            path.chmod(0o644)
        for name in ('server', 'worker'):
            service = document['services'][name]
            service.pop('ports', None)
            service['security_opt'] = ['no-new-privileges']
            service['cap_drop'] = ['ALL']
            service['volumes'] = ['secrets:/run/secrets:ro', 'media:/media', 'templates:/templates']
            if name == 'worker':
                service['volumes'].append('certs:/certs')
            # Test database admission is fixture-only. The production stack's
            # Redis health dependency is preserved exactly by this extension.
            service['depends_on']['postgres'] = {'condition': 'service_healthy'}
        redis = document['services']['redis']
        redis['volumes'] = ['redis:/data']
        redis['cap_drop'] = ['ALL']
        redis['cap_add'] = ['CHOWN', 'SETUID', 'SETGID']
        redis['security_opt'] = ['no-new-privileges']
        redis['healthcheck']['test'][1] += (
            ' && ([ -f /tmp/fixture-first-healthy ] || date -u +%s > /tmp/fixture-first-healthy)')
        document['services']['postgres'] = {
            'image': POSTGRES, 'user': '999:999', 'cap_drop': ['ALL'],
            'security_opt': ['no-new-privileges'], 'mem_limit': '256m', 'cpus': 1, 'pids_limit': 100,
            'environment': {'POSTGRES_DB': 'authentik', 'POSTGRES_USER': 'authentik',
                            'POSTGRES_PASSWORD_FILE': '/fixture/postgresql-password',
                            'PGDATA': '/tmp/fixture-pgdata'},
            'volumes': [f'{root}:/fixture:ro'],
            'tmpfs': ['/tmp/fixture-pgdata:rw,nosuid,nodev,size=128m,uid=999,gid=999,mode=0700'],
            'healthcheck': {'test': ['CMD', 'pg_isready', '-U', 'authentik', '-d', 'authentik'],
                            'interval': '2s', 'timeout': '2s', 'retries': 30},
        }
        seed = ('import json,os; from pathlib import Path; '
                'items=json.loads(Path("/fixture/runtime-files.json").read_text()); '
                '[(Path("/secrets",i["path"]).write_text(i["content"]), '
                'os.chmod(Path("/secrets",i["path"]),0o400), '
                'os.chown(Path("/secrets",i["path"]),1000,1000)) for i in items]; '
                '[(os.chmod(p,0o700),os.chown(p,1000,1000)) '
                'for p in ("/secrets","/media","/templates","/certs")]')
        document['services']['seed'] = {
            'image': args.tools_image, 'profiles': ['seed'], 'user': '0:0', 'entrypoint': 'python3',
            'command': ['-c', seed], 'network_mode': 'none',
            'cap_drop': ['ALL'], 'cap_add': ['CHOWN'], 'security_opt': ['no-new-privileges'],
            'mem_limit': '128m', 'cpus': 1, 'pids_limit': 40,
            'volumes': [f'{root}:/fixture:ro', 'secrets:/secrets', 'media:/media',
                        'templates:/templates', 'certs:/certs'],
        }
        for service in document['services'].values():
            service['platform'] = 'linux/amd64'
        path = root / 'compose.json'
        path.write_text(json.dumps(document))
        command = ['compose', '-p', project, '-f', str(path)]
        try:
            docker(*command, 'run', '--rm', '--no-deps', 'seed', stdout=subprocess.DEVNULL)
            start = time.monotonic()
            docker(*command, 'up', '-d', 'server', 'worker', timeout=300, stdout=subprocess.DEVNULL)
            network = project + '_default'
            docker('run', '--rm', '--name', client_name, '--platform', 'linux/amd64', '--network', network,
                   '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                   '--cpus', '1', '--memory', '128m', '--pids-limit', '40', '--entrypoint', 'python3',
                   '-v', f'{Path(__file__).resolve()}:/fixture.py:ro', args.tools_image,
                   '/fixture.py', 'check', timeout=max(1, int(300 - (time.monotonic() - start))))
            probe = ('import os,stat; from pathlib import Path; from authentik.lib.config import CONFIG; '
                     'assert os.getuid()==1000; '
                     'assert CONFIG.get("secret_key")=="synthetic-$secret_key"; '
                     'assert CONFIG.get("postgresql.password")=="synthetic-$postgresql_password"; '
                     '[(lambda s: (s.st_uid==1000 and stat.S_IMODE(s.st_mode)==0o400) '
                     'or (_ for _ in ()).throw(AssertionError("Secret identity/mode mismatch"))) '
                     '(Path("/run/secrets",n).stat()) '
                     'for n in ("authentik-secret-key","postgresql-password")]; '
                     'print("UID1000 resolved private file-backed Authentik key and PostgreSQL password.")')
            docker(*command, 'exec', '-T', 'server', 'python', '-c', probe, timeout=30)
            docker(*command, 'exec', '-T', 'worker', 'ak', 'healthcheck', timeout=30)
            timestamp = docker(*command, 'exec', '-T', 'redis', 'cat', '/tmp/fixture-first-healthy',
                               capture_output=True, text=True).stdout.strip()
            for service in ('server', 'worker'):
                container = docker(*command, 'ps', '-q', service, capture_output=True, text=True).stdout.strip()
                value = docker('inspect', '--format', '{{.State.StartedAt}}', container,
                               capture_output=True, text=True).stdout.strip()
                assert datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp() >= int(timestamp), service
            print('Pinned Authentik server/worker started after Redis was healthy; '
                  'worker health passed. Synthetic startup only; no restored-data or household-login claim.')
        except Exception:
            subprocess.run(['docker', *command, 'logs', '--tail', '50'], check=False, timeout=30)
            raise
        finally:
            subprocess.run(['docker', 'rm', '-f', client_name], check=False, timeout=30,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['docker', *command, 'down', '--volumes', '--remove-orphans', '--timeout', '20'],
                           check=False, timeout=90, stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    if sys.argv[1:] == ['check']:
        check()
    else:
        main()
