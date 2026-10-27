"""Disposable Lite/MariaDB smoke test: internal network, synthetic empty database.

No host ports, production paths, real keys, users, clients or SMTP recipients.
This proves startup/health and a synthetic attachment's persistence only.
"""
import argparse
import http.client
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bitwarden
import render
from test_bitwarden import fixture

IMAGE = 'ghcr.io/bitwarden/lite:latest'
DATABASE = 'mariadb@sha256:805c8e104bd563d5bfa24fadd3f31cd419ea859cb5277f32b5dbf2db714f9ed1'


def inside():
    def fetch(path):
        connection = http.client.HTTPConnection('bitwarden', 8080, timeout=4)
        try:
            connection.request('GET', path)
            response = connection.getresponse()
            return response.status, response.read(262145)
        finally:
            connection.close()
    deadline = time.monotonic() + 240
    while True:
        try:
            result = bitwarden.health(fetch, 'http://localhost')
            print(json.dumps(result))
            return
        except (OSError, ValueError):
            if time.monotonic() >= deadline:
                raise RuntimeError('Synthetic Bitwarden startup or health contract failed') from None
            time.sleep(2)


def docker(*args, timeout=300, **kwargs):
    return subprocess.run(['docker', *args], check=True, timeout=timeout, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--tools-image', default='homelab-app-test')
    args = parser.parse_args()
    if args.inside:
        return inside()
    # Evidence of this invocation's pull; the deployment reference remains latest.
    docker('image', 'inspect', '--format', '{{json .RepoDigests}}', IMAGE)
    project = 'homelab-bitwarden-fixture-' + uuid.uuid4().hex[:10]
    with tempfile.TemporaryDirectory(prefix=project) as temporary:
        root = Path(temporary)
        cfg = fixture()
        cfg['services']['bitwarden']['image'] = IMAGE
        document = render.compose(cfg)
        document.pop('name')
        document['networks'] = {'default': {'internal': True}}
        document['volumes'] = {name: {} for name in ('data', 'logs', 'database')}
        env = {
            'BW_DOMAIN': 'bitwarden.example.invalid', 'BW_DB_PROVIDER': 'mysql',
            'BW_DB_SERVER': 'database', 'BW_DB_DATABASE': 'bitwarden_fixture',
            'BW_DB_USERNAME': 'fixture', 'BW_DB_PASSWORD': 'synthetic-only-$db-password',
            'BW_INSTALLATION_ID': '00000000-0000-4000-8000-000000000001',
            'BW_INSTALLATION_KEY': 'synthetic-only-installation-key',
            'globalSettings__enableCloudCommunication': 'false',
            'globalSettings__disableUserRegistration': 'true',
            'globalSettings__mail__smtp__host': 'smtp.example.invalid',
        }
        # Single-quoted dotenv values keep dollars literal on the target Compose 2.26.
        env_file = root / 'synthetic.env'
        env_file.write_text(''.join(f"{key}='{value}'\n" for key, value in env.items()))
        env_file.chmod(0o600)
        service = document['services']['bitwarden']
        service['platform'] = 'linux/amd64'
        service.pop('ports')
        service['env_file'] = [str(env_file)]
        service['volumes'] = ['data:/etc/bitwarden', 'logs:/var/log/bitwarden']
        service['depends_on'] = {'database': {'condition': 'service_healthy'}}
        document['services']['database'] = {
            'image': DATABASE, 'platform': 'linux/amd64', 'pull_policy': 'never', 'mem_limit': '512m', 'cpus': 1,
            'pids_limit': 128, 'restart': 'no', 'volumes': ['database:/var/lib/mysql'],
            'environment': {'MARIADB_DATABASE': 'bitwarden_fixture', 'MARIADB_USER': 'fixture',
                            'MARIADB_PASSWORD': 'synthetic-only-$$db-password',
                            'MARIADB_ROOT_PASSWORD': 'synthetic-only-root'},
            'healthcheck': {'test': ['CMD', 'healthcheck.sh', '--connect', '--innodb_initialized'],
                            'interval': '2s', 'timeout': '3s', 'retries': 60},
            'logging': {'driver': 'json-file', 'options': {'max-size': '2m', 'max-file': '1'}},
        }
        compose = root / 'compose.json'
        compose.write_text(json.dumps(document))
        command = ['compose', '-p', project, '-f', str(compose)]
        client_name = project + '-client'
        seed_name = project + '-seed'
        source = Path(__file__).resolve().parents[1]
        try:
            docker(*command, 'config', '--quiet')
            docker(*command, 'up', '-d', '--pull', 'never')
            docker('run', '--rm', '--name', client_name, '--platform', 'linux/amd64',
                   '--network', project + '_default', '--read-only', '--cap-drop', 'ALL',
                   '--security-opt', 'no-new-privileges', '--cpus', '0.5', '--memory', '128m',
                   '--pids-limit', '32', '-v', f'{source}:/source:ro',
                   '--entrypoint', 'python3', args.tools_image,
                   '/source/tests/bitwarden_fixture.py', '--inside')
            seed = ('from pathlib import Path; '
                    'p=Path("/data/attachments/synthetic-preservation.bin"); '
                    'p.parent.mkdir(exist_ok=True); p.write_bytes(b"synthetic-ciphertext-fixture")')
            # The application owns its private directory. Use its observed synthetic
            # ownership rather than granting root DAC bypass or changing ownership.
            owner = subprocess.check_output(['docker', *command, 'exec', '-T', 'bitwarden',
                                             'stat', '-c', '%u:%g', '/etc/bitwarden/attachments'],
                                            text=True, timeout=15).strip()
            if not re.fullmatch(r'[0-9]+:[0-9]+', owner):
                raise ValueError('Expected numeric synthetic attachment ownership')
            docker('run', '--rm', '--platform', 'linux/amd64', '--user', owner,
                   '--name', seed_name, '--network', 'none', '--read-only',
                   '--cap-drop', 'ALL', '--cpus', '0.5', '--memory', '128m', '--pids-limit', '32',
                   '-v', project + '_data:/data', '--entrypoint', 'python3', args.tools_image, '-c', seed)
            # This restart touches only the uniquely named synthetic project.
            docker(*command, 'restart', 'bitwarden')
            docker('run', '--rm', '--name', client_name, '--platform', 'linux/amd64',
                   '--network', project + '_default', '--read-only', '--cap-drop', 'ALL',
                   '--cpus', '0.5', '--memory', '128m', '--pids-limit', '32',
                   '-v', f'{source}:/source:ro', '--entrypoint', 'python3', args.tools_image,
                   '/source/tests/bitwarden_fixture.py', '--inside')
            check = ('from pathlib import Path; assert '
                     'Path("/data/attachments/synthetic-preservation.bin").read_bytes() '
                     '== b"synthetic-ciphertext-fixture"; print("SYNTHETIC_ATTACHMENT_OK")')
            docker('run', '--rm', '--platform', 'linux/amd64', '--user', owner,
                   '--name', seed_name, '--network', 'none', '--read-only',
                   '--cap-drop', 'ALL', '--cpus', '0.5', '--memory', '128m', '--pids-limit', '32',
                   '-v', project + '_data:/data:ro', '--entrypoint', 'python3', args.tools_image, '-c', check)
            print('Synthetic Lite latest / MariaDB 12.3.3 startup and restart passed; no migration acceptance.')
        finally:
            # Only resources with this invocation's random project/name are removed.
            subprocess.run(['docker', 'rm', '-f', client_name, seed_name],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            docker(*command, 'down', '--volumes', '--remove-orphans', '--timeout', '10', timeout=60)


if __name__ == '__main__':
    main()
