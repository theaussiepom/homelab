"""Exercise the real DB helper SQL/HBA against an isolated PostgreSQL16 server."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import monitoring


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='homelab-zabbix-db-test:1')
    args = parser.parse_args()
    image = monitoring.VERSIONS['fixture_postgresql']
    name = 'homelab-zabbix-db-' + uuid.uuid4().hex[:10]
    original_run = subprocess.run
    def docker(*args, check=True, **kwargs):
        return original_run(['docker', *args], check=check, timeout=90, **kwargs)
    with tempfile.TemporaryDirectory(prefix=name) as tmp:
        root = Path(tmp); root.chmod(0o755)
        password = 'synthetic-database-owner-password-1234'
        try:
            docker('network', 'create', '--internal', '--subnet', '198.18.156.0/24', name, stdout=subprocess.DEVNULL)
            docker('run', '-d', '--platform', 'linux/amd64', '--network', name, '--network-alias', 'postgres',
                   '--name', name, '-e', 'POSTGRES_PASSWORD=synthetic-fixture-admin',
                   '-v', f'{Path(__file__).resolve().parents[3]}:/src:ro',
                   '--tmpfs', '/var/lib/postgresql/data:rw,nosuid,nodev,size=128m', args.image, stdout=subprocess.DEVNULL)
            until = time.monotonic() + 90
            while docker('exec', name, 'pg_isready', '-U', 'postgres', capture_output=True, check=False).returncode:
                if time.monotonic() > until: raise RuntimeError('Fixture PostgreSQL did not become ready')
                time.sleep(1)
            original = docker('exec', name, 'cat', '/var/lib/postgresql/data/pg_hba.conf', capture_output=True).stdout
            expected = hashlib.sha256(original).hexdigest()
            program = ("import sys;sys.path.insert(0,'/src/proxmox/applications');import monitoring_database as d;"
                "from pathlib import Path;import json;"
                "print(json.dumps(d.provision(Path('/tmp/monitoring-state'),Path('/var/lib/postgresql/data/pg_hba.conf'),"
                + repr(expected) + ",'198.18.156.10'," + repr(password) + ")))")
            first = docker('exec', name, 'python3', '-c', program, capture_output=True, text=True)
            assert json.loads(first.stdout) == {'created': True}, first.stdout
            second = docker('exec', name, 'python3', '-c', program, capture_output=True, text=True)
            assert json.loads(second.stdout) == {'created': False}, second.stdout
            updated = docker('exec', name, 'cat', '/var/lib/postgresql/data/pg_hba.conf', capture_output=True).stdout
            assert updated.endswith(original)
            def connect(address, db='zabbix', statement='SELECT 1'):
                return docker('run', '--rm', '--platform', 'linux/amd64', '--network', name, '--ip', address,
                    '-e', 'PGPASSWORD=' + password, image, 'psql', '-X', '-At', '-h', 'postgres',
                    '-U', 'zabbix', '-d', db, '-v', 'ON_ERROR_STOP=1', '-c', statement,
                    capture_output=True, text=True, check=False)
            good = connect('198.18.156.10')
            assert good.returncode == 0 and good.stdout.strip() == '1', good.stderr
            def refused(result, message):
                assert result.returncode != 0 and message in result.stderr, result.stderr
            refused(connect('198.18.156.11'), 'pg_hba.conf rejects connection')
            refused(connect('198.18.156.10', 'postgres'), 'pg_hba.conf rejects connection')
            refused(connect('198.18.156.10', statement='CREATE DATABASE forbidden'), 'permission denied to create database')
            refused(connect('198.18.156.10', statement='CREATE ROLE forbidden'), 'permission denied to create role')
            print(json.dumps({'new_database': True, 'owner_not_cluster_admin': True,
                'single_source_and_database': True, 'second_run_changed': False,
                'original_hba_preserved': True, 'postgresql_restarted': False}))
        finally:
            docker('rm', '-f', name, check=False, capture_output=True)
            docker('network', 'rm', name, check=False, capture_output=True)


if __name__ == '__main__':
    main()
