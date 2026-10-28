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
        root = Path(tmp)
        password = 'synthetic-database-owner-password-1234'
        try:
            docker('network', 'create', '--internal', '--subnet', '198.18.156.0/24', name, stdout=subprocess.DEVNULL)
            docker('run', '-d', '--platform', 'linux/amd64', '--network', name, '--network-alias', 'postgres',
                   '--name', name, '-e', 'POSTGRES_PASSWORD=synthetic-fixture-admin',
                   '-v', f'{Path(__file__).resolve().parents[3]}:/src:ro',
                   '--tmpfs', '/var/lib/postgresql/data:rw,nosuid,nodev,size=128m', args.image, stdout=subprocess.DEVNULL)
            until = time.monotonic() + 90
            while docker('exec', name, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres', capture_output=True, check=False).returncode:
                if time.monotonic() > until: raise RuntimeError('Fixture PostgreSQL did not become ready')
                time.sleep(1)
            started = docker('exec', name, 'psql', '-U', 'postgres', '-Atc', 'SELECT pg_postmaster_start_time()', capture_output=True).stdout
            original = docker('exec', name, 'cat', '/var/lib/postgresql/data/pg_hba.conf', capture_output=True).stdout
            expected = hashlib.sha256(original).hexdigest()
            program = ("import sys;sys.path.insert(0,'/src/proxmox/applications');import monitoring_database as d;"
                "from pathlib import Path;import json;"
                "print(json.dumps(d.provision(Path('/tmp/monitoring-state'),Path('/var/lib/postgresql/data/pg_hba.conf'),"
                + repr(expected) + ",'198.18.156.10'," + repr(password) + ")))")
            docker('exec',name,'psql','-U','postgres','-c',"ALTER SYSTEM SET log_statement='all'",capture_output=True)
            docker('exec',name,'psql','-U','postgres','-c','SELECT pg_reload_conf()',capture_output=True)
            first = docker('exec', name, 'python3', '-c', program, capture_output=True, text=True)
            assert json.loads(first.stdout) == {'created': True}, first.stdout
            second = docker('exec', name, 'python3', '-c', program, capture_output=True, text=True)
            assert json.loads(second.stdout) == {'created': False}, second.stdout
            ended = docker('exec', name, 'psql', '-U', 'postgres', '-Atc', 'SELECT pg_postmaster_start_time()', capture_output=True).stdout
            assert started == ended, 'PostgreSQL restarted during provisioning'
            updated = docker('exec', name, 'cat', '/var/lib/postgresql/data/pg_hba.conf', capture_output=True).stdout
            assert updated.endswith(original)
            # Force duplicate-role CREATE after the preflight, reproducing the
            # error path that used to log the original password in SQL.
            force = ("import sys;sys.path.insert(0,'/src/proxmox/applications');import monitoring_database as d;"
                "from pathlib import Path;from unittest.mock import patch;"
                "h=Path('/tmp/forced-hba');h.write_bytes(" + repr(original) + ");query=d.sql;"
                "fake=lambda s:'0' if 'SELECT count(*) FROM pg_roles' in s or 'SELECT count(*) FROM pg_database' in s else query(s);"
                "p=patch.object(d,'sql',side_effect=fake);p.start();"
                "d.provision(Path('/tmp/forced-state'),h," + repr(expected) + ",'198.18.156.10'," + repr(password) + ")")
            failed=docker('exec',name,'python3','-c',force,check=False,capture_output=True,text=True)
            assert failed.returncode != 0 and 'PostgreSQL monitoring operation failed' in failed.stderr
            logs=docker('logs',name,capture_output=True,text=True)
            assert 'already exists' in logs.stderr, 'Forced duplicate-role failure was not logged'
            assert password not in logs.stdout+logs.stderr, 'Original password reached PostgreSQL logs'
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
                'single_source_and_database': True, 'second_run_changed': json.loads(second.stdout)['created'],
                'original_hba_preserved': True, 'postgresql_restarted': started != ended, 'original_password_absent_from_statement_logs': True}))
        finally:
            docker('rm', '-f', name, check=False, capture_output=True)
            docker('network', 'rm', name, check=False, capture_output=True)


if __name__ == '__main__':
    main()
