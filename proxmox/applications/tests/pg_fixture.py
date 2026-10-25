"""Prove the native clean-dump SQL adapter against two disposable PG16 clusters.

No published ports, production data, host mounts or external container networks.
"""
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pg_clean import restore_clean

IMAGE = 'postgres@sha256:9d4951e6dc70422022512ff05ac86e0ae360da051c563accbed85d6f654c3357'


def sql(name, text):
    return subprocess.check_output(['docker', 'exec', '-i', '--user', 'postgres', name,
                                    'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-U', 'postgres', '-d', 'postgres'], input=text, text=True)


def main():
    names = []
    try:
        for side in ('source', 'target'):
            name = 'homelab-pg-source-fixture-' + side + '-' + uuid.uuid4().hex[:10]
            subprocess.run(['docker', 'run', '-d', '--rm', '--platform', 'linux/amd64', '--network', 'none',
                            '--cpus', '1', '--memory', '512m', '--name', name,
                            '--tmpfs', '/var/lib/postgresql/data:rw,nosuid,nodev,size=384m',
                            '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', IMAGE], check=True, stdout=subprocess.DEVNULL)
            names.append(name)
            for attempt in range(40):
                ready = subprocess.run(['docker', 'exec', name, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if ready.returncode == 0:
                    break
                if attempt == 39:
                    raise RuntimeError('Synthetic PostgreSQL startup exceeded its bound')
                time.sleep(0.5)
        source, target = names
        sql(source, "CREATE ROLE fixture_app LOGIN;\nCREATE DATABASE fixture_home OWNER fixture_app;\nREVOKE CONNECT ON DATABASE postgres FROM PUBLIC;\nGRANT CONNECT ON DATABASE postgres TO fixture_app;\nCOMMENT ON DATABASE fixture_home IS 'synthetic-only';\n")
        subprocess.run(['docker', 'exec', '-i', source, 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'fixture_home'],
                       input='CREATE TABLE fixture_data(value integer); INSERT INTO fixture_data VALUES (42); ALTER TABLE fixture_data OWNER TO fixture_app;\n', text=True, check=True, stdout=subprocess.DEVNULL)
        evidence_parent = Path('.work/pg-clean-fixtures')
        evidence_parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        tmp = tempfile.mkdtemp(prefix='run-', dir=evidence_parent)
        root = Path(tmp)
        print('Synthetic PG fixture evidence: ' + str(root), flush=True)
        capture = root / 'unchanged.sql'
        with capture.open('wb') as output:
            subprocess.run(['docker', 'exec', source, 'pg_dumpall', '-U', 'postgres', '--clean', '--if-exists'], stdout=output, check=True)
        import hashlib
        checksum = hashlib.sha256(capture.read_bytes()).hexdigest()
        def execute(command, **kwargs):
            assert command[:4] == ['runuser', '-u', 'postgres', '--']
            prefix = ['docker', 'exec', '-i', '--user', 'postgres']
            if kwargs.get('env', {}).get('PGPASSWORD'):
                prefix += ['--env', 'PGPASSWORD']
            return subprocess.run(prefix + [target] + command[4:], **kwargs)
        restore_clean(capture, root, execute=execute)
        assert hashlib.sha256(capture.read_bytes()).hexdigest() == checksum
        assert sql(target, "SELECT oid FROM pg_roles WHERE rolname='postgres';\n").strip() == '10'
        assert sql(target, "SELECT datname||':'||pg_get_userbyid(datdba)||':'||shobj_description(oid,'pg_database') FROM pg_database WHERE datname='fixture_home';\n").strip() == 'fixture_home:fixture_app:synthetic-only'
        assert sql(target, "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'homelab_restore_%';\n").strip() == '0'
        value = subprocess.check_output(['docker', 'exec', target, 'psql', '-X', '-At', '-U', 'postgres', '-d', 'fixture_home', '-c', 'SELECT value FROM fixture_data'], text=True)
        assert value.strip() == '42'
        assert sql(target, "SELECT has_database_privilege('fixture_app','postgres','CONNECT');\n").strip() == 't'
        print('PG clean fixture passed: unchanged dump, exact diagnostic pair, OID 10, data/owner/comment/grant and maintenance-identity removal')
    finally:
        # Only our exact newly created synthetic targets, never a prune operation.
        for name in names:
            # A crashed --rm container may already be gone; try every exact name
            # and keep Docker's diagnostics without replacing the original error.
            subprocess.run(['docker', 'rm', '-f', name], check=False, stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
