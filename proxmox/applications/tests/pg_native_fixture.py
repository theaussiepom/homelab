"""Exercise unchanged clean SQL using matching native PG16.10 Debian packages.

Only disposable Docker, loopback sockets and synthetic rows/roles are used.
The systemctl calls are intercepted, so this is not systemd/LXC qualification.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import database


def require(condition, message):
    if not condition:
        raise AssertionError(message)


BIN = '/usr/lib/postgresql/16/bin/'


def pg(command, **kwargs):
    return subprocess.run(['runuser', '-u', 'postgres', '--'] + command, **kwargs)


def sql(text, port=5432, db='postgres'):
    return subprocess.check_output(['runuser', '-u', 'postgres', '--', 'psql', '-X', '-At',
        '-v', 'ON_ERROR_STOP=1', '--host=127.0.0.1', '--port=' + str(port), '--dbname=' + db], input=text, text=True)


def main():
    require(Path('/.dockerenv').exists() and os.geteuid() == 0, 'Run only as root inside a disposable Docker container')
    version = subprocess.check_output([BIN + 'postgres', '--version'], text=True)
    require(version.strip() == 'postgres (PostgreSQL) 16.10 (Debian 16.10-1.pgdg13+1)', version)
    with tempfile.TemporaryDirectory(prefix='homelab-native-pg-', dir='/var/lib') as tmp:
        root = Path(tmp)
        os.chown(root, 70, 1000)
        os.chmod(root, 0o700)
        clusters = []
        try:
            socket = Path('/var/run/postgresql')
            socket.mkdir(exist_ok=True)
            os.chown(socket, 70, 1000)
            for side, port in [('source', 55432), ('target', 5432)]:
                data = root / side
                data.mkdir(mode=0o700)
                os.chown(data, 70, 1000)
                pg([BIN + 'initdb', '-D', str(data), '-A', 'trust', '--no-locale'], check=True, stdout=subprocess.DEVNULL)
                pg([BIN + 'pg_ctl', '-D', str(data), '-l', str(data / 'server.log'), '-w', '-t', '30',
                    '-o', '-h 127.0.0.1 -p ' + str(port) + ' -k /var/run/postgresql', 'start'], check=True, stdout=subprocess.DEVNULL)
                clusters.append(data)
            sql("CREATE ROLE fixture_app LOGIN; CREATE DATABASE fixture_home OWNER fixture_app; COMMENT ON DATABASE fixture_home IS 'synthetic-only'; GRANT CONNECT ON DATABASE postgres TO fixture_app;\n", port=55432)
            sql('CREATE TABLE fixture_data(value integer); INSERT INTO fixture_data VALUES (42); ALTER TABLE fixture_data OWNER TO fixture_app;\n', port=55432, db='fixture_home')
            capture = root / 'database.capture'
            with capture.open('wb') as output:
                pg(['pg_dumpall', '--host=127.0.0.1', '--port=55432', '--clean', '--if-exists'], check=True, stdout=output)
            cfg = {'kind': 'postgresql', 'user': 'postgres', 'exclusive_writer_confirmed': True,
                   'capture': {'format': 'pg-dumpall-clean', 'sha256': database.digest(capture)}}
            execute = subprocess.run
            service_calls = []
            def selected(command, **kwargs):
                if command[0] == 'systemctl':
                    service_calls.append(command)
                    return subprocess.CompletedProcess(command, 0)
                return execute(command, **kwargs)
            with patch.object(database.subprocess, 'run', side_effect=selected):
                require(database.run(cfg, root), 'Synthetic database fixture check failed')
                require(not database.run(cfg, root), 'Synthetic database fixture check failed')
            require(database.digest(capture) == cfg['capture']['sha256'], 'Synthetic database fixture check failed')
            require(service_calls == [['systemctl', 'start', 'postgresql'], ['systemctl', 'enable', 'postgresql']], 'Synthetic database fixture check failed')
            require(sql('SELECT value FROM fixture_data;\n', db='fixture_home').strip() == '42', 'Synthetic database fixture check failed')
            require(sql("SELECT pg_get_userbyid(datdba)||':'||shobj_description(oid,'pg_database') FROM pg_database WHERE datname='fixture_home';\n").strip() == 'fixture_app:synthetic-only', 'Synthetic database fixture check failed')
            require(sql("SELECT has_database_privilege('fixture_app','postgres','CONNECT');\n").strip() == 't', 'Synthetic database fixture check failed')
            require(sql("SELECT oid FROM pg_roles WHERE rolname='postgres';\n").strip() == '10', 'Synthetic database fixture check failed')
            require(sql("SELECT count(*) FROM pg_roles WHERE rolname LIKE 'homelab_restore_%';\n").strip() == '0', 'Synthetic database fixture check failed')
            require(json.loads((root / 'database-restore.json').read_text())['state'] == 'complete', 'Synthetic database fixture check failed')
            print('Native PostgreSQL 16.10 clean restore passed: unchanged dump, exact exception pair, restored data/owner/comment/grant, OID 10 and maintenance identity removal')
        except Exception:
            for log in [root / 'postgresql-clean.stderr'] + list(root.glob('*/server.log')):
                if log.exists():
                    print(log.name + ':\n' + log.read_text()[-6000:], file=sys.stderr)
            raise
        finally:
            for data in clusters:
                pg([BIN + 'pg_ctl', '-D', str(data), '-m', 'fast', '-w', '-t', '30', 'stop'], check=False, stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
