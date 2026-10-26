"""Test the native SQL restore helper with two disposable MariaDB datadirs.

Run only in a disposable Docker image with matching native MariaDB packages.
The helper's systemctl calls are intercepted: this is not a systemd/LXC test.
No production inputs, network listeners or published ports are used.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import database


def sql(text):
    return subprocess.check_output(['mariadb', '--protocol=socket', '--user=root', '--batch', '--skip-column-names'], input=text, text=True)


def main():
    assert Path('/.dockerenv').exists() and os.geteuid() == 0
    version = subprocess.check_output(['mariadb', '--version'], text=True)
    assert '12.3.3-MariaDB' in version, version
    socket_directory = Path('/run/mysqld')
    socket_directory.mkdir(mode=0o755, exist_ok=True)
    os.chown(socket_directory, 999, 999)
    with tempfile.TemporaryDirectory(prefix='homelab-native-db-', dir='/var/lib') as tmp:
        root = Path(tmp)
        os.chmod(root, 0o755)
        processes = []
        def start(side):
            data = root / side
            data.mkdir(mode=0o700)
            os.chown(data, 999, 999)
            subprocess.run(['mariadb-install-db', '--no-defaults', '--user=mysql', '--datadir=' + str(data),
                            '--auth-root-authentication-method=socket'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            log = (root / (side + '.stderr')).open('wb')
            process = subprocess.Popen(['mariadbd', '--no-defaults', '--user=mysql', '--datadir=' + str(data),
                '--socket=/run/mysqld/mysqld.sock', '--skip-networking', '--pid-file=' + str(data / 'server.pid')],
                stdout=log, stderr=log)
            processes.append((process, log))
            for _ in range(60):
                if process.poll() is not None:
                    raise RuntimeError('Synthetic MariaDB exited during startup: ' + (root / (side + '.stderr')).read_text()[-3000:])
                ready = subprocess.run(['mariadb-admin', '--protocol=socket', '--user=root', 'ping'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if ready.returncode == 0:
                    return process
                time.sleep(0.25)
            raise RuntimeError('Synthetic MariaDB startup exceeded its bound')
        try:
            source = start('source')
            sql("CREATE DATABASE fixture_home; CREATE TABLE fixture_home.fixture_data(value integer); INSERT INTO fixture_home.fixture_data VALUES (42); CREATE USER 'fixture_app'@'localhost' IDENTIFIED BY 'synthetic-only-password'; GRANT SELECT ON fixture_home.* TO 'fixture_app'@'localhost';\n")
            capture = root / 'database.capture'
            with capture.open('wb') as stream:
                subprocess.run(['mariadb-dump', '--protocol=socket', '--user=root', '--all-databases', '--routines', '--events', '--triggers'], check=True, stdout=stream)
            source.terminate()
            source.wait(timeout=20)
            start('target')
            cfg = {'kind': 'mariadb', 'exclusive_writer_confirmed': True, 'capture': {'sha256': database.digest(capture)}}
            execute = subprocess.run
            service_calls = []
            def selected(command, **kwargs):
                if command[0] == 'systemctl':
                    service_calls.append(command)
                    return subprocess.CompletedProcess(command, 0)
                return execute(command, **kwargs)
            with patch.object(database.subprocess, 'run', side_effect=selected):
                assert database.run(cfg, root)
                assert not database.run(cfg, root)
            assert service_calls == [['systemctl', 'start', 'mariadb'], ['systemctl', 'enable', 'mariadb']]
            assert sql('SELECT value FROM fixture_home.fixture_data;\n').strip() == '42'
            assert 'GRANT SELECT ON `fixture_home`.*' in sql("SHOW GRANTS FOR 'fixture_app'@'localhost';\n")
            client = subprocess.check_output(['mariadb', '--protocol=socket', '--user=fixture_app',
                '--batch', '--skip-column-names', '--database=fixture_home', '--execute=SELECT value FROM fixture_data'],
                env=dict(os.environ, MYSQL_PWD='synthetic-only-password'), text=True)
            assert client.strip() == '42'
            assert json.loads((root / 'database-restore.json').read_text())['state'] == 'complete'
            print('MariaDB 12.3.3 native SQL restore passed: unchanged full dump, restored row/account/grant and no-replay receipt')
        except Exception:
            for log in root.glob('*.stderr'):
                print(log.name + ':\n' + log.read_text()[-6000:], file=sys.stderr)
            raise
        finally:
            for process, log in processes:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=20)
                log.close()


if __name__ == '__main__':
    main()
