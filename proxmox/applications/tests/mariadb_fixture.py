"""Test the native SQL restore helper with two disposable MariaDB datadirs.

Run only in a disposable Docker image with matching native MariaDB packages.
The helper's systemctl calls are intercepted: this is not a systemd/LXC test.
No production inputs, network listeners or published ports are used.
"""
from contextlib import ExitStack
import grp
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import database


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def sql(text):
    return subprocess.check_output(['mariadb', '--protocol=socket', '--user=root', '--batch', '--skip-column-names'], input=text, text=True)


def main():
    require(Path('/.dockerenv').exists() and os.geteuid() == 0, 'Run only as root inside a disposable Docker container')
    version = subprocess.check_output(['mariadb', '--version'], text=True)
    require('12.3.3-MariaDB' in version, version)
    mysql = pwd.getpwnam('mysql')
    mysql_group = grp.getgrnam('mysql')
    journal_before = subprocess.check_output(['getent', 'group', 'systemd-journal'], text=True)
    require(grp.getgrnam('systemd-journal').gr_gid == 999, 'The fixture must reproduce the journal GID999 collision')
    require(mysql.pw_gid == mysql_group.gr_gid and mysql_group.gr_gid != 999,
            'The target must use its actual package-created service account')
    # Reproduce the original Docker data ownership in a separate synthetic
    # source. Its SQL dump must not depend on the new daemon's Unix IDs.
    subprocess.run(['useradd', '--uid', '999', '--gid', '999', '--no-create-home',
                    '--shell', '/usr/sbin/nologin', 'fixture_legacy_mysql'], check=True)
    socket_directory = Path('/run/mysqld')
    socket_directory.mkdir(mode=0o755, exist_ok=True)
    with ExitStack() as contexts:
        root = Path(contexts.enter_context(tempfile.TemporaryDirectory(prefix='homelab-native-db-', dir='/var/lib')))
        os.chmod(root, 0o700)
        identities = {'source': ('fixture_legacy_mysql', 999, 999),
                      'target': ('mysql', mysql.pw_uid, mysql_group.gr_gid)}
        data_directories = {}
        for side, (_, uid, gid) in identities.items():
            data = Path(contexts.enter_context(tempfile.TemporaryDirectory(prefix='homelab-mariadb-' + side + '-', dir='/var/lib')))
            os.chown(data, uid, gid)
            os.chmod(data, 0o700)
            data_directories[side] = data
        processes = []
        def start(side):
            data = data_directories[side]
            user, uid, gid = identities[side]
            os.chown(socket_directory, uid, gid)
            subprocess.run(['mariadb-install-db', '--no-defaults', '--user=' + user, '--datadir=' + str(data),
                            '--auth-root-authentication-method=socket'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            log = (root / (side + '.stderr')).open('wb')
            process = subprocess.Popen(['mariadbd', '--no-defaults', '--user=' + user, '--datadir=' + str(data),
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
            capture_sha256 = database.digest(capture)
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
                require(database.run(cfg, root), 'Synthetic database fixture check failed')
                require(not database.run(cfg, root), 'Synthetic database fixture check failed')
            require(service_calls == [['systemctl', 'start', 'mariadb'], ['systemctl', 'enable', 'mariadb']], 'Synthetic database fixture check failed')
            require(sql('SELECT value FROM fixture_home.fixture_data;\n').strip() == '42', 'Synthetic database fixture check failed')
            require('GRANT SELECT ON `fixture_home`.*' in sql("SHOW GRANTS FOR 'fixture_app'@'localhost';\n"), 'Synthetic database fixture check failed')
            client = subprocess.check_output(['mariadb', '--protocol=socket', '--user=fixture_app',
                '--batch', '--skip-column-names', '--database=fixture_home', '--execute=SELECT value FROM fixture_data'],
                env=dict(os.environ, MYSQL_PWD='synthetic-only-password'), text=True)
            require(client.strip() == '42', 'Synthetic database fixture check failed')
            require(json.loads((root / 'database-restore.json').read_text())['state'] == 'complete', 'Synthetic database fixture check failed')
            require(database.digest(capture) == capture_sha256, 'The all-databases dump must remain unchanged')
            require(subprocess.check_output(['getent', 'group', 'systemd-journal'], text=True) == journal_before,
                    'The existing journal identity must remain unchanged')
            for side, (_, uid, gid) in identities.items():
                owner = (data_directories[side] / 'mysql').stat()
                require((owner.st_uid, owner.st_gid) == (uid, gid), 'Source/target file ownership changed unexpectedly')
            result = {'source_uid': 999, 'source_gid': 999, 'target_uid': mysql.pw_uid,
                      'target_gid': mysql_group.gr_gid, 'journal_gid': 999, 'journal_unchanged': True,
                      'unchanged_all_databases_dump_sha256': capture_sha256,
                      'restored_row_account_grant_and_application_login': True,
                      'original_and_target_file_ownership_preserved': True,
                      'no_replay_receipt': True, 'native_systemd_lxc_qualified': False}
            Path('/tmp/mariadb-native-identity-restore.json').write_text(json.dumps(result, indent=2) + '\n')
            print('MariaDB12.3.3 full SQL restore passed: source999:999 to package-created target, unchanged journal999/dump, restored account/grant/login and no-replay receipt')
            print(json.dumps(result))
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
