"""Native restore tests never contact a database or start a service."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import database


class DatabaseTests(unittest.TestCase):
    def test_native_engines_use_local_auth_and_no_shell(self):
        for kind, user, service in [('mariadb', 'mysql', 'mariadb'), ('postgresql', 'postgres', 'postgresql')]:
            commands, actual = database.commands({'kind': kind, 'user': user})
            self.assertEqual(actual, service)
            self.assertNotIn('sh', commands[0]); self.assertFalse(any('password' in a for a in commands[0]))

    def test_influx_requires_original_operator_credentials(self):
        with self.assertRaises(ValueError): database.commands({'kind': 'influxdb'})
        cfg = dict(kind='influxdb', source_version='2.7.12', **{key: 'synthetic' for key in ['influx_operator_token', 'influx_username', 'influx_password', 'influx_org', 'influx_bucket']})
        commands, service = database.commands(cfg)
        self.assertEqual(service, 'influxdb'); self.assertIn('--full', commands[0])
        self.assertNotIn('synthetic', str(commands))

    def test_influx_setup_uses_private_http_body_and_original_operator_token(self):
        cfg = {key: 'synthetic-' + key for key in ['influx_operator_token', 'influx_username', 'influx_password', 'influx_org', 'influx_bucket']}
        from unittest.mock import Mock
        request = Mock(side_effect=[{'allowed': True}, {}])
        database.setup_influx(cfg, request=request)
        self.assertEqual(request.call_args.args[:2], ('POST', '/api/v2/setup'))
        self.assertEqual(request.call_args.args[2]['token'], cfg['influx_operator_token'])
        self.assertEqual(request.call_args.args[2]['password'], cfg['influx_password'])
        request = Mock(return_value={'allowed': False})
        with self.assertRaises(ValueError): database.setup_influx(cfg, request=request)
        self.assertEqual(request.call_count, 1)

    def test_failed_sql_restore_is_held_without_automatic_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); capture = root / 'database.capture'; capture.write_text('-- synthetic SQL')
            cfg = {'kind': 'mariadb', 'exclusive_writer_confirmed': True, 'capture': {'sha256': database.digest(capture)}}
            import subprocess
            with patch.object(database.subprocess, 'run', side_effect=[None, subprocess.CalledProcessError(1, ['mariadb'])]):
                with self.assertRaises(subprocess.CalledProcessError): database.run(cfg, root)
            self.assertEqual(json.loads((root / 'database-restore.json').read_text())['state'], 'started')
            with patch.object(database.subprocess, 'run') as run:
                with self.assertRaises(ValueError): database.run(cfg, root)
                run.assert_not_called()

    def test_no_start_without_exclusive_writer_decision(self):
        with self.assertRaises(ValueError): database.run({'exclusive_writer_confirmed': False})

    def test_mariadb_reload_grants_before_completing_the_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / 'database.capture'
            capture.write_text('-- synthetic SQL, including mysql grant tables')
            cfg = {'kind': 'mariadb', 'exclusive_writer_confirmed': True,
                   'capture': {'sha256': database.digest(capture)}}
            with patch.object(database.subprocess, 'run') as run:
                self.assertTrue(database.run(cfg, root))
            calls = run.call_args_list
            self.assertEqual(calls[2].args[0], ['mariadb', '--protocol=socket', '--user=root', '--binary-mode'])
            self.assertEqual(calls[2].kwargs['input'], b'FLUSH PRIVILEGES;\n')
            self.assertEqual(calls[3].args[0], ['systemctl', 'enable', 'mariadb'])

    def test_mariadb_failed_grant_reload_remains_held(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / 'database.capture'
            capture.write_text('-- synthetic SQL')
            cfg = {'kind': 'mariadb', 'exclusive_writer_confirmed': True,
                   'capture': {'sha256': database.digest(capture)}}
            import subprocess
            with patch.object(database.subprocess, 'run', side_effect=[None, None, subprocess.CalledProcessError(1, ['mariadb'])]):
                with self.assertRaises(subprocess.CalledProcessError):
                    database.run(cfg, root)
            self.assertEqual(json.loads((root / 'database-restore.json').read_text())['state'], 'started')


if __name__ == '__main__':
    unittest.main()
