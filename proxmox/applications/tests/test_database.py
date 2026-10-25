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
        cfg = dict(kind='influxdb', **{key: 'synthetic' for key in ['influx_operator_token', 'influx_username', 'influx_password', 'influx_org', 'influx_bucket']})
        commands, service = database.commands(cfg)
        self.assertEqual(service, 'influxdb'); self.assertIn('--full', commands[1])
        self.assertNotIn('synthetic', str(commands))

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


if __name__ == '__main__':
    unittest.main()
