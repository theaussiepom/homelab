"""Failure notification input isolation and bounded request tests."""
import json
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backup_notify


VALUE = {'host': 'ha.example.test', 'address': '192.0.2.8', 'webhook_id': 'f'*32}
FAILURE = {'stage': 'verify-readback', 'error_type': 'ValueError', 'reason': 'private failure reason'}


class NotificationTests(unittest.TestCase):
    def test_optional_webhook_is_published_privately_and_sent_without_a_secret_in_argv(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp)/'state'; state.mkdir(mode=0o700)
            schedules = state/'schedules'; schedules.mkdir(mode=0o700)
            schedule = schedules/'homelab-backup-example.json'
            execute = Mock()
            self.assertEqual(backup_notify.send(schedule, FAILURE, execute=execute), 'not-configured')
            execute.assert_not_called()
            path = schedule.with_suffix('.webhook')
            for _ in range(2):
                backup_notify.install(path, json.dumps(VALUE))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaisesRegex(ValueError, 'Rotate'):
                backup_notify.install(path, json.dumps({**VALUE, 'webhook_id': 'd'*32}))
            for status, code, expected in [('200', 0, 'submitted'), ('403', 0, 'failed'), ('200', 7, 'failed')]:
                with self.subTest(status=status, code=code):
                    execute.return_value = SimpleNamespace(stdout=status, returncode=code)
                    self.assertEqual(backup_notify.send(schedule, FAILURE, execute=execute), expected)
                    argv = execute.call_args.args[0]
                    self.assertIn('ha.example.test:443:192.0.2.8', argv)
                    self.assertNotIn(VALUE['webhook_id'], ' '.join(argv))
                    config = execute.call_args.kwargs['input']
                    self.assertNotIn(FAILURE['reason'], config)
                    event = json.loads(json.loads(config.splitlines()[1].split(' = ', 1)[1]))
                    self.assertEqual(event, {'event': 'homelab.backup.failed', 'group': 'example',
                        'stage': 'verify-readback', 'error_type': 'ValueError', 'event_id': event['event_id']})
                    self.assertRegex(event['event_id'], '^[0-9a-f]{32}$')

    def test_webhook_target_rejects_unexpected_shapes(self):
        for value in ([], {}, {**VALUE, 'host': 'http://ha.example.test'},
                      {**VALUE, 'host': 'ha..example.test'}, {**VALUE, 'host': None},
                      {**VALUE, 'address': None}, {**VALUE, 'address': '127.1'},
                      {**VALUE, 'webhook_id': None}, {**VALUE, 'webhook_id': 'bad'}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                backup_notify.configuration(json.dumps(value))
