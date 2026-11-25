"""Exercise monitoring custody and ACLs without contacting PBS."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

import backup_monitoring as subject


class MonitoringProvisionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.token_file = Path(temporary.name) / 'monitoring-token'
        self.secret = '01234567-0123-0123-0123-0123456789ab'
        self.destination = {'server': '192.0.2.20', 'port': 8007, 'fingerprint': 'ab:' * 31 + 'ab'}
        self.accounts, self.grants = [], []
        self.api = Mock()
        self.api.users.side_effect = lambda: self.accounts
        self.api.request.side_effect = self.request
        self.api.permission.return_value = {'/system/status': subject.AUDIT,
            '/system/tasks': subject.AUDIT, '/datastore': subject.DATASTORE,
            '/datastore/recovery/applications': subject.DATASTORE}
        self.factory = Mock(return_value=self.api)

    def request(self, method, path, data=None):
        if method == 'GET':
            return {'data': [], 'digest': 'a' * 64}
        if method == 'PUT':
            self.grants.append(data)
            return {'data': None}
        if path == '/access/users':
            self.accounts.append({'userid': data['userid'], 'comment': data['comment']})
            return {'data': None}
        self.assertEqual(path, '/access/users/' + subject.MONITOR_USER + '/token/monitoring')
        self.accounts[0]['tokens'] = [{'tokenid': subject.MONITOR_TOKEN, 'comment': data['comment']}]
        return {'data': {'tokenid': subject.MONITOR_TOKEN, 'value': self.secret}}

    def provision(self):
        subject.provision(self.api, self.destination, self.token_file, self.factory)

    def test_create_and_repeat_keep_the_token_and_only_scoped_permissions(self):
        self.provision()
        self.assertEqual(self.token_file.read_text(), self.secret)
        self.assertEqual(self.token_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(self.grants), 6)
        for identity in (subject.MONITOR_USER, subject.MONITOR_TOKEN):
            self.assertEqual({(row['path'], row['role'], bool(row['propagate']))
                              for row in self.grants if row['auth-id'] == identity}, subject.GRANTS)
        self.factory.assert_called_once_with(self.destination, subject.MONITOR_TOKEN + ':' + self.secret)
        self.api.request.reset_mock()
        self.provision()
        self.api.request.assert_not_called()
        self.assertEqual(self.token_file.read_text(), self.secret)

    def test_existing_unowned_or_interrupted_credential_is_preserved(self):
        self.accounts.append({'userid': subject.MONITOR_USER})
        with self.assertRaisesRegex(ValueError, 'unowned'):
            self.provision()
        self.assertFalse(self.token_file.exists())
        self.accounts.clear()
        self.api.permission.return_value = {'/': {'Sys.Modify': True}}
        with self.assertRaisesRegex(ValueError, 'audit only'):
            self.provision()
        self.api.request.reset_mock()
        with self.assertRaisesRegex(ValueError, 'interrupted'):
            self.provision()
        self.api.request.assert_not_called()

    def test_management_transport_preserves_existing_monitoring_custody(self):
        self.provision()
        receipt = self.token_file.with_name(self.token_file.name + '.owner.json')
        original = receipt.read_bytes()
        token_inode = self.token_file.stat().st_ino
        admin = {**self.destination, 'server': '192.0.2.51'}
        self.api.request.reset_mock()
        self.factory.reset_mock()

        subject.provision(self.api, self.destination, self.token_file, self.factory,
                          api_destination=admin)

        self.api.request.assert_not_called()
        self.factory.assert_called_once_with(admin, subject.MONITOR_TOKEN + ':' + self.secret)
        self.assertEqual(receipt.read_bytes(), original)
        self.assertEqual(self.token_file.stat().st_ino, token_inode)
        self.assertEqual(self.token_file.read_text(), self.secret)

    def test_invalid_acl_generation_stops_before_any_grant(self):
        self.api.request.side_effect = lambda method, path, data=None: (
            {'data': [], 'digest': 'bad'} if method == 'GET' else self.request(method, path, data))
        with self.assertRaisesRegex(ValueError, 'ACL generation'):
            self.provision()
        self.assertFalse(self.grants)
