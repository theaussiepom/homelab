"""New monitoring authority must remain read-only and failed mints must hold."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import monitoring_access as access


class MonitoringAccessTests(unittest.TestCase):
    def test_success_retains_only_the_validated_credential_and_invalid_mint_keeps_evidence(self):
        config = {'schema': 'homelab-zabbix-access-v1', 'endpoint': 'https://10.88.25.10:8006/',
                  'node': 'practice-pve', 'address': '10.88.30.50', 'backup_source': 'nas.invalid:/fixture'}
        before = {'users': [], 'roles': [], 'tokens': [], 'acl': [], 'rules': [], 'options': {}}
        for valid in (True, False):
            with self.subTest(valid=valid), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); state = root / 'state'; nas = root / 'nas'
                state.mkdir(mode=0o700); nas.mkdir(mode=0o700)
                api = Mock()
                def call(path, method='GET', values=None):
                    return {'data': {'full-tokenid': access.IDENTITY if valid else 'unexpected@pve!identity',
                                     'value': 'synthetic-fixture-key'}} if '/token/' in path else {'data': None}
                api.call.side_effect = call
                with patch.object(access, 'check_backup'), patch.object(access, 'inspect', return_value=before), patch.object(access, 'verify', return_value={'options': {}}):
                    if valid:
                        access.initialize(api, config, state, nas)
                    else:
                        with self.assertRaises(ValueError): access.initialize(api, config, state, nas)
                for directory in (state, nas):
                    self.assertEqual((directory / 'monitoring-access/minted-response.json').exists(), not valid)
                    self.assertEqual((directory / 'monitoring-access/token.json').exists(), valid)
                    self.assertEqual((directory / 'monitoring-access/HOLD.json').exists(), not valid)

    def test_unreviewed_peer_firewall_changes_remain_drift_holds(self):
        config = {'schema': 'homelab-zabbix-access-v1', 'endpoint': 'https://10.88.25.10:8006/',
                  'node': 'practice-pve', 'address': '10.88.30.50', 'backup_source': 'nas.invalid:/fixture'}
        after = {'users': [{'userid': access.USER, 'enable': 1}],
                 'roles': [{'roleid': access.ROLE, 'privs': ','.join(access.PRIVILEGES)}],
                 'tokens': [{'tokenid': access.TOKEN, 'privsep': 1, 'expire': 0}],
                 'acl': [{'type': kind, 'ugid': identity, 'path': '/', 'roleid': access.ROLE, 'propagate': 1}
                         for kind, identity in [('user', access.USER), ('token', access.IDENTITY)]],
                 'rules': [{'comment': 'Unreviewed peer rule'}, access.rule(config)], 'options': {}}
        api = Mock()
        with patch.object(access, 'inspect', return_value=after):
            with self.assertRaisesRegex(ValueError, 'firewall readback differs'):
                access.verify(api, config, {'token': 'unused'}, [])
        api.call.assert_not_called()

    def test_failure_before_token_return_is_held_locally_and_on_nas(self):
        config = {'schema': 'homelab-zabbix-access-v1', 'endpoint': 'https://198.18.25.10:8006/',
                  'node': 'practice-pve', 'address': '10.88.30.50', 'backup_source': 'nas.invalid:/fixture'}
        before = {'users': [], 'roles': [], 'tokens': [], 'acl': [], 'rules': [], 'options': {}}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); state = root / 'state'; nas = root / 'nas'
            state.mkdir(mode=0o700); nas.mkdir(mode=0o700)
            api = Mock()
            def call(path, method='GET', values=None):
                if '/token/' in path: raise OSError('synthetic interrupted mint')
                return {'data': None}
            api.call.side_effect = call
            with patch.object(access, 'check_backup'), patch.object(access, 'inspect', return_value=before):
                with self.assertRaises(OSError): access.initialize(api, config, state, nas)
                for directory in (state, nas):
                    self.assertTrue((directory / 'monitoring-access/HOLD.json').is_file())
                    self.assertFalse((directory / 'monitoring-access/READY.json').exists())
                role = next(call for call in api.call.call_args_list if call.args[0] == '/access/roles')
                self.assertEqual(set(role.args[2]['privs'].split(',')), {'Sys.Audit', 'VM.Audit', 'Datastore.Audit'})
                api.reset_mock()
                with self.assertRaisesRegex(ValueError, 'held'): access.initialize(api, config, state, nas)
                api.call.assert_not_called()

    def test_existing_identity_is_never_adopted(self):
        config = {'schema': 'homelab-zabbix-access-v1', 'endpoint': 'https://198.18.25.10:8006/',
                  'node': 'practice-pve', 'address': '10.88.30.50', 'backup_source': 'nas.invalid:/fixture'}
        before = {'users': [{'userid': access.USER}], 'roles': [], 'tokens': [], 'acl': [], 'rules': [], 'options': {}}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); nas = root / 'nas'; nas.mkdir(mode=0o700)
            api = Mock()
            with patch.object(access, 'check_backup'), patch.object(access, 'inspect', return_value=before):
                with self.assertRaisesRegex(ValueError, 'no adoption'): access.initialize(api, config, root, nas)
            api.call.assert_not_called()
