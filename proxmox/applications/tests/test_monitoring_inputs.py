"""Create-once secret identity and safe concurrent credential publication."""
from concurrent.futures import ThreadPoolExecutor
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import monitoring_inputs as inputs


class MonitoringInputsTests(unittest.TestCase):
    def test_credential_creation_reuse_concurrency_and_no_implicit_rotation(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / 'credentials'
            owner = {'node': 'fixture', 'vmid': 216, 'hostname': 'zabbix'}
            with ThreadPoolExecutor(max_workers=8) as pool:
                values = list(pool.map(lambda _: inputs.credential(root, 'server-216.json', owner, ['key']), range(16)))
            self.assertTrue(all(v == values[0] for v in values))
            path = root / 'server-216.json'
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(set(p.name for p in root.iterdir()), {'server-216.json', 'credentials.lock'})
            before = path.read_bytes()
            for bad_owner, fields in [({**owner, 'vmid': 217}, ['key']), (owner, ['other'])]:
                with self.assertRaises(ValueError):
                    inputs.credential(root, 'server-216.json', bad_owner, fields)
                self.assertEqual(path.read_bytes(), before)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                inputs.credential(root, 'server-216.json', owner, ['key'])

    def test_path_symlink_and_malformed_existing_records_refuse(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / 'credentials'
            with self.assertRaises(ValueError):
                inputs.credential(root, '../escape.json', {}, ['psk'])
            root.mkdir(mode=0o700)
            target = root / 'agent-1.json'
            target.write_text('{}');target.chmod(0o600)
            with self.assertRaises(ValueError):
                inputs.credential(root, 'agent-1.json', {}, ['psk'])
            (root / 'agent-2.json').symlink_to(target)
            with self.assertRaises(ValueError):
                inputs.credential(root, 'agent-2.json', {}, ['psk'])

    def test_absent_feature_does_not_touch_any_credential_path(self):
        with patch.object(inputs, 'private_directory') as paths:
            self.assertEqual(inputs.prepare({'app': {}}, None, Path('/unused')), {})
            paths.assert_not_called()

    def test_agent_database_and_server_share_exact_retained_keys(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td);root.chmod(0o700)
            cfg = {'site': {'node': 'fixture', 'api_endpoint': 'https://198.18.25.10:8006/'}, 'guest': {'vmid': 216, 'hostname': 'zabbix'},
                   'paths': {'state_root': str(root), 'ca_file': str(root/'ca')},
                   'app': {'kind': 'monitoring', 'monitoring': {'server_active':'198.18.25.36:10051', 'server_vmid': 216, 'profiles': ['linux', 'docker'],
                           'members': [{'vmid': 216, 'guest_hostname': 'zabbix'}], 'proxmox': {}}}}
            (root/'ca').write_text('public fixture CA')
            provider = root/'provider';provider.write_text(json.dumps({'identity': inputs.TOKEN_ID, 'token': inputs.TOKEN_ID+'=synthetic-token'}));provider.chmod(0o600)
            owner={'schema':'homelab-zabbix-access-v1','endpoint':cfg['site']['api_endpoint'],'node':'fixture','address':'198.18.25.36','backup_source':'nas:/fixture'}
            for filename,value in [('owner.json',owner),('READY.json',{'identity':inputs.TOKEN_ID,'read_only':True})]:
                path=root/filename;path.write_text(json.dumps(value));path.chmod(0o600)
            with patch.object(inputs, 'PROVIDER', provider):
                self.assertEqual(set(inputs.source_files()), {str(provider),str(root/'owner.json'),str(root/'READY.json')})
                first = inputs.prepare(cfg, {}, root/'packet')
                again = inputs.prepare(cfg, {}, root/'other-packet')
                self.assertEqual(first, again)
                server = json.loads(first['monitoring-server.json'])
                self.assertEqual(server['members'][0]['psk'], json.loads(first['monitoring-agent.json'])['psk'])
                self.assertEqual(first['database-password'], first['monitoring-storage-password'])
                self.assertNotIn('admin_password', json.loads(first['monitoring-agent.json']))
                database = copy.deepcopy(cfg)
                database['guest'] = {'vmid': 208, 'hostname': 'postgresql'}
                database['app'] = {'kind': 'postgresql', 'monitoring': {'profiles': ['linux', 'postgresql'], 'server_vmid': 216, 'server_active':'198.18.25.36:10051'}}
                pg = inputs.prepare(database, None, root/'pg')
                self.assertEqual(pg['monitoring-storage-password'], first['database-password'])
                self.assertNotIn('monitoring-server.json', pg)
                plain=copy.deepcopy(database);plain['app']['kind']='dns';plain['app']['monitoring']['profiles']=['linux']
                self.assertEqual(set(inputs.prepare(plain,None,root/'dns')),{'monitoring-agent.json'})
                (root/'HOLD.json').write_text('{}')
                with self.assertRaises(ValueError):inputs.prepare(plain,None,root/'held')
                (root/'HOLD.json').unlink()
                (root/'READY.json').write_text('{}')
                with self.assertRaises(ValueError):inputs.prepare(plain,None,root/'unready')
                (root/'READY.json').write_text(json.dumps({'identity':inputs.TOKEN_ID,'read_only':True}))
                (root/'owner.json').write_text(json.dumps(dict(owner,node='foreign')))
                with self.assertRaises(ValueError):inputs.prepare(plain,None,root/'foreign')
                (root/'owner.json').write_text(json.dumps(owner))
                provider.write_text(json.dumps({'identity': 'foreign', 'token': 'foreign=secret'}))
                with self.assertRaises(ValueError):
                    inputs.prepare(cfg, {}, root/'refuse')
