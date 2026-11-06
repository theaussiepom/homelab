"""Owned-only CD appends one real mirrored scope receipt, never a host plan."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bootstrap_cd as cd
import provider_access as discovery
from test_bootstrap_cd import config
from test_provider_access import ProviderAPI


class ScopeAPI(ProviderAPI):
    def __init__(self):
        super().__init__()
        self.reads = []
        self.identity = {'hostname': 'fixture-mqtt'}
        self.identity_reads = 0
        self.change_identity = False

    def call(self, path, method='GET', values=None):
        if method == 'GET':
            self.reads.append(path)
        if path == '/nodes/pve/lxc/12015/config':
            self.identity_reads += 1
            if self.change_identity and self.identity_reads > 1:
                return {'data': {'hostname': 'foreign-mqtt'}}
            return {'data': copy.deepcopy(self.identity)}
        return super().call(path, method, values)


class OwnedScopeTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root, self.nas = Path(tmp.name)/'state', Path(tmp.name)/'nas'
        self.root.mkdir(mode=0o700); self.nas.mkdir(mode=0o700)
        self.api = ScopeAPI()
        base = config()
        base['endpoint'] = 'https://198.19.125.11:8006/'
        base['applications'] = [{'vmid': value} for value in (12002, 12011, 12012)]
        base['service_discovery'] = {'vmid': 12012, 'address': '198.19.125.43',
                                     'guests': [12002, 12011, 12012]}
        before = discovery.inspect(self.api, base, self.root, self.nas)
        discovery.reconcile(self.api, base, before, self.root, self.nas)
        self.value = {'schema': 'homelab-owned-discovery-extension-v1',
            **{key: copy.deepcopy(base[key]) for key in ('endpoint', 'node', 'backup_source', 'service_discovery')},
            'application_vmids': [12002, 12011, 12012, 12015],
            'service_discovery_extension': {'owner_sha256': discovery.owner_sha256(discovery.owner(base)),
                                             'guests': [12015]},
            'added_guests': [{'node': 'pve', 'vmid': 12015, 'hostname': 'fixture-mqtt', 'type': 'lxc'}]}
        self.value['service_discovery']['guests'].append(12015)
        self.api.writes.clear(); self.api.reads.clear()

    def run_scope(self):
        mount = {'filesystems': [{'target': str(self.nas), 'source': self.value['backup_source'], 'fstype': 'nfs4'}]}
        with patch.object(cd.subprocess, 'check_output', return_value=json.dumps(mount).encode()), \
                patch.object(cd, 'run', side_effect=AssertionError('Full host CD must remain unreachable')):
            return cd.run_owned_discovery_extension(self.value, self.api, self.root, self.nas)

    def test_actual_json_writer_mirrors_plan_result_and_one_acl_then_repeat_is_read_only(self):
        originals = {path.name: path.read_bytes() for path in (self.root/'service-discovery').iterdir()}
        rules, network = copy.deepcopy(self.api.rules), copy.deepcopy(self.api.network)
        result = self.run_scope()
        self.assertEqual(result['new_acl_rows'], 1)
        self.assertFalse(result['created']); self.assertFalse(result['firewall_rule_created'])
        self.assertEqual(self.api.writes, [('/access/acl', 'PUT', {'path': '/vms/12015',
            'roles': 'HomelabTraefikRead12012', 'tokens': 'root@pam!homelab-traefik-12012', 'propagate': 0})])
        self.assertEqual((self.api.rules, self.api.network), (rules, network))
        for name, raw in originals.items():
            self.assertEqual((self.root/'service-discovery'/name).read_bytes(), raw)
        attempt, = self.root.glob('discovery-cd-*')
        for name in ('plan.json', 'result.json'):
            self.assertEqual(discovery.read_private(attempt/name), discovery.read_private(self.nas/attempt.name/name))
            self.assertIsInstance(json.loads(discovery.read_private(attempt/name)), dict)
        self.assertFalse((self.root/'CONFIGURING').exists()); self.assertFalse((self.root/'BOOTSTRAP-CD-HOLD.json').exists())
        writes = copy.deepcopy(self.api.writes)
        self.assertTrue(self.run_scope()['already_owned'])
        self.assertEqual(self.api.writes, writes)
        self.assertEqual(len(list(self.root.glob('discovery-cd-*'))), 1)
        self.assertNotIn('/cluster/resources?type=vm', self.api.reads)
        self.assertFalse(any(path.endswith('/network') for path in self.api.reads))

    def test_actual_json_writer_preserves_failure_hold_and_never_replays(self):
        self.api.fail_provider_acl = True
        with self.assertRaisesRegex(ValueError, 'ACL failure'):
            self.run_scope()
        attempt, = self.root.glob('discovery-cd-*')
        failure = json.loads(discovery.read_private(attempt/'failure.json'))
        self.assertEqual(failure, {'status': 'held', 'error_type': 'ProviderAccessError', 'automatic_retry': False})
        self.assertEqual(discovery.read_private(attempt/'failure.json'),
                         discovery.read_private(self.nas/attempt.name/'failure.json'))
        self.assertEqual(discovery.read_private(self.root/'CONFIGURING'), discovery.read_private(self.root/'BOOTSTRAP-CD-HOLD.json'))
        writes = copy.deepcopy(self.api.writes)
        with self.assertRaisesRegex(ValueError, 'hold'):
            self.run_scope()
        self.assertEqual(self.api.writes, writes)

    def test_existing_disjoint_source_rule_keeps_position_and_bytes_during_extension(self):
        self.api.rules.insert(0, {'type':'in','action':'ACCEPT','enable':1,'source':'198.19.126.0/24',
                                  'comment':'Unrelated synthetic clients'})
        before=copy.deepcopy(self.api.rules)
        self.assertEqual(self.run_scope()['new_acl_rows'],1)
        self.assertEqual(self.api.rules,before)
        self.assertTrue(all(path=='/access/acl'for path,_,_ in self.api.writes))

    def test_earlier_overlapping_unknown_or_compound_rule_refuses_without_writes(self):
        for source in ('198.19.125.43','198.19.125.0/24','0.0.0.0/0','!198.19.126.0/24',
                       '198.19.126.0/24,198.19.127.0/24','+alias',None,'invalid','2001:db8::/32'):
            row={'type':'in','action':'ACCEPT','source':source,'enable':1}
            self.api.rules.insert(0,row)
            with self.subTest(source=source),self.assertRaises(ValueError):self.run_scope()
            self.assertEqual(self.api.writes,[]);self.api.rules.pop(0)
        for row in (None,{'type':'group','action':'ACCEPT','source':'198.19.126.0/24'},
                    {'type':'in','action':[],'source':'198.19.126.0/24'}):
            self.assertFalse(discovery.preceding_rules_irrelevant([row],'198.19.125.43'))
        self.assertTrue(discovery.preceding_rules_irrelevant([
            {'type':'in','action':'DROP','source':'198.19.125.42/32'}],'198.19.125.43'))

    def test_added_native_identity_refusal_is_before_any_grant(self):
        for actual in ({'hostname': 'foreign'}, {}, [], None):
            with self.subTest(actual=actual):
                self.api.identity = actual
                with self.assertRaisesRegex(ValueError, 'native identity'):
                    self.run_scope()
                self.assertEqual(self.api.writes, [])
                self.assertFalse(list(self.root.glob('discovery-cd-*')))

    def test_identity_drift_after_plan_stays_held_without_grant(self):
        self.api.change_identity = True
        with self.assertRaisesRegex(ValueError, 'native identity'):
            self.run_scope()
        self.assertEqual(self.api.writes, [])
        self.assertTrue((self.root/'BOOTSTRAP-CD-HOLD.json').is_file())

    def test_never_mints_or_adopts_unowned_or_partial_custody(self):
        for folder in (self.root/'service-discovery', self.nas/'service-discovery'):
            for path in folder.iterdir(): path.unlink()
            folder.rmdir()
        self.api.roles.clear(); self.api.tokens.clear()
        self.api.acls = [row for row in self.api.acls if row['ugid'] != 'root@pam!homelab-traefik-12012']
        self.api.rules = self.api.rules[1:]
        with self.assertRaisesRegex(ValueError, 'existing owned'):
            self.run_scope()
        self.assertEqual(self.api.writes, [])

    def test_exact_completed_operation_cannot_be_claimed_by_foreign_packet(self):
        self.run_scope(); self.api.writes.clear()
        self.value['service_discovery_extension']['owner_sha256'] = '0'*64
        with self.assertRaises(ValueError): self.run_scope()
        self.assertEqual(self.api.writes, [])

    def test_closed_input_types_and_added_identity_order(self):
        changes = [('', {}), ('schema', 'foreign'), ('endpoint', 'http://198.18.0.1:8006/'),
            ('endpoint', 'https://198.18.0.1:bad/'), ('endpoint', 'https://198.18.0.1:8006/?'),
            ('node', []), ('backup_source', 'bad\nsource'), ('application_vmids', [True]),
            ('application_vmids', [12012, 12012]), ('added_guests', []),
            ('added_guests', [{'node': 'pve', 'vmid': 12015, 'hostname': 'fixture-mqtt', 'type': 'other'}]),
            ('added_guests', [{'node': 'pve', 'vmid': 12011, 'hostname': 'fixture-identity', 'type': 'lxc'}])]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                data = copy.deepcopy(self.value)
                if key: data[key] = value
                else: data['unrelated_host_plan'] = value
                with self.assertRaises(ValueError): cd.owned_scope_configuration(data)

    def test_qemu_identity_uses_native_name(self):
        value = {'added_guests': [{'node': 'fixture', 'vmid': 12100, 'type': 'qemu', 'hostname': 'fixture-vm'}]}
        class VMAPI:
            def call(self, path):
                if path != '/nodes/fixture/qemu/12100/config': raise AssertionError(path)
                return {'data': {'name': 'fixture-vm'}}
        self.assertEqual(cd.added_discovery_identities(VMAPI(), value), value['added_guests'])

    def test_cli_uses_only_owned_entrypoint(self):
        path = self.root/'input.json'; path.write_text(json.dumps(self.value))
        with patch.object(sys, 'argv', ['bootstrap_cd', '--config', str(path), '--owned-discovery-extension']), \
                patch.dict(cd.os.environ, {'PROXMOX_BOOTSTRAP_TOKEN': 'synthetic'}), \
                patch.object(cd, 'API') as api, patch.object(cd, 'run_owned_discovery_extension', return_value={'status':'ready'}) as owned, \
                patch.object(cd, 'run', side_effect=AssertionError('full host')), contextlib.redirect_stdout(io.StringIO()) as output:
            cd.main()
        owned.assert_called_once_with(self.value, api.return_value)
        self.assertEqual(json.loads(output.getvalue()), {'status':'ready'})


if __name__ == '__main__':
    unittest.main()
