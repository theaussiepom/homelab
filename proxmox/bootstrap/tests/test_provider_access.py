"""Discovery access is finite, retained privately, and never silently repaired."""
import contextlib
import copy
import io
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bootstrap_cd as cd
import provider_access as discovery
from test_bootstrap_cd import FakeAPI, config

SECRET = 'synthetic-discovery-secret'


class ProviderAPI(FakeAPI):
    def __init__(self):
        super().__init__()
        self.roles, self.tokens = [], []
        self.rules = [{'type': 'in', 'action': 'DROP', 'enable': 1, 'comment': 'Existing final deny'}]
        self.options = {'enable': 1, 'policy_in': 'DROP', 'policy_out': 'ACCEPT'}
        self.fail_provider_acl = False
        self.lose_rule = False
        self.fail_token_response = False
        self.string_mint_metadata = False
        self.secret_was_saved = None
        self.extra_permission = False
        self.valid_secret = 'root@pam!homelab-traefik-212=' + SECRET

    def discovery(self, token):
        fixture = self
        class Reader:
            def call(self, path, method='GET', values=None):
                if token != fixture.valid_secret:
                    raise discovery.ProviderAccessError('Discovery authentication failed')
                if path != '/access/permissions' or method != 'GET' or values is not None:
                    raise AssertionError((path, method, values))
                permissions = {r['path']: {'Sys.Audit': 0, 'VM.Audit': 0} for r in fixture.acls
                               if r['ugid'] == 'root@pam!homelab-traefik-212'}
                if fixture.extra_permission:
                    permissions['/'] = {'VM.PowerMgmt': 1}
                return {'data': permissions}
        return Reader()

    def call(self, path, method='GET', values=None):
        provider_write = (method != 'GET' and (path == '/access/roles' or '/token/homelab-traefik-' in path
                         or '/firewall/' in path or values.get('tokens', '').startswith('root@pam!homelab-traefik-')))
        if provider_write:
            self.writes.append((path, method, copy.deepcopy(values)))
            if path == '/access/roles':
                self.roles.append({'roleid': values['roleid'], 'privs': values['privs'], 'special': 0})
            elif '/token/homelab-traefik-' in path:
                self.tokens.append({'tokenid': 'homelab-traefik-212', **values})
                if self.fail_token_response:
                    raise discovery.ProviderAccessError('Synthetic lost token response')
                info = {k:str(v) if type(v) is int else v for k,v in values.items()} if self.string_mint_metadata else values
                return {'data': {'full-tokenid': 'root@pam!homelab-traefik-212', 'value': SECRET, 'info': info}}
            elif path == '/access/acl':
                if self.secret_was_saved:
                    self.secret_was_saved()
                if self.fail_provider_acl:
                    raise discovery.ProviderAccessError('Synthetic discovery ACL failure')
                self.acls.append({'path': values['path'], 'roleid': values['roles'], 'propagate': values['propagate'],
                                  'ugid': values['tokens'], 'type': 'token'})
            elif path.endswith('/rules'):
                self.rules.insert(0, copy.deepcopy(values))
                if self.lose_rule:
                    self.rules.pop()
            else:
                raise AssertionError((path, method))
            return {'data': None}
        if path == '/access/roles':
            return {'data': copy.deepcopy(self.roles)}
        if path == '/access/users/root@pam/token':
            return {'data': copy.deepcopy(self.tokens)}
        if path.endswith('/firewall/rules'):
            return {'data': [dict(row, pos=i, digest='synthetic') for i, row in enumerate(self.rules)]}
        if path.endswith('/firewall/options'):
            return {'data': dict(self.options, digest='synthetic')}
        if path.startswith('/access/permissions?'):
            return {'data': {r['path']: {'VM.Allocate' if r['roleid'] == 'PVEVMAdmin' else 'SDN.Use': 0}
                             for r in self.acls if r['ugid'] == 'root@pam!homelab-deploy-900'}}
        return super().call(path, method, values)


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'state'; self.root.mkdir()
        self.nas = Path(self.tmp.name) / 'nas'; self.nas.mkdir()
        self.c = config()
        self.c['applications'] += [{'vmid': 212, 'hostname': 'traefik'}, {'vmid': 211, 'hostname': 'security'},
                                   {'vmid': 202, 'hostname': 'db-tools'}]
        self.c['service_discovery'] = {'vmid': 212, 'address': '10.77.25.33', 'guests': [202, 211, 212]}
        self.c['endpoint'] = 'https://10.77.25.10:8006/'
        self.api = ProviderAPI()

    def run_cd(self):
        mount = {'filesystems': [{'target': str(self.nas), 'source': self.c['backup_source'], 'fstype': 'nfs4'}]}
        with patch.object(cd.subprocess, 'check_output', return_value=json.dumps(mount).encode()):
            return cd.run(self.c, self.api, self.root, self.nas)

    def test_create_has_only_read_grants_and_exact_firewall_then_repeat_has_no_writes(self):
        old_rules, old_options = copy.deepcopy(self.api.rules), copy.deepcopy(self.api.options)
        result = self.run_cd()['service_discovery']
        self.assertTrue(result['created'])
        self.assertEqual(self.api.roles, [{'roleid': 'HomelabTraefikRead212', 'privs': 'Sys.Audit,VM.Audit', 'special': 0}])
        grants = [r for r in self.api.acls if r['ugid'] == 'root@pam!homelab-traefik-212']
        self.assertEqual({r['path'] for r in grants}, {'/nodes/pve', '/vms/202', '/vms/211', '/vms/212'})
        self.assertTrue(all(r['propagate'] == 0 for r in grants))
        rule = self.api.rules[0]
        self.assertEqual((rule['source'], rule['dest'], rule['dport'], rule['proto']),
                         ('10.77.25.33/32', '10.77.25.10/32', '8006', 'tcp'))
        self.assertEqual(self.api.rules[1:], old_rules)
        self.assertEqual(self.api.options, old_options)
        writes = copy.deepcopy(self.api.writes)
        self.assertFalse(self.run_cd()['service_discovery']['created'])
        self.assertEqual(self.api.writes, writes)

    def test_native_mint_metadata_may_be_decimal_strings_without_changing_scope(self):
        self.api.string_mint_metadata = True
        self.assertTrue(self.run_cd()['service_discovery']['created'])
        self.assertEqual(len(self.api.tokens), 1)
        self.assertFalse(self.run_cd()['service_discovery']['created'])

    def failed_mint_packet(self):
        self.api.string_mint_metadata = True
        with patch.object(discovery, 'validate_minted', side_effect=discovery.ProviderAccessError(
                'Created discovery token response differs; preserve its private partial receipt')):
            with self.assertRaisesRegex(ValueError, 'Created discovery token response'):
                self.run_cd()
        attempt = json.loads((self.root / 'BOOTSTRAP-CD-HOLD.json').read_text())['attempt']
        return {'attempt':attempt, 'plan_sha256':hashlib.sha256((self.root / attempt / 'plan.json').read_bytes()).hexdigest(),
                'minted_sha256':hashlib.sha256((self.root / 'service-discovery/minted-response.json').read_bytes()).hexdigest()}

    def continue_cd(self, packet):
        mount = {'filesystems': [{'target':str(self.nas), 'source':self.c['backup_source'], 'fstype':'nfs4'}]}
        with patch.object(cd.subprocess, 'check_output', return_value=json.dumps(mount).encode()):
            return cd.run(self.c, self.api, self.root, self.nas, resume=packet)

    def test_exact_continuation_reuses_token_and_archives_matching_hold(self):
        packet = self.failed_mint_packet()
        original_failure = (self.root / packet['attempt'] / 'failure.json').read_bytes()
        writes = len(self.api.writes)
        with self.assertRaisesRegex(ValueError, 'hold'): self.run_cd()
        result = self.continue_cd(packet)
        self.assertTrue(result['service_discovery']['resumed'])
        self.assertFalse(result['service_discovery']['created'])
        self.assertEqual(len(self.api.writes)-writes, 5)  # Four exact ACL rows and one API rule.
        self.assertEqual(len(self.api.tokens), 1)
        self.assertEqual(len(self.api.roles), 1)
        self.assertEqual((self.root / packet['attempt'] / 'failure.json').read_bytes(), original_failure)
        self.assertTrue((self.root / packet['attempt'] / 'CONFIGURING.original').exists())
        self.assertTrue((self.root / packet['attempt'] / 'BOOTSTRAP-CD-HOLD.json.original').exists())
        self.assertFalse((self.root / 'CONFIGURING').exists())
        self.assertFalse((self.root / 'BOOTSTRAP-CD-HOLD.json').exists())
        self.assertEqual((self.root / packet['attempt'] / 'continuation-result.json').read_bytes(),
                         (self.nas / packet['attempt'] / 'continuation-result.json').read_bytes())
        writes = copy.deepcopy(self.api.writes)
        with self.assertRaisesRegex(ValueError, 'hold'): self.continue_cd(packet)
        self.run_cd()  # Completed setup uses ordinary unchanged verification, never the resume flag.
        self.assertEqual(self.api.writes, writes)
        self.assertNotIn(SECRET, json.dumps(result))

    def test_resume_never_falls_through_without_both_failed_markers(self):
        packet = {'attempt':'cd-1', 'plan_sha256':'0'*64, 'minted_sha256':'0'*64}
        with self.assertRaisesRegex(ValueError, 'hold'): self.continue_cd(packet)
        self.assertEqual(self.api.writes, [])
        for missing in ('BOOTSTRAP-CD-HOLD.json', 'CONFIGURING'):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as directory:
                self.root = Path(directory)/'state'; self.root.mkdir()
                self.nas = Path(directory)/'nas'; self.nas.mkdir()
                self.api = ProviderAPI(); packet = self.failed_mint_packet()
                (self.root/missing).unlink()
                writes = copy.deepcopy(self.api.writes)
                with self.assertRaisesRegex(ValueError, 'hold'): self.continue_cd(packet)
                self.assertEqual(self.api.writes, writes)

    def test_marker_archive_error_restores_both_holds_and_records_completed_native_phase(self):
        packet = self.failed_mint_packet()
        rename = Path.rename
        def second_marker_fails(path, destination):
            if path.name == 'CONFIGURING': raise OSError('synthetic marker archive failure')
            return rename(path, destination)
        with patch.object(Path, 'rename', second_marker_fails), self.assertRaisesRegex(OSError, 'marker archive'):
            self.continue_cd(packet)
        self.assertTrue((self.root/'BOOTSTRAP-CD-HOLD.json').exists())
        self.assertTrue((self.root/'CONFIGURING').exists())
        failure = json.loads((self.root/packet['attempt']/'continuation-failure.json').read_text())
        self.assertEqual(failure['status'], 'completion-held')
        self.assertEqual(failure['native_outcome'], 'completed')
        self.assertEqual(failure['phase'], 'marker-archival')
        writes = copy.deepcopy(self.api.writes)
        with self.assertRaisesRegex(ValueError, 'already consumed'): self.continue_cd(packet)
        self.assertEqual(self.api.writes, writes)

    def test_failed_continuation_is_consumed_and_cannot_be_replayed(self):
        packet = self.failed_mint_packet()
        self.api.fail_provider_acl = True
        with self.assertRaisesRegex(ValueError, 'ACL failure'): self.continue_cd(packet)
        writes = copy.deepcopy(self.api.writes)
        self.assertTrue((self.root / 'BOOTSTRAP-CD-HOLD.json').exists())
        self.assertTrue((self.nas / packet['attempt'] / 'continuation-failure.json').exists())
        with self.assertRaisesRegex(ValueError, 'already consumed'): self.continue_cd(packet)
        self.assertEqual(self.api.writes, writes)

    def test_failed_admission_consumes_the_approved_continuation(self):
        packet = self.failed_mint_packet()
        self.api.rules[0]['action'] = 'ACCEPT'
        writes = copy.deepcopy(self.api.writes)
        with self.assertRaises(ValueError): self.continue_cd(packet)
        self.api.rules[0]['action'] = 'DROP'
        with self.assertRaisesRegex(ValueError, 'already consumed'): self.continue_cd(packet)
        self.assertEqual(self.api.writes, writes)

    def test_missing_nas_consumes_claim_without_writing_unmounted_backup_path(self):
        packet = self.failed_mint_packet()
        with patch.object(cd.subprocess, 'check_output', return_value=b'{"filesystems":[]}'):
            with self.assertRaisesRegex(ValueError, 'mounted filesystem'):
                cd.run(self.c, self.api, self.root, self.nas, resume=packet)
        self.assertTrue((self.root/packet['attempt']/'continuation-failure.json').exists())
        self.assertFalse((self.nas/packet['attempt']/'continuation-failure.json').exists())
        with self.assertRaisesRegex(ValueError, 'already consumed'): self.continue_cd(packet)

    def test_continuation_rejects_drift_before_any_write(self):
        for drift in ('plan_hash', 'response_hash', 'nas_response', 'owner', 'config', 'marker',
                      'role', 'token_expiry', 'secret', 'effective_permission', 'extra_acl', 'firewall', 'host_network', 'partial_token'):
            with self.subTest(drift=drift), tempfile.TemporaryDirectory() as directory:
                self.root = Path(directory)/'state'; self.root.mkdir()
                self.nas = Path(directory)/'nas'; self.nas.mkdir()
                self.api = ProviderAPI()
                packet = self.failed_mint_packet()
                if drift == 'plan_hash': packet['plan_sha256'] = '0'*64
                elif drift == 'response_hash': packet['minted_sha256'] = '0'*64
                elif drift == 'nas_response': (self.nas/'service-discovery/minted-response.json').write_text('{}')
                elif drift == 'owner': (self.root/'service-discovery/owner.json').write_text('{}')
                elif drift == 'config': self.c['node'] = 'other-node'
                elif drift == 'marker': (self.root/'CONFIGURING').write_text('{}')
                elif drift == 'role': self.api.roles[0]['privs'] += ',VM.PowerMgmt'
                elif drift == 'token_expiry': self.api.tokens[0]['expire'] = 123
                elif drift == 'secret': self.api.valid_secret += '-changed'
                elif drift == 'effective_permission': self.api.extra_permission = True
                elif drift == 'extra_acl': self.api.acls.append({'path':'/', 'roleid':'HomelabTraefikRead212',
                    'propagate':1, 'type':'token', 'ugid':'root@pam!other'})
                elif drift == 'firewall': self.api.rules[0]['action'] = 'ACCEPT'
                elif drift == 'host_network': self.api.network[0]['bridge_ports'] = 'different0'
                elif drift == 'partial_token': (self.root/'service-discovery/token.json').write_text('{}')
                writes = copy.deepcopy(self.api.writes)
                with self.assertRaises(ValueError): self.continue_cd(packet)
                self.assertEqual(self.api.writes, writes)
                if drift == 'config': self.c['node'] = 'pve'

    def test_mint_numeric_metadata_is_exact_not_coerced(self):
        base = {'full-tokenid':'root@pam!homelab-traefik-212', 'value':SECRET, 'info':{'privsep':1,'expire':0}}
        for key, value in (('privsep', True), ('privsep', 1.0), ('privsep','01'), ('privsep','0'),
                           ('expire',False), ('expire',0.0), ('expire','00'), ('expire',None)):
            minted = copy.deepcopy(base); minted['info'][key] = value
            with self.subTest(key=key,value=value), self.assertRaises(ValueError):
                discovery.validate_minted(self.c, minted)

    def test_secret_is_saved_locally_and_on_nas_before_any_acl_grant(self):
        checks = []
        def saved():
            local = self.root / 'service-discovery' / 'token.json'
            remote = self.nas / 'service-discovery' / 'token.json'
            self.assertEqual(local.read_bytes(), remote.read_bytes())
            self.assertEqual(local.stat().st_mode & 0o777, 0o600)
            self.assertEqual(remote.stat().st_mode & 0o777, 0o600)
            self.assertEqual(local.parent.stat().st_mode & 0o777, 0o700)
            self.assertIn(SECRET, local.read_text())
            checks.append(True)
        self.api.secret_was_saved = saved
        self.run_cd()
        self.assertEqual(len(checks), 4)

    def test_results_plans_failure_and_stdout_never_contain_secret(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = self.run_cd()
        self.assertNotIn(SECRET, json.dumps(result) + output.getvalue())
        for folder in (self.root, self.nas):
            for receipt in folder.glob('cd-*/*.json'):
                self.assertNotIn(SECRET, receipt.read_text())

    def test_existing_unknown_token_role_or_owned_firewall_rule_never_adopted(self):
        for kind in ('token', 'role', 'rule'):
            self.api = ProviderAPI()
            if kind == 'token': self.api.tokens.append({'tokenid': 'homelab-traefik-212'})
            if kind == 'role': self.api.roles.append({'roleid': 'HomelabTraefikRead212', 'privs': 'Sys.Audit,VM.Audit'})
            if kind == 'rule': self.api.rules.insert(0, discovery.allowance(self.c))
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'no adoption'):
                self.run_cd()
            self.assertEqual(self.api.writes, [])

    def test_unmanaged_equivalent_rule_is_a_conflict(self):
        self.api.rules.insert(0, dict(discovery.allowance(self.c), comment='Other owner'))
        with self.assertRaisesRegex(ValueError, 'unmanaged'):
            self.run_cd()
        self.assertEqual(self.api.writes, [])

    def test_partial_grant_failure_keeps_secret_and_hold_without_replay(self):
        self.api.fail_provider_acl = True
        with self.assertRaisesRegex(ValueError, 'ACL failure'):
            self.run_cd()
        self.assertTrue((self.root / 'service-discovery/token.json').exists())
        self.assertTrue((self.nas / 'service-discovery/token.json').exists())
        self.assertTrue((self.root / 'BOOTSTRAP-CD-HOLD.json').exists())
        writes = copy.deepcopy(self.api.writes)
        with self.assertRaisesRegex(ValueError, 'hold'):
            self.run_cd()
        self.assertEqual(self.api.writes, writes)

    def test_lost_mint_response_leaves_hold_and_never_rotates_token(self):
        self.api.fail_token_response = True
        with self.assertRaisesRegex(ValueError, 'lost token'):
            self.run_cd()
        self.assertTrue(self.api.tokens)
        self.assertFalse((self.root / 'service-discovery/token.json').exists())
        writes = copy.deepcopy(self.api.writes)
        with self.assertRaisesRegex(ValueError, 'hold'):
            self.run_cd()
        self.assertEqual(self.api.writes, writes)

    def test_scope_role_lifetime_secret_and_firewall_drift_stop_without_writes(self):
        for kind in ('acl', 'role', 'expire', 'secret', 'firewall'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                self.root = Path(tmp) / 'root'; self.root.mkdir()
                self.nas = Path(tmp) / 'nas'; self.nas.mkdir()
                self.api = ProviderAPI(); self.run_cd()
                if kind == 'acl': self.api.acls[-1]['propagate'] = 1
                if kind == 'role': self.api.roles[0]['privs'] += ',VM.PowerMgmt'
                if kind == 'expire': self.api.tokens[0]['expire'] = 1234
                if kind == 'secret': self.api.valid_secret += '-rotated'
                if kind == 'firewall': self.api.rules[0]['source'] = '10.77.25.0/24'
                self.api.writes.clear()
                with self.assertRaises(ValueError): self.run_cd()
                self.assertEqual(self.api.writes, [])

    def test_changed_declared_scope_is_not_silently_expanded(self):
        self.run_cd()
        self.c['service_discovery']['guests'].append(208)
        self.api.writes.clear()
        with self.assertRaisesRegex(ValueError, 'configuration changed'):
            self.run_cd()
        self.assertEqual(self.api.writes, [])

    def test_firewall_readback_failure_keeps_hold_and_preserves_failed_evidence(self):
        self.api.lose_rule = True
        with self.assertRaisesRegex(ValueError, 'readback'):
            self.run_cd()
        self.assertTrue((self.root / 'BOOTSTRAP-CD-HOLD.json').exists())
        self.assertFalse((self.root / 'service-discovery/READY.json').exists())
        self.assertTrue(list(self.nas.glob('cd-*/failure.json')))

    def test_extra_effective_permission_stops_before_firewall_change(self):
        self.api.extra_permission = True
        with self.assertRaisesRegex(ValueError, 'effective permissions'):
            self.run_cd()
        self.assertFalse(any('/firewall/' in path for path, _, _ in self.api.writes))

    def test_secret_file_permissions_and_symlinks_are_refused(self):
        self.run_cd()
        (self.root / 'service-discovery/token.json').chmod(0o644)
        self.api.writes.clear()
        with self.assertRaisesRegex(ValueError, 'mode differs'):
            self.run_cd()
        self.assertEqual(self.api.writes, [])

    def test_missing_nas_secret_and_symlinked_state_are_never_reconstructed(self):
        self.run_cd()
        path = self.nas / 'service-discovery/token.json'
        target = self.nas / 'saved-private.json'
        path.rename(target)
        path.symlink_to(target)
        self.api.writes.clear()
        with self.assertRaisesRegex(ValueError, 'Missing private'):
            self.run_cd()
        self.assertEqual(self.api.writes, [])

    def test_nas_save_failure_retains_the_once_returned_secret_and_no_acl_is_added(self):
        original = discovery.save_new
        def fail_nas(path, value):
            if path == self.nas / 'service-discovery/minted-response.json':
                raise OSError('Synthetic NAS write failure')
            return original(path, value)
        with patch.object(discovery, 'save_new', side_effect=fail_nas), self.assertRaises(OSError):
            self.run_cd()
        self.assertIn(SECRET, (self.root / 'service-discovery/minted-response.json').read_text())
        self.assertFalse(any(values.get('tokens', '').startswith('root@pam!homelab-traefik-')
                             for _, _, values in self.api.writes))
        self.assertTrue((self.root / 'BOOTSTRAP-CD-HOLD.json').exists())

    def test_closed_configuration_rejects_extra_fields_unknown_guests_and_network_ranges(self):
        mutations = [lambda s: s.update(privileges=['Administrator']), lambda s: s['guests'].append(900),
                     lambda s: s.update(vmid=4915), lambda s: s.update(address='10.77.25.0/24'),
                     lambda s: s.update(address='10.77.25.10'), lambda s: s['guests'].append(211),
                     lambda s: s.update(address='8.8.8.8')]
        for change in mutations:
            c = copy.deepcopy(self.c); change(c['service_discovery'])
            with self.subTest(c=c), self.assertRaises(ValueError): cd.validate(c)

    def test_discovery_verifier_has_no_api_write_method(self):
        reader = object.__new__(cd.DiscoveryAPI)
        with self.assertRaisesRegex(ValueError, 'read-only'):
            reader.call('/nodes/pve/status', 'POST', {'command': 'reboot'})


if __name__ == '__main__':
    unittest.main()
