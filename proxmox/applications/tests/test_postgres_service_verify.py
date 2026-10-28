"""Normal checks retain provenance without replaying cutover or freezing history."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import postgres_service_verify as service


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.packet = {'schema': 'homelab-postgresql-cutover-v1', 'operation': 'postgresql-example',
            'members': {r: {'vmid': 110 + n, 'installer_revision': 'a' * 40} for n, r in enumerate(service.ROLES)}}
        self.catalogue = {'schema': 'homelab-database-networks-v1',
                          'networks': {'postgresql': {'bridge': 'vmbr31'}, 'mariadb': {}, 'influxdb': {}}}
        self.packet['catalogue_sha256'] = service.sha(service.encoded(self.catalogue))
        self.value = {'schema': service.SCHEMA, 'request_sha256': service.sha(service.encoded(self.packet)),
            'catalogue_sha256': self.packet['catalogue_sha256'], 'complete_sha256': 'b' * 64,
            'network_revision': 'c' * 40, 'service_revision': 'd' * 40}
        self.accepted = {'status': 'network31_group_and_saved_credential_SQL_accepted',
            'qualified_request_sha256': self.value['request_sha256'],
            'qualified_completion_sha256': self.value['complete_sha256']}
        self.value['acceptance_sha256'] = service.sha(service.encoded(self.accepted))

    def check(self, value=None, desired=None, acceptance=None):
        return service.selection(value or self.value, service.encoded(self.packet), service.encoded(self.catalogue),
            service.encoded(desired or self.catalogue), service.encoded(acceptance or self.accepted))

    def test_exact_acceptance_and_unrelated_database_successor(self):
        self.assertEqual(self.check(), self.packet)
        desired = copy.deepcopy(self.catalogue); desired['networks']['influxdb']['clients'] = ['later-proposal']
        self.assertEqual(self.check(desired=desired), self.packet)

    def test_pg_endpoint_or_client_drift_and_missing_acceptance_are_not_adopted(self):
        desired = copy.deepcopy(self.catalogue); desired['networks']['postgresql']['bridge'] = 'vmbr99'
        with self.assertRaises(ValueError): self.check(desired=desired)
        for key in ('request_sha256', 'catalogue_sha256', 'complete_sha256', 'acceptance_sha256'):
            wrong = dict(self.value, **{key: '0' * 64})
            with self.subTest(key=key), self.assertRaises(ValueError): self.check(value=wrong)
        wrong = dict(self.accepted, status='prepared')
        value = dict(self.value, acceptance_sha256=service.sha(service.encoded(wrong)))
        with self.assertRaises(ValueError): self.check(value=value, acceptance=wrong)

    def test_selection_has_no_native_mode_or_phase(self):
        for key, value in [('action', 'apply'), ('phase', 'activate'), ('resume', True)]:
            with self.subTest(key=key), self.assertRaises(ValueError): self.check(dict(self.value, **{key: value}))


class MemberTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve(); self.state = self.root / 'state'; self.state.mkdir(mode=0o700)
        self.group = self.state / 'database-network-cutover-postgresql-example'; self.group.mkdir(mode=0o700)
        self.remote = self.root / 'remote'; self.remote.mkdir(mode=0o700)
        self.events = []
        self.packet = {'operation': 'postgresql-example', 'members': {}}
        for n, role in enumerate(service.ROLES):
            vmid = 110 + n
            work = self.state / str(vmid); work.mkdir(mode=0o700)
            directory = work / 'database-network-runtime-postgresql-example'; directory.mkdir(mode=0o700)
            member = {'vmid': vmid, 'installer_revision': 'a' * 40, 'plan_directory': 'database-network-plan-example',
                      'network_packet': {'vmid': vmid}, 'runtime_packet': {'original': role}}
            self.packet['members'][role] = member
            (directory / 'network-packet.json').write_bytes(service.encoded(member['network_packet']))
            (directory / 'startup-after.json').write_text('{}')
            cfg = {'app': {'kind': role}, 'guest': {'vmid': vmid}, 'paths': {'state_root': str(self.state)}}
            (self.root / (role + '.json')).write_text(json.dumps(cfg))
        receipt = {'phase': 'quiesce', 'role': 'db-tools',
                   'result': {'status': 'passed', 'action': 'quiesce', 'quiesced': {'original': 'backup'}}}
        for p in (self.group, self.remote): (p / '01-quiesce-db-tools.json').write_bytes(service.encoded(receipt))
        (self.remote / 'identity-original-compose.yml').write_bytes(b'original compose')
        self.installer = self.root / 'installer'; self.helper = self.root / 'helper'; self.source = self.root / 'source'
        deployment = SimpleNamespace(__file__=str(self.installer / 'proxmox/applications/deploy.py'), validate=lambda cfg: None)
        self.worker = SimpleNamespace(site_path=lambda role: self.root / (role + '.json'), regular=lambda p: p.read_bytes(),
            maintenance=SimpleNamespace(write_new=self.write_new),
            network_apply=SimpleNamespace(sync=lambda p: None, load=lambda *a: {}, verify=lambda *a: self.events.append('network-verify')),
            bind_runtime=lambda *a: self.events.append('bind-original-runtime'),
            startup_probe=lambda *a: self.events.append('startup-verify'),
            identity_recovery=lambda *a: b'original compose',
            runtime=self.runtime, ansible=self.ansible)
        self.stack = __import__('contextlib').ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(sys.modules, {'deploy': deployment}))
        self.stack.enter_context(patch.object(service, 'source_revision'))
        self.stack.enter_context(patch.object(service, 'load_worker', return_value=self.worker))
        self.stack.enter_context(patch.object(service, 'completed', return_value=(self.group, self.remote)))
        self.original_path = list(sys.path); self.addCleanup(lambda: sys.path.__setitem__(slice(None), self.original_path))

    def write_new(self, path, raw):
        with path.open('xb') as f: f.write(raw)

    def runtime(self, deployment, cfg, adapter, role, member, directory, action):
        self.assertEqual(action, 'verify'); self.events.append('runtime-' + role)
        return {'status': 'passed', 'changed': False}

    def ansible(self, deployment, cfg, source, playbook, variables, directory, label):
        self.events.append(playbook)
        if playbook == 'pgadmin-service-binding.yml':
            self.assertEqual(variables['pgadmin_service_request']['quiesced'], {'original': 'backup'})
            result = {'status': 'passed', 'kind': 'pgadmin-accepted-binding', 'binding': {'from': 'original backup'}}
        else:
            self.assertEqual(playbook, 'pgadmin-service-verify.yml')
            self.assertEqual(variables['pgadmin_service_binding'], {'from': 'original backup'})
            result = {'status': 'passed', 'kind': 'pgadmin-accepted-service', 'changed': False}
        self.write_new(Path(variables['pgadmin_service_result_path']), json.dumps(result).encode())

    def run_role(self, role):
        return service.verify(role, {'network_revision': 'b'*40, 'service_revision': 'c'*40,
            'request_sha256': 'd'*64}, self.packet, self.helper, self.installer, self.source,
            self.root / 'catalogue.json', state=self.state)

    def test_each_member_uses_only_network_startup_and_read_only_runtime(self):
        for role in service.ROLES:
            self.events.clear()
            result = self.run_role(role)
            self.assertFalse(result['changed']); self.assertFalse(result['current_browser_sql_tested'])
            self.assertEqual(self.events[:3], ['bind-original-runtime', 'network-verify', 'startup-verify'])
            if role == 'db-tools':
                self.assertEqual(self.events[3:], ['pgadmin-service-binding.yml', 'pgadmin-service-verify.yml'])
            else: self.assertEqual(self.events[3:], ['runtime-' + role])
            self.assertFalse((self.state / str(self.packet['members'][role]['vmid']) / 'SERVICE-VERIFY-HOLD.json').exists())
            self.assertFalse((self.state / str(self.packet['members'][role]['vmid']) / 'SERVICE-VERIFYING.json').exists())

    def test_runtime_failure_remains_held_and_next_attempt_cannot_contact_guest(self):
        self.worker.runtime = lambda *a: (_ for _ in ()).throw(ValueError('not healthy'))
        with self.assertRaises(ValueError): self.run_role('postgresql')
        hold = self.state / '110/SERVICE-VERIFY-HOLD.json'
        self.assertTrue(hold.exists()); before = list(self.events)
        with self.assertRaises(ValueError): self.run_role('postgresql')
        self.assertEqual(before, self.events)
        self.assertFalse(json.loads(hold.read_text())['automatic_retry'])

    def test_in_progress_claim_is_compatible_with_pinned_network_failure_gate(self):
        import database_network_maintenance as maintenance
        work = self.state / '110'
        with patch.object(maintenance, 'BOOTSTRAP_HOLD', self.root / 'bootstrap-CONFIGURING'):
            with service.verification_hold(self.worker, work, {'request_sha256': 'd'*64}):
                maintenance.no_holds(work)
                self.assertTrue((work / 'SERVICE-VERIFYING.json').exists())
            # A failed normal check is still rejected by that same old gate.
            (work / 'SERVICE-VERIFY-HOLD.json').write_text('{}')
            with self.assertRaises(ValueError): maintenance.no_holds(work)

    def test_interrupted_claim_refuses_new_verification_before_network_contact(self):
        (self.state / '110/SERVICE-VERIFYING.json').write_text('{}')
        with self.assertRaises(FileExistsError): self.run_role('postgresql')
        self.assertEqual(self.events, [])


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.state = self.root / 'state'; self.state.mkdir(mode=0o700)
        self.mount = self.root / 'nas'; self.mount.mkdir(mode=0o700)
        self.request = {'operation': 'postgresql-example'}
        self.group = self.state / 'database-network-cutover-postgresql-example'; self.group.mkdir(mode=0o700)
        self.remote = self.mount / self.group.name; self.remote.mkdir(mode=0o700)
        self.value = {'request_sha256': service.sha(service.encoded(self.request))}
        complete = {'status': 'passed', 'operation': self.request['operation'],
                    'packet_sha256': self.value['request_sha256'], 'roles': list(service.ROLES)}
        self.value['complete_sha256'] = service.sha(service.encoded(complete))
        for directory in (self.group, self.remote):
            for name in ('request.json', 'claim.json'): (directory / name).write_bytes(service.encoded(self.request))
            (directory / 'complete.json').write_bytes(service.encoded(complete))
        self.worker = SimpleNamespace(regular=lambda path: path.read_bytes())
        self.cfg = {'paths': {'backup_mount': str(self.mount), 'backup_directory': str(self.mount),
                              'backup_source': 'nas.example:/backups'}}
        self.stack = __import__('contextlib').ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(service.os.path, 'ismount', return_value=True))
        self.stack.enter_context(patch.object(service.subprocess, 'check_output', return_value='nfs4 nas.example:/backups\n'))

    def check(self):
        return service.completed(self.worker, self.request, self.value, self.cfg, self.state)

    def test_completion_requires_exact_local_nas_request_claim_and_result(self):
        self.assertEqual(self.check(), (self.group, self.remote))
        for directory in (self.group, self.remote):
            for name in ('request.json', 'claim.json', 'complete.json'):
                path = directory / name; raw = path.read_bytes(); path.write_bytes(b'{}')
                with self.subTest(directory=directory, name=name), self.assertRaises(ValueError): self.check()
                path.write_bytes(raw)

    def test_existing_failure_interruption_or_incomplete_other_group_blocks_normal_path(self):
        for name in ('HOLD.json', 'VERIFYING.json', 'ACTIVATION-FINISH-HOLD.json'):
            path = self.group / name; path.write_text('{}')
            with self.subTest(name=name), self.assertRaises(ValueError): self.check()
            path.unlink()
        (self.state / 'database-network-cutover-postgresql-unfinished').mkdir(mode=0o700)
        with self.assertRaises(ValueError): self.check()

    def test_no_nas_route_fallback(self):
        with patch.object(service.subprocess, 'check_output', return_value='nfs4 other:/backups\n'), self.assertRaises(ValueError):
            self.check()
        with patch.object(service.os.path, 'ismount', return_value=False), self.assertRaises(ValueError): self.check()


if __name__ == '__main__': unittest.main()
