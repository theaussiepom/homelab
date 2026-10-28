"""Durable group ordering and interruption tests, without any guest operation."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import database_network_cutover as cutover


def packet():
    return {'schema': 'homelab-postgresql-cutover-v1', 'operation': 'postgresql-example',
        'catalogue_sha256': 'a' * 64, 'members': {role: {
            'vmid': vmid, 'installer_revision': 'b' * 40, 'adapter_revision': 'c' * 40,
            'plan_directory': 'database-network-plan-123-1',
            'network_packet': {'vmid': vmid, 'allow_guest_restart': True},
            'runtime_packet': {}, 'startup': {'gate_sha256': 'd' * 64, 'dependency_sha256': 'e' * 64}}
            for role, vmid in [('postgresql', 208), ('identity', 211), ('db-tools', 202)]}}


class Driver:
    def __init__(self, fail=None):
        self.calls = []; self.nas = {}; self.fail = fail

    def custody(self, name, raw):
        if self.fail == ('custody', name): raise OSError('synthetic unavailable NAS')
        if name in self.nas: raise ValueError('no replacement')
        self.nas[name] = raw

    def check_custody(self, name, raw):
        if self.nas.get(name) != raw: raise ValueError('synthetic custody drift')

    def __getattr__(self, action):
        if action not in ('preflight', 'quiesce', 'network', 'startup', 'activate', 'verify'):
            raise AttributeError(action)
        def call(role, member):
            self.calls.append((action, role))
            if self.fail == (action, role): raise RuntimeError('synthetic phase failure')
            return {'status': 'passed'}
        return call


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name); self.state.chmod(0o700)
        self.value = packet(); self.driver = Driver()

    def test_both_clients_stop_before_any_network_and_server_resumes_first(self):
        result = cutover.run(self.value, self.state, self.driver)
        self.assertTrue(result['changed'])
        self.assertEqual(self.driver.calls[:5], [('preflight', r) for r in cutover.ROLES]
                         + [('quiesce', 'identity'), ('quiesce', 'db-tools')])
        self.assertEqual(self.driver.calls[5], ('startup', 'postgresql'))
        self.assertEqual(self.driver.calls[6:9], [('network', r) for r in cutover.ROLES])
        self.assertEqual([r for action, r in self.driver.calls if action == 'activate'], list(cutover.ROLES))
        self.assertIn('complete.json', self.driver.nas)

    def test_later_push_only_verifies_and_does_not_reapply_restart_or_quiesce(self):
        cutover.run(self.value, self.state, self.driver); self.driver.calls.clear()
        self.assertFalse(cutover.run(self.value, self.state, self.driver)['changed'])
        self.assertEqual(self.driver.calls, [('verify', r) for r in cutover.ROLES])

    def test_any_members_admission_failure_precedes_all_native_changes(self):
        for role in cutover.ROLES:
            with self.subTest(role=role), tempfile.TemporaryDirectory() as tmp:
                state = Path(tmp); state.chmod(0o700); driver = Driver(('preflight', role))
                with self.assertRaises(RuntimeError): cutover.run(self.value, state, driver)
                self.assertTrue(all(action == 'preflight' for action, _ in driver.calls))

    def test_failure_never_resumes_clients_or_replays_with_a_new_operation_id(self):
        self.driver.fail = ('network', 'postgresql')
        with self.assertRaises(RuntimeError): cutover.run(self.value, self.state, self.driver)
        calls = list(self.driver.calls)
        self.assertFalse(any(action == 'activate' for action, _ in calls))
        self.driver.fail = None
        for value in (self.value, dict(self.value, operation='postgresql-different-run')):
            with self.assertRaises(ValueError): cutover.run(value, self.state, self.driver)
        self.assertEqual(self.driver.calls, calls)

    def test_missing_nas_claim_prevents_first_client_stop(self):
        self.driver.fail = ('custody', 'claim.json')
        with self.assertRaises(OSError): cutover.run(self.value, self.state, self.driver)
        self.assertTrue(all(action == 'preflight' for action, _ in self.driver.calls))

    def test_sigkill_without_exception_marker_is_not_permission_to_resume(self):
        directory = self.state / ('database-network-cutover-' + self.value['operation'])
        directory.mkdir(mode=0o700)
        cutover.write_new(directory / 'request.json', cutover.encoded(self.value))
        with self.assertRaises(ValueError): cutover.run(self.value, self.state, self.driver)
        self.assertEqual(self.driver.calls, [])

    def test_unapproved_lifecycle_or_path_or_target_is_refused_before_claim(self):
        for mutate in (lambda v: v['members']['identity']['network_packet'].update(allow_guest_restart=False),
                       lambda v: v['members']['identity'].update(plan_directory='../other'),
                       lambda v: v['members']['identity'].update(vmid=900),
                       lambda v: v['members'].pop('db-tools')):
            value = copy.deepcopy(self.value); mutate(value)
            with self.assertRaises(ValueError): cutover.run(value, self.state, self.driver)
        self.assertEqual(self.driver.calls, [])

    def test_completed_custody_or_readonly_verification_failure_stays_held(self):
        cutover.run(self.value, self.state, self.driver); self.driver.calls.clear()
        self.driver.fail = ('verify', 'identity')
        with self.assertRaises(RuntimeError): cutover.run(self.value, self.state, self.driver)
        with self.assertRaises(ValueError): cutover.run(self.value, self.state, self.driver)
        self.assertFalse(any(action != 'verify' for action, _ in self.driver.calls))

    def test_missing_completed_nas_custody_is_held_without_an_automatic_retry(self):
        cutover.run(self.value, self.state, self.driver)
        del self.driver.nas['complete.json']; self.driver.calls.clear()
        with self.assertRaises(ValueError): cutover.run(self.value, self.state, self.driver)
        directory = self.state / ('database-network-cutover-' + self.value['operation'])
        self.assertTrue((directory / 'HOLD.json').is_file())
        self.assertTrue((directory / 'VERIFYING.json').is_file())
        with self.assertRaises(ValueError): cutover.run(self.value, self.state, self.driver)
        self.assertEqual(self.driver.calls, [])

    def test_interrupted_later_verification_is_held_even_with_an_existing_completion(self):
        cutover.run(self.value, self.state, self.driver); self.driver.calls.clear()
        directory = self.state / ('database-network-cutover-' + self.value['operation'])
        cutover.write_new(directory / 'VERIFYING.json', b'{"interrupted":true}')
        with self.assertRaises(ValueError): cutover.run(self.value, self.state, self.driver)
        self.assertEqual(self.driver.calls, [])

    def test_an_explicit_failed_result_cannot_be_recorded_as_group_success(self):
        self.driver.activate = lambda role, member: {'status':'held'}
        with self.assertRaises(ValueError): cutover.run(self.value, self.state, self.driver)
        directory = self.state / ('database-network-cutover-' + self.value['operation'])
        self.assertFalse((directory / 'complete.json').exists())
        self.assertTrue((directory / 'HOLD.json').is_file())

    def test_native_identity_admission_copies_exact_recovery_bytes_to_nas(self):
        driver = object.__new__(cutover.NativeDriver)
        raw = b'private synthetic configuration'
        driver.call = Mock(return_value={'status':'admitted', 'recovery_sha256':cutover.digest(raw)})
        driver.identity_recovery = Mock(return_value=raw)
        driver.custody = Mock()
        member = self.value['members']['identity']
        self.assertEqual(driver.preflight('identity', member)['status'], 'admitted')
        driver.custody.assert_called_once_with('identity-original-compose.yml', raw)
        driver.call.return_value['recovery_sha256'] = 'f'*64
        driver.custody.reset_mock()
        with self.assertRaises(ValueError): driver.preflight('identity', member)
        driver.custody.assert_not_called()

    def test_native_identity_missing_recovery_custody_prevents_stop_and_activation(self):
        driver = object.__new__(cutover.NativeDriver)
        driver.identity_recovery = Mock(return_value=b'private configuration')
        driver.check_custody = Mock(side_effect=ValueError('missing private recovery copy'))
        for phase in ('quiesce', 'activate', 'verify'):
            with patch.object(cutover.subprocess, 'run') as remote, self.assertRaises(ValueError):
                driver.call(phase, 'identity', self.value['members']['identity'])
            remote.assert_not_called()


if __name__ == '__main__': unittest.main()
