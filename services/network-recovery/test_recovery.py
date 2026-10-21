import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import recovery

CONFIG = json.loads((Path(__file__).parent / "fixtures" / "network-recovery.synthetic.json").read_text())
CANDIDATE = {'kind': 'fdb', 'key': 'overlay/service', 'identity': {'endpoint': 'old', 'mac': '02:42:00:00:00:02'}}


class Scenario(recovery.Engine):
    def __init__(self, directory, now, boot='boot1'):
        super().__init__(CONFIG, directory, clock=lambda: now[0], boot=boot)
        self.links = [{'name': 'lan', 'index': 2, 'mac': 'aa'}]
        self.candidate = copy.deepcopy(CANDIDATE)
        self.probes_healthy = True

    def observe_links(self):
        if isinstance(self.links, Exception):
            raise self.links
        return self.links

    def observe_modules(self):
        return {'fdb': {'healthy': not self.candidate, 'candidates': [self.candidate] if self.candidate else [], 'issues': []},
                'macvlan': {'healthy': True, 'candidates': [], 'issues': []}}

    def observe_probes(self):
        return [{'name': 'test', 'healthy': self.probes_healthy}]


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        (self.directory / 'receipts').mkdir()
        self.now = [100.0]
        self.engine = Scenario(self.directory, self.now)

    def perform(self, candidate, config, record):
        state = json.loads((self.directory / 'state.json').read_text())
        self.assertTrue(state['pending'])
        record('before_mutation', {'target': 'test'})
        receipt = self.directory / 'receipts' / (state['pending'] + '.json')
        self.assertTrue(receipt.is_file())
        self.assertEqual(json.loads(receipt.read_text())['steps'][-1]['phase'], 'before_mutation')
        self.engine.candidate = None
        return {'success': True}

    def test_healthy_audit_is_noop(self):
        self.engine.candidate = None
        with patch.object(recovery.fdb, 'repair') as action:
            result = self.engine.tick()
        self.assertTrue(result['healthy'])
        action.assert_not_called()

    def test_audit_never_repairs_even_after_settle(self):
        self.engine.tick()
        self.now[0] += 1000
        with patch.object(recovery.fdb, 'repair') as action:
            self.assertFalse(self.engine.tick()['healthy'])
        action.assert_not_called()

    def test_requires_stable_link_and_persistent_identical_fault(self):
        with patch.object(recovery.fdb, 'repair', side_effect=self.perform) as action:
            self.assertEqual(self.engine.tick(True)['phase'], 'settling')
            self.now[0] += 59
            self.engine.tick(True)
            action.assert_not_called()
            self.now[0] += 1
            self.assertTrue(self.engine.tick(True)['healthy'])
            action.assert_called_once()

    def test_endpoint_change_restarts_fault_wait(self):
        self.engine.tick(True)
        self.now[0] += 60
        self.engine.candidate['identity']['endpoint'] = 'replacement'
        with patch.object(recovery.fdb, 'repair') as action:
            self.engine.tick(True)
            action.assert_not_called()

    def test_link_generation_change_restarts_wait(self):
        self.engine.tick(True)
        self.now[0] += 100
        self.engine.links[0]['index'] = 8
        with patch.object(recovery.fdb, 'repair') as action:
            self.assertEqual(self.engine.tick(True)['phase'], 'settling')
            action.assert_not_called()

    def test_link_loss_clears_stability_without_repair(self):
        self.engine.tick(True)
        self.engine.links = ValueError('down')
        result = self.engine.tick(True)
        self.assertEqual(result['phase'], 'waiting_for_network')
        self.assertIsNone(self.engine.state['stable'])

    def test_long_observation_gap_requires_fresh_settling(self):
        self.engine.tick(True)
        self.now[0] += 1000
        with patch.object(recovery.fdb, 'repair') as action:
            self.assertEqual(self.engine.tick(True)['phase'], 'settling')
            action.assert_not_called()

    def test_configuration_change_requires_fresh_settling(self):
        self.engine.tick(True)
        self.now[0] += 61
        self.engine.state['config_hash'] = 'prior-configuration'
        self.engine.save()
        reloaded = Scenario(self.directory, self.now)
        with patch.object(recovery.fdb, 'repair') as action:
            self.assertEqual(reloaded.tick(True)['phase'], 'settling')
            action.assert_not_called()

    def test_last_second_link_change_prevents_mutation(self):
        self.engine.tick(True)
        self.now[0] += 61
        with patch.object(self.engine, 'observe_links', side_effect=[self.engine.links, [{'index': 99}]]):
            with patch.object(recovery.fdb, 'repair') as action:
                self.assertEqual(self.engine.tick(True)['phase'], 'network_changed')
                action.assert_not_called()

    def test_failed_operation_halts_and_keeps_receipt(self):
        self.engine.tick(True)
        self.now[0] += 61
        with patch.object(recovery.fdb, 'repair', side_effect=RuntimeError('postcheck failed')):
            result = self.engine.tick(True)
        self.assertTrue(result['halted'])
        self.assertFalse(result['healthy'])
        reloaded = Scenario(self.directory, self.now, boot='newboot')
        self.assertTrue(reloaded.state['halted'])
        with patch.object(recovery.fdb, 'repair') as action:
            reloaded.tick(True)
            action.assert_not_called()

    def test_proven_prerequisite_failure_defers_without_using_mutation_budget(self):
        self.engine.tick(True)
        self.now[0] += 61
        wait = {'deferred': True, 'changed': False, 'mutation_attempted': False, 'reason': 'peer_unreachable'}
        with patch.object(recovery.fdb, 'repair', return_value=wait):
            result = self.engine.tick(True)
        self.assertEqual(result['phase'], 'waiting_for_dependency')
        self.assertFalse(result['halted'])
        self.assertIsNone(self.engine.state['pending'])
        self.assertEqual(self.engine.state['attempts'], [])
        self.now[0] += 61
        with patch.object(recovery.fdb, 'repair', side_effect=self.perform):
            self.assertTrue(self.engine.tick(True)['healthy'])
        self.assertEqual(len(list((self.directory / 'receipts').glob('*.json'))), 2)

    def test_uncertain_mutation_cannot_claim_safe_deferral(self):
        self.engine.tick(True)
        self.now[0] += 61
        wait = {'deferred': True, 'changed': False, 'mutation_attempted': True}
        with patch.object(recovery.fdb, 'repair', return_value=wait):
            result = self.engine.tick(True)
        self.assertTrue(result['halted'])

    def test_interrupted_intent_halts_on_restart(self):
        self.engine.state['pending'] = 'interrupted'
        self.engine.save()
        reloaded = Scenario(self.directory, self.now)
        self.assertTrue(reloaded.state['halted'])

    def test_unreaped_observation_child_halts_future_work(self):
        value = {'macvlan': {'healthy': False, 'candidates': [], 'issues': [{'reason': 'timeout', 'orphan_pid': 42}]}}
        with patch.object(self.engine, 'observe_modules', return_value=value):
            result = self.engine.tick(True)
        self.assertTrue(result['halted'])
        self.assertFalse(result['healthy'])
        with patch.object(self.engine, 'observe_modules') as observe:
            self.engine.tick(True)
            observe.assert_not_called()

    def test_post_repair_orphan_halts_immediately(self):
        self.engine.tick(True)
        self.now[0] += 61
        original = self.engine.observe_modules
        calls = [0]
        def observe():
            calls[0] += 1
            if calls[0] == 1:
                return original()
            return {'macvlan': {'healthy': False, 'candidates': [], 'issues': [{'orphan_pid': 42}]}}
        with patch.object(self.engine, 'observe_modules', side_effect=observe):
            with patch.object(recovery.fdb, 'repair', side_effect=self.perform):
                result = self.engine.tick(True)
        self.assertTrue(result['halted'])
        self.assertEqual(result['phase'], 'manual_review_required')

    def test_cooldown_survives_reload(self):
        self.engine.tick(True)
        self.now[0] += 61
        with patch.object(recovery.fdb, 'repair', side_effect=self.perform):
            self.engine.tick(True)
        reloaded = Scenario(self.directory, self.now)
        reloaded.tick(True)
        self.now[0] += 61
        with patch.object(recovery.fdb, 'repair') as action:
            reloaded.tick(True)
            action.assert_not_called()

    def test_hourly_budget_limits_different_targets(self):
        self.engine.tick(True)
        self.engine.state['attempts'] = [{'key': str(i), 'epoch': recovery.time.time()} for i in range(6)]
        self.now[0] += 61
        with patch.object(recovery.fdb, 'repair') as action:
            self.assertEqual(self.engine.tick(True)['phase'], 'rate_limited')
            action.assert_not_called()

    def test_repair_success_does_not_hide_failed_service(self):
        self.engine.tick(True)
        self.now[0] += 61
        self.engine.probes_healthy = False
        with patch.object(recovery.fdb, 'repair', side_effect=self.perform):
            result = self.engine.tick(True)
        self.assertFalse(result['healthy'])
        self.assertEqual(result['phase'], 'repair_verified_services_pending')

    def test_acknowledge_requires_healthy_observation(self):
        self.engine.state['halted'] = True
        with self.assertRaises(ValueError):
            self.engine.tick(acknowledge=True)
        self.engine.candidate = None
        self.assertTrue(self.engine.tick(acknowledge=True)['healthy'])
        self.assertFalse(self.engine.state['halted'])

    def test_unsafe_policy_rejected(self):
        baseline = copy.deepcopy(CONFIG)
        baseline['hostname'] = 'ben-beast'
        recovery.validate_config(baseline)
        for key in CONFIG['policy']:
            bad = copy.deepcopy(baseline)
            bad['policy'][key] = 0
            with self.assertRaisesRegex(ValueError, '^Unsafe policy: ' + key + '$'):
                recovery.validate_config(bad)

    def test_invalid_state_is_not_silently_reset(self):
        self.engine.state_file.write_text('{invalid')
        with self.assertRaises(json.JSONDecodeError):
            Scenario(self.directory, self.now)
        self.assertEqual(self.engine.state_file.read_text(), '{invalid')

    def test_public_status_and_private_state_modes(self):
        self.engine.candidate = None
        self.engine.tick()
        self.assertEqual((self.directory / 'status.json').stat().st_mode & 0o777, 0o644)
        self.assertEqual((self.directory / 'state.json').stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
