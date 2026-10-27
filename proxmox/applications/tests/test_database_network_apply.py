"""Saved-plan apply/overlay custody guards, using only disposable local fixtures."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import database_network_apply as apply_network
import database_network_maintenance as maintenance
import test_database_network_maintenance as fixtures

OP = fixtures.OP


class ApplyTests(unittest.TestCase):
    def setUp(self):
        fixtures.ReadOnlyPlannerTests.setUp(self)
        self.cfg['paths'].update(backup_directory=str(self.root / 'nas'), backup_mount=str(self.root / 'mount'),
                                 backup_source='synthetic-nas:/approved')
        self.site.write_bytes(maintenance.encoded(self.cfg))
        for name in ('plan.json', 'applied.json', 'started.json'):
            value = json.loads((self.work / name).read_bytes())
            value['site_sha256'] = maintenance.digest(self.site.read_bytes())
            (self.work / name).write_bytes(maintenance.encoded(value))
        (self.source / 'tofu/.terraform.lock.hcl').write_text('# synthetic pinned provider lock\n')
        with patch.object(maintenance, 'tofu', side_effect=self.fake_plan):
            maintenance.plan(self.deployment, self.site, self.catalogue, self.evidence, 'postgresql', **OP)
        self.selected = {'schema': apply_network.SCHEMA, 'vmid': 208,
            'request_sha256': maintenance.digest((self.evidence / 'request.json').read_bytes()),
            'review_packet_sha256': maintenance.digest((self.evidence / 'review-packet.json').read_bytes()),
            'apply_helper_sha256': maintenance.digest(Path(apply_network.__file__).read_bytes()), 'allow_guest_restart': True}
        self.packet_path = self.root / 'operation.json'; maintenance.write_new(self.packet_path, maintenance.encoded(self.selected))
        self.packet_path.chmod(0o644)  # A non-secret reviewed packet may come from private Git.
        self.packet_sha = maintenance.digest(self.packet_path.read_bytes())
        self.nas = self.root / 'nas/208'; self.nas.mkdir(parents=True, mode=0o700)
        self.deployment.backup = Mock()
        patcher = patch.object(apply_network, 'nas_root', return_value=self.nas); patcher.start(); self.addCleanup(patcher.stop)
        self.attempt = self.work / ('database-network-apply-' + self.selected['review_packet_sha256'])
        self.originals = {p: p.read_bytes() for p in self.work.rglob('*') if p.is_file() and self.evidence not in p.parents}
        self.originals[self.site] = self.site.read_bytes()
        self.calls = []

    def fake_plan(self, command, environment, log, output=None):
        fixtures.ReadOnlyPlannerTests.fake_tofu(self, command, environment, log, output)

    def fake_native(self, command, environment, log, output=None):
        self.calls.append(command)
        self.assertEqual(environment['TF_WORKSPACE'], 'default')
        if 'apply' in command:
            self.assertEqual(command[-1], str(self.evidence / 'guest.tfplan'))
            state = json.loads((self.work / 'terraform.tfstate').read_bytes()); state['serial'] += 1
            (self.work / 'terraform.tfstate').write_bytes(maintenance.encoded(state))
        if 'plan' in command:
            destination = Path(next(part.split('=', 1)[1] for part in command if part.startswith('-out=')))
            maintenance.write_new(destination, b'SYNTHETIC_READ_ONLY_OVERLAY_PLAN')
            variables = json.loads((self.evidence / 'tofu/site.auto.tfvars.json').read_bytes())
            self.assertNotIn('vmbr30', str(variables['guest']['interfaces']))
        if output:
            value = json.loads((self.evidence / 'guest.tfplan.json').read_bytes())
            if command[-1] != str(self.evidence / 'guest.tfplan'):
                for row in value['resource_changes']:
                    row['change']['before'] = copy.deepcopy(row['change']['after'])
                    row['change']['actions'] = ['no-op']
            maintenance.write_new(output, maintenance.encoded(value))

    def args(self):
        return self.deployment, self.site, self.catalogue, self.evidence, self.packet_path, self.packet_sha

    def apply(self):
        return apply_network.apply(*self.args())

    def verify(self):
        return apply_network.verify(*self.args())

    def resave_packet(self):
        self.packet_path.write_bytes(maintenance.encoded(self.selected))
        self.packet_sha = maintenance.digest(self.packet_path.read_bytes())

    def assert_originals_preserved(self):
        for path, content in self.originals.items():
            if path.name != 'terraform.tfstate': self.assertEqual(path.read_bytes(), content)
        self.deployment.execute.assert_not_called()

    def test_apply_uses_exact_plan_once_preserves_originals_and_creates_matching_nas_overlay(self):
        with patch.object(maintenance, 'tofu', side_effect=self.fake_native):
            result = self.apply()
            with self.assertRaises(ValueError): self.apply()
        self.assertEqual(result['status'], 'network_overlay_verified')
        self.assertFalse(result['service_acceptance_verified'])
        self.assertFalse(result['guest_lifecycle_observed'])
        self.assertEqual(result['state_lineage'], 'original-lineage'); self.assertEqual(result['state_serial'], 8)
        self.assertEqual(sum('apply' in c for c in self.calls), 1)
        self.assertEqual(sum('plan' in c for c in self.calls), 1)  # Post-apply read-only no-op check only.
        self.assertIn('-backend-config=path=' + str(self.work / 'terraform.tfstate'), self.calls[0])
        self.assertFalse((self.work / 'HOLD.json').exists())
        for name in ('claim.json', 'request.json', 'review-packet.json', 'guest.tfplan', 'guest.tfplan.json',
                     'state-before.json', 'state-after.json', 'overlay.json'):
            self.assertEqual((self.attempt / name).read_bytes(), (self.nas / self.attempt.name / name).read_bytes())
            self.assertEqual((self.attempt / name).stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.deployment.backup.call_count, 2)
        self.assert_originals_preserved()

    def test_completed_overlay_verifies_new_candidate_without_reapplying_or_using_old_inputs(self):
        with patch.object(maintenance, 'tofu', side_effect=self.fake_native):
            self.apply(); self.calls.clear()
            result = self.verify()
            result_again = self.verify()
        self.assertEqual(result['status'], result_again['status'])
        self.assertTrue(all('apply' not in call and 'stage' not in call and 'start' not in call for call in self.calls))
        self.assertEqual(sum('plan' in call for call in self.calls), 2)
        self.assertFalse((self.work / 'HOLD.json').exists())
        self.assert_originals_preserved()

    def test_false_restart_permission_wrong_digest_or_helper_source_refuse_before_claim(self):
        mutations = [lambda: self.selected.update(allow_guest_restart=False),
                     lambda: self.selected.update(apply_helper_sha256='0' * 64),
                     lambda: self.selected.update(vmid=900), lambda: self.selected.update(extra='not allowed')]
        original = dict(self.selected)
        for mutate in mutations:
            self.selected = dict(original); mutate(); self.resave_packet()
            with patch.object(maintenance, 'tofu') as tofu, self.assertRaises(ValueError): self.apply()
            tofu.assert_not_called(); self.assertFalse(self.attempt.exists())
        self.selected = original; self.resave_packet(); self.packet_sha = 'f' * 64
        with patch.object(maintenance, 'tofu') as tofu, self.assertRaises(ValueError): self.apply()
        tofu.assert_not_called()

    def test_plan_or_copied_source_or_original_state_drift_refuses_before_native_action(self):
        for target in (self.evidence / 'guest.tfplan', self.evidence / 'tofu/main.tf', self.work / 'terraform.tfstate', self.catalogue):
            before = target.read_bytes(); target.write_bytes(before + b' ')
            with patch.object(maintenance, 'tofu') as tofu, self.assertRaises(ValueError): self.apply()
            tofu.assert_not_called(); self.assertFalse(self.attempt.exists()); target.write_bytes(before)

    def test_unknown_or_unrelated_plan_changes_are_refused_even_with_updated_review_digests(self):
        shown = json.loads((self.evidence / 'guest.tfplan.json').read_bytes())
        shown['resource_changes'][0]['change']['after']['cpu'][0]['cores'] = 99
        (self.evidence / 'guest.tfplan.json').write_bytes(maintenance.encoded(shown))
        review = json.loads((self.evidence / 'review-packet.json').read_bytes())
        review['plan_json_sha256'] = maintenance.digest((self.evidence / 'guest.tfplan.json').read_bytes())
        (self.evidence / 'review-packet.json').write_bytes(maintenance.encoded(review))
        self.selected['review_packet_sha256'] = maintenance.digest((self.evidence / 'review-packet.json').read_bytes()); self.resave_packet()
        with patch.object(maintenance, 'tofu') as tofu, self.assertRaises(ValueError): self.apply()
        tofu.assert_not_called()

    def test_partial_native_failure_preserves_claim_hold_failed_state_and_prevents_replay(self):
        def failed(command, environment, log, output=None):
            self.fake_native(command, environment, log, output)
            if 'apply' in command: raise RuntimeError('synthetic partial apply')
        with patch.object(maintenance, 'tofu', side_effect=failed):
            with self.assertRaises(RuntimeError): self.apply()
            before = len(self.calls)
            with self.assertRaises(ValueError): self.apply()
            self.assertEqual(len(self.calls), before)
        self.assertTrue((self.work / 'HOLD.json').exists())
        self.assertTrue((self.attempt / 'claim.json').exists())
        self.assertEqual((self.attempt / 'failed-state.json').read_bytes(), (self.work / 'terraform.tfstate').read_bytes())
        self.assertFalse((self.attempt / 'overlay.json').exists())
        self.assert_originals_preserved()

    def test_interruption_retains_marker_and_cannot_resume_or_replay(self):
        def interrupted(command, environment, log, output=None):
            self.fake_native(command, environment, log, output)
            if 'apply' in command: raise KeyboardInterrupt()
        with patch.object(maintenance, 'tofu', side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt): self.apply()
            before = len(self.calls)
            with self.assertRaises(ValueError): self.apply()
            self.assertEqual(len(self.calls), before)
        self.assertTrue((self.work / 'HOLD.json').exists())
        self.assertTrue((self.attempt / 'claim.json').exists())
        self.assertFalse((self.attempt / 'overlay.json').exists())

    def test_nas_custody_failure_stops_before_native_commands_and_never_falls_back(self):
        with patch.object(apply_network, 'nas_root', side_effect=ValueError('NAS unavailable')):
            with patch.object(maintenance, 'tofu') as tofu, self.assertRaises(ValueError): self.apply()
        tofu.assert_not_called()
        self.assertTrue((self.work / 'HOLD.json').exists())
        self.assertTrue((self.attempt / 'claim.json').exists())
        self.assertFalse((self.attempt / 'overlay.json').exists())

    def test_post_apply_nas_backup_failure_remains_held_with_original_receipts(self):
        self.deployment.backup.side_effect = [None, RuntimeError('synthetic post-apply NAS outage')]
        with patch.object(maintenance, 'tofu', side_effect=self.fake_native), self.assertRaises(RuntimeError): self.apply()
        self.assertTrue((self.work / 'HOLD.json').exists())
        self.assertFalse((self.attempt / 'overlay.json').exists())
        self.assert_originals_preserved()

    def test_post_apply_unknown_or_non_noop_verification_is_held(self):
        def drift(command, environment, log, output=None):
            self.fake_native(command, environment, log, output)
            if output and command[-1] != str(self.evidence / 'guest.tfplan'):
                value = json.loads(output.read_bytes()); value['resource_changes'][0]['change']['actions'] = ['update']
                output.write_bytes(maintenance.encoded(value))
        with patch.object(maintenance, 'tofu', side_effect=drift), self.assertRaises(ValueError): self.apply()
        self.assertTrue((self.work / 'HOLD.json').exists())
        self.assertFalse((self.attempt / 'overlay.json').exists())

    def test_later_state_or_nas_overlay_drift_is_not_adopted(self):
        with patch.object(maintenance, 'tofu', side_effect=self.fake_native): self.apply()
        for target in (self.work / 'terraform.tfstate', self.nas / self.attempt.name / 'overlay.json'):
            before = target.read_bytes(); target.write_bytes(before + b' ')
            with patch.object(maintenance, 'tofu') as tofu, self.assertRaises(ValueError): self.verify()
            tofu.assert_not_called(); target.write_bytes(before)
            self.assertTrue((self.work / 'HOLD.json').exists())
            (self.work / 'HOLD.json').unlink()  # Reset only the disposable test fixture between independent cases.
        self.assert_originals_preserved()

    def test_saved_plan_drift_during_init_stops_before_apply(self):
        def changed(command, environment, log, output=None):
            self.fake_native(command, environment, log, output)
            if 'init' in command:
                (self.evidence / 'guest.tfplan').write_bytes(b'changed after initial admission')
        with patch.object(maintenance, 'tofu', side_effect=changed), self.assertRaises(ValueError): self.apply()
        self.assertTrue(all('apply' not in call for call in self.calls))
        self.assertTrue((self.work / 'HOLD.json').exists())

    def test_extra_automatic_variables_refuse_before_any_native_command(self):
        (self.evidence / 'tofu/zz.auto.tfvars.json').write_text('{"site": "unreviewed"}')
        with patch.object(maintenance, 'tofu') as tofu, self.assertRaises(ValueError): self.apply()
        tofu.assert_not_called()

    def test_actual_saved_binary_json_mismatch_stops_before_apply(self):
        def different_binary(command, environment, log, output=None):
            self.fake_native(command, environment, log, output)
            if output and command[-1] == str(self.evidence / 'guest.tfplan'):
                output.write_bytes(b'{"actual_saved_binary":"does not match reviewed JSON"}')
        with patch.object(maintenance, 'tofu', side_effect=different_binary), self.assertRaises(ValueError): self.apply()
        self.assertTrue(all('apply' not in call for call in self.calls))
        self.assertTrue((self.work / 'HOLD.json').exists())


if __name__ == '__main__':
    unittest.main()
