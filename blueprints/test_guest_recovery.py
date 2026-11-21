"""Protected orchestration uses real private receipts; native engines are fakes."""
import copy
from contextlib import ExitStack, nullcontext
import io
import json
import os
from pathlib import Path
import runpy
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'proxmox/applications/tests'))
import guest_recovery as m
import test_component_recovery as recovery_fixture
from private_io import encoded, read_json, write_bytes, write_new


class OrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.transaction = recovery_fixture.RecoveryTransactions(); self.transaction.setUp()
        self.addCleanup(self.transaction.doCleanups)
        self.case = self.transaction.case
        self.env = {**os.environ, 'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'push',
            'GITHUB_WORKFLOW_REF': 'example/private/.github/workflows/deploy.yml@refs/heads/main',
            'RUNNER_TEMP': str(self.case.root)}
        self.packet = read_json(self.case.packet, private=True)
        self.packets = {'resolver': self.packet}

    def run_recovery(self, mode, result=None, **kwargs):
        kwargs.setdefault('guest', 'resolver')
        if mode == 'finish' and result is None: result = 'failure'
        with ExitStack() as opened:
            opened.enter_context(patch.dict(os.environ, self.env))
            opened.enter_context(patch.object(m.compiler, 'resolve_plan', return_value=self.case.plan))
            opened.enter_context(patch.object(m.compiler, 'site_path', return_value=self.case.root/'consumer/site.json'))
            opened.enter_context(patch.object(m.compiler, 'lower_plan', return_value=self.packets))
            return m.run(self.case.root/'library', self.case.root/'consumer', '[]', mode, result=result,
                         environment=self.env, **kwargs)

    def test_final_success_commits_and_later_pending_scan_does_not_reverse_accepted_history(self):
        self.case.all_phases()
        result = self.run_recovery('finish', 'success')
        self.assertEqual(result['status'], 'passed')
        self.assertFalse((self.transaction.work/'ORDINARY-HOLD.json').exists())
        self.env.update(GITHUB_RUN_ID='103', GITHUB_RUN_NUMBER='12')
        result = self.run_recovery('pending')
        self.assertEqual(result, {'status': 'ready', 'guests': []})

    def test_failed_guest_rolls_back_candidate_and_failure_is_preserved(self):
        self.case.all_phases()
        result = self.run_recovery('finish', 'failure')
        self.assertEqual(result['status'], 'failed_rolled_back')
        self.assertFalse(result['deployment_passed'])
        self.assertEqual(m.current.read(self.transaction.work)[0]['kind'], 'rollback')
        self.env.update(GITHUB_RUN_ID='103', GITHUB_RUN_NUMBER='12')
        self.assertEqual(self.run_recovery('pending')['guests'], [])

    def test_interrupted_run_recovers_before_new_guests_and_foreign_or_terminal_holds_refuse(self):
        self.transaction.fail_after_preparation()
        self.env.update(GITHUB_RUN_ID='103', GITHUB_RUN_NUMBER='12')
        result = self.run_recovery('pending')
        self.assertEqual(result['status'], 'ready')
        self.assertEqual(result['guests'][0]['status'], 'failed_rolled_back')
        write_new(self.transaction.work/'ORDINARY-HOLD.json', encoded({'operation': '/foreign/ordinary-101-1'}))
        with self.assertRaisesRegex(ValueError, 'foreign hold'):
            self.run_recovery('pending')

    def test_reverse_failure_records_terminal_result_and_does_not_retry_next_cd(self):
        operation = self.transaction.fail_after_preparation()
        with patch.object(m.recovery, 'restore', side_effect=ValueError('PRIVATE')):
            result = self.run_recovery('finish', 'failure')
        self.assertEqual(result['status'], 'recovery_required')
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertTrue((self.transaction.work/'ORDINARY-HOLD.json').exists())
        proof = operation.parent/'recovery-102-1/result.json'
        self.assertEqual(read_json(proof, private=True)['status'], 'recovery_required')
        self.env.update(GITHUB_RUN_ID='103', GITHUB_RUN_NUMBER='12')
        with patch.object(m.recovery, 'restore') as native, self.assertRaisesRegex(ValueError, 'Rollback failed'):
            self.run_recovery('pending')
        native.assert_not_called()

    def test_pending_uses_the_settled_growth_verifier_without_retrying_the_failed_writer(self):
        failed = self.transaction.fail_after_preparation()
        with patch.object(m.recovery, 'restore', side_effect=ValueError('synthetic')):
            self.assertEqual(self.run_recovery('finish')['status'], 'recovery_required')
        self.env.update(GITHUB_RUN_ID='103', GITHUB_RUN_NUMBER='12')
        with patch.object(m.recovery, 'reconcile_staging_growth', return_value=True) as verify, \
                patch.object(m.recovery, 'restore') as rollback:
            outcome = self.run_recovery('pending')
        self.assertEqual(outcome['status'], 'ready')
        self.assertEqual(verify.call_args.args[1], failed)
        rollback.assert_not_called()

    def test_reconcile_last_good_and_current_main_keep_distinct_owner_and_scoped_inputs(self):
        operation = self.transaction.fail_after_preparation()
        self.transaction.native = 'old'
        self.env.update(GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ID='104', GITHUB_RUN_NUMBER='13',
            GITHUB_WORKFLOW_REF='example/private/.github/workflows/reconcile-guest.yml@refs/heads/main')
        # Existing sealed app inputs are reused by read-only preparation. No app
        # secrets, enrollment, configuration or service writes are performed.
        for phase in self.case.cfg['deployment']['phases']:
            result = self.run_recovery('prepare', guest='resolver', baseline='current_main', reason='Engineer verified', phase=phase)
            self.assertFalse(result['guest_changed'])
        result = self.run_recovery('reconcile', guest='resolver', baseline='current_main', reason='-verified repair')
        self.assertEqual(result['status'], 'reconciled')
        self.assertEqual(m.current.read(self.transaction.work)[0]['kind'], 'reconciled')
        self.assertTrue(operation.exists())

    def test_last_good_legacy_hold_without_new_baseline_and_no_change_finish(self):
        self.assertEqual(self.run_recovery('finish')['status'], 'failed_no_change')
        operation = self.transaction.fail_after_preparation()
        (operation/'rollback-baseline.json').unlink()
        self.transaction.native = 'old'
        self.env.update(GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ID='104', GITHUB_RUN_NUMBER='13',
            GITHUB_WORKFLOW_REF='example/private/.github/workflows/reconcile-guest.yml@refs/heads/main')
        self.assertEqual(self.run_recovery('reconcile', guest='resolver', reason='Reviewed legacy repair')['status'], 'reconciled')

    def test_last_good_captured_baseline_and_source_choice_refusals(self):
        self.transaction.fail_after_preparation(); self.transaction.native = 'old'
        self.env.update(GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ID='104', GITHUB_RUN_NUMBER='13',
            GITHUB_WORKFLOW_REF='example/private/.github/workflows/reconcile-guest.yml@refs/heads/main')
        with self.assertRaises(ValueError): self.run_recovery('prepare', guest='resolver', baseline='last_good', reason='repair', phase='preparation')
        self.assertEqual(self.run_recovery('reconcile', guest='resolver', reason='Reviewed captured repair')['status'], 'reconciled')

    def test_new_control_namespace_cannot_borrow_incomplete_last_good_verification(self):
        operation = self.transaction.fail_after_preparation()
        write_new(operation/'application-rollback-limit.json', encoded({
            'schema': 'homelab-component-rollback-limit-v1', 'phase': 'application',
            'new_control_paths': ['/opt/example/new.conf']}))
        self.env.update(GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ID='104', GITHUB_RUN_NUMBER='13',
            GITHUB_WORKFLOW_REF='example/private/.github/workflows/reconcile-guest.yml@refs/heads/main')
        with patch.object(m.recovery, 'reconcile') as native, self.assertRaisesRegex(ValueError, 'complete last-good baseline'):
            self.run_recovery('reconcile', guest='resolver', reason='repair')
        native.assert_not_called()
        self.assertTrue((self.transaction.work/'ORDINARY-HOLD.json').exists())

    def test_unfinished_capture_can_be_manually_verified_and_published_acceptance_is_selectable(self):
        with patch.object(m.recovery.component_restore, 'execute', side_effect=ValueError('capture failed')):
            with self.assertRaises(ValueError): m.deploy.run('infrastructure', self.case.packet, inputs=self.case.inputs, environment={})
        self.env.update(GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ID='104', GITHUB_RUN_NUMBER='13',
            GITHUB_WORKFLOW_REF='example/private/.github/workflows/reconcile-guest.yml@refs/heads/main')
        self.assertEqual(self.run_recovery('reconcile', guest='resolver', reason='Verified unchanged baseline')['status'], 'reconciled')

    def test_pointer_before_canonical_acceptance_preserves_exact_current_run_membership(self):
        self.case.all_phases()
        with patch.object(m.recovery, 'replace_receipt', side_effect=OSError('interrupted publication')):
            with self.assertRaises(OSError): m.recovery.accept(self.case.cfg, self.transaction.work/'ordinary-102-1')
        rows = m.operations({'resolver': self.packet}, pending=False, environment=self.env)
        self.assertEqual(set(rows), {'resolver'})
        self.assertTrue(m.recovery.close_published(self.case.cfg))

    def test_selection_does_not_replay_current_future_or_omitted_cohort_operations(self):
        operation = self.transaction.fail_after_preparation()
        self.assertEqual(self.run_recovery('pending')['guests'], [])
        cfg = copy.deepcopy(self.case.cfg); cfg['paths']['state_root'] = str(self.case.root/'absent')
        packet = {'files': {'site.json': json.dumps(cfg)}}
        self.assertEqual(m.operations({'resolver': packet}, pending=True, environment=self.env), {})
        rows = m.operations({'resolver': self.packet}, pending=False, environment=self.env)
        decision = m.decision('resolver', self.case.cfg, operation, 'accept'); self.assertEqual(decision, 'accept')
        self.assertEqual(m.decision('resolver', self.case.cfg, operation, 'rollback'), decision)
        # Another guest's failed operation is not part of this guest's decision.
        foreign = self.case.state/'611'/operation.name; foreign.mkdir(parents=True, mode=0o700)
        write_new(foreign/'rollback-baseline.json', b'{}\n')
        write_new(foreign.parent/'ORDINARY-HOLD.json', b'{}\n')
        self.assertEqual(m.decision('resolver', self.case.cfg, operation, 'rollback'), 'accept')
        self.assertTrue((foreign.parent/'ORDINARY-HOLD.json').exists())

    def test_other_guest_failed_or_unknown_custody_cannot_block_success_or_trigger_rollback(self):
        # A sibling packet cannot even be decoded. It is outside this job's scope.
        self.packets['sibling'] = {'files': {'site.json': 'unreadable sibling configuration'}}
        foreign = self.case.state/'611'; foreign.mkdir(mode=0o700)
        write_new(foreign/'ORDINARY-HOLD.json', b'preserved sibling failure\n')
        write_new(foreign/'ordinary-complete.json', b'preserved sibling success\n')
        before = {p.name: p.read_bytes() for p in foreign.iterdir()}
        self.case.all_phases()
        self.assertEqual(self.run_recovery('finish', 'success')['status'], 'passed')
        self.assertFalse((self.transaction.work/'ORDINARY-HOLD.json').exists())
        self.assertEqual({p.name: p.read_bytes() for p in foreign.iterdir()}, before)
        self.env.update(GITHUB_RUN_ID='103', GITHUB_RUN_NUMBER='12')
        self.assertEqual(self.run_recovery('pending')['status'], 'ready')
        self.assertEqual({p.name: p.read_bytes() for p in foreign.iterdir()}, before)

    def test_failed_guest_recovery_does_not_touch_sibling_success(self):
        self.packets['sibling'] = {'files': {'site.json': 'outside this guest'}}
        foreign = self.case.state/'611'; foreign.mkdir(mode=0o700)
        write_new(foreign/'ordinary-complete.json', b'completed sibling deployment\n')
        before = (foreign/'ordinary-complete.json').read_bytes()
        self.transaction.fail_after_preparation()
        self.assertEqual(self.run_recovery('finish', 'failure')['status'], 'failed_rolled_back')
        self.assertEqual((foreign/'ordinary-complete.json').read_bytes(), before)
        self.assertEqual(sorted(p.name for p in foreign.iterdir()), ['ordinary-complete.json'])

    def test_legacy_accept_decision_is_resumed_for_only_its_selected_guest(self):
        self.case.all_phases()
        operation = self.transaction.work/'ordinary-102-1'
        root = self.case.state/'deployments'; root.mkdir(mode=0o700)
        folder = root/'102-1'; folder.mkdir(mode=0o700)
        from private_io import sha
        legacy = {'schema': 'homelab-component-deployment-decision-v1', 'mode': 'accept',
                  'members': {'resolver': {'operation': str(operation), 'baseline_sha256': sha(operation/'rollback-baseline.json')},
                              'other': {'operation': '/not-read', 'baseline_sha256': 'not-read'}}}
        write_new(folder/'decision.json', encoded(legacy))
        self.env.update(GITHUB_RUN_ID='103', GITHUB_RUN_NUMBER='12')
        self.assertEqual(self.run_recovery('pending')['guests'][0]['status'], 'accepted')
        self.assertEqual(read_json(folder/'decision.json', private=True), legacy)
        self.assertFalse((self.transaction.work/'ORDINARY-HOLD.json').exists())

    def test_guest_decision_refuses_changed_baseline_or_conflicting_legacy_decision(self):
        operation = self.transaction.fail_after_preparation()
        self.assertEqual(m.decision('resolver', self.case.cfg, operation, 'rollback'), 'rollback')
        path = self.transaction.work/'recovery-102-1/decision.json'
        saved = read_json(path, private=True)
        write_bytes(path, encoded({**saved, 'mode': 'unknown'}))
        with self.assertRaisesRegex(ValueError, 'exact guest'): m.decision('resolver', self.case.cfg, operation, 'accept')
        write_bytes(path, encoded(saved))
        root = self.case.state/'deployments'; root.mkdir(mode=0o700)
        folder = root/'102-1'; folder.mkdir(mode=0o700)
        write_new(folder/'decision.json', encoded({'schema': 'bad'}))
        with self.assertRaisesRegex(ValueError, 'legacy'): m.decision('resolver', self.case.cfg, operation, 'accept')
        write_bytes(folder/'decision.json', encoded({'schema': 'homelab-component-deployment-decision-v1',
            'mode': 'accept', 'members': {'resolver': saved['member']}}))
        with self.assertRaisesRegex(ValueError, 'exact guest'): m.decision('resolver', self.case.cfg, operation, 'accept')

    def test_legacy_decision_rejects_public_parent(self):
        operation = self.transaction.fail_after_preparation()
        root = self.case.state/'deployments'; root.mkdir(mode=0o700)
        folder = root/'102-1'; folder.mkdir(mode=0o700)
        write_new(folder/'decision.json', encoded({'schema': 'unused'}))
        root.chmod(0o755)
        with self.assertRaises(ValueError):
            m.decision('resolver', self.case.cfg, operation, 'rollback')

    def test_success_without_completed_candidate_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'completed deployment candidate'):
            self.run_recovery('finish', 'success')

    def test_scoped_expected_input_preparation_reuses_readonly_agent_and_backup_contracts(self):
        import component_inputs
        import component_prepare
        import component_ownership
        import component_input_secrets
        import backup_agent
        from unittest.mock import Mock
        cfg = copy.deepcopy(self.case.cfg)
        phases = cfg['deployment']['phases']
        app_phase = next(iter(cfg['deployment']['applications']))
        phases.extend(['zabbix-agent', 'pbs-agent'])
        cfg['deployment']['payload_phases'].update({'zabbix-agent': 'agent', 'pbs-agent': 'backup-agent'})
        cfg['app']['backup'] = {'profile': 'pbs'}
        runtime = read_json(Path(cfg['deployment']['runtime_file']), private=True)['applications']
        payload = Mock(); payload.check.return_value = {'synthetic': True}
        packet = {'files': {'site.json': json.dumps(cfg)}}
        with patch.object(component_inputs, 'prepare', return_value=(cfg, Path(cfg['deployment']['input_directory'])/'site.json')), \
                patch.object(component_inputs, 'binding', return_value={'fixed': True}), \
                patch.object(m.generation, 'previous', return_value=(self.transaction.owner, self.case.cfg, runtime)), \
                patch.object(component_prepare, 'prepare_agent', return_value=payload) as agent, \
                patch.object(backup_agent, 'inputs', return_value={}) as backup, \
                patch.object(component_prepare, 'prepare_backup') as enroll, \
                patch.object(component_ownership, 'prior', return_value=True), \
                patch.object(component_input_secrets, 'slots', return_value={'secret': 'HOMELAB_APP_SECRET_SELECTED'}), \
                patch.object(component_prepare, 'prepare', return_value=payload) as app:
            env = {**self.env, 'HOMELAB_APP_SECRET_SELECTED': 'scoped', 'HOMELAB_APP_SECRET_FOREIGN': 'foreign'}
            for phase in ('zabbix-agent', 'pbs-agent', app_phase): m.target(packet, self.transaction.work, env, phase=phase)
            self.assertFalse(any(key.startswith('HOMELAB_APP_SECRET_') for key in agent.call_args.args[1]))
            self.assertEqual(app.call_args.args[2]['HOMELAB_APP_SECRET_SELECTED'], 'scoped')
            self.assertNotIn('HOMELAB_APP_SECRET_FOREIGN', app.call_args.args[2])
            backup.assert_called_once(); enroll.assert_not_called()

    def test_context_results_choices_and_reason_reject_untrusted_inputs_before_native(self):
        for key, value in [('GITHUB_REF', 'refs/heads/feature'), ('GITHUB_EVENT_NAME', 'pull_request'),
                           ('GITHUB_REPOSITORY', 'invalid'), ('GITHUB_WORKFLOW_REF', 'foreign@refs/heads/main'),
                           ('GITHUB_RUN_ID', '0'), ('GITHUB_RUN_ATTEMPT', 'bad'), ('GITHUB_RUN_NUMBER', '0')]:
            with self.subTest(key=key), patch.dict(self.env, {key: value}), self.assertRaises(ValueError):
                self.run_recovery('pending')
        for result in ('passed', 'cancelled', 'skipped', '{}'):
            with self.assertRaises(ValueError): self.run_recovery('finish', result)
        with self.assertRaises(ValueError): self.run_recovery('pending', 'success')
        for guest in (None, 'unknown'):
            with self.assertRaises(ValueError): self.run_recovery('pending', guest=guest)
        self.env.update(GITHUB_EVENT_NAME='workflow_dispatch',
            GITHUB_WORKFLOW_REF='example/private/.github/workflows/reconcile-guest.yml@refs/heads/main')
        for kwargs in ({'guest': 'unknown'}, {'guest': 'resolver', 'baseline': 'unknown'},
                       {'guest': 'resolver', 'reason': ' '}, {'guest': 'resolver', 'reason': 'x'*1025}):
            with self.assertRaises(ValueError): self.run_recovery('reconcile', **kwargs)
        self.env['GITHUB_WORKFLOW_REF'] = 'example/private/.github/workflows/other.yml@refs/heads/main'
        with self.assertRaises(ValueError): self.run_recovery('reconcile', guest='resolver', reason='repair')

    def test_cli_exit_codes_summary_and_sanitized_errors(self):
        argv = ['recovery', '--stack', 'stack', '--site-root', 'site', '--mode', 'finish', '--guest', 'resolver', '--result', 'success']
        summary = self.case.root/'summary.txt'
        for status, code in [('passed', 0), ('ready', 0), ('reconciled', 0), ('prepared', 0),
                             ('failed_rolled_back', 1), ('failed_no_change', 1), ('recovery_required', 1)]:
            with patch.object(sys, 'argv', argv), patch.object(m, 'run', return_value={'status': status}), \
                    patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': str(summary)}), patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(m.main(), code)
        self.assertIn('failed_rolled_back', summary.read_text())
        with patch.object(sys, 'argv', argv), patch.object(m, 'run', side_effect=ValueError('PRIVATE')), \
                patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(m.main(), 1)
        self.assertNotIn('PRIVATE', out.getvalue())
        with patch.object(sys, 'argv', argv), patch.object(m, 'run', return_value={'status': 'passed'}), \
                patch.dict(os.environ, {}, clear=True), patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(m.main(), 0)
        with patch.object(sys, 'argv', argv), patch.object(m.compiler, 'site_path', side_effect=ValueError), \
                patch('sys.stdout', new_callable=io.StringIO), self.assertRaises(SystemExit) as stopped:
            runpy.run_path(m.__file__, run_name='__main__')
        self.assertEqual(stopped.exception.code, 1)


class GuestIsolationTests(unittest.TestCase):
    def test_multiple_guest_settlement_is_refused_before_any_native_action(self):
        rows = {name: ({}, Path('/unused')/name/'ordinary-102-1', {}) for name in ['provider', 'consumer']}
        with patch.object(m.recovery, 'locked') as native, self.assertRaisesRegex(ValueError, 'only the selected guest'):
            m.settle(rows, 'rollback')
        native.assert_not_called()


if __name__ == '__main__': unittest.main()
