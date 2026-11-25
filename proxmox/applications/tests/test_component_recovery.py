"""Real custody/receipt transactions; native deployment and inspection are fakes."""
import copy
import base64
import os
from pathlib import Path
import sys
import tempfile
import subprocess
from types import SimpleNamespace
from contextlib import nullcontext
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT/'blueprints'), str(ROOT/'proxmox/applications')]
import component_current
import component_ansible
import component_generation
import component_recovery
import component_restore
import deploy
from private_io import encoded, read_json, sha, write_new, write_bytes
import test_component_deployment as fixture


class RecoveryTransactions(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.trust = Path(temporary.name).resolve(); self.trust.chmod(0o700)
        for name in ('key', 'token', 'known_hosts'):
            write_new(self.trust/name, ('synthetic-'+name+'\n').encode())
        original = fixture.site
        def source():
            value = original()
            value['secret_sources']['token']['path'] = str(self.trust/'token')
            value['secret_sources']['ssh']['path'] = str(self.trust/'key')
            value['contexts']['lab']['trust']['known_hosts'] = str(self.trust/'known_hosts')
            return value
        with patch.object(fixture, 'site', side_effect=source):
            self.case = fixture.DeploymentIntegrationTests(); self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.case.all_phases()
        self.cfg, self.work = self.case.cfg, self.case.state/'610'
        self.before = (self.work/'ordinary-complete.json').read_bytes()
        self.owner = read_json(self.work/'ordinary-complete.json', private=True)
        self.native = 'old'; self.inspections = []
        context = patch('component_restore.execute', side_effect=self.controls)
        context.start(); self.addCleanup(context.stop)
        context = patch.dict(os.environ, {'HOMELAB_CD_RECOVERY': 'v1', 'GITHUB_ACTOR': 'example-engineer',
            'GITHUB_RUN_ID': '102', 'GITHUB_RUN_NUMBER': '11',
            'HOMELAB_CD_DEPENDENCIES': '{"resolver": []}'})
        context.start(); self.addCleanup(context.stop)

    def controls(self, cfg, operation, selection, *, mode, captured=None, allowed=None):
        self.inspections.append(mode)
        self.assertEqual(cfg['guest']['vmid'], 610)
        if mode == 'restore':
            self.native = 'old'
        elif mode == 'verify' and self.native != 'old':
            raise ValueError('Synthetic service has not been restored')
        files = {}
        sources = [*Path(cfg['deployment']['input_directory']).rglob('*'),
                   ROOT/'proxmox/applications/component-preflight.py']
        raw = {sha(path): path.read_bytes() for path in sources if path.is_file()}
        for path in selection['files']:
            wanted = selection['expected'].get(path)
            files[path] = ({'exists': True, 'content': base64.b64encode(raw[wanted]).decode(),
                'sha256': wanted, **selection['metadata'][path]} if wanted else {'exists': False})
        return {'files': files,
                'packages': [], 'images': []}

    def fail_after_preparation(self):
        deploy.run('infrastructure', self.case.packet, inputs=self.case.inputs, environment={})
        deploy.run('preparation', self.case.packet, inputs=self.case.inputs, environment={})
        self.native = 'new'
        return self.work/'ordinary-102-1'

    def test_caught_failure_can_reverse_but_unknown_or_timed_out_writer_requires_reconciliation(self):
        failed = self.fail_after_preparation()
        phase = next(iter(self.cfg['deployment']['applications']))
        with patch('component_ansible.run_phase', side_effect=ValueError('PRIVATE')):
            with self.assertRaises(ValueError): deploy.run(phase, self.case.packet, inputs=self.case.inputs, environment={})
        marker = read_json(failed/'forward-failure.json', private=True)
        self.assertTrue(marker['command_returned'])
        self.assertNotIn('PRIVATE', (failed/'forward-failure.json').read_text())
        marker['command_returned'] = False
        write_bytes(failed/'forward-failure.json', encoded(marker))
        with self.assertRaisesRegex(ValueError, 'uncertain forward'): component_recovery.restore(self.cfg, failed)
        write_bytes(failed/'forward-failure.json', encoded({**marker, 'command_returned': True}))
        self.assertEqual(component_recovery.restore(self.cfg, failed)['status'], 'failed_rolled_back')

    def test_timeout_record_and_incomplete_reverse_apply_or_configuration_are_not_replayed(self):
        failed = self.fail_after_preparation()
        phase = next(iter(self.cfg['deployment']['applications']))
        with patch('component_ansible.run_phase', side_effect=subprocess.TimeoutExpired('PRIVATE', 1)):
            with self.assertRaises(subprocess.TimeoutExpired): deploy.run(phase, self.case.packet, inputs=self.case.inputs, environment={})
        self.assertFalse(read_json(failed/'forward-failure.json', private=True)['command_returned'])
        write_new(failed/'apply-window.json', encoded({'started_at_ns': 1}))
        with self.assertRaises(ValueError): component_recovery.forward_settled(failed, read_json(self.work/'ORDINARY-HOLD.json', private=True))
        recovery = self.work/'recovery-102-1'; recovery.mkdir(mode=0o700)
        folder = recovery/'infrastructure-1'; folder.mkdir(mode=0o700)
        write_new(folder/'apply-window.json', encoded({'started_at_ns': 1}))
        with self.assertRaises(ValueError): component_recovery.reverse_settled(recovery, 'infrastructure')
        write_bytes(folder/'apply-window.json', encoded({'started_at_ns': 1, 'finished_at_ns': 2}))
        component_recovery.reverse_settled(recovery, 'infrastructure')
        folder = recovery/'controls-restore-1'; folder.mkdir(mode=0o700)
        with self.assertRaises(ValueError): component_recovery.reverse_settled(recovery, 'controls-restore')
        write_new(folder/'result.json', encoded({'files': {}}))
        component_recovery.reverse_settled(recovery, 'controls-restore')

    def test_ansible_unreachable_return_preserves_hold_without_reversing_remote_writer(self):
        failed = self.fail_after_preparation()
        phase = next(iter(self.cfg['deployment']['applications']))
        def unreachable(argv, environment, log):
            write_new(log, ('PLAY RECAP '+ '*'*20+'\n'+self.cfg['app']['hostname']+
                ' : ok=1 changed=1 unreachable=1 failed=0 skipped=0 rescued=0 ignored=0\n').encode())
            raise subprocess.CalledProcessError(4, argv, output='PRIVATE')
        with patch.object(component_ansible, 'quiet', side_effect=unreachable):
            with self.assertRaises(subprocess.CalledProcessError):
                deploy.run(phase, self.case.packet, inputs=self.case.inputs, environment={})
        self.assertFalse(read_json(failed/'forward-failure.json', private=True)['command_returned'])
        self.assertNotIn('PRIVATE', (failed/'forward-failure.json').read_text())
        calls = len(self.case.infra)
        self.inspections.clear()
        with self.assertRaisesRegex(ValueError, 'uncertain forward'): component_recovery.restore(self.cfg, failed)
        self.assertEqual(len(self.case.infra), calls)
        self.assertEqual(self.inspections, [])
        self.assertTrue((self.work/'ORDINARY-HOLD.json').exists())

    def test_ansible_completed_task_failure_can_rollback_with_failed_run_evidence(self):
        failed = self.fail_after_preparation()
        phase = next(iter(self.cfg['deployment']['applications']))
        def failed_task(argv, environment, log):
            write_new(log, ('PLAY RECAP '+ '*'*20+'\n'+self.cfg['app']['hostname']+
                ' : ok=1 changed=1 unreachable=0 failed=1 skipped=0 rescued=0 ignored=0\n').encode())
            raise subprocess.CalledProcessError(2, argv)
        with patch.object(component_ansible, 'quiet', side_effect=failed_task):
            with self.assertRaises(component_ansible.CompletedTaskFailure):
                deploy.run(phase, self.case.packet, inputs=self.case.inputs, environment={})
        self.assertTrue(read_json(failed/'forward-failure.json', private=True)['command_returned'])
        self.assertEqual(component_recovery.restore(self.cfg, failed)['status'], 'failed_rolled_back')
        self.assertTrue((failed/'forward-failure.json').exists())

    def test_only_a_complete_reachable_single_host_failure_recap_is_settled(self):
        log = self.trust/'failed.log'
        error = subprocess.CalledProcessError(2, ['ansible-playbook'])
        valid = 'PLAY RECAP '+ '*'*20+'\nexample : ok=1 changed=0 unreachable=0 failed=1 skipped=0 rescued=0 ignored=0\n'
        for content in (b'no recap', valid.replace('unreachable=0', 'unreachable=1').encode(),
                        valid.replace('failed=1', 'failed=0').encode(),
                        (valid+valid.partition('\n')[2].replace('example', 'foreign')).encode(), b'\xff'):
            write_bytes(log, content)
            self.assertFalse(component_ansible.completed_failure(error, log, 'example'))
        write_bytes(log, valid.encode())
        self.assertTrue(component_ansible.completed_failure(error, log, 'example'))
        self.assertFalse(component_ansible.completed_failure(error, log, 'other'))
        self.assertFalse(component_ansible.completed_failure(subprocess.CalledProcessError(-9, error.cmd), log, 'example'))
        self.assertFalse(component_ansible.completed_failure(error, self.trust/'missing.log', 'example'))

    def test_pre_mutation_failure_releases_only_its_unchanged_hold(self):
        before = sha(self.work/'terraform.tfstate')
        with patch.object(component_restore, 'execute', side_effect=ValueError('capture refused')):
            with self.assertRaises(ValueError): deploy.run('infrastructure', self.case.packet, inputs=self.case.inputs, environment={})
        with patch.object(component_restore, 'verify_agents') as agents:
            result = component_recovery.restore(self.cfg, self.work/'ordinary-102-1')
        agents.assert_not_called()
        self.assertEqual(result['status'], 'failed_no_change')
        self.assertEqual(sha(self.work/'terraform.tfstate'), before)
        self.assertFalse((self.work/'ORDINARY-HOLD.json').exists())
        component_recovery.release(self.work, {})

    def test_first_installation_can_complete_without_a_rollback_owner(self):
        original = fixture.site
        def source():
            value = original()
            value['secret_sources']['token']['path'] = str(self.trust/'token')
            value['secret_sources']['ssh']['path'] = str(self.trust/'key')
            value['contexts']['lab']['trust']['known_hosts'] = str(self.trust/'known_hosts')
            return value
        with patch.object(fixture, 'site', side_effect=source):
            case = fixture.DeploymentIntegrationTests(); case.setUp(); self.addCleanup(case.doCleanups)
        case.all_phases()
        work = case.state/'610'; operation = work/'ordinary-101-1'
        self.assertIsNone(read_json(operation/'rollback-baseline.json', private=True)['owner'])
        self.assertEqual(component_recovery.accept(case.cfg, operation)['status'], 'accepted')
        self.assertFalse((work/'ORDINARY-HOLD.json').exists())

    def test_completed_verification_is_immutable_and_new_held_operation_is_not_closed(self):
        operation = self.fail_after_preparation()
        component_recovery.restore(self.cfg, operation)
        state, _ = component_current.read(self.work)
        proof = Path(state['verification']['path']); raw = proof.read_bytes()
        component_recovery.verified(self.work, proof.parent, 'rollback', Path(state['owner']['path']),
            state['state_sha256'], state['state_identity'], state['resolved'], reason='Continuation preserves original note')
        self.assertEqual(proof.read_bytes(), raw)
        with patch.dict(os.environ, {'GITHUB_RUN_ID': '103', 'GITHUB_RUN_NUMBER': '12'}):
            deploy.run('infrastructure', self.case.packet, inputs=self.case.inputs, environment={})
        self.assertFalse(component_recovery.close_published(self.cfg))
        self.assertTrue((self.work/'ORDINARY-HOLD.json').exists())

    def test_backend_change_after_reverse_checkpoint_refuses_verification(self):
        operation = self.fail_after_preparation()
        component_recovery.restore(self.cfg, operation, finalize=False)
        backend = self.work/'terraform.tfstate'; state = read_json(backend, private=True); state['serial'] += 1
        write_bytes(backend, encoded(state))
        with self.assertRaisesRegex(ValueError, 'checkpoint changed'):
            component_recovery.verify_restore(self.cfg, operation)
        self.assertTrue((self.work/'ORDINARY-HOLD.json').exists())

    def test_foreign_repository_workflow_and_fabricated_canonical_owner_refuse_before_native(self):
        operation = self.fail_after_preparation()
        import proxmox_guest
        with patch.object(proxmox_guest, 'infrastructure') as native:
            with patch.dict(os.environ, {'GITHUB_REPOSITORY': 'foreign/repository'}):
                with self.assertRaisesRegex(ValueError, 'another repository'):
                    component_recovery.restore(self.cfg, operation)
                with self.assertRaisesRegex(ValueError, 'foreign workflow'):
                    component_recovery.reconcile(self.cfg, operation, Path(self.owner['operation'])/'complete.json', self.owner,
                        reason='repair', actor_context='protected-main-reconciliation')
            hold = read_json(self.work/'ORDINARY-HOLD.json', private=True)
            hold['workflow'] = ['foreign/repository', 'foreign/repository/.github/workflows/deploy.yml']
            write_bytes(self.work/'ORDINARY-HOLD.json', encoded(hold))
            with self.assertRaisesRegex(ValueError, 'foreign workflow'):
                component_recovery.reconcile(self.cfg, operation, Path(self.owner['operation'])/'complete.json', self.owner,
                    reason='repair', actor_context='protected-main-reconciliation')
            forged = copy.deepcopy(self.owner); forged['operation'] = str(self.work/'ordinary-99-1')
            write_bytes(self.work/'ordinary-complete.json', encoded(forged))
            with self.assertRaises(FileNotFoundError):
                component_recovery.reconcile(self.cfg, operation, Path(self.owner['operation'])/'complete.json', self.owner,
                    reason='repair', actor_context='protected-main-reconciliation')
        native.assert_not_called()
        self.assertTrue((self.work/'ORDINARY-HOLD.json').exists())

    def test_same_repository_foreign_workflow_cannot_borrow_a_previous_owner(self):
        operation = self.fail_after_preparation()
        baseline = read_json(operation/'rollback-baseline.json', private=True)
        baseline['marker']['workflow'][1] = 'example/private/.github/workflows/foreign.yml'
        write_bytes(operation/'rollback-baseline.json', encoded(baseline))
        write_bytes(self.work/'ORDINARY-HOLD.json', encoded(baseline['marker']))
        import proxmox_guest
        with patch.object(proxmox_guest, 'infrastructure') as native, self.assertRaisesRegex(ValueError, 'deployment workflows'):
            component_recovery.restore(self.cfg, operation)
        native.assert_not_called()

    def test_immutable_recovery_attempts_are_bounded_and_new_installations_remain_allowed(self):
        directory = self.work/'recovery-200-1'; directory.mkdir(mode=0o700)
        for index in range(8): self.assertEqual(component_recovery.attempt_directory(directory, 'infrastructure').name, 'infrastructure-'+str(index+1))
        with self.assertRaisesRegex(ValueError, 'limit reached'): component_recovery.attempt_directory(directory, 'infrastructure')
        with self.assertRaises(ValueError): component_recovery.attempt_directory(directory, '../foreign')
        file = directory/'proof.json'; component_recovery.once(file, {'a': 1}); component_recovery.once(file, {'a': 1})
        with self.assertRaises(ValueError): component_recovery.once(file, {'a': 2})
        self.fail_after_preparation()
        phase = next(iter(self.cfg['deployment']['applications']))
        import component_ansible
        original = component_ansible.run_phase
        with patch.object(component_restore, 'descriptor', return_value={'files': {'/opt/example/new.conf': None}}), \
                patch('component_ansible.run_phase', wraps=original) as native:
            self.assertEqual(deploy.run(phase, self.case.packet, inputs=self.case.inputs, environment={})['status'], 'passed')
        native.assert_called_once()
        operation = self.work/'ordinary-102-1'
        self.assertEqual(read_json(operation/(phase+'-rollback-limit.json'), private=True)['new_control_paths'], ['/opt/example/new.conf'])
        with self.assertRaisesRegex(ValueError, 'newly installed control namespace'):
            component_recovery.restore(self.cfg, operation)
        with patch.dict(os.environ, {'HOMELAB_CD_RECOVERY': 'unknown'}), self.assertRaises(ValueError): component_recovery.enabled()

    def test_candidate_accept_interruption_finishes_metadata_without_repeating_native_work(self):
        self.case.all_phases(); operation = self.work/'ordinary-102-1'
        with patch.object(component_recovery, 'replace_receipt', side_effect=OSError('synthetic publication interruption')):
            with self.assertRaises(OSError): component_recovery.accept(self.cfg, operation)
        calls = list(self.inspections)
        self.assertTrue(component_recovery.close_published(self.cfg))
        self.assertEqual(calls, self.inspections)
        self.assertFalse(component_recovery.close_published(self.cfg))
        self.assertEqual(component_current.read(self.work)[0]['kind'], 'ordinary')

    def test_reversal_resumes_completed_native_checkpoints_and_published_exact_hold(self):
        operation = self.fail_after_preparation()
        component_recovery.restore(self.cfg, operation, finalize=False)
        calls = list(self.inspections)
        component_recovery.restore(self.cfg, operation, finalize=False)
        self.assertEqual(self.inspections, calls)
        release = component_recovery.release
        with patch.object(component_recovery, 'release', side_effect=OSError('synthetic interruption')):
            with self.assertRaises(OSError): component_recovery.finish_restore(self.cfg, operation)
        self.assertEqual(component_recovery.restore(self.cfg, operation)['status'], 'failed_rolled_back')
        self.assertFalse((self.work/'ORDINARY-HOLD.json').exists())

    def test_manual_last_good_with_captured_controls_and_legacy_identity(self):
        operation = self.fail_after_preparation(); self.native = 'old'
        owner = copy.deepcopy(self.owner); owner.pop('state_identity')
        write_bytes(self.work/'ordinary-complete.json', encoded(owner))
        immutable = Path(owner['operation'])/'complete.json'; write_bytes(immutable, encoded(owner))
        with patch.dict(os.environ, {'GITHUB_RUN_ID': '104', 'GITHUB_RUN_NUMBER': '13'}):
            result = component_recovery.reconcile(self.cfg, operation, immutable, owner,
                reason='Verified engineer repair', actor_context='protected-main-reconciliation',
                expected_controls=read_json(operation/'controls-before.json', private=True))
        self.assertEqual(result['status'], 'reconciled')

    def test_settled_growth_reconcile_keeps_old_controls_and_allows_the_fresh_run(self):
        import proxmox_guest

        failed = self.fail_after_preparation()
        self.native = 'old'
        immutable = Path(self.owner['operation'])/'complete.json'
        proof = {'bytes': 5*1024**3, 'inode': 9, 'mode': 0o755, 'uid': 0, 'gid': 0, 'source': 'synthetic'}
        write_new(failed/'backup-staging-after.json', encoded(proof))
        held = copy.deepcopy(self.cfg)
        verified_mounted_proof = dict(proof, inode=15)

        def inspect(cfg, source, work, operation, binding, **kwargs):
            self.assertEqual(cfg, held)
            self.assertEqual(kwargs['previous_configuration'], held)
            self.assertTrue(kwargs['verify_only'])
            write_bytes(operation/'backup-staging-after.json', encoded(verified_mounted_proof))

        options = {'reason': 'Verified staging', 'actor_context': 'protected-main-reconciliation',
                   'expected_controls': read_json(failed/'controls-before.json', private=True),
                   'staging_growth': (held, self.owner['binding'])}
        with patch.dict(os.environ, {'GITHUB_RUN_ID': '104', 'GITHUB_RUN_NUMBER': '13'}):
            with patch.object(proxmox_guest, 'infrastructure', side_effect=inspect):
                with self.assertRaisesRegex(ValueError, 'exact expanded staging filesystem'):
                    component_recovery.reconcile(self.cfg, failed, immutable, self.owner, **options)
                self.assertTrue((self.work/'ORDINARY-HOLD.json').exists())
                verified_mounted_proof = proof
                self.assertEqual(component_recovery.reconcile(self.cfg, failed, immutable, self.owner,
                    **options)['status'], 'reconciled')
            state, owner = component_current.read(self.work)
            self.assertEqual(component_current.epoch(state), (102, 1))
            self.assertEqual(owner['phase_inputs'], self.owner['phase_inputs'])
            self.assertFalse((self.work/'ORDINARY-HOLD.json').exists())
            self.case.all_phases()
            self.assertTrue((self.work/'ordinary-104-1/complete.json').is_file())

    def test_staging_reconciliation_requires_the_exact_settled_receipts(self):
        import backup_staging

        failed = self.work/'ordinary-102-1'
        failed.mkdir(mode=0o700)
        self.assertFalse(component_recovery.reconcile_staging_growth(self.cfg, failed))
        growth = failed/'staging-growth'
        growth.mkdir(mode=0o700)
        marker = {'operation': str(failed), 'binding': {'vmid': 610}}
        previous = {'guest': {'vmid': 610}, 'site': {'node': 'test'}, 'app': {'backup': {'job': {
            'staging': {'path': '/srv/stage', 'size_bytes': 4*1024**3}}}}}
        previous['guest']['storage_id'] = 'local'
        held = copy.deepcopy(previous)
        held['app']['backup']['job']['staging']['size_bytes'] = 5*1024**3
        volume = 'local:subvol-610-disk-2'
        task = 'UPID:test:AB:CD:EF:resize:610:synthetic:'
        receipts = {
            self.work/'ORDINARY-HOLD.json': marker,
            failed/'rollback-baseline.json': {'synthetic': True},
            failed/'forward-failure.json': {'schema': 'homelab-component-forward-failure-v1',
                'marker_sha256': component_recovery.digest(encoded(marker)), 'command_returned': True},
            failed/'apply-window.json': {'finished_at_ns': 5, 'plan_sha256': 'mocked'},
            failed/'plan.json': {'binding': marker['binding'], 'plan_sha256': 'mocked'},
            failed/'controls-before.json': {'files': {}},
            growth/'request.json': {'volume': volume, 'previous_size': '4G',
                                   'request': {'disk': 'mp1', 'size': '5G'}},
            growth/'task.json': {'upid': task},
            growth/'result.json': {'upid': task, 'status': 'stopped', 'exitstatus': 'OK'},
        }
        for path, value in receipts.items():
            write_new(path, encoded(value))
        write_new(failed/'rollback-ready.json', encoded({
            'baseline_sha256': sha(failed/'rollback-baseline.json'),
            'controls_sha256': sha(failed/'controls-before.json')}))
        original = Path(self.owner['operation'])/'complete.json'
        with patch.object(component_recovery, 'locked', side_effect=lambda cfg: nullcontext(self.work)), \
                patch.object(component_recovery, 'baseline', return_value={'marker': marker}), \
                patch.object(component_recovery, 'owner', return_value=(original, self.owner, previous)), \
                patch.object(component_generation, 'sealed_inputs', return_value=(held, {})), \
                patch.object(backup_staging, 'original', return_value=False), \
                patch.object(backup_staging, 'backend_mounts', return_value=[{'path': '/srv/data'},
                    {'path': '/srv/stage', 'volume': volume}]), patch.object(component_recovery, 'reconcile') as publish:
            for name, key, value in (('apply-window.json', 'plan_sha256', 'changed'),
                                     ('forward-failure.json', 'command_returned', False),
                                     ('staging-growth/result.json', 'exitstatus', 'failed')):
                path = failed/name
                write_bytes(path, encoded({**receipts[path], key: value}))
                with self.assertRaises(ValueError):
                    component_recovery.reconcile_staging_growth(held, failed)
                write_bytes(path, encoded(receipts[path]))
            publish.assert_not_called()
            self.assertTrue(component_recovery.reconcile_staging_growth(held, failed))
        publish.assert_called_once()
        self.assertEqual(publish.call_args.kwargs['staging_growth'], (held, marker['binding']))

    def test_partial_failure_rolls_back_without_history_rewrite_and_next_cd_completes(self):
        failed = self.fail_after_preparation()
        old = {p.name: p.read_bytes() for p in Path(self.owner['operation']).glob('*.json')}
        with component_recovery.locked(self.cfg):
            result = component_recovery.restore(self.cfg, failed)
        self.assertEqual(result['status'], 'failed_rolled_back')
        self.assertEqual(self.native, 'old')
        self.assertFalse((self.work/'ORDINARY-HOLD.json').exists())
        self.assertEqual((self.work/'ordinary-complete.json').read_bytes(), self.before)
        self.assertEqual(old, {p.name: p.read_bytes() for p in Path(self.owner['operation']).glob('*.json')})
        self.assertTrue(failed.is_dir())
        self.assertFalse((failed/'complete.json').exists())
        state, owner = component_current.read(self.work)
        self.assertEqual(state['kind'], 'rollback')
        self.assertEqual(owner, self.owner)
        self.assertNotEqual(state['state_sha256'], owner['state_sha256'])
        with patch.dict(os.environ, {'GITHUB_RUN_ID': '103', 'GITHUB_RUN_NUMBER': '12'}):
            self.case.all_phases()
            self.assertEqual((self.work/'ordinary-complete.json').read_bytes(), self.before)
            with component_recovery.locked(self.cfg):
                component_recovery.accept(self.cfg, self.work/'ordinary-103-1')
        self.assertEqual(component_current.read(self.work)[0]['kind'], 'ordinary')
        self.assertFalse((self.work/'ORDINARY-HOLD.json').exists())
        self.assertEqual(read_json(self.work/'ordinary-complete.json', private=True)['run_number'], 12)

    def test_failed_restore_keeps_hold_and_old_pointer(self):
        failed = self.fail_after_preparation()
        hold = (self.work/'ORDINARY-HOLD.json').read_bytes()
        with patch.object(component_restore, 'execute', side_effect=ValueError('restore refused')):
            with component_recovery.locked(self.cfg), self.assertRaises(ValueError):
                component_recovery.restore(self.cfg, failed)
        self.assertEqual((self.work/'ORDINARY-HOLD.json').read_bytes(), hold)
        self.assertEqual((self.work/'ordinary-complete.json').read_bytes(), self.before)
        self.assertFalse((self.work/'current-state.json').exists())

    def test_changed_credentials_or_foreign_hold_refuse_before_native_restore(self):
        failed = self.fail_after_preparation()
        self.inspections.clear()
        token = self.trust/'token'; original = token.read_bytes()
        write_bytes(token, b'different\n')
        with self.assertRaisesRegex(ValueError, 'credentials'):
            component_recovery.restore(self.cfg, failed)
        write_bytes(token, original)
        write_bytes(self.work/'ORDINARY-HOLD.json', encoded({'foreign': True}))
        with self.assertRaisesRegex(ValueError, 'exact unresolved'):
            component_recovery.restore(self.cfg, failed)
        self.assertEqual(self.inspections, [])

    def test_new_sealed_monitoring_payload_path_is_not_new_monitoring_ownership(self):
        failed = self.fail_after_preparation()
        # This unit varies monitoring ownership only; keep the independently
        # bound control descriptor conforming before its fake native boundary.
        selection = component_restore.descriptor(self.owner, self.cfg)
        previous = copy.deepcopy(self.cfg)
        candidate = copy.deepcopy(self.cfg)
        candidate['deployment']['input_directory'] = str(self.trust/'new-static-inputs')
        for cfg in (previous, candidate):
            cfg['app']['monitoring'] = {
                'hostname': 'example-resolver', 'psk_identity': 'example-resolver',
                'credential_file': str(Path(cfg['deployment']['input_directory'])/
                                       'applications/agent/monitoring-agent.json')}
        import proxmox_guest
        with patch.object(component_recovery, 'owner', return_value=(
                Path(self.owner['operation'])/'complete.json', self.owner, previous)), \
                patch.object(component_restore, 'verify_agents') as agents, \
                patch.object(component_restore, 'descriptor', return_value=selection), \
                patch.object(proxmox_guest, 'infrastructure', side_effect=RuntimeError('native boundary reached')) as native:
            with self.assertRaisesRegex(RuntimeError, 'native boundary reached'):
                component_recovery.restore(candidate, failed, finalize=False)
        native.assert_called_once()
        agents.assert_called_once_with(self.owner, previous, self.work/'recovery-102-1')
        self.assertTrue((self.work/'ORDINARY-HOLD.json').exists())

    def test_payload_relocation_does_not_excuse_monitoring_or_backup_changes(self):
        failed = self.fail_after_preparation()
        original_hold = (self.work/'ORDINARY-HOLD.json').read_bytes()
        import proxmox_guest
        for change in ('hostname', 'psk_identity', 'foreign_path', 'missing_path',
                       'removed', 'added', 'invalid_type', 'backup'):
            with self.subTest(change=change):
                previous = copy.deepcopy(self.cfg)
                candidate = copy.deepcopy(self.cfg)
                candidate['deployment']['input_directory'] = str(self.trust/'new-static-inputs')
                for cfg in (previous, candidate):
                    cfg['app']['monitoring'] = {
                        'hostname': 'example-resolver', 'psk_identity': 'example-resolver',
                        'credential_file': str(Path(cfg['deployment']['input_directory'])/
                                               'applications/agent/monitoring-agent.json')}
                if change in ('hostname', 'psk_identity'):
                    candidate['app']['monitoring'][change] = 'another-agent'
                elif change == 'foreign_path':
                    candidate['app']['monitoring']['credential_file'] = str(self.trust/'foreign.json')
                elif change == 'missing_path':
                    del candidate['app']['monitoring']['credential_file']
                elif change == 'removed':
                    del candidate['app']['monitoring']
                elif change == 'added':
                    del previous['app']['monitoring']
                elif change == 'invalid_type':
                    candidate['app']['monitoring'] = []
                else:
                    candidate['app']['backup'] = {'changed': True}
                with patch.object(component_recovery, 'owner', return_value=(
                        Path(self.owner['operation'])/'complete.json', self.owner, previous)), \
                        patch.object(component_restore, 'verify_agents') as agents, \
                        patch.object(proxmox_guest, 'infrastructure') as native:
                    with self.assertRaises(ValueError):
                        component_recovery.restore(candidate, failed, finalize=False)
                native.assert_not_called()
                agents.assert_not_called()
                self.assertEqual((self.work/'ORDINARY-HOLD.json').read_bytes(), original_hold)

    def monitoring_relocation(self, field):
        previous = copy.deepcopy(self.cfg)
        candidate = copy.deepcopy(self.cfg)
        candidate['deployment']['input_directory'] = str(self.trust/'new-static-inputs')
        leaves = {'database_password_file': ('agent', 'monitoring-database-password'),
                  'storage_password_file': ('monitor-db', 'monitoring-storage-password'),
                  'server_file': ('monitor-server', 'monitoring-server.json')}
        for cfg in (previous, candidate):
            cfg['deployment']['applications'].update({
                'monitor-db': {'id': 'monitor-db', 'adapter': 'postgresql'},
                'monitor-server': {'id': 'monitor-server', 'adapter': 'zabbix'},
                'other-server': {'id': 'other-server', 'adapter': 'zabbix'}})
            directory = Path(cfg['deployment']['input_directory'])/'applications'
            owner, leaf = leaves[field]
            cfg['app']['monitoring'] = {
                'hostname': 'example-resolver', 'psk_identity': 'example-resolver',
                'credential_file': str(directory/'agent/monitoring-agent.json'),
                field: str(directory/owner/leaf)}
        return previous, candidate

    def assert_optional_monitoring_relocation_reaches_native(self, field):
        failed = self.fail_after_preparation()
        selection = component_restore.descriptor(self.owner, self.cfg)
        previous, candidate = self.monitoring_relocation(field)
        import proxmox_guest
        with patch.object(component_recovery, 'owner', return_value=(
                Path(self.owner['operation'])/'complete.json', self.owner, previous)), \
                patch.object(component_restore, 'verify_agents') as agents, \
                patch.object(component_restore, 'descriptor', return_value=selection), \
                patch.object(proxmox_guest, 'infrastructure', side_effect=RuntimeError('native boundary reached')) as native:
            with self.assertRaisesRegex(RuntimeError, 'native boundary reached'):
                component_recovery.restore(candidate, failed, finalize=False)
        native.assert_called_once()
        agents.assert_called_once_with(self.owner, previous, self.work/'recovery-102-1')
        self.assertTrue((self.work/'ORDINARY-HOLD.json').exists())

    def test_database_monitoring_payload_relocation_preserves_ownership(self):
        self.assert_optional_monitoring_relocation_reaches_native('database_password_file')

    def test_storage_monitoring_payload_relocation_preserves_ownership(self):
        self.assert_optional_monitoring_relocation_reaches_native('storage_password_file')

    def test_server_monitoring_payload_relocation_preserves_ownership(self):
        self.assert_optional_monitoring_relocation_reaches_native('server_file')

    def test_optional_monitoring_paths_preserve_presence_owner_and_exact_location(self):
        failed = self.fail_after_preparation()
        original_hold = (self.work/'ORDINARY-HOLD.json').read_bytes()
        import proxmox_guest
        for field in ('database_password_file', 'storage_password_file', 'server_file'):
            for change in ('foreign_path', 'removed', 'added', 'invalid_type', 'owner'):
                with self.subTest(field=field, change=change):
                    previous, candidate = self.monitoring_relocation(field)
                    if change == 'foreign_path':
                        candidate['app']['monitoring'][field] = str(self.trust/Path(candidate['app']['monitoring'][field]).name)
                    elif change == 'removed':
                        del candidate['app']['monitoring'][field]
                    elif change == 'added':
                        del previous['app']['monitoring'][field]
                    elif change == 'invalid_type':
                        candidate['app']['monitoring'][field] = []
                    else:
                        path = Path(candidate['app']['monitoring'][field])
                        candidate['app']['monitoring'][field] = str(path.parent.parent/'other-server'/path.name)
                    with patch.object(component_recovery, 'owner', return_value=(
                            Path(self.owner['operation'])/'complete.json', self.owner, previous)), \
                            patch.object(component_restore, 'verify_agents') as agents, \
                            patch.object(proxmox_guest, 'infrastructure') as native:
                        with self.assertRaises(ValueError):
                            component_recovery.restore(candidate, failed, finalize=False)
                    native.assert_not_called()
                    agents.assert_not_called()
                    self.assertFalse((self.work/'recovery-102-1/started.json').exists())
                    self.assertEqual((self.work/'ORDINARY-HOLD.json').read_bytes(), original_hold)

    def test_installed_agent_drift_refuses_before_any_native_reversal(self):
        failed = self.fail_after_preparation()
        original_hold = (self.work/'ORDINARY-HOLD.json').read_bytes()
        import proxmox_guest
        with patch.object(component_restore, 'verify_agents', side_effect=ValueError('agent drift')), \
                patch.object(proxmox_guest, 'infrastructure') as native:
            with self.assertRaisesRegex(ValueError, 'agent drift'):
                component_recovery.restore(self.cfg, failed, finalize=False)
        native.assert_not_called()
        self.assertFalse((self.work/'recovery-102-1/started.json').exists())
        self.assertEqual((self.work/'ORDINARY-HOLD.json').read_bytes(), original_hold)

    def test_restored_group_requires_installed_agent_verification_before_release(self):
        failed = self.fail_after_preparation()
        component_recovery.restore(self.cfg, failed, finalize=False)
        original_hold = (self.work/'ORDINARY-HOLD.json').read_bytes()
        with patch.object(component_restore, 'verify_agents', side_effect=ValueError('agent drift')):
            with self.assertRaisesRegex(ValueError, 'agent drift'):
                component_recovery.verify_restore(self.cfg, failed)
        self.assertEqual((self.work/'ORDINARY-HOLD.json').read_bytes(), original_hold)
        self.assertFalse((self.work/'current-state.json').exists())

    def test_final_acceptance_keeps_candidate_pending_until_checks_pass(self):
        self.case.all_phases()
        operation = self.work/'ordinary-102-1'
        self.assertTrue((operation/'complete.json').exists())
        self.assertTrue((self.work/'ORDINARY-HOLD.json').exists())
        self.assertEqual((self.work/'ordinary-complete.json').read_bytes(), self.before)
        with component_recovery.locked(self.cfg):
            component_recovery.accept(self.cfg, operation)
        self.assertEqual(component_current.read(self.work)[0]['kind'], 'ordinary')
        self.assertFalse((self.work/'ORDINARY-HOLD.json').exists())

    def test_resolved_failure_tampering_is_not_a_new_admission(self):
        failed = self.fail_after_preparation()
        with component_recovery.locked(self.cfg):
            component_recovery.restore(self.cfg, failed)
        write_bytes(failed/'preparation-complete.json', encoded({'tampered': True}))
        with self.assertRaisesRegex(ValueError, 'failure evidence changed'):
            component_current.read(self.work)

    def test_manual_reconciliation_creates_distinct_owner_then_fresh_cd_succeeds(self):
        failed = self.fail_after_preparation()
        self.native = 'old'  # The engineer repaired the application/data.
        with patch.dict(os.environ, {'GITHUB_RUN_ID': '104', 'GITHUB_RUN_NUMBER': '13'}):
            with component_recovery.locked(self.cfg):
                result = component_recovery.reconcile(self.cfg, failed,
                    Path(self.owner['operation'])/'complete.json', self.owner,
                    reason='Engineer repaired the failed application', actor_context='protected-main-reconciliation')
        self.assertEqual(result['status'], 'reconciled')
        state, owner = component_current.read(self.work)
        self.assertEqual(state['kind'], 'reconciled')
        self.assertEqual(owner['status'], 'reconciled')
        with self.assertRaises(ValueError):
            component_generation.component_success(owner, Path(owner['operation']))
        self.assertEqual((self.work/'ordinary-complete.json').read_bytes(), self.before)
        self.assertFalse((self.work/'ORDINARY-HOLD.json').exists())
        with patch.dict(os.environ, {'GITHUB_RUN_ID': '105', 'GITHUB_RUN_NUMBER': '14'}):
            self.case.all_phases()
            with component_recovery.locked(self.cfg):
                component_recovery.accept(self.cfg, self.work/'ordinary-105-1')
        self.assertEqual(component_current.read(self.work)[0]['kind'], 'ordinary')

    def test_forward_reconciliation_does_not_take_the_new_ordinary_runs_receipt_path(self):
        failed = self.fail_after_preparation()
        self.native = 'old'
        with patch.dict(os.environ, {'GITHUB_RUN_ID': '105', 'GITHUB_RUN_NUMBER': '14'}):
            with component_recovery.locked(self.cfg):
                component_recovery.reconcile(self.cfg, failed, Path(self.owner['operation'])/'complete.json',
                    self.owner, reason='Verified forward recovery', actor_context='protected-main-reconciliation',
                    pending_forward=True)
            state, _ = component_current.read(self.work)
            self.assertEqual(Path(state['verification']['path']).parent.name, failed.name.replace('ordinary-', 'recovery-'))
            self.case.all_phases()
            with component_recovery.locked(self.cfg):
                component_recovery.accept(self.cfg, self.work/'ordinary-105-1')
        self.assertEqual(component_current.read(self.work)[0]['kind'], 'ordinary')

    def test_pointer_before_hold_release_interruption_is_metadata_only_on_resume(self):
        failed = self.fail_after_preparation()
        class Interrupted(BaseException): pass
        with patch.object(component_recovery, 'release', side_effect=Interrupted):
            with component_recovery.locked(self.cfg), self.assertRaises(Interrupted):
                component_recovery.restore(self.cfg, failed)
        self.assertTrue((self.work/'ORDINARY-HOLD.json').exists())
        self.inspections.clear()
        self.assertTrue(component_recovery.close_published(self.cfg))
        self.assertFalse((self.work/'ORDINARY-HOLD.json').exists())
        self.assertEqual(self.inspections, [])
        self.assertFalse(component_recovery.close_published(self.cfg))

    def test_failed_read_only_reconciliation_never_releases_hold_or_applies_configuration(self):
        failed = self.fail_after_preparation()
        original = (self.work/'ORDINARY-HOLD.json').read_bytes()
        with patch.object(component_restore, 'expected', side_effect=ValueError('mismatch')):
            with component_recovery.locked(self.cfg), self.assertRaises(ValueError):
                component_recovery.reconcile(self.cfg, failed, Path(self.owner['operation'])/'complete.json',
                    self.owner, reason='Repair reviewed', actor_context='protected-main-reconciliation')
        self.assertEqual((self.work/'ORDINARY-HOLD.json').read_bytes(), original)
        self.assertNotIn('restore', self.inspections)


if __name__ == '__main__':
    unittest.main()
