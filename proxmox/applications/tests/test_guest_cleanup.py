"""Real receipts, inputs, deletion and custody locks; native deployment is fake."""
import json
import os
from pathlib import Path
import subprocess
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch

F = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(F/'proxmox/applications'), str(F/'proxmox/applications/tests')]
import cleanup_files
import component_generation
import component_process_fixtures as fixtures
import deploy
import deployment_state
import guest_cleanup as cleanup
import private_io as io
from fixtures import github_source


class GuestCleanupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source, self.revisions = github_source(self.root)
        self.cfg = fixtures.initialize(self.root, workspace=self.source, revision=self.revisions[0])
        self.work = self.root/'state/808'; self.inputs = self.root/'inputs'
        self.packet = self.root/'packet.json'
        metadata = {'GITHUB_RUN_ID': '777', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_RUN_NUMBER': '777',
            'GITHUB_SHA': self.revisions[0], 'GITHUB_WORKSPACE': str(self.source),
            'GITHUB_REPOSITORY': 'example/private-site',
            'HOMELAB_DEPLOYMENT_WORKFLOW': 'example/private-site/.github/workflows/deploy.yml@refs/heads/main'}
        for context in (patch.dict(os.environ, metadata), patch.object(cleanup, 'bootstrap_closed'),
                        patch.object(deploy, 'bootstrap_closed'), patch('deployment_inputs.source_hash', return_value='b'*64)):
            context.start(); self.addCleanup(context.stop)

    def complete(self, number=777, identity='a'*64):
        fixtures.seed(self.root, self.source, self.revisions[0], run_id=str(number), identity=identity)
        self.packet = self.root/('seed-'+identity+'.json')
        self.cfg = json.loads(io.read_json(self.packet)['files']['site.json'])
        return self.work/('ordinary-'+str(number)+'-1')

    def clean(self, outcome='success'):
        return cleanup.run(self.packet, outcome, inputs=self.inputs)

    def scratch(self, operation):
        for name in ('tofu/.terraform/providers/example/1', 'preparation/rendered'):
            (operation/name).mkdir(mode=0o700, parents=True)
        (operation/'preparation').chmod(0o700)
        for name in ('tofu/.terraform/providers/example/1/provider', 'guest.tfplan',
                     'preparation/inventory.json', 'preparation/variables.json', 'preparation/rendered/compose.yml'):
            io.write_new(operation/name, b'generated disposable bytes')
        io.write_new(operation/'infrastructure.log', b'long output\n'*1000+b'last infrastructure error\n')
        io.write_new(operation/'preparation/application.log', b'long output\n'*1000+b'last application error\n')

    def test_success_keeps_one_active_generation_and_all_external_owners(self):
        old = self.work/'ordinary-1-1'; self.scratch(old)
        active = self.complete(); self.scratch(active)
        before = {path: path.read_bytes() for path in (self.work/'terraform.tfstate', self.work/'ordinary-complete.json')}
        for name in ('application-data/database', 'backup-records/complete.json', 'credentials/key', 'imports/config'):
            path = self.root/name; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            io.write_new(path, b'required live data'); before[path] = path.read_bytes()
        self.assertEqual(self.clean(), {'status': 'cleaned', 'retired': 1})
        self.assertFalse(old.exists()); self.assertFalse((self.inputs/'mariadb'/('e'*64)).exists())
        self.assertFalse((active/'tofu').exists()); self.assertFalse((active/'preparation').exists())
        self.assertTrue((active/'complete.json').exists())
        for path, raw in before.items(): self.assertEqual(path.read_bytes(), raw)
        receipt = io.read_json(self.work/'ordinary-complete.json')
        self.assertTrue(component_generation.component_success(receipt, active))
        self.assertEqual(self.clean()['retired'], 0)
        # The real next deployment still consumes the active immutable proof.
        self.complete(778, 'c'*64)

    def test_failure_reclaims_bulk_and_preserves_exact_hold_backend_and_inputs(self):
        active = self.work/'ordinary-777-1'
        def fail(*args, **kwargs):
            self.scratch(active)
            raise RuntimeError('synthetic native failure')
        with patch.object(deploy.proxmox_guest, 'infrastructure', side_effect=fail), self.assertRaises(RuntimeError):
            deploy.run('infrastructure', self.packet, inputs=self.inputs, environment={})
        held = (self.work/'ORDINARY-HOLD.json').read_bytes()
        state = (self.work/'terraform.tfstate').read_bytes()
        self.clean('failure')
        self.assertEqual((self.work/'ORDINARY-HOLD.json').read_bytes(), held)
        self.assertEqual((self.work/'terraform.tfstate').read_bytes(), state)
        self.assertFalse((active/'tofu').exists()); self.assertFalse((active/'complete.json').exists())
        self.assertTrue((Path(self.cfg['deployment']['input_directory'])/'site.json').exists())
        history = io.read_json(self.work/cleanup.HISTORY)
        self.assertEqual(history[-1]['outcome'], 'failure')
        self.assertIn('last application error', history[-1]['logs']['preparation/application.log'])
        self.scratch(active)
        with patch.dict(os.environ, GITHUB_RUN_ID='778', GITHUB_RUN_NUMBER='778'):
            self.clean('failure')
        self.assertFalse((active/'tofu').exists())
        with patch.object(deploy.proxmox_guest, 'infrastructure') as native, self.assertRaises((ValueError, FileNotFoundError)):
            deploy.run('infrastructure', self.packet, inputs=self.inputs, environment={})
        native.assert_not_called()

    def test_unfinished_foreign_run_is_preserved_between_phases(self):
        active = self.work/'ordinary-777-1'
        def infra(*args, **kwargs):
            self.scratch(active)
            return {'changed': False, 'state_sha256': io.sha(self.work/'terraform.tfstate')}
        with patch.object(deploy.proxmox_guest, 'infrastructure', side_effect=infra):
            deploy.run('infrastructure', self.packet, inputs=self.inputs, environment={})
        with patch.dict(os.environ, GITHUB_RUN_ID='778', GITHUB_RUN_NUMBER='778'):
            self.clean('failure')
        self.assertTrue((active/'tofu').exists()); self.assertFalse((active/cleanup.FINISHED).exists())

    def test_each_custody_lock_blocks_cleanup_without_changes(self):
        active = self.complete(); self.scratch(active)
        import fcntl
        for path, _ in deployment_state.custody_paths(self.root/'state', self.work):
            with path.open('r+') as stream:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(BlockingIOError): self.clean()
            self.assertTrue((active/'tofu').exists())

    def test_no_follow_or_unknown_state_deletion(self):
        active = self.complete()
        outside = self.root/'runtime'; outside.mkdir(mode=0o700)
        io.write_new(outside/'data', b'live application data')
        (active/'tofu').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError): self.clean()
        self.assertEqual((outside/'data').read_bytes(), b'live application data')
        (active/'tofu').unlink(); self.scratch(active)
        io.write_new(active/'tofu/terraform.tfstate', b'recovery state')
        with self.assertRaisesRegex(ValueError, 'state or recovery'): self.clean()
        self.assertTrue((active/'tofu/terraform.tfstate').exists())

    def test_retirement_retries_after_partial_deletion(self):
        self.complete()
        original = cleanup_files.remove
        count = 0
        def interrupted(parent, entries):
            nonlocal count
            count += 1
            original(parent, entries)
            if count == 2: raise OSError('synthetic interruption')
        with patch.object(cleanup_files, 'remove', side_effect=interrupted), self.assertRaises(OSError): self.clean()
        old = self.work/'ordinary-1-1'
        self.assertTrue((old/cleanup.RETIRING).is_file())
        self.clean()
        self.assertFalse(old.exists())
        self.assertTrue(component_generation.component_success(io.read_json(self.work/'ordinary-complete.json'), self.work/'ordinary-777-1'))

    def test_history_is_bounded_across_many_runs_and_same_input_is_not_removed_early(self):
        self.complete()
        for number in range(2, 30):
            cleanup.remember(self.work, {'operation':f'ordinary-{number}-1', 'outcome':'failure'})
        self.assertEqual(len(io.read_json(self.work/cleanup.HISTORY)), cleanup.HISTORY_LIMIT)
        # Both retained historical operations use the same source namespace.
        self.complete(778, 'c'*64)
        self.complete(779, 'd'*64)
        with patch.dict(os.environ, GITHUB_RUN_ID='779', GITHUB_RUN_NUMBER='779'):
            self.assertEqual(self.clean()['retired'], 3)
        self.assertEqual(len(list((self.inputs/'mariadb').iterdir())), 1)

    def fail_job(self):
        with patch.object(deploy.proxmox_guest, 'infrastructure', side_effect=RuntimeError('synthetic')):
            with self.assertRaises(RuntimeError):
                deploy.run('infrastructure', self.packet, inputs=self.inputs, environment={})
        return self.work/'ordinary-777-1'

    def test_failed_generation_without_app_payload_can_retire_only_after_recovery(self):
        operation = self.fail_job(); self.scratch(operation)
        held = (self.work/'ORDINARY-HOLD.json').read_bytes()
        self.clean('cancelled')
        self.assertEqual((self.work/'ORDINARY-HOLD.json').read_bytes(), held)
        # Test-only explicit operator recovery, never performed by cleanup.
        (self.work/'ORDINARY-HOLD.json').unlink()
        saved = self.work/'reviewed-failure'; operation.rename(saved)
        self.complete(778, 'c'*64)
        saved.rename(operation)
        with patch.dict(os.environ, GITHUB_RUN_ID='778', GITHUB_RUN_NUMBER='778'):
            self.clean()
        self.assertFalse(operation.exists())
        self.assertFalse((self.inputs/'mariadb'/('a'*64)).exists())

    def test_unclassified_legacy_evidence_retains_shared_inputs(self):
        self.complete()
        canonical = io.read_json(self.work/'ordinary-complete.json')
        legacy = self.work/'ordinary-2-1'; legacy.mkdir(mode=0o700)
        io.write_new(legacy/'preparation-started.json', io.encoded({'binding': canonical['binding'],
            'workflow':canonical['workflow'], 'run_number':2}))
        self.complete(778, 'c'*64)
        with patch.dict(os.environ, GITHUB_RUN_ID='778', GITHUB_RUN_NUMBER='778'):
            self.clean()
        self.assertTrue((self.inputs/'mariadb'/('a'*64)).exists())
        self.assertTrue((legacy/'preparation-started.json').exists())

    def test_unversioned_history_preserves_custody_without_blocking_current_cleanup(self):
        active = self.complete(); self.scratch(active)
        old = self.work/'ordinary-1-1'
        # Both traversal positions matter: an earlier candidate must not retire
        # inputs after a later legacy record makes its references unknowable.
        for number in (2, 900):
            legacy = self.work/f'ordinary-{number}-1'; legacy.mkdir(mode=0o700)
            io.write_new(legacy/'complete.json', io.encoded({'binding': {'legacy': 'unclassified'}}))
            self.scratch(legacy)
        preserved = {p: p.read_bytes() for number in (2, 900)
                     for p in (self.work/f'ordinary-{number}-1').rglob('*') if p.is_file()}
        preserved.update({p: p.read_bytes() for p in self.inputs.rglob('*') if p.is_file()})
        self.assertEqual(self.clean(), {'status': 'cleaned', 'retired': 0})
        self.assertTrue(old.is_dir())
        self.assertTrue((active/cleanup.FINISHED).is_file())
        self.assertFalse((active/'tofu').exists())
        self.assertFalse((active/'preparation').exists())
        for path, raw in preserved.items(): self.assertEqual(path.read_bytes(), raw)
        self.assertTrue(component_generation.component_success(
            io.read_json(self.work/'ordinary-complete.json'), active))

    def test_unversioned_current_job_is_not_treated_as_historical(self):
        active = self.complete(); self.scratch(active)
        cleanup_files.replace(active/'complete.json', {'binding': {}})
        with self.assertRaisesRegex(ValueError, 'exact canonical and immutable'):
            self.clean()
        self.assertTrue((active/'tofu').exists())
        self.assertFalse((active/cleanup.FINISHED).exists())

    def test_unversioned_incomplete_history_keeps_all_inputs_and_cleans_current_scratch(self):
        active = self.complete(); self.scratch(active)
        canonical = io.read_json(self.work/'ordinary-complete.json')
        legacy_records = ('plan.json', 'preparation-started.json', 'infrastructure-complete.json')
        preserved = {}
        for number, name in zip((2, 3, 900), legacy_records):
            legacy = self.work/f'ordinary-{number}-1'; legacy.mkdir(mode=0o700)
            io.write_new(legacy/name, io.encoded({'binding': {'legacy': 'unclassified'}}))
            # Mixed history retains the supported record as well.
            io.write_new(legacy/'other-started.json', io.encoded({'binding': canonical['binding']}))
            self.scratch(legacy)
            preserved.update({p: p.read_bytes() for p in legacy.rglob('*') if p.is_file()})
        preserved.update({p: p.read_bytes() for p in self.inputs.rglob('*') if p.is_file()})
        self.assertEqual(self.clean(), {'status': 'cleaned', 'retired': 0})
        self.assertTrue((self.work/'ordinary-1-1').is_dir())
        self.assertTrue((active/cleanup.FINISHED).is_file())
        self.assertFalse((active/'tofu').exists())
        self.assertFalse((active/'preparation').exists())
        for path, raw in preserved.items(): self.assertEqual(path.read_bytes(), raw)

    def test_unversioned_active_incomplete_record_is_not_skipped(self):
        self.complete()
        operation = self.work/'ordinary-778-1'; operation.mkdir(mode=0o700)
        io.write_new(operation/'plan.json', io.encoded({'binding': {}}))
        self.scratch(operation)
        with patch.dict(os.environ, GITHUB_RUN_ID='778', GITHUB_RUN_NUMBER='778'):
            with self.assertRaisesRegex(ValueError, 'unsupported active ordinary'):
                self.clean('failure')
        self.assertTrue((operation/'tofu').exists())
        self.assertFalse((operation/cleanup.FINISHED).exists())

    def test_malformed_versioned_incomplete_record_still_refuses_cleanup(self):
        active = self.complete(); self.scratch(active)
        operation = self.work/'ordinary-2-1'; operation.mkdir(mode=0o700)
        io.write_new(operation/'plan.json', io.encoded({'schema': 'invalid', 'binding': {}}))
        with self.assertRaisesRegex(ValueError, 'closed component ordinary binding'):
            self.clean()
        self.assertTrue((active/'tofu').exists())

    def test_unversioned_held_or_own_failure_is_not_skipped(self):
        active = self.fail_job(); self.scratch(active)
        io.write_new(active/'complete.json', io.encoded({'binding': {}}))
        for run in ('777', '778'):
            with patch.dict(os.environ, GITHUB_RUN_ID=run, GITHUB_RUN_NUMBER=run):
                with self.assertRaisesRegex(ValueError, 'unsupported active ordinary'):
                    self.clean('failure')
            self.assertTrue((active/'tofu').exists())

    def test_malformed_versioned_history_still_refuses_cleanup(self):
        active = self.complete(); self.scratch(active)
        old = self.work/'ordinary-1-1'
        cleanup_files.replace(old/'complete.json', {'schema': 'invalid', 'binding': {}})
        with self.assertRaisesRegex(ValueError, 'closed component ordinary binding'):
            self.clean()
        self.assertTrue((active/'tofu').exists())

    def test_recovery_and_reviewed_checkpoint_records_preserve_all_generations(self):
        active = self.complete(); self.scratch(active)
        old = self.work/'ordinary-1-1'
        records = [self.work/'recovery-2-1', self.work/'operator-recovery-2-1',
                   self.work/'infrastructure-admission.json', self.work/'infrastructure-admission-claim.json',
                   *(active/name for name in ('rollback-baseline.json', 'rollback-ready.json',
                       'controls-before.json', 'forward-failure.json', 'infrastructure-invocation.json',
                       'infrastructure-admission.json'))]
        for path in records:
            with self.subTest(record=path.name):
                io.write_new(path, b'preserved recovery evidence')
                self.assertEqual(self.clean()['retired'], 0)
                self.assertTrue(old.is_dir())
                self.assertTrue((self.inputs/'mariadb'/('e'*64)/'site.json').is_file())
                self.assertEqual(path.read_bytes(), b'preserved recovery evidence')
                path.unlink()
        self.assertFalse((active/'tofu').exists())
        self.assertEqual(self.clean()['retired'], 1)

    def test_recovery_custody_defers_an_interrupted_retirement(self):
        self.complete(); old = self.work/'ordinary-1-1'
        with patch.object(cleanup_files, 'remove', side_effect=OSError('synthetic')), self.assertRaises(OSError):
            self.clean()
        ticket = (old/cleanup.RETIRING).read_bytes()
        archive = self.work/'operator-recovery-2-1'; archive.mkdir(mode=0o700)
        self.assertEqual(self.clean()['retired'], 0)
        self.assertEqual((old/cleanup.RETIRING).read_bytes(), ticket)
        archive.rmdir()
        self.assertEqual(self.clean()['retired'], 1)

    def test_first_install_failure_and_missing_attempt_do_not_require_or_invent_success(self):
        # A separate genuine fresh fixture has neither canonical proof nor history.
        fresh = self.root/'fresh'; fresh.mkdir(mode=0o700)
        cfg = fixtures.initialize(fresh, fresh=True)
        (fresh/'state/808/terraform.tfstate').unlink()
        with patch.dict(os.environ, GITHUB_RUN_ID='900', GITHUB_RUN_NUMBER='900'):
            with patch.object(deploy.proxmox_guest, 'infrastructure', side_effect=RuntimeError('synthetic')):
                with self.assertRaises(RuntimeError):
                    deploy.run('infrastructure', fresh/'packet.json', inputs=fresh/'inputs', environment={})
            self.assertEqual(cleanup.run(fresh/'packet.json', 'failure', inputs=fresh/'inputs')['retired'], 0)
        self.assertFalse((fresh/'state/808/ordinary-complete.json').exists())
        self.assertTrue((fresh/'state/808/ORDINARY-HOLD.json').exists())
        # Compile-only failure has no deployment directory to clean.
        vacant = fresh/'state/808'; vacant.rename(fresh/'state/retained-evidence')
        self.assertEqual(cleanup.run(fresh/'packet.json', 'failure', inputs=fresh/'inputs'), {'status':'no_attempt'})

    def test_pending_and_recovery_markers_and_backend_lock_defer_all_cleanup(self):
        operation = self.complete(); self.scratch(operation)
        paths = [self.work/'ordinary-complete.json.pending', self.work/'FOUNDATION-HOLD.json', self.work/'ORDINARY-HOLD.json',
                 self.work/'.terraform.tfstate.lock.info', operation/'VERIFYING.json',
                 self.root/'state/database-network-cutover-test/HOLD.json', self.work/'database-import/HOLD.json']
        for path in paths:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            io.write_new(path, b'preserve this marker')
            with self.subTest(marker=path.name), self.assertRaises(ValueError): self.clean()
            self.assertEqual(path.read_bytes(), b'preserve this marker')
            self.assertTrue((operation/'tofu').exists())
            path.unlink()
        self.clean()

    def test_retirement_rejects_unknown_files_and_preserves_new_or_held_retry_targets(self):
        self.complete(); old = self.work/'ordinary-1-1'
        io.write_new(old/'imported-database', b'not generated scratch')
        with self.assertRaisesRegex(ValueError, 'unknown files'): self.clean()
        self.assertEqual((old/'imported-database').read_bytes(), b'not generated scratch')
        (old/'imported-database').unlink()
        with patch.object(cleanup_files, 'remove', side_effect=OSError('synthetic')), self.assertRaises(OSError): self.clean()
        ticket = io.read_json(old/cleanup.RETIRING)
        io.write_new(old/'new-file', b'new recovery evidence')
        with self.assertRaisesRegex(ValueError, 'unexpected files'): self.clean()
        self.assertTrue((old/'new-file').exists())
        (old/'new-file').unlink()
        terminal = io.read_json(old/cleanup.FINISHED)
        io.write_new(self.work/'ORDINARY-HOLD.json', io.encoded(terminal['marker']))
        with self.assertRaisesRegex(ValueError, 'held retirement'): self.clean()
        self.assertEqual(io.read_json(old/cleanup.RETIRING), ticket)

    def test_deletion_primitive_rejects_links_special_files_mounts_and_replaced_inodes(self):
        root = self.root/'scratch'; root.mkdir(mode=0o700)
        io.write_new(root/'file', b'original')
        entries = cleanup_files.inventory(self.root, 'scratch')
        io.write_bytes(root/'file', b'new content on the same inode')
        with self.assertRaisesRegex(ValueError, 'new or replaced'): cleanup_files.remove(self.root, entries)
        (root/'file').rename(root/'original')
        io.write_new(root/'file', b'replaced')
        with self.assertRaisesRegex(ValueError, 'new or replaced'): cleanup_files.remove(self.root, entries)
        for name, make in [('link', lambda p:p.symlink_to(self.root/'packet.json')),
                           ('hardlink', lambda p:os.link(root/'file', p)), ('pipe', lambda p:os.mkfifo(p, 0o600))]:
            target = root/name; make(target)
            with self.subTest(kind=name), self.assertRaises(ValueError): cleanup_files.inventory(self.root, 'scratch')
            target.unlink()
        with cleanup_files._directory(self.root) as fd:
            original = os.fstat
            def cross_device(number):
                result = original(number)
                if number != fd:
                    from types import SimpleNamespace
                    return SimpleNamespace(st_dev=result.st_dev+1)
                return result
            with patch.object(cleanup_files.os, 'fstat', side_effect=cross_device), self.assertRaises(ValueError):
                with cleanup_files.child(fd, 'scratch'): self.fail('cross-device traversal')

    def test_cli_dispatch_and_redaction_in_process(self):
        import io as streams
        with patch.object(sys, 'argv', ['cleanup','--packet',str(self.root/'absent'),'--outcome','failure']), \
             patch('sys.stdout', new_callable=streams.StringIO) as output, patch.object(cleanup.os,'umask'):
            runpy.run_path(str(F/'proxmox/applications/guest_cleanup.py'), run_name='__main__')
        self.assertEqual(json.loads(output.getvalue()), {'status':'no_packet'})
        with patch.object(sys, 'argv', ['cleanup','--packet','/private-sentinel','--outcome','private-sentinel']), \
             patch.object(cleanup.os,'umask'), self.assertRaises(SystemExit) as error:
            cleanup.main()
        self.assertNotIn('private-sentinel', str(error.exception))

    def test_bounded_diagnostics_keep_the_latest_failure_among_many_phases(self):
        operation = self.complete()
        for number in range(12):
            phase = operation/f'phase-{number:02d}'; phase.mkdir(mode=0o700)
            path = phase/'application.log'
            io.write_new(path, b'x'*4000+f'last error {number}'.encode())
            os.utime(path, ns=(number+1, number+1))
        marker = io.read_json(operation/'complete.json')
        record = cleanup.summary(operation, marker, 'failure')
        self.assertEqual(len(record['logs']), 8)
        self.assertIn('last error 11', record['logs']['phase-11/application.log'])
        self.assertTrue(all(len(tail) <= cleanup.LOG_LIMIT for tail in record['logs'].values()))

    def test_cli_absent_packet_and_redacted_failure(self):
        self.assertEqual(cleanup.run(self.root/'absent', 'failure'), {'status': 'no_packet'})
        command = [sys.executable, str(F/'proxmox/applications/guest_cleanup.py'), '--outcome', 'bad-private-value',
                   '--packet', str(self.root/'absent')]
        result = subprocess.run(command, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('bad-private-value', result.stderr)
        result = subprocess.run(command[:3]+['failure']+command[4:], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), {'status':'no_packet'})


class RecoveryCleanupTests(unittest.TestCase):
    def setUp(self):
        # Reuse genuine current recovery transactions, replacing only native
        # execution through the existing fixture.
        import test_component_recovery as transactions
        self.transaction = transactions.RecoveryTransactions()
        self.transaction.setUp(); self.addCleanup(self.transaction.doCleanups)
        self.case = self.transaction.case
        self.work = self.transaction.work
        context = patch.object(cleanup, 'bootstrap_closed')
        context.start(); self.addCleanup(context.stop)

    def clean(self, outcome='success'):
        return cleanup.run(self.case.packet, outcome, inputs=self.case.inputs)

    def downloads(self, operation):
        (operation/'tofu').mkdir(mode=0o700)
        io.write_new(operation/'tofu/provider', b'reproducible provider download')

    def test_cleanup_before_acceptance_preserves_the_baseline_and_later_owner(self):
        import component_current as current
        import component_recovery as recovery
        self.case.all_phases(); operation = self.work/'ordinary-102-1'
        self.downloads(operation)
        paths = [self.work/'ORDINARY-HOLD.json', self.work/'ordinary-complete.json',
                 self.work/'terraform.tfstate', operation/'rollback-baseline.json', operation/'controls-before.json']
        before = {path: path.read_bytes() for path in paths}
        self.assertEqual(self.clean()['retired'], 0)
        self.assertFalse((operation/'tofu').exists())
        self.assertEqual({path: path.read_bytes() for path in paths}, before)
        self.assertEqual(recovery.accept(self.case.cfg, operation)['status'], 'accepted')
        effective = current.read(self.work)
        self.assertEqual(self.clean()['retired'], 0)
        self.assertEqual(current.read(self.work), effective)
        # The accepted operation's rollback baseline still resolves the old
        # immutable owner after cleanup, including when a later job starts.
        baseline = recovery.baseline(operation, self.case.cfg)
        self.assertEqual(recovery.owner(baseline, self.work)[1], self.transaction.owner)
        with patch.dict(os.environ, GITHUB_RUN_ID='103', GITHUB_RUN_NUMBER='12'):
            self.case.all_phases()
            self.assertEqual(self.clean()['retired'], 0)
            self.assertEqual(recovery.accept(self.case.cfg, self.work/'ordinary-103-1')['status'], 'accepted')
        self.assertEqual(current.read(self.work)[0]['kind'], 'ordinary')

    def test_failure_cleanup_preserves_real_rollback_and_resolved_failure_evidence(self):
        import component_current as current
        import component_recovery as recovery
        operation = self.transaction.fail_after_preparation(); self.downloads(operation)
        held = (self.work/'ORDINARY-HOLD.json').read_bytes()
        self.assertEqual(self.clean('failure')['retired'], 0)
        self.assertEqual((self.work/'ORDINARY-HOLD.json').read_bytes(), held)
        self.assertFalse((operation/'tofu').exists())
        self.assertEqual(recovery.restore(self.case.cfg, operation)['status'], 'failed_rolled_back')
        effective = current.read(self.work)
        self.assertIn(operation.name, effective[0]['resolved'])
        self.assertEqual(self.clean('failure')['retired'], 0)
        self.assertEqual(current.read(self.work), effective)

    def test_reconciled_owner_and_corrupt_current_pointer_are_not_retired(self):
        import component_current as current
        import component_recovery as recovery
        operation = self.transaction.fail_after_preparation()
        self.clean('failure'); self.transaction.native = 'old'
        owner = self.transaction.owner
        with patch.dict(os.environ, GITHUB_RUN_ID='104', GITHUB_RUN_NUMBER='13'):
            self.assertEqual(recovery.reconcile(self.case.cfg, operation,
                Path(owner['operation'])/'complete.json', owner,
                reason='Verified synthetic repair', actor_context='protected-main-reconciliation')['status'], 'reconciled')
            effective = current.read(self.work)
            self.assertEqual(effective[1]['schema'], current.OWNER)
            self.assertEqual(self.clean('failure')['retired'], 0)
            self.assertEqual(current.read(self.work), effective)
        self.downloads(operation)
        io.write_bytes(self.work/current.NAME, io.encoded({}))
        with self.assertRaises(ValueError): self.clean('failure')
        self.assertTrue((operation/'tofu/provider').exists())


if __name__ == '__main__': unittest.main()
