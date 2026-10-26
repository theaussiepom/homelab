"""One approved CD run completes every phase or stops without replay."""
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from test_deploy import deploy, fixture


class RolloutTests(unittest.TestCase):
    def prepare(self, root):
        cfg = fixture(root)
        (root / 'ca').write_text('synthetic CA fixture')
        archive = root / 'capture.tar'
        with tarfile.open(archive, 'w') as stream:
            item = tarfile.TarInfo('synthetic-config'); item.size = 2
            stream.addfile(item, io.BytesIO(b'ok'))
        cfg['app'].update(kind='dns', exclusive_writer_confirmed=True,
                          capture={'path': str(archive), 'sha256': deploy.sha(archive), 'coherent': True})
        site = root / 'site.json'; site.write_text(json.dumps(cfg))
        work = root / 'state' / '6101'; work.mkdir(parents=True)
        plan = work / 'guest.tfplan'; plan.write_bytes(b'synthetic-reviewed-plan')
        deploy.write(work / 'plan.json', {'site_sha256': deploy.sha(site),
            'source_sha256': deploy.source_hash(), 'plan_sha256': deploy.sha(plan),
            'input_hashes': deploy.input_hashes(cfg)})
        return cfg, site, work, deploy.sha(plan)

    def test_one_call_runs_apply_identity_stage_start_verify_in_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); cfg, site, work, plan = self.prepare(root); calls = []
            def step(action, *args):
                self.assertEqual(json.loads((work / 'ROLLOUT-HOLD.json').read_text())['step'], action)
                calls.append(action)
                return {'step': action, 'status': 'passed'}
            def pin(*args):
                calls.append('identity'); return {'fingerprint': 'synthetic'}
            with patch.object(deploy, '_execute_step', side_effect=step), \
                    patch.object(deploy.guest_identity, 'pin', side_effect=pin):
                result = deploy.execute('deploy', site, plan)
            self.assertEqual(calls, ['apply', 'identity', 'stage', 'start', 'verify'])
            self.assertEqual(result['status'], 'passed')
            self.assertFalse((work / 'ROLLOUT-HOLD.json').exists())
            self.assertTrue((work / 'rollout-complete.json').is_file())

    def test_a_failure_in_any_phase_stops_later_phases_and_refuses_another_job(self):
        for failure in ('apply', 'identity', 'stage', 'start', 'verify'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); cfg, site, work, plan = self.prepare(root); calls = []
                def step(action, *args):
                    calls.append(action)
                    if action == failure: raise subprocess.CalledProcessError(1, ['synthetic'])
                    return {'status': 'passed'}
                def pin(*args):
                    calls.append('identity')
                    if failure == 'identity': raise ValueError('synthetic identity mismatch')
                    return {'fingerprint': 'synthetic'}
                with patch.object(deploy, '_execute_step', side_effect=step) as runner, \
                        patch.object(deploy.guest_identity, 'pin', side_effect=pin):
                    with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                        deploy.execute('deploy', site, plan)
                    sequence = ['apply', 'identity', 'stage', 'start', 'verify']
                    self.assertEqual(calls, sequence[:sequence.index(failure) + 1])
                    self.assertEqual(json.loads((work / 'ROLLOUT-HOLD.json').read_text())['step'], failure)
                    previous = runner.call_count
                    with self.assertRaises(deploy.InputNeeded): deploy.execute('plan', site)
                    self.assertEqual(runner.call_count, previous)

    def test_missing_capture_or_wrong_plan_cannot_create_a_guest(self):
        for problem in ('missing-capture', 'wrong-plan', 'old-writer', 'already-applied'):
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); cfg, site, work, plan = self.prepare(root)
                if problem == 'missing-capture': (root / 'capture.tar').unlink()
                if problem == 'wrong-plan': plan = '0' * 64
                if problem == 'already-applied': (work / 'applied.json').write_text('{}')
                if problem == 'old-writer':
                    cfg['app']['exclusive_writer_confirmed'] = False
                    site.write_text(json.dumps(cfg))
                    receipt = json.loads((work / 'plan.json').read_text()); receipt['site_sha256'] = deploy.sha(site)
                    deploy.write(work / 'plan.json', receipt)
                with patch.object(deploy, '_execute_step') as runner, self.assertRaises((ValueError, OSError)):
                    deploy.execute('deploy', site, plan)
                runner.assert_not_called()
                self.assertFalse((work / 'ROLLOUT-HOLD.json').exists())

    def test_process_interruption_keeps_the_pipeline_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); cfg, site, work, plan = self.prepare(root)
            with patch.object(deploy, '_execute_step', side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                deploy.execute('deploy', site, plan)
            self.assertTrue((work / 'ROLLOUT-HOLD.json').is_file())


if __name__ == '__main__':
    unittest.main()
