"""Bind immutable private settings before one create-only guest preparation."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from test_deploy import deploy, fixture, ROOT
import automation_cd
from test_automation_maintenance import setup as maintenance_setup
import automation_maintenance
import foundation_cd


class AutomationCDTests(unittest.TestCase):
    def test_guest_requires_exact_completed_prerequisites_and_unchanged_custody(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg, work, site, packet, _, nas = maintenance_setup(root)
            selected = root / 'maintenance.json'
            selected.write_text(json.dumps(packet))
            cfg['app']['prerequisite_packet_sha256'] = deploy.sha(selected)
            for phase in ('ingress', 'identity'):
                row = packet[phase]
                state = root / 'state' / str(row['vmid'])
                state.mkdir(parents=True, exist_ok=True)
                (state / 'terraform.tfstate').write_text('synthetic state')
                operation = state / 'automation-200-prerequisite'
                operation.mkdir(mode=0o700)
                receipt = {'binding': {'packet': row, 'maintenance_source_sha256': automation_maintenance.source_hash()},
                           'state_sha256': deploy.sha(state / 'terraform.tfstate')}
                target = root / 'nas/backups' / str(row['vmid'])
                target.mkdir(parents=True, exist_ok=True)
                foundation_cd.write_new(operation / 'complete.json', foundation_cd.encoded(receipt))
                foundation_cd.write_new(target / 'automation-200-complete.json', foundation_cd.encoded(receipt))
            automation_cd.prerequisites(cfg, selected)
            with self.assertRaisesRegex(ValueError, 'exact reviewed'):
                automation_cd.prerequisites(cfg, None)
            (work / 'CONTINUATION-HOLD.json').write_text('held')
            with self.assertRaisesRegex(ValueError, 'incomplete, changed or held'):
                automation_cd.prerequisites(cfg, selected)
            (work / 'CONTINUATION-HOLD.json').unlink()
            (work / 'terraform.tfstate').write_text('changed')
            with self.assertRaisesRegex(ValueError, 'incomplete, changed or held'):
                automation_cd.prerequisites(cfg, selected)
            (work / 'terraform.tfstate').write_text('synthetic state')
            (nas / 'automation-200-complete.json').write_text('changed')
            with self.assertRaisesRegex(ValueError, 'incomplete, changed or held'):
                automation_cd.prerequisites(cfg, selected)

    def setup(self, root):
        inputs = root / 'inputs'; inputs.mkdir(mode=0o700)
        destination = inputs / 'automation'
        cfg = fixture(root)
        cfg['app'].update(kind='automation', stack_config=str(destination / 'stack.json'))
        stack = json.loads((ROOT / 'examples/automation.stack.example.json').read_text())
        config = root / 'deployment.json'
        config.write_text(json.dumps({'schema': 'homelab-automation-deployment-v1', 'enabled': True,
                                     'discovery_previous_guests': [202, 211, 212], 'site': cfg, 'stack': stack}))
        return config, destination, cfg

    def test_secret_is_bound_privately_and_cannot_be_changed_on_the_next_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); config, destination, cfg = self.setup(root)
            original = config.read_bytes()
            automation_cd.prepare_inputs(config, destination, {'NODE_RED_API_TOKEN': 'synthetic-token'})
            self.assertEqual(config.read_bytes(), original)
            for path in destination.iterdir(): self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            stack = json.loads((destination / 'stack.json').read_text())
            self.assertEqual(stack['services']['node_red']['environment']['NODE_RED_API_TOKEN'], 'synthetic-token')
            automation_cd.prepare_inputs(config, destination, {'NODE_RED_API_TOKEN': 'synthetic-token'})
            with self.assertRaisesRegex(ValueError, 'changed'):
                automation_cd.prepare_inputs(config, destination, {'NODE_RED_API_TOKEN': 'different-token'})

    def test_missing_secret_or_token_in_git_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); config, destination, cfg = self.setup(root)
            with self.assertRaises(ValueError): automation_cd.prepare_inputs(config, destination, {})
            self.assertFalse(destination.exists())
            value = json.loads(config.read_text())
            value['stack']['services']['node_red']['environment']['NODE_RED_API_TOKEN'] = 'wrong-place'
            config.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                automation_cd.prepare_inputs(config, destination, {'NODE_RED_API_TOKEN': 'synthetic-token'})
            self.assertFalse(destination.exists())

    def test_failed_plan_is_held_and_cannot_be_started_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); config, destination, cfg = self.setup(root)
            runner = Mock(wraps=deploy)
            runner.execute.side_effect = ValueError('synthetic plan failure')
            with self.assertRaises(ValueError):
                automation_cd.run('guest', config, destination, {'NODE_RED_API_TOKEN': 'synthetic-token'}, runner)
            self.assertTrue((root / 'state/6101/AUTOMATION-CD-HOLD.json').exists())
            self.assertEqual(runner.execute.call_count, 1)
            with self.assertRaises(ValueError):
                automation_cd.run('guest', config, destination, {'NODE_RED_API_TOKEN': 'synthetic-token'}, runner)
            self.assertEqual(runner.execute.call_count, 1)

    def test_completed_guest_uses_bound_preparation_and_never_plans_or_applies_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); config, destination, cfg = self.setup(root)
            work = root / 'state/6101'; work.mkdir(parents=True)
            (work / 'prepare-complete.json').write_text('synthetic verified receipt')
            runner = Mock(wraps=deploy)
            runner.automation_binding.return_value = {'vmid': 6101}
            result = automation_cd.run('guest', config, destination, {'NODE_RED_API_TOKEN': 'synthetic-token'}, runner)
            self.assertTrue(result['already_prepared'])
            runner.execute.assert_not_called()

    def test_original_image_missing_stops_before_the_plan_or_hold(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); config, destination, cfg = self.setup(root)
            value = json.loads(config.read_text())
            value['stack']['services']['homeassistant'].update(image='sha256:' + '1'*64,
                archive=str(root / 'missing-image.tar'), archive_sha256='2'*64)
            config.write_text(json.dumps(value))
            runner = Mock(wraps=deploy)
            with self.assertRaisesRegex(ValueError, 'image archive'):
                automation_cd.run('guest', config, destination, {'NODE_RED_API_TOKEN': 'synthetic-token'}, runner)
            runner.execute.assert_not_called()
            self.assertFalse((root / 'state/6101/AUTOMATION-CD-HOLD.json').exists())


if __name__ == '__main__': unittest.main()
