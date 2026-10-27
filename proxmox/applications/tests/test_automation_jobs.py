"""Prepare once, then run service jobs without repeating shared guest changes."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_rollout
from test_deploy import deploy


def prepared(root):
    cfg, site, work, plan = test_rollout.RolloutTests().prepare(root)
    cfg['app'].update(kind='automation', service_health_checks={
        name: [{'name': name, 'argv': ['true']}]
        for name in ('mqtt', 'homeassistant', 'node_red')})
    site.write_text(json.dumps(cfg))
    receipt = json.loads((work / 'plan.json').read_text())
    receipt['site_sha256'] = deploy.sha(site)
    deploy.write(work / 'plan.json', receipt)
    return cfg, site, work, plan


class AutomationJobTests(unittest.TestCase):
    def prepare_guest(self, root):
        cfg, site, work, plan = prepared(root)
        def step(action, *args):
            if action == 'apply':
                deploy.write(work / 'applied.json', json.loads((work / 'plan.json').read_text()))
            if action == 'stage':
                (work / 'rendered').mkdir()
                (work / 'rendered' / 'compose.yml').write_text('synthetic compose')
            return {'status': 'passed', 'vmid': cfg['guest']['vmid']}
        with patch.object(deploy, '_execute_step', side_effect=step), \
                patch.object(deploy.guest_identity, 'pin', return_value={'fingerprint': 'synthetic'}):
            result = deploy.execute('prepare', site, plan)
        return cfg, site, work, plan, result

    def test_prepare_reuses_the_guest_pipeline_but_does_not_start_services(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg, site, work, plan, result = self.prepare_guest(Path(tmp))
            self.assertEqual([r['step'] for r in result['steps']], ['apply', 'identity', 'stage'])
            self.assertTrue((work / 'prepare-complete.json').exists())
            self.assertFalse((work / 'rollout-complete.json').exists())
            self.assertFalse((work / 'ROLLOUT-HOLD.json').exists())
            with patch.object(deploy, '_execute_step') as native, self.assertRaises(deploy.InputNeeded):
                deploy.execute('prepare', site, plan)
            native.assert_not_called()

    def test_consumers_require_mqtt_and_each_successful_job_only_verifies_on_a_later_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg, site, work, plan, _ = self.prepare_guest(Path(tmp))
            with patch.object(deploy, '_automation_service_step', return_value={'status': 'passed'}) as native:
                with self.assertRaisesRegex(deploy.InputNeeded, 'MQTT'):
                    deploy.automation_service(site, 'homeassistant')
                native.assert_not_called()
                deploy.automation_service(site, 'mqtt')
                deploy.automation_service(site, 'homeassistant')
                deploy.automation_service(site, 'node_red')
                self.assertEqual([call.args[3] for call in native.call_args_list], [True, True, True])
                deploy.automation_service(site, 'mqtt')
                self.assertFalse(native.call_args.args[3])

    def test_service_failure_or_interruption_holds_the_whole_guest_and_never_replays(self):
        for failure in (subprocess.CalledProcessError(1, ['synthetic']), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as tmp:
                _, site, work, _, _ = self.prepare_guest(Path(tmp))
                with patch.object(deploy, '_automation_service_step', side_effect=failure), \
                        self.assertRaises(type(failure)):
                    deploy.automation_service(site, 'mqtt')
                self.assertTrue((work / 'ROLLOUT-HOLD.json').exists())
                with patch.object(deploy, '_automation_service_step') as native, self.assertRaises(deploy.InputNeeded):
                    deploy.automation_service(site, 'mqtt')
                native.assert_not_called()

    def test_changed_inputs_or_shared_compose_cannot_be_started(self):
        for problem in ('site', 'compose', 'plan', 'missing-prepare'):
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as tmp:
                _, site, work, _, _ = self.prepare_guest(Path(tmp))
                if problem == 'site': site.write_text(site.read_text() + '\n')
                if problem == 'compose': (work / 'rendered/compose.yml').write_text('changed')
                if problem == 'plan': (work / 'guest.tfplan').write_bytes(b'changed')
                if problem == 'missing-prepare': (work / 'prepare-complete.json').unlink()
                with patch.object(deploy, '_automation_service_step') as native, self.assertRaises((deploy.InputNeeded, OSError)):
                    deploy.automation_service(site, 'mqtt')
                native.assert_not_called()

    def test_service_job_playbook_does_not_restore_rewrite_compose_or_start_other_services(self):
        import yaml
        path = deploy.SOURCE / 'ansible/automation-service.yml'
        tasks = yaml.safe_load(path.read_text())[0]['tasks']
        commands = [t['ansible.builtin.command']['argv'] for t in tasks if 'ansible.builtin.command' in t]
        starts = [args for args in commands if 'up' in args]
        self.assertEqual(len(starts), 1)
        self.assertEqual(starts[0][-1], '{{ automation_service }}')
        self.assertIn('--no-deps', starts[0])
        self.assertFalse(any('ansible.builtin.copy' in t or 'ansible.builtin.import_tasks' in t for t in tasks))


if __name__ == '__main__':
    unittest.main()
