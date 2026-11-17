"""Managed-control transport uses real local files and synthetic remote commands."""
import copy
import base64
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import component_control
import component_restore as m
from private_io import digest, encoded, read_json, write_new
import test_component_recovery as fixture


class RestoreTests(unittest.TestCase):
    def setUp(self):
        self.tx = fixture.RecoveryTransactions(); self.tx.setUp(); self.addCleanup(self.tx.doCleanups)
        self.cfg, self.owner = self.tx.cfg, self.tx.owner
        self.control = self.tx.trust/'managed.conf'; write_new(self.control, b'previous\n')
        self.selection = {'files': {str(self.control): None}, 'packages': [], 'images': [],
            'projects': [], 'units': [], 'health': [], 'native_files': [], 'expected': {str(self.control): digest(b'previous\n')},
            'metadata': {str(self.control): {'uid': os.getuid(), 'gid': os.getgid(), 'mode': 0o600}}}
        self.transport = []

    def quiet(self, args, environment, log):
        self.transport.append(args)
        self.assertNotIn('PBS_API_TOKEN', environment)
        self.assertFalse(any(key.startswith('HOMELAB_APP_SECRET_') for key in environment))
        value = read_json(Path(args[-1][1:]), private=True)
        if value['recovery_mode'] == 'restore': component_control.run(value['recovery_restore'])
        result = component_control.run(value['recovery_request'])
        write_new(Path(value['recovery_output']), encoded(result))

    def test_capture_restore_verify_keep_exact_bytes_permissions_and_private_transport(self):
        captured = self.actual_execute('capture')
        m.expected(self.selection, captured)
        self.control.write_bytes(b'forward\n')
        restored = self.actual_execute('restore', captured=captured,
            allowed={str(self.control): [digest(b'forward\n')]})
        self.assertEqual(restored, captured)
        self.assertEqual(self.control.read_bytes(), b'previous\n')
        self.assertEqual(self.actual_execute('verify', captured=captured), captured)
        self.assertEqual(len(self.transport), 3)
        self.assertEqual(len(list(self.tx.work.glob('controls-*-1/result.json'))), 3)
        for command in self.transport:
            self.assertEqual(command[0], 'ansible-playbook')
            self.assertTrue(command[-1].startswith('@'))

    def actual_execute(self, mode, **kwargs):
        with patch.object(m.component_ansible, 'quiet', side_effect=self.quiet), \
                patch.dict(os.environ, {'PBS_API_TOKEN': 'private-sentinel', 'HOMELAB_APP_SECRET_A': 'private-sentinel'}):
            return EXECUTE(self.cfg, self.tx.work, self.selection, mode=mode, **kwargs)

    def test_mismatched_expected_controls_and_transport_results_are_refused(self):
        captured = self.actual_execute('capture')
        for mutate in [lambda v: v['files'][str(self.control)].update(sha256='a'*64),
                       lambda v: v['files'][str(self.control)].update(mode=0o644),
                       lambda v: v.update(packages=['example=2'])]:
            value = copy.deepcopy(captured); mutate(value)
            chosen = copy.deepcopy(self.selection)
            if value['packages']: chosen['packages'] = ['example=1']
            with self.assertRaises(ValueError): m.expected(chosen, value)
        with patch.object(m.component_ansible, 'quiet', side_effect=lambda args, env, log:
            write_new(log.parent/'result.json', encoded({'foreign': True}))), self.assertRaises(ValueError):
            EXECUTE(self.cfg, self.tx.work, self.selection, mode='capture')
        with self.assertRaises(ValueError): EXECUTE(self.cfg, self.tx.work, self.selection, mode='arbitrary')

    def test_descriptor_inventories_owned_runtime_helpers_overlay_native_units_and_routing(self):
        phase, proof = next((phase, proof) for phase, proof in self.owner['phase_inputs'].items() if proof)
        payload = Path(self.owner['binding']['app_inputs_directory'])/proof['app']
        app = {'project_name': 'example', 'identity': {'services': {'resolver': 'recursive'}},
            'software_selection': {'images': {'resolver': {'image': 'example/resolver@sha256:'+'a'*64}}}}
        variables = {'component_application': app,
            'component_runtime_files': [{'source': 'application.json', 'destination': '/opt/example/runtime.json',
                'uid': 10, 'gid': 20, 'mode': '0600'}],
            'component_helpers': [{'source': 'component-preflight.py', 'destination': '/opt/example/check.py', 'mode': '0700'}],
            'component_compose_file': '/opt/example/compose.yml', 'component_compose_source': str(payload/'application.json'),
            'component_environment_file': '/opt/example/environment.yml', 'component_environment_source': str(payload/'application.json'),
            'component_services': ['recursive'], 'app': {'health_checks': [{'argv': ['true']}]}}
        cfg = copy.deepcopy(self.cfg); cfg['app']['frontend_routing'] = {'policy': 'synthetic'}
        owner = copy.deepcopy(self.owner); owner['phase_inputs']['zabbix-agent'] = proof
        with patch.object(m.component_ansible, 'variables', return_value=variables), \
                patch('component_generation.sealed_inputs', return_value=(cfg, {})):
            selected = m.descriptor(owner, cfg)
            self.assertIn('/opt/homelab-app/frontend-routing.json', selected['files'])
            self.assertEqual(selected['images'][0]['service'], 'recursive')
            self.assertIn('/opt/example/runtime.json', selected['expected'])
            self.assertEqual(selected['metadata']['/opt/example/runtime.json'], {'uid': 10, 'gid': 20, 'mode': 0o600})
            variables.pop('component_compose_file'); variables['component_native_services'] = ['example.service']
            variables['app']['database'] = {'user': 'example', 'group': 'example',
                'config_files': [{'source': str(payload/'application.json'), 'destination': '/etc/example/native.conf'}]}
            selected = m.descriptor(owner, cfg)
            self.assertEqual(selected['units'], ['example.service'])
            self.assertEqual(selected['metadata']['/etc/example/native.conf'], {'mode': 0o600})
            self.assertEqual(selected['native_files'], [{'path': '/etc/example/native.conf', 'user': 'example', 'group': 'example'}])

    def test_native_permission_check_cannot_accept_foreign_owner_or_link(self):
        import yaml
        tasks = yaml.safe_load((m.SOURCE/'ansible/component-rollback.yml').read_text())[0]['tasks']
        stat = next(task for task in tasks if task['name'].startswith('Inspect declared native'))
        self.assertFalse(stat['ansible.builtin.stat']['follow'])
        checks = next(task for task in tasks if task['name'].startswith('Verify the declared native'))['ansible.builtin.assert']['that']
        self.assertIn('item.stat.pw_name == item.item.user and item.stat.gr_name == item.item.group', checks)
        self.assertIn("item.stat.nlink == 1 and item.stat.mode == item.item.mode | default('0600')", checks)
        self.assertIn('item.stat.exists and item.stat.isreg and not item.stat.islnk', checks)
        compose = next(task for task in tasks if task['name'] == 'Restore only the owned Compose services')
        self.assertIn("'--pull', 'never', '--no-build'", compose['ansible.builtin.command']['argv'])

    def test_monitoring_reconciliation_checks_installed_config_key_owner_version_and_no_hold(self):
        import component_ansible
        import monitoring_paths
        import test_component_agent_phase
        case = test_component_agent_phase.AgentCallerTests(); case.setUp(); self.addCleanup(case.doCleanups)
        with patch.object(component_ansible, 'quiet', side_effect=case.ansible), \
                patch.dict(os.environ, {'HOMELAB_CD_RECOVERY': ''}): case.fixture.all_phases()
        cfg = case.cfg
        owner = read_json(case.fixture.state/'610/ordinary-complete.json', private=True)
        selected = m.agent_descriptor(owner, cfg)
        paths = monitoring_paths.PATHS
        payload = Path(owner['binding']['app_inputs_directory'])/'agent'
        variables = component_ansible.variables(cfg, 'zabbix-agent',
            payload=m.AppPayload.load(payload, owner['phase_inputs']['zabbix-agent']), previously_owned=True)
        raw = {paths['configuration']: variables['monitoring_agent_configuration'].encode(),
               paths['key']: (read_json(payload/'monitoring-agent.json', private=True)['psk']+'\n').encode(),
               paths['receipt']: encoded(selected['json'][paths['receipt']])}
        actual = {'files': {path: {'exists': True, 'content': base64.b64encode(value).decode(),
            'sha256': digest(value), **selected['metadata'][path]} for path, value in raw.items()},
            'packages': selected['packages'], 'images': []}
        actual['files'][paths['hold']] = {'exists': False}
        m.expected(selected, actual)
        self.assertEqual(selected['health'], [{'argv': ['systemctl', 'is-active', '--quiet', 'zabbix-agent2']}])
        self.assertIn({'path': paths['key'], 'user': 'zabbix', 'group': 'zabbix', 'mode': '0400'}, selected['native_files'])
        for mutate in (lambda v: v['files'][paths['configuration']].update(sha256='a'*64),
                       lambda v: v['files'][paths['key']].update(sha256='a'*64),
                       lambda v: v['files'][paths['key']].update(mode=0o600),
                       lambda v: v['files'][paths['receipt']].update(content=base64.b64encode(b'{}').decode()),
                       lambda v: v['files'][paths['hold']].update(exists=True),
                       lambda v: v.update(packages=['zabbix-agent2=old'])):
            bad = copy.deepcopy(actual); mutate(bad)
            with patch.object(m, 'execute', return_value=bad) as inspect, self.assertRaises(ValueError):
                m.verify_agents(owner, cfg, self.tx.work)
            self.assertEqual(inspect.call_args.kwargs, {'mode': 'capture'})
        with patch.object(m, 'execute', return_value=actual): m.verify_agents(owner, cfg, self.tx.work)
        cfg = copy.deepcopy(cfg); cfg['app']['monitoring']['profiles'].append('postgresql')
        with patch.object(m.component_ansible, 'variables', return_value=variables):
            selected = m.agent_descriptor(owner, cfg)
        self.assertIn('zabbix-agent2-plugin-postgresql='+variables['monitoring_postgresql_package']['version'], selected['packages'])


EXECUTE = m.execute
if __name__ == '__main__': unittest.main()
