"""Ordinary PBS phase preserves locks, private payload binding and repeat behavior."""
import copy
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import component_ansible
import component_guest
import component_prepare
import deploy
from private_io import encoded, read_json, write_bytes, write_new
import test_component_deployment as fixture_module


class BackupPhaseTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture_module.DeploymentIntegrationTests('test_real_source_and_receiver_repeat_owned_fresh_guest_without_lifecycle_flip')
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.cfg = self.fixture.cfg
        self.cfg['app']['packages'].append('proxmox-backup-client=4.2.8-1')
        self.cfg['app']['backup'] = {'schema': 'homelab-pbs-coverage-v1', 'profile': 'pbs',
            'owner': {'node': self.cfg['site']['node'], 'vmid': 610, 'hostname': self.cfg['guest']['hostname']},
            'configuration': {}, 'managed_volumes': {},
            'applications': {'recursive_a': {'adapter': 'unbound', 'runtime_files': [], 'storage': {},
                                           'configuration': {}, 'databases': []}}}
        self.cfg['deployment']['phases'].append('pbs-agent')
        self.cfg['deployment']['payload_phases']['pbs-agent'] = 'backup-agent'
        packet = read_json(self.fixture.packet, private=True)
        packet['files']['site.json'] = encoded(self.cfg).decode()
        write_bytes(self.fixture.packet, encoded(packet)); self.calls = []

    def ansible(self, argv, environment, log):
        if log.parent.name != 'pbs-agent': return self.fixture.ansible(argv, environment, log)
        value = read_json(Path(argv[-1][1:]), private=True)
        started = read_json(log.parent.parent/'pbs-agent-started.json', private=True)
        self.assertEqual(started['phase_inputs']['app'], 'backup-agent')
        self.assertTrue(any(name.endswith('/component-backup.yml') for name in argv))
        self.assertFalse(value['app']['start_services'])
        self.assertNotIn('component_application', value)
        self.assertEqual(json.loads(value['backup_agent']['inventory']), self.cfg['app']['backup'])
        self.assertFalse(any(key.startswith('HOMELAB_APP_SECRET_') for key in environment))
        self.calls.append(started['phase_inputs'])
        write_new(log, b'example : ok=1 changed=0 failed=0\n')

    def test_complete_ordinary_phase_and_repeat_keep_one_sealed_payload(self):
        with patch.object(component_ansible, 'quiet', side_effect=self.ansible):
            self.fixture.all_phases()
            receipt = read_json(self.fixture.state/'610/ordinary-complete.json', private=True)
            parent = Path(receipt['binding']['app_inputs_directory'])/'backup-agent'
            before = {p.name: (p.stat().st_ino, p.read_bytes()) for p in parent.iterdir()}
            self.assertEqual(set(before), {'application.json', 'selected-app.json'})
            with patch.dict(os.environ, {'GITHUB_RUN_ID': '102', 'GITHUB_RUN_NUMBER': '11'}):
                self.fixture.all_phases()
            self.assertEqual(before, {p.name: (p.stat().st_ino, p.read_bytes()) for p in parent.iterdir()})
            self.assertEqual(len(self.calls), 2)
            self.assertFalse((self.fixture.state/'610/ORDINARY-HOLD.json').exists())

    def test_unselected_phase_does_not_contact_a_target(self):
        cfg = self.cfg; cfg['app'].pop('backup')
        cfg['deployment']['phases'].remove('pbs-agent'); cfg['deployment']['payload_phases'].pop('pbs-agent')
        packet = read_json(self.fixture.packet, private=True); packet['files']['site.json'] = encoded(cfg).decode()
        write_bytes(self.fixture.packet, encoded(packet))
        self.assertEqual(deploy.run('pbs-agent', self.fixture.packet, inputs=self.fixture.inputs)['status'], 'not_selected')

    def test_foreign_payload_and_changed_manifest_refuse(self):
        with patch.object(component_ansible, 'quiet', side_effect=self.ansible):
            for phase in ('infrastructure', 'preparation', 'recursive_a'):
                deploy.run(phase, self.fixture.packet, inputs=self.fixture.inputs, environment={})
        payload = component_prepare.prepare_backup(self.cfg, {})
        with self.assertRaises(ValueError): component_ansible.variables(self.cfg, 'pbs-agent')
        foreign = copy.deepcopy(self.cfg); foreign['app']['backup']['configuration'] = {
            'different': {'path': '/etc/hosts', 'kind': 'file'}}
        with self.assertRaises(ValueError): component_ansible.variables(foreign, 'pbs-agent', payload=payload)
        foreign = copy.deepcopy(self.cfg); foreign['deployment']['phases'].reverse()
        with self.assertRaises(ValueError): component_guest.phases(foreign)


if __name__ == '__main__': unittest.main()
