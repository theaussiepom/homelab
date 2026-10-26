"""Configuration reruns must never copy stale workstation state or replay failures."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import configuration
from bootstrap import read, write, Refused


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.work = self.root / 'bundle'; (self.work / 'tofu').mkdir(parents=True)
        write(self.work / 'tofu/site.auto.tfvars.json', {
            'site': {'node': 'pve', 'api_endpoint': 'https://pve.example.invalid:8006/'},
            'deploy': {'vmid': 900, 'storage_id': 'local-lvm', 'template_file_id': 'local:vztmpl/debian.tar.zst',
                       'bridge': 'vmbr0', 'vlan': 25, 'mac': '02:00:00:00:09:00', 'ipv4': '198.18.25.10/24'}})
        self.saved = {'status': 'ready', 'token_id': 'root@pam!homelab-deploy-900',
                      'PROXMOX_VE_API_TOKEN': 'synthetic-secret', 'expires_at': 0,
                      'grants': [{'path': '/vms/900', 'roles': 'PVEVMAdmin', 'propagate': False}]}
        write(self.work / 'access.json', self.saved)
        write(self.work / 'settings.json', {'repository': 'example/private-site', 'runner_name': 'deploy'})
        write(self.work / 'HANDOVER.json', {'active_owner': 'runner'})
        self.state = self.work / 'tofu/terraform.tfstate'; self.state.write_bytes(b'old backup only')
        self.deployment = self.root / 'deployment.json'
        write(self.deployment, {'schema': 'homelab-bootstrap-deployment-v1', 'applications': [],
             'restart_deploy': False, 'nas': {'server': '198.18.20.2', 'export': '/volume1/test',
                                            'version': '4.1', 'directory': 'bootstrap-state'}})
        self.report = {'status': 'ready', 'plan_sha256': 'a' * 64,
                       'plan': {'access': {}, 'nas': {}}, 'access': dict(self.saved, changed=False),
                       'nas': {'changed': False, 'backup_source': '198.18.20.2:/volume1/test[/bootstrap-state]'},
                       'addresses': ['198.18.25.10'], 'guest_host_key': 'ssh-ed25519 AAAAsynthetic'}

    def tearDown(self):
        self.temp.cleanup()

    def remote(self, *args, **kwargs):
        value = {'status': 'ready'} if kwargs.get('finish') else self.report
        return subprocess.CompletedProcess([], 0, json.dumps(value), '')

    def test_plan_and_completed_rerun_leave_stale_state_and_token_unchanged(self):
        with patch.object(configuration, 'remote', side_effect=self.remote), \
                patch.object(configuration.subprocess, 'run') as ansible:
            for _ in range(2):
                plan = configuration.configure(self.work, self.deployment)
                result = configuration.configure(self.work, self.deployment, plan['plan_sha256'])
                self.assertFalse(result['changed'])
            self.assertEqual(ansible.call_count, 2)
        self.assertEqual(self.state.read_bytes(), b'old backup only')
        self.assertEqual(read(self.work / 'access.json'), self.saved)
        self.assertTrue((self.work / 'HANDOVER.json').exists())
        self.assertFalse((self.work / 'CONFIGURATION-HOLD.json').exists())

    def test_changed_inputs_refuse_before_remote_mutation(self):
        with patch.object(configuration, 'remote', side_effect=self.remote):
            configuration.configure(self.work, self.deployment)
        value = read(self.deployment); value['restart_deploy'] = True; write(self.deployment, value)
        with patch.object(configuration, 'remote') as remote:
            with self.assertRaisesRegex(Refused, 'inputs changed'):
                configuration.configure(self.work, self.deployment, 'a' * 64)
            remote.assert_not_called()

    def test_interrupted_apply_leaves_hold_and_never_automatically_retries(self):
        with patch.object(configuration, 'remote', side_effect=self.remote):
            configuration.configure(self.work, self.deployment)
        with patch.object(configuration, 'remote', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                configuration.configure(self.work, self.deployment, 'a' * 64)
        self.assertTrue((self.work / 'CONFIGURATION-HOLD.json').exists())
        with patch.object(configuration, 'remote') as remote:
            with self.assertRaisesRegex(Refused, 'Previous configuration failed'):
                configuration.configure(self.work, self.deployment, 'a' * 64)
            remote.assert_not_called()

    def test_guest_configuration_failure_keeps_hold_and_does_not_clear_remote_marker(self):
        with patch.object(configuration, 'remote', side_effect=self.remote) as remote:
            configuration.configure(self.work, self.deployment)
            with patch.object(configuration.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, ['ansible-playbook'])):
                with self.assertRaises(subprocess.CalledProcessError):
                    configuration.configure(self.work, self.deployment, 'a' * 64)
            self.assertFalse(any(c.kwargs.get('finish') for c in remote.call_args_list))
        self.assertEqual(self.state.read_bytes(), b'old backup only')
        self.assertTrue((self.work / 'CONFIGURATION-HOLD.json').exists())


if __name__ == '__main__':
    unittest.main()
