"""Keep existing-guest network maintenance separate from first installation."""
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


class NetworkUpdateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.play = yaml.safe_load((ROOT / 'ansible/network-update.yml').read_text())[0]
        cls.tasks = cls.play['tasks']

    def task(self, name):
        return next(task for task in self.tasks if task['name'] == name)

    def test_existing_guest_update_is_a_separate_single_application_play(self):
        self.assertEqual(self.play['hosts'], 'application')
        self.assertIs(self.play['become'], True)
        self.assertIs(self.play['any_errors_fatal'], True)
        install = yaml.safe_load((ROOT / 'ansible/network-startup.yml').read_text())[0]['tasks']
        refusal = next(t for t in install if t['name'] == 'Preserve any pre-existing network startup definition for review')
        self.assertEqual(refusal['ansible.builtin.assert']['that'], 'not item.stat.exists')

    def test_approved_hashes_and_native_identity_precede_the_only_common_import(self):
        names = [t['name'] for t in self.tasks]
        imported = self.task('Update only the common network gate and selected application dependency')
        self.assertEqual(imported['ansible.builtin.import_tasks'], '../../common/ansible/network-ready.yml')
        self.assertEqual(imported['vars'], {'network_ready_unit': '{{ network_update_unit }}', 'network_ready_activate': True})
        for name in ('Require both reviewed regular startup files before any copy',
                     'Match the commissioned guest before editing its startup files',
                     'Refuse a privileged or host-root-mapped container',
                     'Refuse drift during network readiness admission'):
            self.assertLess(names.index(name), names.index(imported['name']))
        expressions = '\n'.join(self.task('Require both reviewed regular startup files before any copy')['ansible.builtin.assert']['that'])
        self.assertIn('network_ready_gate_sha256', expressions)
        self.assertIn('network_ready_dependency_sha256', expressions)
        self.assertEqual(sum('ansible.builtin.import_tasks' in task for task in self.tasks), 1)

    def test_wait_is_one_bounded_ipv4_command_for_every_selected_interface(self):
        wait = self.task('Wait at most thirty seconds for all selected IPv4 interfaces')
        argv = wait['ansible.builtin.command']['argv']
        self.assertIn('/usr/lib/systemd/systemd-networkd-wait-online', argv)
        self.assertIn('--ipv4', argv)
        self.assertIn('--timeout=30', argv)
        self.assertIn('network_ready_interfaces', argv)
        self.assertIn(':routable', argv)
        self.assertNotIn('ansible.builtin.shell', wait)
        names = [task['name'] for task in self.tasks]
        self.assertLess(names.index(wait['name']), names.index('Update only the common network gate and selected application dependency'))

    def test_process_comparison_includes_pid_state_and_both_activation_timestamps(self):
        before = self.task('Record the active application process before the update')
        after = self.task('Verify the application process and activation timestamps are unchanged')
        self.assertEqual(before['ansible.builtin.command']['argv'], after['ansible.builtin.command']['argv'])
        for property_name in ('MainPID', 'ActiveEnterTimestamp', 'ActiveEnterTimestampMonotonic', 'ActiveState'):
            self.assertIn(property_name, before['ansible.builtin.command']['argv'][-1])
        self.assertEqual(after['failed_when'], 'network_update_process_after.stdout != network_update_process_before.stdout')

    def test_the_update_offers_no_app_or_guest_activation_path(self):
        for task in self.tasks:
            self.assertNotIn('ansible.builtin.shell', task)
            self.assertNotIn('ansible.builtin.service', task)
            systemd = task.get('ansible.builtin.systemd_service', {})
            self.assertNotIn('state', systemd)
            command = task.get('ansible.builtin.command', {}).get('argv', [])
            if isinstance(command, list):
                self.assertTrue(not command or command[0] == 'systemctl')
                self.assertFalse(set(command) & {'start', 'stop', 'restart', 'reload', 'docker', 'pct', 'qm'})
        common = yaml.safe_load((ROOT.parent / 'common/ansible/network-ready.yml').read_text())
        systemd_actions = [task['ansible.builtin.systemd_service'] for task in common if 'ansible.builtin.systemd_service' in task]
        self.assertEqual(systemd_actions, [{'daemon_reload': True}])


if __name__ == '__main__':
    unittest.main()
