import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import monitoring_cd


class MonitoringCDTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.cfg = {'app': {'kind': 'monitoring'}, 'paths': {
            'state_root': str(self.root / 'state'), 'backup_directory': str(self.root / 'backup')}}
        self.packet = {'enabled': True, 'schema': 'homelab-monitoring-cd-v2', 'plan_sha256': '0' * 64}
        for key in ('site_file', 'inventory', 'variables', 'known_hosts', 'ssh_key'):
            path = self.root / key
            path.write_text(json.dumps(self.cfg if key == 'site_file' else {}))
            path.chmod(0o600)
            self.packet[key] = str(path)
        self.packet['input_sha256'] = {self.packet[key]: monitoring_cd.deploy.sha(self.packet[key])
            for key in ('site_file', 'inventory', 'variables', 'known_hosts', 'ssh_key')}
        self.work = self.root / 'state/213'; self.work.mkdir(mode=0o700, parents=True)
        (self.root / 'backup/213').mkdir(mode=0o700, parents=True)
        self.commands = {}
        for name, options in [('validate', {'return_value': 213}), ('input_hashes', {'return_value': {}}),
                              ('backup', {}), ('quiet', {}), ('execute', {})]:
            patcher = patch.object(monitoring_cd.deploy, name, **options)
            self.commands[name] = patcher.start(); self.addCleanup(patcher.stop)

    def receipt(self, phase, packet=None):
        binding = monitoring_cd.hashlib.sha256(monitoring_cd.encoded(packet or self.packet)).hexdigest()
        monitoring_cd.write_new(self.work / ('monitoring-' + phase + '.json'),
                                monitoring_cd.encoded({'packet_sha256': binding}))

    def assert_no_commands(self):
        for name in ('backup', 'quiet', 'execute'):
            self.commands[name].assert_not_called()

    def test_server_cannot_own_guest_agent_or_database_phases(self):
        for phase in ('agents', 'database'):
            with self.subTest(phase=phase), self.assertRaises(ValueError):
                monitoring_cd.run(self.packet, phase)
        self.assert_no_commands()
        self.packet['schema'] = 'homelab-monitoring-cd-v1'
        with self.assertRaises(ValueError): monitoring_cd.run(self.packet, 'server')
        self.assert_no_commands()

    def test_incomplete_bootstrap_access_cannot_create_a_hold(self):
        for value in (None, {}, {'config':'/private/config','token':'/private/token','ca':'/private/ca'}, []):
            with self.subTest(value=value):
                packet=dict(self.packet)
                if value is not None: packet['access']=value
                with self.assertRaisesRegex(ValueError,'complete access packet'):
                    monitoring_cd.run(packet,'bootstrap')
                self.assert_no_commands()
                self.assertFalse((self.work/'MONITORING-HOLD.json').exists())

    def test_completed_phase_is_not_replayed(self):
        self.receipt('configure')
        self.assertEqual(monitoring_cd.run(self.packet, 'configure'),
                         {'status': 'completed', 'phase': 'configure', 'replayed': False})
        self.assert_no_commands()

    def test_completed_receipt_rejects_changed_packet(self):
        self.receipt('configure', dict(self.packet, plan_sha256='1' * 64))
        with self.assertRaisesRegex(ValueError, 'packet changed'):
            monitoring_cd.run(self.packet, 'configure')
        self.assert_no_commands()

    def test_missing_or_mismatched_dependency_cannot_run(self):
        for present in (False, True):
            with self.subTest(present=present):
                if present: self.receipt('server', dict(self.packet, plan_sha256='1' * 64))
                with self.assertRaisesRegex(ValueError, 'matching monitoring dependency'):
                    monitoring_cd.run(self.packet, 'configure')
                self.assert_no_commands()

    def test_failed_phase_retains_local_and_nas_holds_and_cannot_retry(self):
        self.receipt('server')
        self.commands['quiet'].side_effect = RuntimeError('synthetic command failure')
        with self.assertRaisesRegex(RuntimeError, 'synthetic command failure'):
            monitoring_cd.run(self.packet, 'configure')
        self.assertTrue((self.work / 'MONITORING-HOLD.json').is_file())
        self.assertEqual(len(list((self.root / 'backup/213').glob('monitoring-*/HOLD.json'))), 1)
        self.assertFalse((self.work / 'monitoring-configure.json').exists())
        for command in self.commands.values(): command.reset_mock()
        with self.assertRaisesRegex(ValueError, 'held'):
            monitoring_cd.run(self.packet, 'configure')
        self.assert_no_commands()

    def test_existing_hold_markers_block_every_command(self):
        for marker in ('MONITORING-HOLD.json', 'HOLD.json', 'ROLLOUT-HOLD.json', 'CONTINUATION-HOLD.json'):
            with self.subTest(marker=marker):
                path = self.work / marker; path.write_text('{}'); path.chmod(0o600)
                with self.assertRaisesRegex(ValueError, 'held'):
                    monitoring_cd.run(self.packet, 'configure')
                self.assert_no_commands(); path.unlink()

    def test_success_records_receipt_and_clears_both_holds_before_no_replay(self):
        self.receipt('server')
        self.assertEqual(monitoring_cd.run(self.packet, 'configure')['status'], 'passed')
        self.commands['quiet'].assert_called_once()
        self.assertTrue((self.work / 'monitoring-configure.json').is_file())
        self.assertFalse((self.work / 'MONITORING-HOLD.json').exists())
        self.assertFalse(list((self.root / 'backup/213').glob('monitoring-*/HOLD.json')))
        self.assertEqual(len(list((self.root / 'backup/213').glob('monitoring-*/complete.json'))), 1)
        for command in self.commands.values(): command.reset_mock()
        self.assertFalse(monitoring_cd.run(self.packet, 'configure')['replayed'])
        self.assert_no_commands()

    def test_nested_secret_and_package_files_are_bound(self):
        files = monitoring_cd.file_references({'hosts': [{'psk_file': '/private/agent.psk',
                     'package_file': '/private/agent.deb', 'address': '198.18.30.50'}],
                     'monitoring_verification_file': '/private/verification.json'})
        self.assertEqual(files, {'/private/agent.psk', '/private/agent.deb', '/private/verification.json'})
        with self.assertRaises(ValueError): monitoring_cd.file_references({'psk_file': 'relative'})
    def test_disabled_proposal_cannot_reach_any_target(self):
        with patch.object(monitoring_cd.deploy, 'validate') as validate, patch.object(monitoring_cd.deploy, 'quiet') as command:
            for phase in [*monitoring_cd.PHASES, 'server', 'verify']:
                result = monitoring_cd.run({'enabled': False}, phase)
                self.assertEqual(result, {'status': 'disabled', 'production_changed': False})
            validate.assert_not_called(); command.assert_not_called()

    def test_enabled_packet_needs_reviewed_exact_inputs_before_target_access(self):
        with patch.object(monitoring_cd.deploy, 'validate') as validate:
            packet = {'enabled': True, 'schema': 'homelab-monitoring-cd-v2',
                      'input_sha256': {'relative-path': '0' * 64}}
            with self.assertRaises(ValueError): monitoring_cd.run(packet, 'server')
            validate.assert_not_called()
