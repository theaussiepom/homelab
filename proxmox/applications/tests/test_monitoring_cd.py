import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import monitoring_cd


class MonitoringCDTests(unittest.TestCase):
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
            packet = {'enabled': True, 'schema': 'homelab-monitoring-cd-v1',
                      'input_sha256': {'relative-path': '0' * 64}}
            with self.assertRaises(ValueError): monitoring_cd.run(packet, 'server')
            validate.assert_not_called()
