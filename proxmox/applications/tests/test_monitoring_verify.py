import sys
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import monitoring_verify as verification


class InitialCollectionTests(unittest.TestCase):
    def test_cli_reports_fixed_acceptance_reasons_without_private_exception_details(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.json'
            for content, expected in [(json.dumps({'url': 'http://fixture.invalid'}),
                                       'Use the reviewed HTTPS frontend origin'),
                                      ('private-synthetic-data', 'cause was withheld')]:
                path.write_text(content)
                result = subprocess.run([sys.executable, str(Path(verification.__file__)), '--config', str(path)],
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)
                self.assertNotIn('private-synthetic-data', result.stderr)

    def test_missing_samples_wait_within_one_attempt(self):
        with patch.object(verification, '_verify_once', side_effect=[verification.FreshnessPending(), {'status': 'passed'}]) as read, \
                patch.object(verification.time, 'monotonic', side_effect=[0, 1]), patch.object(verification.time, 'sleep') as sleep:
            self.assertEqual(verification.verify({}), {'status': 'passed'})
            self.assertEqual(read.call_count, 2)
            sleep.assert_called_once_with(5)

    def test_identity_tls_errors_fail_immediately_and_freshness_wait_is_finite(self):
        with patch.object(verification, '_verify_once', side_effect=ValueError('TLS identity differs')) as read, patch.object(verification.time, 'sleep') as sleep:
            with self.assertRaisesRegex(ValueError, 'TLS identity'): verification.verify({})
            self.assertEqual(read.call_count, 1); sleep.assert_not_called()
        with patch.object(verification, '_verify_once', side_effect=verification.FreshnessPending()), \
                patch.object(verification.time, 'monotonic', side_effect=[0, 601]), patch.object(verification.time, 'sleep') as sleep:
            with self.assertRaisesRegex(ValueError, 'did not arrive'): verification.verify({})
            sleep.assert_not_called()
