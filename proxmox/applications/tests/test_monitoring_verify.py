import sys
import json
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import monitoring_verify as verification


class InitialCollectionTests(unittest.TestCase):
    def test_logout_failure_preserves_acceptance_and_freshness_errors_but_fails_success(self):
        now = int(verification.time.time())
        with tempfile.TemporaryDirectory() as tmp:
            password = Path(tmp) / 'password'; password.write_text('synthetic-password')
            config = {'url': 'https://fixture.invalid', 'password_file': str(password), 'not_before': 0,
                      'agents': [{'hostname': 'fixture-linux', 'psk_identity': 'fixture-linux'}],
                      'proxmox_hostname': 'fixture-pve', 'commissioned_vmids': [213]}
            def response(result): return io.StringIO(json.dumps({'result': result}))
            for outcome in ('identity', 'pending', 'passed', 'passed_outer'):
                with self.subTest(outcome=outcome):
                    values = [response('fixture-token')]
                    if outcome == 'identity':
                        values.append(response([]))
                        expected, message = verification.AcceptanceFailure, 'individual PSK'
                    else:
                        values.extend([
                            response([{'hostid': '1', 'tls_accept': '2',
                                       'description': 'HomeLab active agent; PSK identity=fixture-linux'}]),
                            response([{'type': '7', 'state': '0',
                                       'lastclock': str(0 if outcome == 'pending' else now), 'lastvalue': '1'}]),
                            response([{'hostid': '2', 'macros': [{'macro': '{$HTTP.TLS.VERIFY}', 'value': 'full'}]}]),
                            response([{'key_': key, 'state': '0', 'lastclock': str(now), 'lastvalue': value}
                                      for key, value in [('proxmox.api.available', '200'),
                                          ('proxmox.cluster.resources', '{"data":[{"type":"node"},{"vmid":213}]}')]]),
                            response([{'verify_peer': '1', 'verify_host': '1'}]),
                            response([{'verify_peer': '1', 'verify_host': '1'}])])
                        expected, message = verification.FreshnessPending, 'Waiting for fresh'
                        if outcome.startswith('passed'):
                            ui = io.BytesIO(b'Zabbix'); ui.status = 200; values.append(ui)
                            expected, message = OSError, 'synthetic logout failure'
                    values.append(OSError('synthetic logout failure'))
                    opener = Mock(); opener.open.side_effect = values
                    with patch.object(verification, 'build_opener', return_value=opener):
                        if outcome == 'passed_outer':
                            try:
                                raise RuntimeError('unrelated caller exception')
                            except RuntimeError:
                                with self.assertRaisesRegex(expected, message): verification.verify(config)
                        else:
                            with self.assertRaisesRegex(expected, message): verification._verify_once(config)

    def test_resource_inventory_rejects_malformed_samples_with_fixed_safe_reason(self):
        for raw in ('private-synthetic-data', 'null', '{}', '{"data":null}', '{"data":{}}',
                    '{"data":[null]}', '{"data":["private-synthetic-data"]}', '{"data":[{"vmid":[]}]}'):
            with self.subTest(raw=raw), self.assertRaisesRegex(verification.AcceptanceFailure,
                                                               '^The Proxmox API sample is malformed$'):
                verification.resource_inventory(raw)
        self.assertEqual(verification.resource_inventory('{"data":[{"type":"node"},{"vmid":213}]}'),
                         ({None, 213}, True))

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
