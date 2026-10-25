"""Contract for the single automatic guest-to-host API allowance."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
import host_api
import runner


class ProxmoxFixture:
    def __init__(self):
        """Initialize the in-memory API fixture without a live connection."""
        self.rules = [
            {'type': 'in', 'action': 'ACCEPT', 'source': '198.18.25.0/24',
             'proto': 'tcp', 'dport': '22', 'enable': 1, 'comment': 'Existing admin access'},
            {'type': 'in', 'action': 'DROP', 'enable': 1, 'comment': 'Existing final deny'},
        ]
        self.options = {'enable': 1, 'policy_in': 'DROP', 'policy_out': 'ACCEPT'}
        self.calls = []
        self.lose_other_rule = False
        self.fail_create = False

    def execute(self, args):
        """Simulate only the expected Proxmox commands and record their effects."""
        self.calls.append(args)
        if args[:2] == ['ip', '-j']:
            return json.dumps([{'addr_info': [{'family': 'inet', 'local': '198.18.25.2'}]}])
        if args[:2] == ['pct', 'exec']:
            return '198.18.25.90\n'
        if args[:2] == ['pvesh', 'get']:
            if args[2].endswith('/options'):
                return json.dumps(self.options)
            return json.dumps([dict(r, pos=i, digest='synthetic') for i, r in enumerate(self.rules)])
        if args[:2] == ['pvesh', 'create']:
            if self.fail_create:
                raise RuntimeError('synthetic create failure')
            rule = dict(zip((key[2:] for key in args[3::2]), args[4::2]))
            self.rules.insert(0, rule)
            if self.lose_other_rule:
                self.rules.pop()
            return 'null'
        raise AssertionError(args)


class HostApiTests(unittest.TestCase):
    def setUp(self):
        """Create isolated synthetic inputs for this test case."""
        self.host = ProxmoxFixture()
        self.request = {'node': 'pve', 'vmid': 900, 'guest_address': '198.18.25.90',
                        'api_endpoint': 'https://pve.example.invalid:8006/'}
        self.hostname = patch.object(host_api.socket, 'gethostname', return_value='pve')
        self.dns = patch.object(host_api.socket, 'getaddrinfo', return_value=[
            (2, 1, 6, '', ('198.18.25.2', 8006))])
        self.hostname.start()
        self.dns.start()
        self.addCleanup(self.hostname.stop)
        self.addCleanup(self.dns.stop)

    def test_prepend_one_narrow_rule_preserving_existing_rules_and_options(self):
        """Verify prepend one narrow rule preserving existing rules and options."""
        old_rules, old_options = copy.deepcopy(self.host.rules), dict(self.host.options)
        result = host_api.ensure_rule(self.request, self.host.execute)
        rule = self.host.rules[0]
        self.assertTrue(result['changed'])
        self.assertEqual((rule['source'], rule['dest'], rule['proto'], rule['dport']),
                         ('198.18.25.90/32', '198.18.25.2/32', 'tcp', '8006'))
        self.assertEqual((rule['type'], rule['action'], str(rule['enable'])), ('in', 'ACCEPT', '1'))
        self.assertEqual(self.host.rules[1:], old_rules)
        self.assertEqual(self.host.options, old_options)
        self.assertFalse(any(args[1] in ('set', 'delete') for args in self.host.calls if args[0] == 'pvesh'))

    def test_second_run_reuses_the_exact_first_rule_without_another_write(self):
        """Verify second run reuses the exact first rule without another write."""
        host_api.ensure_rule(self.request, self.host.execute)
        result = host_api.ensure_rule(self.request, self.host.execute)
        self.assertFalse(result['changed'])
        self.assertEqual(sum(args[:2] == ['pvesh', 'create'] for args in self.host.calls), 1)

    def test_conflicting_owned_rule_is_held_without_rewrite(self):
        """Verify conflicting owned rule is held without rewrite."""
        host_api.ensure_rule(self.request, self.host.execute)
        self.host.rules[0]['source'] = '198.18.25.0/24'
        self.host.calls.clear()
        with self.assertRaisesRegex(RuntimeError, 'conflict'):
            host_api.ensure_rule(self.request, self.host.execute)
        self.assertFalse(any(args[:2] == ['pvesh', 'create'] for args in self.host.calls))

    def test_incomplete_post_write_readback_fails_without_retry_or_cleanup(self):
        """Verify incomplete post write readback fails without retry or cleanup."""
        self.host.lose_other_rule = True
        with self.assertRaisesRegex(RuntimeError, 'preserv'):
            host_api.ensure_rule(self.request, self.host.execute)
        self.assertEqual(sum(args[:2] == ['pvesh', 'create'] for args in self.host.calls), 1)
        self.assertFalse(any(args[:2] == ['pvesh', 'delete'] for args in self.host.calls))

    def test_create_failure_is_not_retried(self):
        """Verify create failure is not retried."""
        self.host.fail_create = True
        with self.assertRaisesRegex(RuntimeError, 'create failure'):
            host_api.ensure_rule(self.request, self.host.execute)
        self.assertEqual(sum(args[:2] == ['pvesh', 'create'] for args in self.host.calls), 1)

    def test_unrelated_destination_or_wrong_node_never_writes(self):
        """Verify unrelated destination or wrong node never writes."""
        with patch.object(host_api.socket, 'getaddrinfo', return_value=[
                (2, 1, 6, '', ('198.18.25.99', 8006))]):
            with self.assertRaisesRegex(RuntimeError, 'local'):
                host_api.ensure_rule(self.request, self.host.execute)
        with patch.object(host_api.socket, 'gethostname', return_value='other-pve'):
            with self.assertRaisesRegex(RuntimeError, 'node'):
                host_api.ensure_rule(self.request, self.host.execute)
        self.assertFalse(any(args[:2] == ['pvesh', 'create'] for args in self.host.calls))

    def test_source_must_be_the_actual_guest_address_and_endpoint_8006(self):
        """Verify source must be the actual guest address and endpoint 8006."""
        for key, value in [('guest_address', '198.18.25.0/24'),
                           ('guest_address', '198.18.25.91'),
                           ('api_endpoint', 'https://pve.example.invalid:443/'),
                           ('vmid', 4916 + 4)]:
            request = dict(self.request, **{key: value})
            with self.assertRaises((RuntimeError, ValueError)):
                host_api.ensure_rule(request, self.host.execute)
        self.assertFalse(any(args[:2] == ['pvesh', 'create'] for args in self.host.calls))

    def test_firewall_failure_does_not_freeze_or_start_handover(self):
        """Verify firewall failure does not freeze or start handover."""
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            with patch.object(runner.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'synthetic failure')):
                with self.assertRaises(ValueError):
                    runner.allow_host_api(work, ['ssh', 'root@pve'], self.request)
            self.assertFalse((work / 'HANDOVER.json').exists())
            self.assertTrue((work / 'host-firewall-attempt.json').exists())
            self.assertTrue((work / 'host-firewall-result.json').exists())
            with patch.object(runner.subprocess, 'run') as repeated:
                with self.assertRaises(ValueError):
                    runner.allow_host_api(work, ['ssh', 'root@pve'], self.request)
                repeated.assert_not_called()


if __name__ == '__main__':
    unittest.main()
