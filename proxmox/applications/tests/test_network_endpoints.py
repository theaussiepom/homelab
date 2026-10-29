"""Allocation and qualified endpoint identities stay separate, using synthetic CIDRs."""

import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import network_endpoints as endpoints


class EndpointTests(unittest.TestCase):
    def test_static_and_dhcp_resolve_one_concrete_endpoint_without_mutating_allocation(self):
        static = {'ipv4': '198.18.40.2/27'}
        dynamic = {'ipv4': 'dhcp', 'ipv4_endpoint': '198.18.40.3/27', 'gateway': None}
        guest = {'interfaces': [static, dynamic, {'ipv4': 'manual'}]}
        before = copy.deepcopy(guest)
        self.assertEqual(endpoints.addresses(guest), {'198.18.40.2', '198.18.40.3'})
        self.assertEqual(endpoints.interface(dynamic).network.prefixlen, 27)
        self.assertEqual(guest, before)

    def test_qualification_is_required_only_for_dhcp_and_never_guesses_a_prefix(self):
        for nic in [
            {'ipv4': 'dhcp'},
            {'ipv4': 'dhcp', 'ipv4_endpoint': '198.18.40.2/27', 'gateway': '198.18.40.1'},
            {'ipv4': '198.18.40.2/27', 'ipv4_endpoint': '198.18.40.2/27'},
            {'ipv4': 'manual', 'ipv4_endpoint': '198.18.40.2/27'},
            *[{'ipv4': 'dhcp', 'ipv4_endpoint': value} for value in
              [None, 24, '198.18.40.2', '2001:db8::2/64', 'not-an-address/24', '198.18.40.2/255.255.255.224']],
        ]:
            with self.subTest(nic=nic), self.assertRaises(ValueError):
                endpoints.addresses({'interfaces': [nic]})

    def test_copied_zigbee_checker_starts_without_controller_only_modules(self):
        import os
        import shutil
        import subprocess
        import tempfile
        import zigbee2mqtt

        with tempfile.TemporaryDirectory() as tmp:
            checker = Path(tmp) / "zigbee2mqtt.py"
            shutil.copyfile(zigbee2mqtt.__file__, checker)
            environment = dict(os.environ)
            environment.pop("PYTHONPATH", None)
            result = subprocess.run([sys.executable, str(checker), "--help"], cwd=tmp, env=environment, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("validate", result.stdout)
