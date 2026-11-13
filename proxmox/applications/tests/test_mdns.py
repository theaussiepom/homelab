"""Exercise the real shell helper using an ip stub, never change host networking."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "mdns-route.sh"


class MdnsTests(unittest.TestCase):
    def run_helper(self, assigned, selected=None, legacy=None, interface="eth0"):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / "calls"
            stub = root / "ip"
            stub.write_text(
                '#!/bin/sh\nif [ "$1" = -o ]; then\n echo "2: '
                + interface
                + " inet "
                + assigned
                + '/24 scope global eth0"\nelse\n echo "$*" >> "$TEST_IP_LOG"\nfi\n'
            )
            stub.chmod(0o700)
            env = dict(
                os.environ,
                PATH=str(root) + ":" + os.environ["PATH"],
                TEST_IP_LOG=str(log),
            )
            env.pop("MACVLAN_PREFIX", None)
            env.pop("HOMELAB_HA_IPV4", None)
            if selected:
                env["HOMELAB_HA_IPV4"] = selected
            if legacy:
                env["MACVLAN_PREFIX"] = legacy
            result = subprocess.run(
                ["sh", str(SCRIPT)], env=env, capture_output=True, text=True
            )
            return result.returncode, log.read_text() if log.exists() else ""

    def test_explicit_rehearsal_address_uses_its_interface_for_both_protocols(self):
        code, calls = self.run_helper("198.18.100.20", selected="198.18.100.20")
        self.assertEqual(code, 0)
        self.assertIn("224.0.0.251/32 dev eth0", calls)
        self.assertIn("ff02::fb dev eth0", calls)

    def test_prefix_only_input_is_refused_without_route_changes(self):
        code, calls = self.run_helper("198.18.100.242", legacy="198.18.100")
        self.assertNotEqual(code, 0)
        self.assertEqual(calls, "")

    def test_a_missing_address_never_changes_a_route(self):
        code, calls = self.run_helper("198.18.100.20", selected="198.18.100.21")
        self.assertNotEqual(code, 0)
        self.assertEqual(calls, "")

    def test_lxc_peer_suffix_is_removed_from_the_route_device(self):
        code, calls = self.run_helper(
            "198.18.100.20", selected="198.18.100.20", interface="eth0@if42"
        )
        self.assertEqual(code, 0)
        self.assertIn("dev eth0", calls)
        self.assertNotIn("@if42", calls)


if __name__ == "__main__":
    unittest.main()
