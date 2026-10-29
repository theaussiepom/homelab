"""PegaProx deployment can verify an existing account but cannot bootstrap one."""

from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pegaprox_health as health
import pegaprox


class HealthTests(unittest.TestCase):
    def test_probe_is_read_only_and_has_no_initial_account_interface(self):
        self.assertNotIn("/api/auth/setup", health.CONTAINER_CODE)
        self.assertNotIn("/api/auth/login", health.CONTAINER_CODE)
        self.assertIn("state.get('initialized') is True", health.CONTAINER_CODE)
        self.assertEqual(
            pegaprox.health_checks()[0]["argv"],
            ["python3", "/opt/homelab-app/pegaprox-health.py"],
        )

    def test_probe_uses_fixed_container_argv_and_suppresses_private_failure_output(
        self,
    ):
        with patch.object(
            health.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(
                [], 0, "PegaProx verification passed\n", ""
            ),
        ) as run:
            self.assertEqual(
                health.verify(["docker", "exec", "fixture"]),
                "PegaProx verification passed",
            )
            self.assertEqual(run.call_args.args[0][:3], ["docker", "exec", "fixture"])
            self.assertNotIn("input", run.call_args.kwargs)
        with patch.object(
            health.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(
                [], 1, "sensitive response", "sensitive error"
            ),
        ):
            with self.assertRaisesRegex(ValueError, "PegaProx verification failed"):
                health.verify(["fixture"])
