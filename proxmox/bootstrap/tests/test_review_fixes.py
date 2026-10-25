"""Regressions for apply shutdown and the runner's token-only boundary."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
import native
import runner
from bootstrap import Refused, write


class CredentialBoundaryTests(unittest.TestCase):
    def test_environment_contains_only_one_single_line_api_token(self):
        """Keep unrelated operator and GitHub secrets out of the guest payload."""
        with patch.dict(os.environ, {'PROXMOX_VE_API_TOKEN': 'synthetic-token',
                                    'GH_TOKEN': 'synthetic-personal-token'}, clear=True):
            self.assertEqual(runner.connection_environment(),
                             {'PROXMOX_VE_API_TOKEN': 'synthetic-token'})
        for value in ('token\nnext', 'token\rnext'):
            with self.subTest(value=repr(value)), patch.dict(os.environ,
                    {'PROXMOX_VE_API_TOKEN': value}, clear=True):
                with self.assertRaises(Refused):
                    runner.connection_environment()

    def test_invalid_credentials_stop_before_native_verification(self):
        """Reject account credentials or a missing token before any host action."""
        for environment in ({}, {'PROXMOX_VE_USERNAME': 'root@pam'},
                            {'PROXMOX_VE_PASSWORD': 'synthetic-password'},
                            {'PROXMOX_VE_API_TOKEN': 'synthetic-token',
                             'PROXMOX_VE_PASSWORD': 'synthetic-password'}):
            with self.subTest(names=sorted(environment)), tempfile.TemporaryDirectory() as tmp:
                work = Path(tmp)
                with patch.dict(os.environ, environment, clear=True), \
                        patch.object(native, 'run_locked', side_effect=AssertionError('host action')) as verify:
                    with self.assertRaises(Refused):
                        runner.install_locked(work)
                verify.assert_not_called()
                self.assertFalse((work / 'HANDOVER.json').exists())
                self.assertFalse((work / 'runner-environment').exists())


class ApplyTimeoutTests(unittest.TestCase):
    def exercise(self, waits):
        """Run the saved-apply caller with a simulated slow OpenTofu child."""
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        work = Path(root.name)
        (work / 'tofu').mkdir()
        (work / 'tofu/backend.tf').write_text('terraform { backend "local" {} }')
        plan = work / 'bootstrap.tfplan'
        plan.write_bytes(b'synthetic saved plan')
        write(work / 'saved-plan.json', {'plan': str(plan), 'sha256': native.sha(plan),
                                       'inputs_sha256': native.binding(work)})
        child = Mock(returncode=0)
        child.wait.side_effect = waits
        def command(arguments, **kwargs):
            """Simulate the expected tool command without contacting external services."""
            if arguments[1] == 'apply':
                raise subprocess.TimeoutExpired(arguments, 900)
            if arguments[1] == 'show':
                json.dump({'resource_changes': [{
                    'address': 'module.guests["deploy"].proxmox_virtual_environment_container.guest',
                    'change': {'actions': ['create']}}]}, kwargs['stdout'])
            return subprocess.CompletedProcess(arguments, 0)
        with patch.object(native.platform, 'system', return_value='Linux'), \
                patch.object(native.subprocess, 'run', side_effect=command), \
                patch.object(native.subprocess, 'Popen', return_value=child) as popen:
            try:
                result = native.run_locked('apply', work)
            except Refused:
                result = json.loads((work / 'HOLD.json').read_text())
        return work, plan, child, popen, result

    def test_apply_timeout_interrupts_and_keeps_unknown_hold(self):
        """Allow partial-state persistence without claiming remote closure."""
        work, _, child, popen, result = self.exercise([
            subprocess.TimeoutExpired('tofu apply', 900), 0])
        popen.assert_called_once()
        child.send_signal.assert_called_once_with(signal.SIGINT)
        self.assertEqual([c.kwargs['timeout'] for c in child.wait.call_args_list], [900, 300])
        child.kill.assert_not_called()
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertTrue((work / 'HOLD.json').exists())

    def test_apply_timeout_escalates_only_after_grace_period(self):
        """Bound a noncooperating local process while preserving UNKNOWN."""
        _, _, child, _, result = self.exercise([
            subprocess.TimeoutExpired('tofu apply', 900),
            subprocess.TimeoutExpired('tofu apply', 300), 0])
        child.send_signal.assert_called_once_with(signal.SIGINT)
        child.kill.assert_called_once_with()
        self.assertEqual([c.kwargs['timeout'] for c in child.wait.call_args_list], [900, 300, 5])
        self.assertEqual(result['status'], 'UNKNOWN')

    def test_successful_apply_keeps_the_saved_plan_and_no_hold(self):
        """Leave ordinary successful apply behaviour intact."""
        work, plan, child, popen, result = self.exercise([0])
        self.assertEqual(popen.call_args.args[0][-1], str(plan))
        child.send_signal.assert_not_called()
        child.kill.assert_not_called()
        self.assertEqual(result['status'], 'passed')
        self.assertFalse((work / 'HOLD.json').exists())


if __name__ == '__main__':
    unittest.main()
