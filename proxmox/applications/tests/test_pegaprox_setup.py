"""Bootstrap secrets stay on stdin or in a strict temporary file."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pegaprox_setup as setup


class SetupTests(unittest.TestCase):
    def test_bootstrap_uses_stdin_and_verify_needs_no_password(self):
        secret = 'Synthetic-only-123'
        with patch.object(setup.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0,
                          'PegaProx verification passed\n', '')) as run:
            setup.invoke(['docker', 'exec', '-i', 'invented-container'], 'bootstrap', 'practice-admin', secret)
            self.assertNotIn(secret, ' '.join(run.call_args.args[0]))
            self.assertIn(secret, run.call_args.kwargs['input'])
            setup.invoke(['docker', 'exec', '-i', 'invented-container'], 'verify')
            self.assertEqual(run.call_args.kwargs['input'], '')

    def test_child_errors_are_fixed_and_do_not_expose_output(self):
        secret = 'Synthetic-only-123'
        with patch.object(setup.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, secret, secret)):
            with self.assertRaises(ValueError) as raised:
                setup.invoke(['docker', 'exec', '-i', 'invented-container'], 'verify')
            self.assertNotIn(secret, str(raised.exception))

    def test_password_file_refuses_loose_modes_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'password'; path.write_text('Synthetic-only-123'); path.chmod(0o600)
            self.assertEqual(setup.password(path), 'Synthetic-only-123')
            path.chmod(0o644)
            with self.assertRaises(ValueError): setup.password(path)
            path.chmod(0o600)
            link = Path(tmp) / 'link'; link.symlink_to(path)
            with self.assertRaises(OSError): setup.password(link)
