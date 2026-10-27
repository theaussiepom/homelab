"""Bootstrap secrets stay on stdin or in a strict temporary file."""
from pathlib import Path
import subprocess
import io
import contextlib
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pegaprox_setup as setup


class SetupTests(unittest.TestCase):
    def test_uninitialised_service_is_never_accepted_under_python_optimisation(self):
        class Reply:
            def __init__(self, code, data): self.code, self.data = code, data
            def read(self, size): return json.dumps(self.data).encode()
            def __enter__(self): return self
            def __exit__(self, *args): pass
        class Opener:
            def open(self, request, **kwargs):
                if request.full_url.endswith('/api/health'):
                    return Reply(200, {'status': 'ok', 'version': '1.4.1'})
                return Reply(401, {'authenticated': False, 'initialized': False})
        with patch('urllib.request.build_opener', return_value=Opener()), \
                patch.object(sys, 'argv', ['python3', 'verify']), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(RuntimeError):
                exec(compile(setup.CONTAINER_CODE, '<local-readiness>', 'exec', optimize=2), {})

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
