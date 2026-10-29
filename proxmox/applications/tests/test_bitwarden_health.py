"""Synthetic Bitwarden preservation and unauthenticated health contracts."""

import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bitwarden


class BitwardenHealthTests(unittest.TestCase):

    def test_copied_health_helper_runs_without_controller_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            helper = Path(tmp) / "bitwarden.py"
            shutil.copyfile(bitwarden.__file__, helper)
            result = subprocess.run(
                [sys.executable, "-I", str(helper), "--help"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("--issuer", result.stdout)

    def test_health_observes_version_and_checks_existing_identity_without_vault_requests(
        self,
    ):
        expected = {"issuer": "http://localhost"}
        responses = {
            "/api/alive": (200, b'"alive"'),
            "/api/config": (200, b'{"version":"2026.4.1"}'),
            "/identity/.well-known/openid-configuration": (
                200,
                b'{"issuer":"http://localhost"}',
            ),
        }
        calls = []

        def fetch(path):
            calls.append(path)
            return responses[path]

        self.assertEqual(bitwarden.health(fetch, **expected)["status"], "passed")
        self.assertEqual(calls, list(responses))
        newer = copy.deepcopy(responses)
        newer["/api/config"] = (200, b'{"version":"2026.10.0"}')
        self.assertEqual(
            bitwarden.health(newer.__getitem__, **expected)["observed_version"],
            "2026.10.0",
        )
        for path, response in [
            ("/api/alive", (302, b"")),
            ("/api/config", (200, b'{"version":""}')),
            (
                "/identity/.well-known/openid-configuration",
                (200, b'{"issuer":"changed"}'),
            ),
            ("/api/config", (200, b"{}")),
        ]:
            changed = copy.deepcopy(responses)
            changed[path] = response
            with self.subTest(path=path), self.assertRaises(ValueError):
                bitwarden.health(changed.__getitem__, **expected)

    def test_backend_health_requires_explicit_private_literal(self):
        self.assertTrue(
            callable(bitwarden.reader("http://10.88.30.35:8080", backend=True))
        )
        for origin in (
            "http://8.8.8.8:8080",
            "http://vault.example.invalid",
            "http://0.0.0.0",
        ):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                bitwarden.reader(origin, backend=True)

    def test_reader_refuses_redirects_and_nonlocal_plaintext(self):
        for origin in (
            "http://vault.example.invalid",
            "https://user:password@example.invalid",
            "https://example.invalid/path",
            "https://example.invalid?secret=x",
        ):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                bitwarden.reader(origin)
        calls = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                calls.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/unexpected")
                self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            fetch = bitwarden.reader(f"http://127.0.0.1:{server.server_port}")
            with self.assertRaises(HTTPError):
                fetch("/api/alive")
            with self.assertRaises(ValueError):
                fetch("/api/sync")
            self.assertEqual(calls, ["/api/alive"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
