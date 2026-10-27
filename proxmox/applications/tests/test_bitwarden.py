"""Synthetic Bitwarden preservation and unauthenticated health contracts."""
import copy
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import threading
import unittest
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bitwarden
import render


def fixture():
    return json.loads((Path(__file__).resolve().parents[1] /
                       'examples/bitwarden.stack.example.json').read_text())


class BitwardenTests(unittest.TestCase):
    def test_preview_keeps_private_env_reference_and_fails_on_missing_capture(self):
        service = render.compose(fixture())['services']['bitwarden']
        self.assertEqual(service['env_file'], ['/opt/homelab-app/runtime/bitwarden.env'])
        self.assertNotIn('network_mode', service)
        self.assertEqual(service['ports'], ['198.18.30.45:8080:8080'])
        self.assertEqual(service['restart'], 'no')
        self.assertEqual([(m['target'], m['bind']['create_host_path']) for m in service['volumes']],
                         [('/etc/bitwarden', False), ('/var/log/bitwarden', False)])
        self.assertNotIn('BW_DB_PASSWORD', json.dumps(service))

    def test_preservation_contract_cannot_substitute_product_or_expose_secrets(self):
        for update in ({'image': 'vaultwarden/server@sha256:' + '1' * 64},
                       {'image': 'ghcr.io/bitwarden/lite:latest'},
                       {'environment': {'BW_INSTALLATION_KEY': 'do-not-commit'}},
                       {'user': '1000:1000'}, {'entrypoint': ['sh']},
                       {'extra_mounts': [{'source': '/tmp', 'target': '/etc/bitwarden'}]}):
            with self.subTest(update=list(update)):
                cfg = fixture()
                cfg['services']['bitwarden'].update(update)
                with self.assertRaises(ValueError): render.compose(cfg)

    def test_binding_requires_explicit_backend_not_all_interfaces(self):
        for address in ('0.0.0.0', '127.0.0.1', '::', '8.8.8.8', 'example.invalid'):
            cfg = fixture(); cfg['bitwarden']['bind_address'] = address
            with self.subTest(address=address), self.assertRaises(ValueError): render.compose(cfg)

    def test_runtime_path_and_database_restore_are_closed(self):
        for key, value in [('runtime_env_file', '/tmp/secret.env'),
                           ('database_provider', 'sqlite'), ('restore_in_cd', True),
                           ('deployment_enabled', True), ('unexpected', 'ignored')]:
            cfg = fixture(); cfg['bitwarden'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): render.compose(cfg)

    def test_health_checks_version_and_existing_identity_without_vault_requests(self):
        expected = {'version': '2026.4.1', 'issuer': 'http://localhost'}
        responses = {'/api/alive': (200, b'"alive"'),
                     '/api/config': (200, b'{"version":"2026.4.1"}'),
                     '/identity/.well-known/openid-configuration':
                         (200, b'{"issuer":"http://localhost"}')}
        calls = []
        def fetch(path):
            calls.append(path)
            return responses[path]
        self.assertEqual(bitwarden.health(fetch, **expected)['status'], 'passed')
        self.assertEqual(calls, list(responses))
        for path, response in [('/api/alive', (302, b'')),
                               ('/api/config', (200, b'{"version":"upgraded"}')),
                               ('/identity/.well-known/openid-configuration', (200, b'{"issuer":"changed"}')),
                               ('/api/config', (200, b'{}'))]:
            changed = copy.deepcopy(responses); changed[path] = response
            with self.subTest(path=path), self.assertRaises(ValueError):
                bitwarden.health(changed.__getitem__, **expected)

    def test_preparation_is_rejected_before_the_generic_deployer_can_touch_a_host(self):
        import deploy
        # The admission refusal must precede reading any site, trust or secret inputs.
        with self.assertRaisesRegex(deploy.InputNeeded, 'preparation'):
            deploy.validate({'app': {'kind': 'bitwarden'}})

    def test_reader_refuses_redirects_and_nonlocal_plaintext(self):
        for origin in ('http://vault.example.invalid', 'https://user:password@example.invalid',
                       'https://example.invalid/path', 'https://example.invalid?secret=x'):
            with self.subTest(origin=origin), self.assertRaises(ValueError): bitwarden.reader(origin)
        calls = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                calls.append(self.path)
                self.send_response(302)
                self.send_header('Location', '/unexpected')
                self.end_headers()
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            fetch = bitwarden.reader(f'http://127.0.0.1:{server.server_port}')
            with self.assertRaises(HTTPError): fetch('/api/alive')
            with self.assertRaises(ValueError): fetch('/api/sync')
            self.assertEqual(calls, ['/api/alive'])
        finally:
            server.shutdown(); server.server_close(); thread.join()


if __name__ == '__main__':
    unittest.main()
