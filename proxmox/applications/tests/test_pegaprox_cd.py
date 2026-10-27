"""The PegaProx profile reuses the foundation saved-plan and hold protocol."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import pegaprox_cd as cd
import pegaprox
import deploy
import foundation_cd as shared
from test_foundation_cd import Deployment


class PegaDeployment(Deployment):
    hold_name = cd.HOLD_NAME

    def input_hashes(self, cfg):
        return deploy.input_hashes(cfg)


class PegaProxCDTests(unittest.TestCase):
    def test_disabled_selection_stops_before_files_secrets_or_target_access(self):
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('no private read')):
            with self.assertRaisesRegex(ValueError, 'disabled'):
                cd.admit({'schema': cd.SCHEMA, 'enabled': False})

    def test_runtime_renderer_is_available_without_preview_activation_flags(self):
        import render
        stack = json.loads((ROOT / 'examples/pegaprox.preparation.example.json').read_text())
        stack.pop('enabled'); stack.pop('deployable')
        self.assertEqual(render.compose(stack), pegaprox.compose(stack))
        self.assertNotIn('PEGAPROX_ADMIN_PASSWORD', json.dumps(render.compose(stack)))

    def test_password_is_bootstrap_only_and_never_a_permanent_input(self):
        self.assertNotIn('password', json.dumps(cd.runtime_secrets()).lower())
        self.assertEqual(cd.BOOTSTRAP_SECRET, 'PEGAPROX_ADMIN_PASSWORD')
        cd.check_bootstrap_password('Synthetic-only-123')
        for value in ('', 'password', 'UPPERCASE1', 'lowercase1', 'NoNumbers'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                cd.check_bootstrap_password(value)

    def test_existing_foundation_profile_still_uses_its_original_protocol(self):
        self.assertEqual(shared.HOLD_NAME, 'FOUNDATION-HOLD.json')
        self.assertEqual(shared.COMPLETE_NAME, 'foundation-complete.json')
        self.assertNotEqual(cd.HOLD_NAME, shared.HOLD_NAME)
        self.assertEqual(cd.run.__module__, 'pegaprox_cd')

    def profile(self, root):
        inputs = root / 'inputs'; inputs.mkdir(mode=0o700)
        state = root / 'state'; state.mkdir(mode=0o700)
        bundles = root / 'bundles'; bundles.mkdir()
        directory = bundles / 'pegaprox'; directory.mkdir()
        cfg = json.loads((ROOT / 'examples/site.example.json').read_text())
        stack = json.loads((ROOT / 'examples/pegaprox.preparation.example.json').read_text())
        stack.pop('enabled'); stack.pop('deployable')
        stack['bind_address'] = '198.18.100.20'
        cfg['guest'].update(vmid=214, hostname='pegaprox', memory_mib=2048, volumes={})
        cfg['guest']['interfaces'][0]['ipv6'] = 'manual'
        cfg['guest']['rules'].append({'direction': 'in', 'proto': 'tcp', 'port': '5000',
            'source': '198.18.25.21/32', 'destination': '198.18.100.20/32'})
        cfg['app'] = {'kind': 'pegaprox', 'vmid': 214, 'hostname': 'pegaprox', 'new_target': True,
            'memory_mib': 2048, 'address': '198.18.100.20', 'mac': '02:00:00:00:61:01',
            'clean_install_confirmed': True, 'exclusive_writer_confirmed': True,
            'packages': ['docker.io=0.0.0-REPLACE'], 'stack_config': str(inputs / 'pegaprox/stack.json'),
            'pegaprox': {'key_source': str(inputs / 'pegaprox/db-key'), 'admin_username': 'practice-admin'},
            'health_checks': pegaprox.health_checks()}
        cfg['paths']['state_root'] = str(state)
        ca = root / 'ca'; ca.write_text('invented public CA'); cfg['paths']['ca_file'] = str(ca)
        (directory / 'site.json').write_bytes(shared.encoded(cfg))
        (directory / 'stack.json').write_bytes(shared.encoded(stack))
        (bundles / 'bindings.json').write_bytes(shared.encoded({'site': cfg['site'],
            'guests': {'pegaprox': [214, 'pegaprox']}}))
        return bundles, inputs, state

    def test_shared_protocol_creates_once_then_verifies_without_bootstrap_secret(self):
        import base64
        with tempfile.TemporaryDirectory() as tmp:
            bundles, inputs, state = self.profile(Path(tmp))
            environment = {'PEGAPROX_ADMIN_PASSWORD': 'Synthetic-only-123',
                           'PEGAPROX_DB_KEY': base64.urlsafe_b64encode(bytes(range(32))).decode()}
            implementation = PegaDeployment()
            cd.run(implementation, bundles, inputs, state, environment)
            self.assertEqual([c[0] for c in implementation.calls], ['plan', 'deploy'])
            self.assertEqual(set(p.name for p in (inputs / 'pegaprox').iterdir()),
                             {'site.json', 'stack.json', 'db-key', 'prepared.json'})
            self.assertNotIn(environment['PEGAPROX_ADMIN_PASSWORD'],
                             ''.join(p.read_text() for p in (inputs / 'pegaprox').iterdir()))
            implementation.calls.clear()
            cd.run(implementation, bundles, inputs, state, {})
            self.assertEqual([c[0] for c in implementation.calls], ['verify'])

    def test_failed_rollout_keeps_its_original_inputs_and_cannot_replay(self):
        import base64
        with tempfile.TemporaryDirectory() as tmp:
            bundles, inputs, state = self.profile(Path(tmp))
            environment = {'PEGAPROX_ADMIN_PASSWORD': 'Synthetic-only-123',
                           'PEGAPROX_DB_KEY': base64.urlsafe_b64encode(bytes(range(32))).decode()}
            implementation = PegaDeployment(); implementation.fail = 'deploy'
            with self.assertRaises(ValueError): cd.run(implementation, bundles, inputs, state, environment)
            self.assertTrue((state / '214' / cd.HOLD_NAME).exists())
            before = (inputs / 'pegaprox/db-key').read_bytes()
            calls = list(implementation.calls)
            with self.assertRaisesRegex(ValueError, 'no automatic retry'):
                cd.run(implementation, bundles, inputs, state, environment)
            self.assertEqual(implementation.calls, calls)
            self.assertEqual((inputs / 'pegaprox/db-key').read_bytes(), before)

    def test_missing_mac_or_client_allowance_refuses_before_secret_reads(self):
        class NoSecrets(dict):
            def get(self, *args):
                raise AssertionError('No secret read before allocation/client admission')
        for missing in ('mac', 'clients'):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as tmp:
                bundles, inputs, state = self.profile(Path(tmp))
                site = bundles / 'pegaprox/site.json'; cfg = json.loads(site.read_text())
                if missing == 'mac': cfg['guest']['interfaces'][0]['mac'] = None
                else: cfg['guest']['rules'] = [r for r in cfg['guest']['rules'] if r.get('port') != '5000']
                site.write_bytes(shared.encoded(cfg))
                implementation = PegaDeployment()
                with self.assertRaises(ValueError):
                    cd.run(implementation, bundles, inputs, state, NoSecrets())
                self.assertEqual(implementation.calls, [])
                self.assertFalse((inputs / 'pegaprox').exists())

    def test_completed_database_key_drift_holds_without_replacing_original(self):
        import base64
        with tempfile.TemporaryDirectory() as tmp:
            bundles, inputs, state = self.profile(Path(tmp))
            environment = {'PEGAPROX_ADMIN_PASSWORD': 'Synthetic-only-123',
                           'PEGAPROX_DB_KEY': base64.urlsafe_b64encode(bytes(range(32))).decode()}
            implementation = PegaDeployment()
            cd.run(implementation, bundles, inputs, state, environment)
            key = inputs / 'pegaprox/db-key'; original = key.read_bytes()
            implementation.calls.clear()
            environment = {'PEGAPROX_DB_KEY': base64.urlsafe_b64encode(bytes(reversed(range(32)))).decode()}
            with self.assertRaisesRegex(ValueError, 'key drift'):
                cd.run(implementation, bundles, inputs, state, environment)
            self.assertEqual(key.read_bytes(), original)
            self.assertEqual(implementation.calls, [])
