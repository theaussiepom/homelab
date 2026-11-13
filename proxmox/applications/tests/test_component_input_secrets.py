"""Secret-slot units isolate adapter contracts; no secret names choose file paths."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import component_input_secrets as inputs


class InputSecretTests(unittest.TestCase):
    def test_only_selected_roles_receive_direct_scalar_values(self):
        source = {'api_token': {'type': 'environment', 'name': 'EXISTING_TOKEN',
                                'workflow_secret': 'EXISTING_GITHUB_KEY'}}
        slot = 'HOMELAB_APP_SECRET_NODE_RED_API_TOKEN'
        self.assertEqual(inputs.slots('node_red', source), {'api_token': slot})
        self.assertEqual(inputs.selected('node_red', source, {slot: 'synthetic-first', 'COMMON': 'ignored'}),
                         {'api_token': b'synthetic-first'})
        self.assertEqual(inputs.selected('node_red', source, {slot: 'synthetic-second'}),
                         {'api_token': b'synthetic-second'})
        for environment in ({}, {'EXISTING_TOKEN': 'wrong-slot'},
                {slot: 'value', 'HOMELAB_APP_SECRET_AUTHENTIK_SECRET_KEY': 'foreign'},
                {slot: ''}, {slot: 'two\nlines'}, {slot: 'nul\x00value'}, {slot: 'x'*65537}):
            with self.subTest(keys=tuple(environment)), self.assertRaises(ValueError):
                inputs.selected('node_red', source, environment)

    def test_file_inputs_stay_private_typed_bytes_for_adapter_parser(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); root.chmod(0o700)
            path = root/'record'; path.write_bytes(b'{"synthetic":"owned-record"}\n'); path.chmod(0o600)
            sources = {'options': {'type': 'file', 'path': str(path), 'source_id': 'existing'}}
            self.assertEqual(inputs.slots('winet', sources), {})
            self.assertEqual(inputs.selected('winet', sources, {}), {'options': path.read_bytes()})
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                inputs.selected('winet', sources, {})
            for sources in ({'unknown': {'type': 'environment', 'name': 'KEY'}},
                    {'options': {'type': 'generated', 'credential_id': 'owned'}},
                    {'options': {'type': 'file', 'path': '../outside'}},
                    {'options': {'type': 'environment', 'name': 'bad-name'}},
                    {'options': {'type': 'file', 'path': str(path), 'extra': True}}):
                with self.subTest(sources=list(sources)), self.assertRaises(ValueError):
                    inputs.slots('winet', sources)

    def test_runtime_input_reader_is_stdlib_only_and_does_not_import_authored_parser(self):
        application = str(Path(__file__).resolve().parents[1])
        completed = subprocess.run([sys.executable, '-I', '-c',
            'import sys; sys.path.insert(0,' + repr(application) + '); import component_input_secrets; '
            'assert "yaml" not in sys.modules and "authored_config" not in sys.modules; print("STDLIB_OK")'],
            capture_output=True, text=True, check=False)
        self.assertEqual((completed.returncode, completed.stdout, completed.stderr), (0, 'STDLIB_OK\n', ''))


if __name__ == '__main__':
    unittest.main()
