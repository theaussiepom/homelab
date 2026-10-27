import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import monitoring_credentials as credentials


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        for name in ('local', 'recovery'):
            (self.root / name).mkdir(mode=0o700)
        self.config = {'schema': 'homelab-agent-secret-v1', 'hostname': 'fixture-linux',
            'machine_id': 'a' * 32, 'store': str(self.root / 'local'),
            'recovery': str(self.root / 'recovery'), 'backup_source': 'nas.invalid:/fixture', 'allow_create': True}
        self.check = patch.object(credentials, 'check_backup'); self.check.start(); self.addCleanup(self.check.stop)

    def test_create_once_both_consumers_share_key_and_replay_does_not_generate(self):
        result = credentials.provision(self.config)
        path = Path(result['credential_file'])
        first = credentials.load(path, 'fixture-linux', 'a' * 32)
        with patch.object(credentials.secrets, 'token_hex', side_effect=AssertionError('must reuse')):
            self.assertFalse(credentials.provision(self.config)['created'])
        self.assertEqual(credentials.load(path, 'fixture-linux', 'a' * 32), first)
        self.assertEqual(path.read_bytes(), (self.root / 'recovery/fixture-linux/credential.json').read_bytes())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(first['psk'], json.dumps(result))

    def test_missing_secret_needs_explicit_commissioning_and_machine_drift_holds(self):
        with self.assertRaises(ValueError): credentials.provision(dict(self.config, allow_create=False))
        result = credentials.provision(self.config)
        with self.assertRaises(ValueError): credentials.provision(dict(self.config, machine_id='b' * 32))
        with self.assertRaises(ValueError): credentials.load(Path(result['credential_file']), 'different', 'a' * 32)

    def test_partial_write_keeps_key_and_holds_without_regeneration(self):
        original = credentials.write_new
        def failed(path, value):
            if path == self.root / 'recovery/fixture-linux/credential.json': raise OSError('synthetic failed mirror')
            original(path, value)
        with patch.object(credentials, 'write_new', side_effect=failed):
            with self.assertRaises(OSError): credentials.provision(self.config)
        self.assertTrue((self.root / 'local/fixture-linux/credential.json').exists())
        for name in ('local', 'recovery'):
            self.assertTrue((self.root / name / 'fixture-linux/PSK-HOLD.json').exists())
        with patch.object(credentials.secrets, 'token_hex', side_effect=AssertionError('must not rotate')):
            with self.assertRaises(ValueError): credentials.provision(self.config)

    def test_unsafe_files_and_mirror_drift_are_refused(self):
        path = Path(credentials.provision(self.config)['credential_file'])
        path.chmod(0o644)
        with self.assertRaises(ValueError): credentials.load(path, 'fixture-linux', 'a' * 32)
        path.chmod(0o600)
        mirror = self.root / 'recovery/fixture-linux/credential.json'
        value = json.loads(mirror.read_text()); value['psk'] = 'b' * 64; mirror.write_text(json.dumps(value))
        with self.assertRaises(ValueError): credentials.provision(self.config)
