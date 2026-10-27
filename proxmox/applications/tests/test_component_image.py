"""Image-only maintenance preserves settings and refuses any failed replay."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import component_image as image

OLD = 'traefik@sha256:' + 'a' * 64
NEW = 'traefik@sha256:' + 'b' * 64
CONFIG = {'name': 'homelab-ingress', 'services': {'traefik': {'image': OLD,
    'volumes': ['/srv/data:/data'], 'environment': {'TOKEN_FILE': '/private/key'},
    'network_mode': 'host', 'command': ['--certificatesresolvers.default.acme.dnschallenge.resolvers=10.88.40.2:53']}}}


class CandidateTests(unittest.TestCase):
    def test_only_the_image_changes_and_original_input_is_unchanged(self):
        original = json.dumps(CONFIG).encode()
        wanted = copy.deepcopy(CONFIG); wanted['services']['traefik']['image'] = NEW
        self.assertEqual(json.loads(image.candidate(original, OLD, NEW)), wanted)
        self.assertEqual(json.loads(original), CONFIG)

    def test_wrong_image_second_service_and_mutable_image_are_refused(self):
        for value in ({**CONFIG, 'name': 'foreign'},
                      {**CONFIG, 'services': {**CONFIG['services'], 'foreign': {}}}):
            with self.assertRaises(ValueError): image.candidate(json.dumps(value).encode(), OLD, NEW)
        for before, after in ((NEW, NEW), (OLD, 'traefik:latest'), ('foreign@sha256:' + 'a'*64, NEW)):
            with self.assertRaises(ValueError): image.candidate(json.dumps(CONFIG).encode(), before, after)


@unittest.skipUnless(os.getuid() == 0, 'Actual ownership checks are exercised in the Linux test container')
class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.compose = self.root / 'compose.json'; self.identity = self.root / 'identity.json'
        self.original = (json.dumps(CONFIG, indent=2) + '\n').encode()
        self.compose.write_bytes(self.original); self.compose.chmod(0o600)
        self.identity.write_text(json.dumps({'vmid': 712, 'kind': 'ingress'})); self.identity.chmod(0o600)
        self.before = self.compose.stat()
        self.hash = hashlib.sha256(self.original).hexdigest()
        self.commands = []; self.fail = None; self.running = OLD
        self.patches = patch.multiple(image, COMPOSE=self.compose, IDENTITY=self.identity,
                                     STATE=self.root / 'state', command=self.command)
        self.patches.start(); self.addCleanup(self.patches.stop)

    def command(self, argv):
        self.commands.append(argv)
        if self.fail and self.fail in argv: raise ValueError('Synthetic command failure')
        if argv[:2] == ['docker', 'inspect']:
            return json.dumps({'State': {'Running': True}, 'Config': {'Image': self.running}}).encode()
        if 'ps' in argv: return ('a' * 64 + '\n').encode()
        if 'up' in argv: self.running = NEW
        return b''

    def test_success_preserves_inode_mode_uid_and_all_other_configuration(self):
        self.assertTrue(image.run(712, OLD, NEW, self.hash)['changed'])
        current = self.compose.stat()
        self.assertEqual((current.st_ino, current.st_mode, current.st_uid, current.st_gid),
                         (self.before.st_ino, self.before.st_mode, self.before.st_uid, self.before.st_gid))
        wanted = copy.deepcopy(CONFIG); wanted['services']['traefik']['image'] = NEW
        self.assertEqual(json.loads(self.compose.read_bytes()), wanted)
        ups = [c for c in self.commands if 'up' in c]
        self.assertEqual(len(ups), 1)
        self.assertEqual(ups[0][-6:], ['up', '-d', '--no-deps', '--pull', 'never', 'traefik'])
        before = list(self.commands)
        self.assertFalse(image.run(712, OLD, NEW, self.hash, True)['changed'])
        self.assertFalse(any('up' in c or 'pull' in c for c in self.commands[len(before):]))
        with self.assertRaises(FileExistsError): image.run(712, OLD, NEW, self.hash)

    def test_pull_failure_keeps_original_file_and_durable_hold_and_refuses_replay(self):
        self.fail = 'pull'
        with self.assertRaises(ValueError): image.run(712, OLD, NEW, self.hash)
        self.assertEqual(self.compose.read_bytes(), self.original)
        self.assertTrue(list((self.root / 'state').glob('*/HOLD.json')))
        self.fail = None
        with self.assertRaises(FileExistsError): image.run(712, OLD, NEW, self.hash)
        self.assertFalse(any('up' in c for c in self.commands))

    def test_start_failure_retains_backup_and_refuses_verify_only_or_replay(self):
        self.fail = 'up'
        with self.assertRaises(ValueError): image.run(712, OLD, NEW, self.hash)
        self.assertTrue(list((self.root / 'state').glob('*/HOLD.json')))
        self.assertEqual(next((self.root / 'state').glob('*/compose-before.json')).read_bytes(), self.original)
        with self.assertRaises(OSError): image.run(712, OLD, NEW, self.hash, True)
        with self.assertRaises(FileExistsError): image.run(712, OLD, NEW, self.hash)

    def test_drift_or_wrong_identity_cannot_pull_or_restart(self):
        with self.assertRaises(ValueError): image.run(999, OLD, NEW, self.hash)
        self.assertEqual(self.commands, [])
        with self.assertRaises(ValueError): image.run(712, OLD, NEW, 'c' * 64)
        self.assertEqual(self.commands, [])

    def test_image_path_injection_is_rejected_before_creating_evidence(self):
        with self.assertRaises(ValueError): image.run(712, OLD, '../../foreign', self.hash)
        self.assertFalse((self.root / 'state').exists())

    def test_private_failure_records_the_controlled_guard_reason(self):
        with self.assertRaises(ValueError): image.run(712, OLD, NEW, 'c'*64)
        record=json.loads(next((self.root/'state').glob('*/FAILURE.json')).read_bytes())
        self.assertEqual(record,{'error':'ValueError','reason':'Installed Compose configuration drifted'})

    def test_parser_failure_never_records_private_configuration_text(self):
        value=b'{"private-value":"must-not-appear" broken'
        self.compose.write_bytes(value)
        with self.assertRaises(json.JSONDecodeError): image.run(712,OLD,NEW,hashlib.sha256(value).hexdigest())
        raw=next((self.root/'state').glob('*/FAILURE.json')).read_bytes()
        self.assertEqual(json.loads(raw),{'error':'JSONDecodeError','reason':None})
        self.assertNotIn(b'must-not-appear',raw)

    def test_command_failure_never_records_private_output(self):
        def failing(argv):
            if 'pull' in argv:
                raise image.CommandFailed('private-output-must-not-appear')
            return self.command(argv)
        with patch.object(image,'command',failing):
            with self.assertRaises(image.CommandFailed):image.run(712,OLD,NEW,self.hash)
        raw=next((self.root/'state').glob('*/FAILURE.json')).read_bytes()
        self.assertEqual(json.loads(raw),{'error':'CommandFailed','reason':None})
        self.assertNotIn(b'private-output-must-not-appear',raw)


if __name__ == '__main__':
    unittest.main()
