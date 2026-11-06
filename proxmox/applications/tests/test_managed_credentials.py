"""A new declared account never adopts, rotates or shares another identity's key."""
import copy
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import managed_credentials as m


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.owner = {'node': 'synthetic-node', 'vmid': 901, 'purpose': 'synthetic-account'}

    def test_create_once_retains_secret_and_immutable_input_binding(self):
        value = m.credential(self.root, 'example-account', self.owner)
        path = self.root/'managed-credentials/example-account.json'
        before = path.read_bytes()
        self.assertEqual(m.credential(self.root, 'example-account', self.owner), value)
        self.assertEqual(path.read_bytes(), before)
        self.assertRegex(value['password'], '^[0-9a-f]{64}$')
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        dest = self.root/'immutable'
        name, payload = m.payload(self.root, 'example-account', self.owner, dest)
        self.assertEqual(name, str(dest/'managed-example-account.json'))
        self.assertEqual(json.loads(payload['managed-example-account.json']), value)
        other = m.credential(self.root, 'other-account', self.owner)
        self.assertNotEqual(value['password'], other['password'])

    def test_ids_and_owners_are_closed(self):
        for value in (None, False, [], '', '../escape', 'UPPER', 'a', 'x'*65):
            with self.subTest(value=value), self.assertRaises(ValueError): m.identifier(value)
        for owner in (None, False, [], {}, {1: 'value'}):
            with self.subTest(owner=owner), self.assertRaises(ValueError): m.credential(self.root, 'example-account', owner)

    def test_foreign_owner_never_rotates_or_adopts(self):
        m.credential(self.root, 'example-account', self.owner)
        path = self.root/'managed-credentials/example-account.json'; before = path.read_bytes()
        with self.assertRaises(ValueError): m.credential(self.root, 'example-account', dict(self.owner, vmid=902))
        self.assertEqual(path.read_bytes(), before)
        original = json.loads(before)
        for key, value in [('schema', 'foreign'), ('password', 'x'), ('password', []), ('owner', {})]:
            row = copy.deepcopy(original); row[key] = value; path.write_text(json.dumps(row))
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): m.credential(self.root, 'example-account', self.owner)
        for row in ([], dict(original, extra=True)):
            path.write_text(json.dumps(row))
            with self.assertRaises(ValueError): m.credential(self.root, 'example-account', self.owner)

    def test_linked_or_public_custody_refuses_without_replacement(self):
        m.credential(self.root, 'example-account', self.owner)
        root = self.root/'managed-credentials'; path = root/'example-account.json'; before = path.read_bytes()
        path.chmod(0o644)
        with self.assertRaises(ValueError): m.credential(self.root, 'example-account', self.owner)
        path.chmod(0o600); os.link(path, root/'alias.json')
        with self.assertRaises(ValueError): m.credential(self.root, 'example-account', self.owner)
        (root/'alias.json').unlink(); path.unlink(); path.symlink_to(root/'missing')
        with self.assertRaises(OSError): m.credential(self.root, 'example-account', self.owner)
        path.unlink(); path.write_bytes(before); path.chmod(0o600)
        lock = root/'example-account.lock'; lock.chmod(0o644)
        with self.assertRaises(ValueError): m.credential(self.root, 'example-account', self.owner)
        self.assertEqual(path.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
