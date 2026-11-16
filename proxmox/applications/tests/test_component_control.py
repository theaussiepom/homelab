"""Real file restoration and refusal boundaries; package/container commands fake."""
import base64
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import runpy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import component_control as c


class ManagedControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.path = self.root/'control.json'; self.path.write_bytes(b'old configuration\n')
        self.path.chmod(0o600)
        self.before = c.capture_file(str(self.path))

    def test_bounded_commands_and_stdin_entry_point_redact_failures(self):
        with patch.object(c.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='1.2\n')):
            self.assertEqual(c.command(['dpkg-query', 'synthetic']), '1.2')
        with patch.object(c.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stdout='PRIVATE')):
            with self.assertRaises(ValueError): c.command(['synthetic'])
        request = {'mode': 'capture', 'files': {str(self.path): None}, 'packages': [], 'images': [], 'allowed': {}}
        for entry in (c.main, lambda: runpy.run_path(c.__file__, run_name='__main__')):
            with patch('sys.stdin', io.TextIOWrapper(io.BytesIO(json.dumps(request).encode()))), \
                    patch('sys.stdout', new_callable=io.StringIO) as output:
                entry()
            self.assertEqual(json.loads(output.getvalue())['files'][str(self.path)], self.before)
        with patch('sys.stdin', io.TextIOWrapper(io.BytesIO(b'PRIVATE'))), self.assertRaises(SystemExit) as error:
            runpy.run_path(c.__file__, run_name='__main__')
        self.assertNotIn('PRIVATE', str(error.exception))

    def test_capture_restore_and_read_only_verification_preserve_exact_bytes_and_mode(self):
        self.path.write_bytes(b'new configuration\n'); self.path.chmod(0o400)
        after = c.capture_file(str(self.path))
        self.assertTrue(c.restore_file(str(self.path), self.before, [after['sha256']]))
        self.assertEqual(c.capture_file(str(self.path)), self.before)
        self.assertFalse(c.restore_file(str(self.path), self.before, []))
        request = {'mode': 'verify', 'files': {str(self.path): self.before},
                   'packages': [], 'images': [], 'allowed': {}}
        inode = self.path.stat().st_ino
        self.assertEqual(c.run(request)['files'][str(self.path)], self.before)
        self.assertEqual(self.path.stat().st_ino, inode)
        self.path.write_bytes(b'foreign edit')
        with self.assertRaises(ValueError): c.run(request)
        self.assertEqual(self.path.read_bytes(), b'foreign edit')

    def test_only_an_inventoried_new_file_can_be_removed(self):
        missing = self.root/'new-control'
        before = c.capture_file(str(missing)); self.assertEqual(before, {'exists': False})
        missing.write_bytes(b'new managed configuration')
        actual = c.capture_file(str(missing))
        self.assertTrue(c.restore_file(str(missing), before, [actual['sha256']]))
        self.assertFalse(missing.exists())
        missing.write_bytes(b'foreign data')
        with self.assertRaises(ValueError): c.restore_file(str(missing), before, [actual['sha256']])
        self.assertEqual(missing.read_bytes(), b'foreign data')

    def test_symlinks_hardlinks_special_files_oversize_and_changed_content_refuse(self):
        link = self.root/'link'; link.symlink_to(self.path)
        with self.assertRaises(OSError): c.capture_file(str(link))
        link.unlink(); os.link(self.path, link)
        with self.assertRaises(ValueError): c.capture_file(str(link))
        link.unlink()
        with self.assertRaises((OSError, ValueError)): c.capture_file(str(self.root))
        self.path.write_bytes(b'x'*(c.MAX_BYTES+1))
        with self.assertRaises(ValueError): c.capture_file(str(self.path))
        for value in ('relative', '/x/../etc/config', '/a//b', '/', '/a'):
            with self.subTest(path=value), self.assertRaises(ValueError): c.capture_file(value)
        invalid = dict(self.before, content=base64.b64encode(b'wrong').decode())
        with self.assertRaises(ValueError): c.validate_file(invalid)

    def test_request_schema_and_total_capture_are_bounded(self):
        request = {'mode': 'capture', 'files': {str(self.path): None},
                   'packages': [], 'images': [], 'allowed': {}}
        self.assertEqual(c.run(request)['files'][str(self.path)], self.before)
        for mutate in (lambda v: v.update(force=True), lambda v: v.update(mode='shell'),
                       lambda v: v.update(allowed={'/unknown': []}),
                       lambda v: v['files'].update({str(self.path): {}})):
            value = copy.deepcopy(request); mutate(value)
            with self.subTest(value=value), self.assertRaises(ValueError): c.run(value)

    def test_package_and_image_verification_uses_exact_public_projections(self):
        selected = {'project': 'example-project', 'service': 'example-service',
                    'image': 'example/service@sha256:'+'a'*64}
        calls = []
        def command(argv):
            calls.append(argv)
            if argv[0] == 'dpkg-query': return '1.2.3'
            if argv[1] == 'ps': return 'b'*64
            if argv[1] == 'image': return 'sha256:'+'c'*64
            return 'sha256:'+'c'*64+' true'
        with patch.object(c, 'command', side_effect=command):
            self.assertEqual(c.packages(['example-package=1.2.3']), ['example-package=1.2.3'])
            self.assertEqual(c.images([selected])[0]['image_id'], 'sha256:'+'c'*64)
        self.assertFalse(any('Env' in str(argv) or 'shell' in str(argv) for argv in calls))
        with patch.object(c, 'command', return_value='not-an-id'), self.assertRaises(ValueError):
            c.images([selected])
        for name in ('--remove', 'x;rm', 'a b', 'a='):
            with self.subTest(package=name), self.assertRaises(ValueError): c.packages([name])


if __name__ == '__main__': unittest.main()
