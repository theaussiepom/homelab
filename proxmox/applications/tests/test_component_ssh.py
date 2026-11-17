"""Root-key additions preserve shared custody and use the existing file writer."""
import base64
import copy
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import component_control
import component_ssh as m

KEY_A = 'ssh-ed25519 ' + base64.b64encode(m.WIRE_PREFIX + b'a' * 32).decode()
KEY_B = 'ssh-ed25519 ' + base64.b64encode(m.WIRE_PREFIX + b'b' * 32).decode()
KEY_C = 'ssh-ed25519 ' + base64.b64encode(m.WIRE_PREFIX + b'c' * 32).decode()


class RootKeyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.folder = self.root / '.ssh'
        self.folder.mkdir(mode=0o700)
        self.path = self.folder / 'authorized_keys'
        self.before = (b'# retained comment ' + bytes([255]) + b'\n' +
            ('command="printf hello",no-agent-forwarding ' + KEY_A + ' retained\n').encode() +
            b'ssh-rsa synthetic-existing-key retained\n')
        self.path.write_bytes(self.before)
        self.path.chmod(0o640)
        if not hasattr(os, 'listxattr'):
            context = patch.object(os, 'listxattr', return_value=[], create=True)
            context.start()
            self.addCleanup(context.stop)
        # Real temporary filesystem ownership; no access to the machine's root keys.
        for key, value in (('ROOT_KEYS', str(self.path)), ('ROOT_UID', os.getuid()), ('ROOT_GID', os.getgid())):
            context = patch.object(m, key, value)
            context.start()
            self.addCleanup(context.stop)

    def test_add_is_atomic_additive_idempotent_and_never_invokes_a_service(self):
        before = self.path.stat()
        with patch('subprocess.run', side_effect=AssertionError('No command or service')):
            self.assertEqual(m.run({'mode': 'install', 'keys': [KEY_A, KEY_B]}),
                             {'changed': True, 'declared_keys': 2})
            added = self.path.read_bytes()
            self.assertEqual(added, self.before + (KEY_B + '\n').encode())
            installed = self.path.stat()
            self.assertNotEqual(before.st_ino, installed.st_ino)
            self.assertEqual((before.st_uid, before.st_gid, before.st_mode),
                             (installed.st_uid, installed.st_gid, installed.st_mode))
            self.assertEqual(m.run({'mode': 'install', 'keys': [KEY_B, KEY_A]})['changed'], False)
            self.assertEqual(m.run({'mode': 'verify', 'keys': [KEY_A, KEY_B]})['changed'], False)
            self.assertEqual(self.path.stat().st_ino, installed.st_ino)
            self.assertEqual(self.path.read_bytes(), added)

    def test_missing_final_newline_is_preserved_as_prefix_and_empty_file_is_supported(self):
        for original in ((KEY_A + ' retained').encode(), b''):
            with self.subTest(original=bool(original)):
                self.path.write_bytes(original)
                result = m.updated(m.inspect(), [KEY_A, KEY_B])
                expected = original + (b'\n' if original else b'')
                if original:
                    expected += (KEY_B + '\n').encode()
                else:
                    expected += (KEY_A + '\n' + KEY_B + '\n').encode()
                self.assertEqual(base64.b64decode(result['content']), expected)

    def test_key_parser_rejects_wrong_types_wire_formats_noncanonical_bytes_and_options(self):
        wrong = base64.b64encode(b'x' * 51).decode()
        cases = [None, True, 1, '', 'x' * 129, 'ssh-rsa ' + KEY_A.split()[1],
                 KEY_A + ' comment', ' ' + KEY_A, KEY_A.replace(' ', '  '),
                 'ssh-ed25519 %', 'ssh-ed25519 ' + chr(255), 'ssh-ed25519 AAAA',
                 'ssh-ed25519 ' + wrong, KEY_A + '=', KEY_A + '\n']
        for value in cases:
            with self.subTest(value=repr(value)[:45]), self.assertRaises(ValueError):
                m.identity(value)
        self.assertEqual(m.identity(KEY_A), KEY_A.split()[1])
        for value in (None, {}, [], [KEY_A, KEY_A], ['bad']):
            with self.subTest(collection=repr(value)[:45]), self.assertRaises(ValueError):
                m.declarations(value)

    def test_existing_options_comments_invalid_and_non_utf8_lines_are_preserved(self):
        original = (b'\n# ' + KEY_B.encode() + b'\nmalformed " quotation\n' +
                    b'ssh-ed25519 invalid\nssh-rsa unrelated\n' +
                    ('command="printf hello there",restrict ' + KEY_A + ' old comment\n').encode() +
                    b'other ' + bytes([255]) + b' retained\n')
        self.path.write_bytes(original)
        self.assertEqual(m.installed(original), {KEY_A.split()[1]})
        m.run({'mode': 'install', 'keys': [KEY_A, KEY_B]})
        self.assertEqual(self.path.read_bytes(), original + (KEY_B + '\n').encode())

    def test_snapshot_validation_and_missing_declared_key_refuse(self):
        original = m.inspect()
        cases = [None, {'exists': False}, dict(original, uid=os.getuid() + 1),
                 dict(original, gid=os.getgid() + 1), dict(original, mode=0o666),
                 dict(original, sha256='0' * 64)]
        for row in cases:
            with self.subTest(row=row), self.assertRaises(ValueError):
                m.contents(row)
        with self.assertRaises(ValueError):
            m.verify(original, [KEY_B])
        self.assertEqual(self.path.read_bytes(), self.before)

    def test_oversized_authorization_file_and_oversized_append_refuse_without_truncation(self):
        with patch.object(component_control, 'MAX_BYTES', len(self.before) + 1):
            with self.assertRaises(ValueError):
                m.updated(m.inspect(), [KEY_B])
        self.assertEqual(self.path.read_bytes(), self.before)
        self.path.write_bytes(b'x' * (component_control.MAX_BYTES + 1))
        with self.assertRaises(ValueError):
            m.inspect()

    def test_unknown_file_custody_and_parent_permissions_refuse_without_chmod(self):
        for mode in (0o666, 0o400):
            self.path.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                m.inspect()
            self.assertEqual(self.path.stat().st_mode & 0o777, mode)
        self.path.chmod(0o600)
        self.folder.chmod(0o770)
        with self.assertRaises(ValueError):
            m.inspect()
        self.folder.chmod(0o700)
        with patch.object(m, 'ROOT_UID', os.getuid() + 1), self.assertRaises(ValueError):
            m.inspect()
        with patch.object(m, 'ROOT_GID', os.getgid() + 1), self.assertRaises(ValueError):
            m.inspect()
        with patch.object(os, 'listxattr', return_value=['user.foreign']), self.assertRaises(ValueError):
            m.inspect()
        self.assertEqual(self.path.read_bytes(), self.before)

    @unittest.skipUnless(hasattr(os, 'setxattr'), 'Requires actual Linux extended attributes')
    def test_actual_extended_attributes_are_preserved_by_refusing_the_shared_file(self):
        os.setxattr(self.path, 'user.homelab-test', b'preserve')
        with self.assertRaises(ValueError):
            m.run({'mode': 'install', 'keys': [KEY_A, KEY_B]})
        self.assertEqual(os.getxattr(self.path, 'user.homelab-test'), b'preserve')
        self.assertEqual(self.path.read_bytes(), self.before)

    def test_linked_and_missing_files_and_parents_are_never_adopted(self):
        other = self.root / 'other'
        os.link(self.path, other)
        with self.assertRaises(ValueError):
            m.inspect()
        other.unlink()
        self.path.rename(other)
        self.path.symlink_to(other)
        with self.assertRaises(OSError):
            m.inspect()
        self.assertEqual(other.read_bytes(), self.before)
        self.path.unlink()
        with self.assertRaises(FileNotFoundError):
            m.inspect()
        self.assertFalse(self.path.exists())
        link = self.root / 'linked'
        link.symlink_to(self.folder, target_is_directory=True)
        with patch.object(m, 'ROOT_KEYS', str(link / 'authorized_keys')), self.assertRaises(OSError):
            m.inspect()

    def test_foreign_edits_before_and_after_write_are_preserved_and_refused(self):
        original = component_control.restore_file
        def edited_before(path, value, allowed):
            self.path.write_bytes(self.before + (KEY_C + '\n').encode())
            return original(path, value, allowed)
        with patch.object(component_control, 'restore_file', side_effect=edited_before), self.assertRaises(ValueError):
            m.run({'mode': 'install', 'keys': [KEY_A, KEY_B]})
        self.assertEqual(self.path.read_bytes(), self.before + (KEY_C + '\n').encode())
        self.path.write_bytes(self.before)
        def edited_after(path, value, allowed):
            changed = original(path, value, allowed)
            self.path.write_bytes(self.path.read_bytes() + (KEY_C + '\n').encode())
            return changed
        with patch.object(component_control, 'restore_file', side_effect=edited_after), self.assertRaises(ValueError):
            m.run({'mode': 'install', 'keys': [KEY_A, KEY_B]})
        self.assertIn(KEY_C.encode(), self.path.read_bytes())

    def test_closed_requests_and_read_only_verification_never_add_a_key(self):
        for value in (None, [], {}, {'mode': 'shell', 'keys': [KEY_A]},
                      {'mode': 'verify', 'keys': [KEY_A], 'path': str(self.path)}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                m.run(value)
        with self.assertRaises(ValueError):
            m.run({'mode': 'verify', 'keys': [KEY_A, KEY_B]})
        self.assertEqual(self.path.read_bytes(), self.before)

    def test_read_only_metadata_binding_refuses_foreign_permission_changes_and_malformed_expectations(self):
        metadata = {key: m.inspect()[key] for key in ('uid', 'gid', 'mode')}
        request = m.transport([KEY_A], mode='verify', metadata=metadata)['request']
        metadata['mode'] = 0o600
        self.assertEqual(request['metadata']['mode'], 0o640)
        self.assertFalse(m.run(request)['changed'])
        for invalid in (None, [], {}, dict(request['metadata'], mode=True),
                        dict(request['metadata'], uid=os.getuid() + 1),
                        dict(request['metadata'], extra=0)):
            with self.subTest(metadata=invalid), self.assertRaises(ValueError):
                m.run(dict(request, metadata=invalid))
        with self.assertRaises(ValueError):
            m.run(dict(request, mode='install'))
        self.path.chmod(0o600)
        with self.assertRaises(ValueError):
            m.run(request)
        self.assertEqual(self.path.read_bytes(), self.before)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_actual_packed_program_reuses_control_writer_with_only_fixture_path_substitution(self):
        keys = [KEY_A, KEY_B]
        value = m.transport(keys, mode='install')
        keys.append(KEY_C)
        self.assertEqual(value['request']['keys'], [KEY_A, KEY_B])
        namespace = {'__name__': 'root_key_fixture'}
        with patch.dict(sys.modules):
            exec(compile(base64.b64decode(value['program']), '<packed-root-keys>', 'exec'), namespace)
            namespace.update(ROOT_KEYS=str(self.path), ROOT_UID=os.getuid(), ROOT_GID=os.getgid())
            self.assertTrue(namespace['run'](value['request'])['changed'])
            self.assertFalse(namespace['run']({'mode': 'verify', 'keys': [KEY_B]})['changed'])
        self.assertEqual(self.path.read_bytes(), self.before + (KEY_B + '\n').encode())

    def test_cli_output_is_metadata_only_and_errors_do_not_export_file_or_key_contents(self):
        stream = io.StringIO()
        request = json.dumps({'mode': 'verify', 'keys': [KEY_A]}).encode()
        with patch.object(sys, 'stdin', type('Input', (), {'buffer': io.BytesIO(request)})()), redirect_stdout(stream):
            m.main()
        self.assertEqual(json.loads(stream.getvalue()), {'changed': False, 'declared_keys': 1})
        with patch.object(sys, 'stdin', type('Input', (), {'buffer': io.BytesIO(b'x' * (2 * component_control.MAX_BYTES + 1))})()):
            with self.assertRaises(ValueError):
                m.main()
        with patch.object(sys, 'stdin', type('Input', (), {'buffer': io.BytesIO(b'{}')})()):
            with self.assertRaises(SystemExit) as error:
                runpy.run_path(m.__file__, run_name='__main__')
        self.assertNotIn(KEY_A, str(error.exception))
        self.assertNotIn(str(self.path), str(error.exception))
