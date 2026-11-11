"""The SSH client must read the same protected trust path admitted locally."""
import os
from pathlib import Path
import shlex
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bootstrap_ssh as ssh


TARGET = {'address': '198.18.25.3', 'hostname': 'backup'}


def options(key, known):
    """Select one explicit key and one literal public pin, without target contact."""
    return {'private_key_file': str(key), 'host_key_checking': True,
            'inline_key_absent': True, 'password_absent': True,
            'ssh_executable': 'ssh', 'ssh_args': '-F /dev/null',
            'ssh_common_args': '-o StrictHostKeyChecking=yes -o ControlMaster=no '
            '-o BatchMode=yes -o IdentitiesOnly=yes -o GlobalKnownHostsFile=/dev/null '
            '-o VerifyHostKeyDNS=no -o UpdateHostKeys=no -o UserKnownHostsFile='
            + shlex.quote(str(known)),
            'ssh_extra_args': '', 'sftp_extra_args': '', 'scp_extra_args': ''}


def files(root):
    """Use fictional key bytes and a synthetic public host entry only."""
    key = root / 'key'; key.write_text('fictional private input'); key.chmod(0o600)
    known = root / 'known_hosts'
    known.write_text('198.18.25.3,backup ssh-ed25519 AAAAfixture\n')
    known.chmod(0o644)
    return key, known


class TrustPathTests(unittest.TestCase):
    """Exercise real file/path admission; never execute SSH or connect to a host."""

    def test_literal_single_file_preserves_existing_read_boundary(self):
        """A protected absolute pin passes; the private key is never opened."""
        with tempfile.TemporaryDirectory() as temporary:
            key, known = files(Path(temporary).resolve())
            with patch.object(ssh.os, 'open', wraps=os.open) as opened:
                ssh.trust(TARGET, options(key, known))
            self.assertEqual(opened.call_count, 1)
            self.assertEqual(opened.call_args.args[0], known)
            self.assertTrue(opened.call_args.args[1] & os.O_NOFOLLOW)

    def test_openssh_path_syntax_refuses_before_opening_the_literal_file(self):
        """Existing literal files cannot hide token expansion or another file list."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); key, known = files(root)
            for name in ('known_%h', 'known_%%', 'known_${USER}', 'known hosts',
                         'known\thosts', 'known\nhosts', 'known"hosts',
                         "known'hosts", 'known\\hosts'):
                with self.subTest(name=name):
                    candidate = root / name
                    candidate.write_bytes(known.read_bytes()); candidate.chmod(0o644)
                    with patch.object(ssh.os, 'open', wraps=os.open) as opened:
                        with self.assertRaisesRegex(ValueError, '^' + ssh.ERROR + '$'):
                            ssh.trust(TARGET, options(key, candidate))
                    opened.assert_not_called()

    def test_writable_ancestors_refuse_for_both_selected_files(self):
        """Correct leaf modes cannot protect names replaceable through a parent."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); root.chmod(0o755)
            key, known = files(root)
            parent = root / 'replaceable'; parent.mkdir()
            nested_key, nested_known = files(parent)
            for mode in (0o770, 0o777):
                parent.chmod(mode)
                for selected in (options(key, nested_known), options(nested_key, known)):
                    with self.subTest(mode=oct(mode), selected=selected['private_key_file']):
                        with self.assertRaisesRegex(ValueError, '^' + ssh.ERROR + '$'):
                            ssh.trust(TARGET, selected)

    def test_symlink_ancestors_refuse_for_both_selected_files(self):
        """A linked directory is refused even when the destination leaves are safe."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); key, known = files(root)
            linked = root / 'linked'; linked.symlink_to(root, target_is_directory=True)
            for selected in (options(key, linked / known.name), options(linked / key.name, known)):
                with self.subTest(selected=selected['private_key_file']):
                    with self.assertRaisesRegex(ValueError, '^' + ssh.ERROR + '$'):
                        ssh.trust(TARGET, selected)

    def test_foreign_owned_or_unreadable_ancestor_refuses(self):
        """Simulate owner/stat refusal without changing users or native permissions."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); key, known = files(root)
            original = Path.lstat
            for unreadable in (False, True):
                def changed(path, *args, **kwargs):
                    if path == root:
                        if unreadable:
                            raise PermissionError('private diagnostic')
                        values = list(original(path, *args, **kwargs))
                        values[4] = os.geteuid() + 10000
                        return os.stat_result(values)
                    return original(path, *args, **kwargs)
                with self.subTest(unreadable=unreadable), patch.object(Path, 'lstat', changed):
                    with self.assertRaisesRegex(ValueError, '^' + ssh.ERROR + '$'):
                        ssh.trust(TARGET, options(key, known))

    def test_sticky_trusted_parent_preserves_protected_temporary_entries(self):
        """Sticky protection admits root/actor-owned entries, as in standard /tmp."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); root.chmod(0o1777)
            self.assertTrue(root.stat().st_mode & stat.S_ISVTX)
            key, known = files(root)
            ssh.trust(TARGET, options(key, known))

    def test_sticky_parent_does_not_admit_a_foreign_owned_child(self):
        """Sticky protection is useful only for entries owned by root/the CD actor."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); root.chmod(0o1777)
            nested = root / 'nested'; nested.mkdir()
            key, known = files(nested)
            original = Path.lstat
            for foreign in (nested, key, known):
                def changed(path, *args, **kwargs):
                    result = original(path, *args, **kwargs)
                    if path == foreign:
                        values = list(result); values[4] = os.geteuid() + 10000
                        return os.stat_result(values)
                    return result
                with self.subTest(foreign=foreign.name), patch.object(Path, 'lstat', changed):
                    with self.assertRaisesRegex(ValueError, '^' + ssh.ERROR + '$'):
                        ssh.trust(TARGET, options(key, known))

    def test_root_is_not_a_known_hosts_file(self):
        """An absolute directory cannot replace the required regular pin file."""
        with tempfile.TemporaryDirectory() as temporary:
            key, _ = files(Path(temporary).resolve())
            with self.assertRaisesRegex(ValueError, '^' + ssh.ERROR + '$'):
                ssh.trust(TARGET, options(key, Path('/')))
