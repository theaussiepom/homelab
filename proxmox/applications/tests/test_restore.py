"""Restore boundary tests use only temporary synthetic archives."""
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('restore', Path(__file__).resolve().parents[1] / 'restore.py')
restore = importlib.util.module_from_spec(spec)
spec.loader.exec_module(restore)


class RestoreTests(unittest.TestCase):
    def archive(self, root, members):
        path = root / 'capture.tar'
        with tarfile.open(path, 'w') as stream:
            for name, link in members:
                item = tarfile.TarInfo(name)
                if link is not None:
                    item.type, item.linkname = tarfile.SYMTYPE, link
                    stream.addfile(item)
                else:
                    item.size = 4
                    stream.addfile(item, io.BytesIO(b'data'))
        return path

    def test_relative_capture_with_safe_link_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.archive(Path(tmp), [('config/a', None), ('link', 'config/a')])
            restore.validate_archive(path)

    def test_original_npm_bin_links_can_point_to_their_sibling_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.archive(Path(tmp), [('node-red/data/node_modules/acorn/bin/acorn', None),
                ('node-red/data/node_modules/.bin/acorn', '../acorn/bin/acorn')])
            restore.validate_archive(path)

    def test_parent_components_cannot_hide_an_intermediate_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.archive(Path(tmp), [('a/link', 'target'), ('a/nested/escape', '../link/../../outside')])
            with self.assertRaisesRegex(ValueError, 'traverses'):
                restore.validate_archive(path)

    def test_hardlink_relocated_symlink_cannot_hide_parent_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'relocated.tar'
            with tarfile.open(path, 'w') as stream:
                for name, kind, target in [('a', tarfile.DIRTYPE, ''),
                        ('a/b', tarfile.SYMTYPE, '.'), ('c', tarfile.LNKTYPE, 'a/b'),
                        ('d', tarfile.SYMTYPE, 'c/../outside-marker')]:
                    member = tarfile.TarInfo(name)
                    member.type, member.linkname = kind, target
                    stream.addfile(member)
            with self.assertRaisesRegex(ValueError, 'traverses'):
                restore.validate_archive(path)

    def test_hardlink_cannot_relocate_a_parent_symlink_or_traverse_one(self):
        for linkname in ('a/b/c', 'a/b/c/file'):
            with self.subTest(linkname=linkname), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'relocated-parent.tar'
                with tarfile.open(path, 'w') as stream:
                    for name, kind, target in [('a', tarfile.DIRTYPE, ''),
                            ('a/b', tarfile.DIRTYPE, ''), ('a/b/c', tarfile.SYMTYPE, '..'),
                            ('relocated', tarfile.LNKTYPE, linkname)]:
                        member = tarfile.TarInfo(name)
                        member.type, member.linkname = kind, target
                        stream.addfile(member)
                with self.assertRaisesRegex(ValueError, 'hardlink traverses'):
                    restore.validate_archive(path)

    def test_regular_file_hardlink_and_npm_sibling_symlink_remain_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.archive(Path(tmp), [('node_modules/acorn/bin/acorn', None),
                ('node_modules/.bin/acorn', '../acorn/bin/acorn')])
            with tarfile.open(path, 'a') as stream:
                member = tarfile.TarInfo('same-file')
                member.type, member.linkname = tarfile.LNKTYPE, 'node_modules/acorn/bin/acorn'
                stream.addfile(member)
            restore.validate_archive(path)

    def test_escape_and_symlink_traversal_are_refused(self):
        for members in ([('../escape', None)], [('/etc/shadow', None)], [('link', '/etc')],
                        [('config/link', '../../etc')], [('config/link', '..')],
                        [('link', 'config'), ('link/a', None)]):
            with self.subTest(members=members), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(ValueError):
                    restore.validate_archive(self.archive(Path(tmp), members))

    def test_mismatched_hash_and_existing_data_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); archive = self.archive(root, [('config/a', None)])
            dest = root / 'target'; dest.mkdir(); (dest / 'live').write_text('untouched')
            for checksum in ('0' * 64, restore.digest(archive)):
                with self.assertRaises(ValueError): restore.restore(archive, dest, root / 'receipt', checksum)
            self.assertEqual((dest / 'live').read_text(), 'untouched')

    def test_incomplete_restore_stays_held(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); archive = self.archive(root, [('config/a', None)])
            (root / 'receipt').write_text('{"state":"started"}')
            with self.assertRaises(ValueError):
                restore.restore(archive, root / 'target', root / 'receipt', restore.digest(archive))


if __name__ == '__main__':
    unittest.main()
