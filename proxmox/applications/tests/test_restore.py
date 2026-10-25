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

    def test_escape_and_symlink_traversal_are_refused(self):
        for members in ([('../escape', None)], [('/etc/shadow', None)], [('link', '/etc')],
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
