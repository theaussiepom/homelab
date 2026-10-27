"""The HA change is exact, repeatable and retains original file metadata."""
import hashlib
from pathlib import Path
import tempfile
import unittest
import os
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import ha_http


class HaHttpTests(unittest.TestCase):
    def test_proxy_is_added_once_and_original_inode_mode_xattr_are_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'configuration.yaml'; backup = Path(tmp) / 'original'
            original = b'default_config:\nrecorder: !include recorder.yaml\n'
            path.write_bytes(original); path.chmod(0o640)
            os.setxattr(path, 'user.homelab-fixture', b'retain')
            before = path.stat(); digest = hashlib.sha256(original).hexdigest()
            self.assertTrue(ha_http.configure(path, backup, digest, '10.88.30.33'))
            self.assertFalse(ha_http.configure(path, backup, digest, '10.88.30.33'))
            self.assertEqual(backup.read_bytes(), original)
            self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.stat().st_ino, before.st_ino)
            self.assertEqual(path.stat().st_mode, before.st_mode)
            self.assertEqual(os.getxattr(path, 'user.homelab-fixture'), b'retain')

    def test_drift_existing_http_symlink_and_wrong_proxy_refuse_before_write(self):
        for content, expected, proxy, symlink in [
                (b'drift\n', '0'*64, '10.88.30.33', False),
                (b'http:\n', None, '10.88.30.33', False),
                (b'default_config:\n', None, '127.0.0.1', False),
                (b'default_config:\n', None, '1.1.1.1', False),
                (b'default_config:\n', None, '10.88.30.33', True)]:
            with self.subTest(content=content,proxy=proxy,symlink=symlink), tempfile.TemporaryDirectory() as tmp:
                original = Path(tmp) / 'original'; original.write_bytes(content)
                path = Path(tmp) / 'configuration.yaml'
                if symlink: path.symlink_to(original)
                else: path.write_bytes(content)
                backup = Path(tmp) / 'backup'
                with self.assertRaises((ValueError,OSError)):
                    ha_http.configure(path, backup, expected or hashlib.sha256(content).hexdigest(), proxy)
                self.assertFalse(backup.exists()); self.assertEqual(path.read_bytes(), content)


if __name__ == '__main__': unittest.main()
