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
    def test_legacy_sensor_and_only_its_allowlist_entry_are_removed_with_originals_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'config';root.mkdir();backup=Path(tmp)/'private';backup.mkdir()
            home=b'packages: !include_dir_named integrations\nallowlist_external_dirs:\n  - /influxdb_data\n  - /config/energy_logs\n'
            other=b'- sensor:\n    name: Other\n    unique_id: keep_this\n    command: "printf value"\n'
            legacy=b'- sensor:\n    name: InfluxDB size\n    unique_id: command_line_influxdb_size\n    command: "du -shm /influxdb_data | cut -f1"\n    unit_of_measurement: MB\n'
            (root/'homeassistant.yaml').write_bytes(home);(root/'command_line.yaml').write_bytes(other+legacy)
            before={p.name:p.stat().st_ino for p in root.iterdir()}
            hashes=[hashlib.sha256(v).hexdigest() for v in (home,other+legacy)]
            self.assertTrue(ha_http.legacy_sensor(root,backup,*hashes))
            self.assertFalse(ha_http.legacy_sensor(root,backup,*hashes))
            self.assertEqual((root/'command_line.yaml').read_bytes(),other)
            self.assertEqual((root/'homeassistant.yaml').read_bytes(),home.replace(b'  - /influxdb_data\n',b''))
            self.assertEqual((backup/'command-line.before-legacy.yaml').read_bytes(),other+legacy)
            self.assertEqual(before,{p.name:p.stat().st_ino for p in root.iterdir()})

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
