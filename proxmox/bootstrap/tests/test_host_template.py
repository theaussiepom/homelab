"""A cached vendor template is installed automatically without overwrites."""
import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import host_template


class HostTemplateTests(unittest.TestCase):
    def setUp(self):
        self.area = tempfile.TemporaryDirectory()
        self.addCleanup(self.area.cleanup)
        self.target = Path(self.area.name) / 'cache/debian.tar.zst'
        self.data = b'synthetic archive bytes'
        self.request = {'node': 'pve', 'file_id': 'local:vztmpl/debian.tar.zst',
                        'sha256': hashlib.sha256(self.data).hexdigest(), 'size_bytes': len(self.data)}

    def upload(self, data=None):
        with patch.object(host_template.socket, 'gethostname', return_value='pve'), \
                patch.object(host_template, 'node_ready', return_value=True):
            return host_template.store(self.request, io.BytesIO(self.data if data is None else data),
                                       execute=lambda args: str(self.target))

    def test_verified_stream_is_published_and_existing_copy_is_reused(self):
        self.assertTrue(self.upload()['changed'])
        self.assertEqual(self.target.read_bytes(), self.data)
        self.assertFalse(self.upload()['changed'])
        self.assertEqual(self.target.read_bytes(), self.data)

    def test_wrong_digest_keeps_partial_evidence_and_publishes_nothing(self):
        with self.assertRaisesRegex(RuntimeError, 'checksum'):
            self.upload(b'X' * len(self.data))
        self.assertFalse(self.target.exists())
        self.assertTrue(self.target.with_name(self.target.name + '.bootstrap-partial').exists())

    def test_existing_different_file_is_never_overwritten(self):
        self.target.parent.mkdir()
        self.target.write_bytes(b'original different archive')
        with self.assertRaises(RuntimeError):
            self.upload()
        self.assertEqual(self.target.read_bytes(), b'original different archive')

    def test_existing_partial_is_not_replayed_or_cleaned_up(self):
        self.target.parent.mkdir()
        partial = self.target.with_name(self.target.name + '.bootstrap-partial')
        partial.write_bytes(b'failed evidence')
        with self.assertRaises(FileExistsError):
            self.upload()
        self.assertEqual(partial.read_bytes(), b'failed evidence')

    def test_size_limit_and_non_template_paths_fail_before_a_write(self):
        for key, value in [('file_id', 'local:snippets/secret'), ('size_bytes', 0),
                           ('size_bytes', 2 * 1024 ** 3), ('file_id', 'local:vztmpl/../other')]:
            before = dict(self.request)
            self.request[key] = value
            with self.assertRaises((RuntimeError, ValueError)):
                self.upload()
            self.assertFalse(self.target.exists())
            self.request = before


if __name__ == '__main__':
    unittest.main()
