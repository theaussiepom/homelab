"""Recovery key component: confined public bytes, never secret input reads."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
import component_backup_key as subject
from component_sources import Sources
from component_errors import ComponentError

PUBLIC = Path(__file__).resolve().parents[1]/'proxmox/applications/tests/backup-synthetic-recovery-public.pem.fixture'


class BackupKeyTests(unittest.TestCase):
    def test_confined_source_is_pinned_and_key_failures_are_redacted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve(); source=Sources(root)
            resolver=SimpleNamespace(site_sources=source)
            (root/'public.pem').write_bytes(PUBLIC.read_bytes())
            value=subject.bind(resolver, {'source':'public.pem'})
            self.assertEqual(value['sha256'], source.pins['public.pem'])
            (root/'link.pem').symlink_to(root/'public.pem')
            for name in ('../public.pem', '/etc/passwd', 'link.pem', 'missing.pem'):
                with self.subTest(path=name), self.assertRaises(ComponentError):
                    subject.bind(resolver, {'source':name})
            (root/'invalid.pem').write_bytes(b'PRIVATE_SENTINEL')
            with self.assertRaisesRegex(ComponentError, 'backup-recovery-key') as error:
                subject.bind(resolver, {'source':'invalid.pem'})
            self.assertNotIn('PRIVATE_SENTINEL', str(error.exception))

    def test_shape_refuses_empty_boolean_and_extra_fields(self):
        for value in (None, {}, {'source':None}, {'source':''}, {'source':True},
                      {'source':'public.pem','private':'never'}):
            with self.subTest(value=value), self.assertRaises(ComponentError): subject.source(value)


if __name__ == '__main__': unittest.main()
