"""Installed source is inspected as data, never imported before verification."""
import hashlib
import os
from pathlib import Path
import runpy
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import backup_source as source


class SourceTests(unittest.TestCase):
    def test_metadata_refuses_links_foreign_owners_and_writable_material(self):
        path=Path('/synthetic/source')
        for directory,mode in [(True,stat.S_IFDIR|0o755),(False,stat.S_IFREG|0o444)]:
            info=SimpleNamespace(st_mode=mode,st_uid=0,st_nlink=1)
            with patch.object(Path,'lstat',return_value=info):source.metadata(path,directory)
            for field,value in [('st_uid',1000),('st_mode',stat.S_IFLNK|0o777),('st_mode',mode|0o022)]:
                bad=SimpleNamespace(**vars(info));setattr(bad,field,value)
                with patch.object(Path,'lstat',return_value=bad),self.assertRaises(ValueError):source.metadata(path,directory)
        with patch.object(Path,'lstat',return_value=SimpleNamespace(st_mode=stat.S_IFREG|0o444,st_uid=0,st_nlink=2)),self.assertRaises(ValueError):
            source.metadata(path,False)

    def test_canonical_ancestors_and_exact_complete_hash_without_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();app=root/'applications';app.mkdir();common=root/'common';common.mkdir()
            (app/'module.py').write_text('raise RuntimeError("MUST NEVER IMPORT")')
            (common/'asset').write_bytes(b'public asset')
            cache=app/'__pycache__';cache.mkdir();(cache/'ignored').write_bytes(b'owned cache')
            expected=hashlib.sha256()
            for path in sorted([app/'module.py',common/'asset']):
                expected.update(str(path.relative_to(root)).encode());expected.update(hashlib.sha256(path.read_bytes()).digest())
            with patch.object(source,'metadata') as metadata:
                source.ancestors(app);self.assertTrue(metadata.called)
                source.verify(app);source.verify(app,expected.hexdigest())
                with self.assertRaises(ValueError):source.verify(app,'wrong')
                with patch.object(Path,'rglob',return_value=iter([])),self.assertRaises(ValueError):source.verify(app,'a'*64)
            (root/'alias').symlink_to(app)
            with self.assertRaises(ValueError):source.ancestors(root/'alias')
            with self.assertRaises(ValueError):source.ancestors('relative')
        with patch.object(source,'verify') as verify,patch.object(sys,'argv',['verify','/opt/source','a'*64]):
            source.main();verify.assert_called_once_with('/opt/source','a'*64)
        with patch.object(sys,'argv',['verify']),self.assertRaises(ValueError):source.main()
        # The exact inline-Ansible entry has no target operation, even on refusal.
        with patch.object(sys,'argv',['verify']),self.assertRaises(ValueError):runpy.run_path(source.__file__,run_name='__main__')
