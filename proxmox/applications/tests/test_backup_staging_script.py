"""Read-only payload under a synthetic fd namespace; no SSH or real mount calls."""
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import backup_staging


class StagingScriptTests(unittest.TestCase):
    def exercise(self, *, mounted=False, contents=False, absent=False, link=False, bad_id=False, foreign=False, writable=False):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();srv=root/'srv';srv.mkdir();target=srv/'stage'
            if not absent:target.mkdir()
            if contents:(target/'existing').write_text('preserve existing material')
            if link:target.rmdir();target.symlink_to(srv)
            if writable:srv.chmod(0o777)
            opened={};original_open=os.open;original_stat=os.fstat
            def open_directory(path,flags,*args,**kwargs):
                actual=root if path=='/' else path
                descriptor=original_open(actual,flags,*args,**kwargs)
                opened[descriptor]=Path(actual) if path=='/' else opened[kwargs['dir_fd']]/path
                return descriptor
            def metadata(descriptor):
                info=original_stat(descriptor)
                return SimpleNamespace(st_uid=1000 if foreign else 0,st_mode=info.st_mode)
            def fdinfo(path,**kwargs):
                self.assertTrue(path.startswith('/proc/self/fdinfo/'))
                descriptor=int(path.rsplit('/',1)[1]);at_target=opened[descriptor]==target
                return io.StringIO('missing: 1\n' if bad_id else 'mnt_id: '+('2' if mounted and at_target else '1')+'\n')
            with patch.object(os,'open',side_effect=open_directory),patch.object(os,'fstat',side_effect=metadata), \
                 patch('builtins.open',side_effect=fdinfo),patch.object(sys,'argv',['-','/srv/stage']),patch('builtins.print'):
                exec(compile(backup_staging.SCRIPT,'<fixed-staging-preimage>','exec'),{})

    def test_empty_same_mount_is_allowed_but_same_device_bind_mount_refuses(self):
        self.exercise()
        for options in ({'mounted':True},{'contents':True},{'bad_id':True},{'foreign':True},{'writable':True}):
            with self.subTest(options=options),self.assertRaises(RuntimeError):self.exercise(**options)
        with self.assertRaises(OSError):self.exercise(link=True)
        with self.assertRaises(SystemExit) as exit:self.exercise(absent=True)
        self.assertEqual(exit.exception.code,0)
