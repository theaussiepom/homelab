"""Real scratch storage; only mount identity/root prefix/numeric ownership are adapted."""
import copy
import importlib.util
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('component_data',Path(__file__).resolve().parents[1]/'component-data.py')
data=importlib.util.module_from_spec(spec);spec.loader.exec_module(data)


class DataTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o700)
        self.volume=self.root/'volume';self.volume.mkdir(mode=0o700)
        self.row={'root':str(self.volume),'path':str(self.volume/'apps'/'configuration'),
                  'uid':os.getuid(),'gid':os.getgid(),'mode':'0700'}
        for context in (patch.object(data,'ROOT_UID',os.geteuid()),
                        patch.object(data,'ROOT_PATTERN',re.escape(str(self.volume))),
                        patch.object(data,'mount',return_value=True)):
            context.start();self.addCleanup(context.stop)

    def call(self,*,owned=False,row=None):
        return data.initialize({'directories':[self.row if row is None else row],'previously_owned':owned})

    def test_scratch_and_exact_owned_repeat_without_data_or_metadata_repair(self):
        result=self.call()
        self.assertEqual((result['initialized'],result['verified']),(1,0))
        leaf=Path(self.row['path']);proof,=result['created_directories']
        self.assertEqual(proof,{'path':str(leaf),'device':leaf.stat().st_dev,'inode':leaf.stat().st_ino,
                              'uid':os.getuid(),'gid':os.getgid(),'mode':'0700'})
        leaf=Path(self.row['path']);source=leaf/'settings';source.write_bytes(b'private synthetic data')
        before=(leaf.stat().st_ino,leaf.stat().st_uid,leaf.stat().st_gid,leaf.stat().st_mode,source.read_bytes())
        with patch.object(data.os,'fchown',side_effect=AssertionError('No repeat chown')), \
             patch.object(data.os,'fchmod',side_effect=AssertionError('No repeat chmod')):
            self.assertEqual(self.call(owned=True),{'initialized':0,'verified':1,'created_directories':[]})
        self.assertEqual(before,(leaf.stat().st_ino,leaf.stat().st_uid,leaf.stat().st_gid,leaf.stat().st_mode,source.read_bytes()))
        with self.assertRaises(ValueError):self.call()

    def test_numeric_owner_is_set_only_on_a_just_created_inode(self):
        owners={};calls=[];actual=data.ownership
        def chown(descriptor,uid,gid):
            info=os.fstat(descriptor);owners[info.st_ino]=(uid,gid,0o700);calls.append(info.st_ino)
        with patch.object(data.os,'fchown',side_effect=chown),patch.object(data,'ownership',
                side_effect=lambda info:owners.get(info.st_ino,actual(info))):
            selected=dict(self.row,uid=(os.getuid()+1)%65536)
            self.call(row=selected)
            inode=Path(selected['path']).stat().st_ino
            self.assertEqual(calls,[inode])
            self.call(owned=True,row=selected)
            self.assertEqual(calls,[inode])

    def test_foreign_existing_leaf_wrong_metadata_missing_owned_path_and_partial_failure_refuse(self):
        leaf=Path(self.row['path']);leaf.mkdir(parents=True,mode=0o700)
        before=leaf.stat().st_ino
        with self.assertRaises(ValueError):self.call()
        leaf.chmod(0o755)
        with self.assertRaises(ValueError):self.call(owned=True)
        self.assertEqual((leaf.stat().st_ino,leaf.stat().st_mode&0o777),(before,0o755))
        missing=dict(self.row,path=str(self.volume/'absent'))
        with self.assertRaises(ValueError):self.call(owned=True,row=missing)
        self.assertFalse(Path(missing['path']).exists())
        partial=dict(self.row,path=str(self.volume/'partial'),uid=(os.getuid()+1)%65536)
        with patch.object(data.os,'fchown',side_effect=OSError('synthetic ownership failure')),self.assertRaises(OSError):
            self.call(row=partial)
        self.assertTrue(Path(partial['path']).is_dir())
        with self.assertRaises(ValueError):self.call(row=partial)

    def test_mount_and_source_scope_negatives_do_not_create_any_directory(self):
        with patch.object(data,'mount',return_value=False),self.assertRaises(ValueError):self.call()
        self.assertEqual(list(self.volume.iterdir()),[])
        for change in ({'root':'/etc'},{'path':str(self.volume)},{'path':str(self.root/'foreign')},
                {'path':str(self.volume/'${SOURCE}')},{'uid':True},{'gid':-1},{'mode':'0777'},
                {'extra':'arbitrary'}):
            with self.subTest(fields=tuple(change)),self.assertRaises(ValueError):self.call(row=dict(self.row,**change))
        self.assertEqual(list(self.volume.iterdir()),[])

    def test_symlink_and_ancestor_swap_never_initialize_outside_the_bound_mount(self):
        outside=self.root/'outside';outside.mkdir(mode=0o700)
        (self.volume/'apps').symlink_to(outside,target_is_directory=True)
        with self.assertRaises(OSError):self.call()
        self.assertEqual(list(outside.iterdir()),[])
        (self.volume/'apps').unlink()
        original=data.os.open;triggered=[]
        def swap(name,flags,*args,**kwargs):
            if name=='volume' and kwargs.get('dir_fd') is not None and not triggered:
                triggered.append(True);self.volume.rename(self.root/'moved')
                self.volume.symlink_to(outside,target_is_directory=True)
            return original(name,flags,*args,**kwargs)
        with patch.object(data.os,'open',side_effect=swap),self.assertRaises(OSError):self.call()
        self.assertEqual(triggered,[True]);self.assertEqual(list(outside.iterdir()),[])


class RuntimeNamespaceTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o700)
        for context in (patch.object(data,'ROOT_UID',os.geteuid()),
                        patch.object(data,'ROOT_GID',os.getgid()),
                        patch.object(data,'RUNTIME_ROOT',str(self.root))):
            context.start();self.addCleanup(context.stop)

    def call(self,name='first',lifecycle='fresh',owned=False):
        return data.runtime({'directory':str(self.root/'runtime'/name),
                             'lifecycle':lifecycle,'previously_owned':owned})

    def test_fresh_namespaces_and_owned_repeats_preserve_peer_files(self):
        self.assertEqual(self.call()['initialized'],2)
        leaf=self.root/'runtime/first';(leaf/'secret').write_bytes(b'owned bytes')
        before=(leaf.stat().st_ino,(leaf/'secret').read_bytes())
        self.assertEqual(self.call('second')['initialized'],1)
        with patch.object(data.os,'mkdir',side_effect=AssertionError('No repeat create')), \
             patch.object(data.os,'fchown',side_effect=AssertionError('No ownership repair')), \
             patch.object(data.os,'fchmod',side_effect=AssertionError('No mode repair')):
            self.assertEqual(self.call(owned=True)['initialized'],0)
            self.call(lifecycle='retained')
        self.assertEqual(before,(leaf.stat().st_ino,(leaf/'secret').read_bytes()))
        with self.assertRaises(ValueError):self.call()

    def test_retained_or_owned_missing_and_foreign_metadata_refuse_without_repair(self):
        for lifecycle,owned in [('retained',False),('fresh',True)]:
            with self.subTest(lifecycle=lifecycle),self.assertRaises((ValueError,OSError)):
                self.call(lifecycle=lifecycle,owned=owned)
        self.assertEqual(list(self.root.iterdir()),[])
        self.call();leaf=self.root/'runtime/first';leaf.chmod(0o755)
        with self.assertRaises(ValueError):self.call(owned=True)
        self.assertEqual(leaf.stat().st_mode&0o777,0o755)

    def test_path_controls_symlink_and_wrong_actor_refuse(self):
        for name in ('../escape','bad/name/../../escape','${ENV}','foreign:name'):
            with self.subTest(name=name),self.assertRaises(ValueError):self.call(name)
        outside=self.root/'outside';outside.mkdir(mode=0o700)
        (self.root/'runtime').symlink_to(outside,target_is_directory=True)
        with self.assertRaises(OSError):self.call()
        self.assertEqual(list(outside.iterdir()),[])
        with patch.object(data.os,'geteuid',return_value=os.getuid()+1),self.assertRaises(ValueError):self.call()


if __name__=='__main__':unittest.main()
