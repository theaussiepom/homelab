"""Explorer accepts only the exact freshly created directory inode proof."""
import copy
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import test_component_explorer_state as base
s,runtime=base.s,base.runtime


class WorkspaceHandoffTests(unittest.TestCase):
    setUp=base.ScratchStateTests.setUp
    write_settings=base.ScratchStateTests.write_settings

    def empty(self):
        for path in (self.data/'settings.json',self.custody/'workspace.json'):
            self.owners.pop(path.stat().st_ino,None);path.unlink()
        info=self.data.stat()
        return {'path':str(self.data),'device':info.st_dev,'inode':info.st_ino,
                'uid':1001,'gid':1001,'mode':'0700'}

    def test_exact_creation_proof_owns_new_workspace_without_chowning_existing_inode(self):
        proof=self.empty();chown=s.os.fchown;changed=[]
        def record(fd,uid,gid):
            changed.append(os.fstat(fd).st_ino);return chown(fd,uid,gid)
        with patch.object(s.os,'fchown',side_effect=record):
            self.assertEqual(runtime.workspace(self.owner,{},proof),{'workspace':'owned'})
        self.assertNotIn(proof['inode'],changed)
        before=(self.custody/'workspace.json').read_bytes()
        self.assertEqual(runtime.workspace(self.owner,{}),{'workspace':'owned'})
        with self.assertRaises(ValueError):runtime.workspace(self.owner,{},proof)
        self.assertEqual(before,(self.custody/'workspace.json').read_bytes())

    def test_actual_directory_initializer_result_survives_ansible_json_handoff(self):
        import re
        import test_component_data
        temporary=self.root/'ansible';temporary.mkdir(mode=0o700)
        with patch.dict(os.environ,{'ANSIBLE_LOCAL_TEMP':str(temporary)}):
            from ansible.plugins.filter.core import FilterModule
        data=test_component_data.data
        self.empty();self.owners.pop(self.data.stat().st_ino,None);self.data.rmdir()
        fstat=os.fstat
        def numeric(fd):
            info=fstat(fd);fields={key:getattr(info,key) for key in dir(info) if key.startswith('st_')}
            fields['st_uid'],fields['st_gid']=s.owner(info)
            return SimpleNamespace(**fields)
        with patch.object(data,'ROOT_UID',0),patch.object(data,'ROOT_PATTERN',re.escape(str(self.parent))), \
             patch.object(data,'mount',return_value=True),patch.object(data.os,'fstat',side_effect=numeric):
            result=data.initialize({'previously_owned':False,'directories':[{
                'root':str(self.parent),'path':str(self.data),'uid':1001,'gid':1001,'mode':'0700'}]})
        proof,=result['created_directories']
        transmitted=json.loads(FilterModule().filters()['to_json'](proof))
        self.assertEqual(runtime.workspace(self.owner,{},transmitted),{'workspace':'owned'})
        self.assertEqual(s.owner(self.data.stat()),(1001,1001))

    def test_missing_wrong_path_inode_or_metadata_proof_cannot_adopt_owned_looking_data(self):
        proof=self.empty()
        with self.assertRaises(ValueError):runtime.workspace(self.owner,{})
        for field,value in [('path',str(self.root/'different')),('device',proof['device']+1),
                ('inode',proof['inode']+1),('uid',0),('gid',0),('mode','0755'),
                ('inode',True),('extra',True)]:
            with self.subTest(field=field),self.assertRaises(ValueError):
                runtime.workspace(self.owner,{},dict(proof,**{field:value}))
        self.assertFalse((self.custody/'workspace.json').exists())
        self.assertEqual(list(self.data.iterdir()),[])

    def test_leaf_substitution_after_proof_does_not_read_or_adopt_outside_directory(self):
        proof=self.empty();outside=self.root/'outside';outside.mkdir(mode=0o700)
        sentinel=outside/'settings.json';sentinel.write_bytes(b'outside synthetic private sentinel')
        original=s.os.open;triggered=[]
        def swapped(path,flags,*args,**kwargs):
            if path==self.data.name and kwargs.get('dir_fd') is not None and not triggered:
                triggered.append(True);self.data.rename(self.parent/'parked')
                self.data.symlink_to(outside,target_is_directory=True)
            return original(path,flags,*args,**kwargs)
        with patch.object(s.os,'open',side_effect=swapped),self.assertRaises((ValueError,OSError)):
            runtime.workspace(self.owner,{},proof)
        self.assertEqual(triggered,[True])
        self.assertEqual(sentinel.read_bytes(),b'outside synthetic private sentinel')
        self.assertFalse((self.custody/'workspace.json').exists())

    def test_actual_task_sources_handoff_created_fd_result_before_workspace_action(self):
        import yaml
        root=Path(runtime.__file__).parent/'ansible'
        ready=yaml.safe_load((root/'tasks/component-ready.yml').read_text())
        create=next(i for i,row in enumerate(ready) if row.get('register')=='component_directory_prepare')
        inspect=next(i for i,row in enumerate(ready) if row.get('register')=='component_required_paths')
        self.assertLess(create,inspect)
        proxy=yaml.safe_load((root/'tasks/component-proxy-ready.yml').read_text())
        select=next(i for i,row in enumerate(proxy) if 'component_explorer_creation' in row.get('ansible.builtin.set_fact',{}))
        workspace=next(i for i,row in enumerate(proxy) if '--created-directory' in str(row.get('ansible.builtin.command',{})))
        self.assertLess(select,workspace)
        self.assertIn('component_directory_prepare.stdout',str(proxy[select]))
        self.assertIn("selectattr('path', 'equalto', component_application.storage_paths.data.source)",str(proxy[select]))
        self.assertIn('component_explorer_creation[0] | to_json',str(proxy[workspace]))
        self.assertTrue(proxy[workspace]['no_log'])


if __name__=='__main__':unittest.main()
