"""Explicit fixed-leaf custody identities, including retained root and child peers."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import test_component_explorer_state as base
s=base.s


class ExplicitCustodyContractTests(unittest.TestCase):
    def test_runtime_id_does_not_select_persisted_custody_and_unsafe_roots_refuse(self):
        self.assertEqual(s.context({'runtime_id':'another-id'})['custody'],s.CUSTODY)
        value=s.context({'runtime_id':'different-id','custody_directory':s.CUSTODY+'/chosen/leaf'})
        self.assertEqual(value['custody'],s.CUSTODY+'/chosen/leaf')
        for value in (None,'/etc','/var/lib/homelab-mqtt-explorer2','/var/lib/homelab-mqtt-explorer/../outside',
                      s.CUSTODY+'/double//leaf',s.CUSTODY+'/./leaf',s.CUSTODY+'/bad\nname'):
            with self.subTest(value=value),self.assertRaises(ValueError):s.context({'custody_directory':value})


class ExplicitCustodyFilesystemTests(unittest.TestCase):
    setUp=base.ScratchStateTests.setUp
    write_settings=base.ScratchStateTests.write_settings

    def test_original_bare_receipt_cannot_be_reused_for_another_owned_looking_workspace(self):
        path=self.custody/'workspace.json';path.write_text(json.dumps(self.owner));path.chmod(0o600)
        before=path.read_bytes();other=self.parent/'other-data';other.mkdir(mode=0o700)
        self.owners[other.stat().st_ino]=(1001,1001)
        with patch.object(s,'public_context',return_value=dict(self.selected,data_path=str(other))), \
             self.assertRaises(ValueError):
            base.runtime.workspace(self.owner,{})
        self.assertEqual(path.read_bytes(),before);self.assertEqual(list(other.iterdir()),[])

    def test_versioned_receipt_binds_workspace_runtime_service_project_and_custody_context(self):
        path=self.custody/'workspace.json';before=(path.stat().st_ino,path.read_bytes())
        cases=[dict(self.selected,data_path=str(self.parent/'other')),dict(self.selected,project='other-project'),
            dict(self.selected,services={'mqtt_explorer':'other','explorer_gateway':'other-gateway'}),
            dict(self.selected,runtime_directory=str(self.programs/'other')),dict(self.selected,runtime_id='other'),
            dict(self.selected,custody=str(self.custody/'other'))]
        with s.custody(self.selected) as fd:
            self.assertEqual(s.workspace_owner(fd,self.selected),self.owner)
            for selected in cases:
                with self.subTest(changed=[key for key in selected if selected[key]!=self.selected[key]]),self.assertRaises(ValueError):
                    s.workspace_owner(fd,selected)
        self.assertEqual((path.stat().st_ino,path.read_bytes()),before)
        value=json.loads(before[1]);value.pop('project');path.write_text(json.dumps(value))
        with s.custody(self.selected) as fd,self.assertRaises(ValueError):s.workspace_owner(fd,self.selected)

    def test_exact_legacy_default_document_preserves_old_bare_owner_bytes(self):
        legacy={'project':s.PROJECT,'services':dict(s.SERVICES),'data_path':s.DATA,
            'runtime_directory':s.RUNTIME,'runtime_id':'mqtt_explorer','custody':s.CUSTODY}
        self.assertEqual(s.workspace_document(self.owner,legacy),self.owner)
        path=self.custody/'workspace.json';path.write_text(json.dumps(self.owner));path.chmod(0o600)
        before=path.read_bytes()
        with s.custody(legacy) as fd:self.assertEqual(s.workspace_owner(fd,legacy),self.owner)
        self.assertEqual(path.read_bytes(),before)

    def test_two_sameguest_instances_keep_root_and_child_fixed_leaves_disjoint(self):
        first=copy.deepcopy(self.selected)
        second=copy.deepcopy(first);second.update(runtime_id='fresh-peer',custody=str(self.custody/'fresh-peer'),
            data_path=str(self.parent/'data-two'),project='second-project',services={'mqtt_explorer':'other-app','explorer_gateway':'other-gate'})
        peer_data=Path(second['data_path']);peer_data.mkdir(mode=0o700);self.owners[peer_data.stat().st_ino]=(1001,1001)
        with s.custody(second,create=True) as fd:s.save(fd,'workspace.json',s.workspace_document(self.owner,second))
        (self.custody/'unrelated.json').write_text('{"marker":"retained"}');(self.custody/'unrelated.json').chmod(0o600)
        def target(ctx,label):
            conn={'name':label,'hostname':'broker.example.invalid','port':1883,'username':'fixture-'+label}
            native=s.native_profile(conn,'fixture-'+label,'existing-'+ctx['runtime_id'])
            owned=dict(self.owner,purpose='mqtt-explorer-existing-profile',profile_id=ctx['runtime_id'],
                broker_hostname=conn['hostname'],broker_port=1883,username=conn['username'])
            return native,owned,'existing-'+ctx['runtime_id']
        def no_container(args):
            self.assertEqual(args[0],'ps');return ''
        n1,o1,r1=target(first,'first');n2,o2,r2=target(second,'second')
        s.seed_profile(first,n1,o1,r1,no_container)
        rootfiles=[self.custody/'workspace.json',self.custody/(r1+'-profile.json'),self.custody/'unrelated.json',self.data/'settings.json']
        snap=lambda paths:{str(p):(p.stat().st_ino,p.read_bytes()) for p in paths}
        root_before=snap(rootfiles)
        s.seed_profile(second,n2,o2,r2,no_container)
        self.assertEqual(snap(rootfiles),root_before)
        childfiles=[Path(second['custody'])/'workspace.json',Path(second['custody'])/(r2+'-profile.json'),peer_data/'settings.json']
        child_before=snap(childfiles)
        s.seed_profile(first,n1,o1,r1,lambda args:(_ for _ in ()).throw(AssertionError('repeat cannot call Docker')))
        self.assertEqual(snap(childfiles),child_before);self.assertEqual(snap(rootfiles),root_before)
        changed=copy.deepcopy(first);changed['custody']=str(self.custody/'changed-path')
        with self.assertRaises(ValueError):s.seed_profile(changed,n1,o1,r1,no_container)
        self.assertEqual(snap(rootfiles),root_before);self.assertEqual(snap(childfiles),child_before)
        self.assertFalse(Path(changed['custody']).exists())


class ExplicitCustodyFileTests(unittest.TestCase):
    setUp=base.ExplorerFileContractTests.setUp

    def test_compiled_custody_path_is_forwarded_and_unsafe_roots_refuse(self):
        self.app['identity']['custody_directory']='/var/lib/homelab-mqtt-explorer/chosen-child'
        rows=self.files.files(self.app,secrets={'broker_password':b'fixture-existing'},records={},public_ca=None)
        values={row['path']:row for row in rows}
        private=json.loads(values['mqtt-explorer-profile.json']['content'])
        public=json.loads(values['mqtt-explorer-public.json']['content'])
        self.assertEqual(private['runtime']['custody_directory'],self.app['identity']['custody_directory'])
        self.assertEqual(public['custody_directory'],self.app['identity']['custody_directory'])
        self.app['identity']['custody_directory']='/var/lib/foreign'
        with self.assertRaises(ValueError):self.files.files(self.app,secrets={'broker_password':b'fixture-existing'},records={},public_ca=None)


if __name__=='__main__':unittest.main()
