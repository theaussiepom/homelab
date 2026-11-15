"""Persistent ownership units and real completed-receipt caller negatives."""
import copy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import component_ownership as ownership
from private_io import read_json
import test_component_deployment as caller
import test_component_agent_phase as agent_caller
import component_ansible


def app(name):
    return {'id':name,'adapter':'unbound','identity':{'services':{'unbound':name},'networks':{}},
        'project_name':'shared-project','storage_paths':{}}


class OwnershipComponentTests(unittest.TestCase):
    def test_shared_project_disjoint_services_and_fixed_leaf_parent_child_are_not_adoption(self):
        first,second=app('one'),app('two')
        self.assertFalse(ownership.conflicts(first,second))
        first['identity']['custody_directory']='/var/lib/homelab-db-tools'
        second['identity']['custody_directory']='/var/lib/homelab-db-tools/two'
        first['runtime_files']={'directory':'/opt/homelab-app/runtime','files':['one.json']}
        second['runtime_files']={'directory':'/opt/homelab-app/runtime/two','files':['two.json']}
        self.assertFalse(ownership.conflicts(first,second))

    def test_service_native_leaf_custody_and_writable_storage_namespaces_remain_owned(self):
        for kind in ('service','native','runtime','sidecar','custody','storage','nested'):
            first,second=app('one'),app('two')
            if kind=='service':second['identity']['services']={'unbound':'one'}
            elif kind=='native':
                first['adapter']=second['adapter']='postgresql'
                first['identity']['services']=second['identity']['services']={}
            elif kind=='runtime':
                first['runtime_files']=second['runtime_files']={'directory':'/opt/homelab-app/runtime','files':['owned.json']}
            elif kind=='sidecar':first['sidecar_files']=second['sidecar_files']={'owned':{'destination':'/opt/homelab-app/dns-records.json'}}
            elif kind=='custody':first['identity']['custody_directory']=second['identity']['custody_directory']='/var/lib/homelab-db-tools'
            else:
                first['storage_paths']={'data':{'source':'/srv/example/one','read_only':False}}
                second['storage_paths']={'data':{'source':'/srv/example/one'+('/nested'if kind=='nested'else''),'read_only':False}}
            with self.subTest(kind=kind):self.assertTrue(ownership.conflicts(first,second))
        first,second=app('one'),app('two')
        first['storage_paths']=second['storage_paths']={'media':{'source':'/srv/example/media','read_only':True}}
        self.assertFalse(ownership.conflicts(first,second))


class OwnershipReceiptIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.fixture=caller.DeploymentIntegrationTests('test_real_source_and_receiver_repeat_owned_fresh_guest_without_lifecycle_flip')
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.fixture.all_phases()
        self.receipt=self.fixture.state/'610/ordinary-complete.json'
        self.attempt=SimpleNamespace(receipt=self.receipt,cfg=self.fixture.cfg)
        self.selected=read_json(Path(self.fixture.cfg['deployment']['runtime_file']),private=True)['applications']['recursive_a']

    def test_renamed_id_cannot_claim_a_completed_peers_namespace_even_when_marked_retained(self):
        before={str(p.relative_to(self.fixture.state)):p.read_bytes()for p in self.fixture.state.rglob('*')if p.is_file()}
        renamed=copy.deepcopy(self.selected);renamed.update(id='another_identity',lifecycle='retained')
        with self.assertRaisesRegex(ValueError,'prior app owns'):ownership.prior(self.attempt,renamed)
        self.assertEqual(before,{str(p.relative_to(self.fixture.state)):p.read_bytes()for p in self.fixture.state.rglob('*')if p.is_file()})

    def test_database_identity_owner_refusal_propagates_before_an_ordinary_repeat(self):
        before = self.receipt.read_bytes()
        with patch.object(ownership.renovate, 'preserve_storage', side_effect=ValueError('database owner differs')) as guard:
            with self.assertRaisesRegex(ValueError, 'database owner differs'):
                ownership.prior(self.attempt, self.selected)
        guard.assert_called_once()
        self.assertEqual(guard.call_args.args, (self.selected, self.selected))
        self.assertEqual(self.receipt.read_bytes(), before)

    def test_exact_owned_repeat_and_genuinely_disjoint_new_app_remain_distinct(self):
        self.assertTrue(ownership.prior(self.attempt,self.selected))
        new=copy.deepcopy(self.selected);new.update(id='new_identity',project_name='different-project')
        new['identity']['services']={'unbound':'new_unbound'}
        self.assertFalse(ownership.prior(self.attempt,new))

    def test_first_fixed_runtime_leaves_keep_the_app_owner_and_reject_other_identity_changes(self):
        import application_contract
        new=copy.deepcopy(self.selected)
        root='/opt/homelab-app/runtime/recursive_a'
        new['identity']['runtime_directory']=root
        new['runtime_files']={'app':new['id'],'guest':new['guest'],'directory':root,
                              'files':['owned.json'],'directory_mounts':[]}
        before=self.receipt.read_bytes()
        with patch.dict(application_contract.RUNTIME_FILES,{'unbound':{'owned.json'}}):
            self.assertEqual(ownership.namespaces(self.attempt,new),(True,False))
            for change in ('storage','service','directory_claim','adapter'):
                other=copy.deepcopy(new)
                if change=='storage':other['storage_paths']={'new':{'source':'/srv/foreign'}}
                elif change=='service':other['identity']['services']['unbound']='foreign'
                elif change=='directory_claim':other['runtime_files']['files']=['foreign.json']
                else:other['adapter']='renovate'
                with self.subTest(change=change),self.assertRaises(ValueError):
                    ownership.namespaces(self.attempt,other)
        self.assertEqual(self.receipt.read_bytes(),before)

    def test_controller_first_runtime_namespace_then_owned_repeat_and_relocation_refusal(self):
        import os,json,application_contract,component_prepare,component_plan,component_packet
        from private_io import encoded,write_bytes
        new_files={'files':[{'path':'owned.json','content':'{}','uid':0,'gid':0,'mode':'0400'}],
                   'environment':{}}
        fixture=self.fixture
        seen=[]
        def ansible(argv,environment,log):
            fixture.ansible(argv,environment,log)
            selected=read_json(Path(argv[-1][1:]),private=True)
            if 'component_runtime_directory'in selected:
                seen.append((selected['component_preflight']['previously_owned'],selected['component_runtime_directory']))
        with patch.dict(application_contract.RUNTIME_FILES,{'unbound':{'owned.json'}}), \
             patch.dict(component_prepare.component_private_inputs.ROLES,{'unbound':set()}), \
             patch.object(component_prepare.component_private_inputs,'bind',return_value=new_files), \
             patch.object(component_ansible,'quiet',side_effect=ansible):
            plan=component_plan.resolve(fixture.root/'library',fixture.root/'consumer/site.json')
            packet=component_packet.lower_plan(plan,inputs=fixture.inputs)['resolver']
            write_bytes(fixture.packet,encoded(packet));fixture.cfg=json.loads(packet['files']['site.json'])
            with patch.dict(os.environ,{'GITHUB_RUN_ID':'102','GITHUB_RUN_NUMBER':'11'}):fixture.all_phases()
            root=plan.resolved['apps']['recursive_a']['identity']['runtime_directory']
            self.assertEqual(seen,[(True,{'directory':root,'lifecycle':'fresh','previously_owned':False})])
            with patch.dict(os.environ,{'GITHUB_RUN_ID':'103','GITHUB_RUN_NUMBER':'12'}):fixture.all_phases()
            self.assertEqual(seen[-1],(True,{'directory':root,'lifecycle':'fresh','previously_owned':True}))
            attempt=SimpleNamespace(receipt=self.receipt,cfg=fixture.cfg)
            app=read_json(Path(fixture.cfg['deployment']['runtime_file']),private=True)['applications']['recursive_a']
            self.assertEqual(ownership.namespaces(attempt,app),(True,True))
            for directory in (None,root+'-moved'):
                changed=copy.deepcopy(app)
                if directory is None:changed['identity'].pop('runtime_directory')
                else:changed['identity']['runtime_directory']=directory
                with self.subTest(directory=directory),self.assertRaisesRegex(ValueError,'no automatic relocation'):
                    ownership.prior(attempt,changed)

    def test_reserved_agent_payload_does_not_hide_or_impersonate_peer_app_ownership(self):
        fixture=agent_caller.AgentCallerTests('test_selected_agent_payload_is_phase_bound_and_repeats_without_rotation')
        fixture.setUp();self.addCleanup(fixture.doCleanups)
        with patch.object(component_ansible,'quiet',side_effect=fixture.ansible):fixture.fixture.all_phases()
        receipt=fixture.fixture.state/'610/ordinary-complete.json'
        value=read_json(receipt,private=True)
        self.assertEqual(value['phase_inputs']['zabbix-agent']['app'],'agent')
        selected=read_json(Path(fixture.cfg['deployment']['runtime_file']),private=True)['applications']['recursive_a']
        attempt=SimpleNamespace(receipt=receipt,cfg=fixture.cfg)
        self.assertTrue(ownership.prior(attempt,selected))
        renamed=copy.deepcopy(selected);renamed.update(id='another_identity',lifecycle='retained')
        before=receipt.read_bytes()
        with self.assertRaisesRegex(ValueError,'prior app owns'):ownership.prior(attempt,renamed)
        self.assertEqual(receipt.read_bytes(),before)


if __name__=='__main__':unittest.main()
