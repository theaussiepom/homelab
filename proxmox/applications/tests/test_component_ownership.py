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
