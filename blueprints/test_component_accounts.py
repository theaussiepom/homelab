"""Direct normalized-account binder units; validators/endpoints are collaborators.

Raw authored account validation and duplicate canonical-principal selection are
owned by component_connections. These tests do not replay that validator matrix.
"""
import copy
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'proxmox/applications'))
import component_accounts as accounts
from component_errors import ComponentError


def database_fixture(engine='postgresql'):
    endpoint={'app':'database','guest':'database_guest','address':'198.18.31.23',
              'protocol':'tcp','port':5432 if engine=='postgresql' else 3306}
    account={'adapter':engine+'-admin','owner':'console','target':{'app':'database','endpoint':'sql_endpoint'},
             'principal':'console_admin','credential':'database_secret','access':'server-administration',
             'lifecycle':'create-once','target_endpoint':endpoint,'credential_id':'console-database'}
    connection={'account':copy.deepcopy(account),'source_address':'198.18.31.32'}
    console={'id':'console','guest':'console_guest','adapter':'cloudbeaver',
             'resolved_connections':{'administrator':connection},'settings':{
                'connections':{'metadata':{'name':'Existing metadata'}},
                'managed_connections':{'administrator':{'account':copy.deepcopy(account),
                    'name':'Database administrator','driver':engine,'database':'postgres',
                    'host':endpoint['address'],'port':endpoint['port']}}}}
    producer={'id':'database','guest':'database_guest','adapter':engine}
    resolver=SimpleNamespace(apps={'console':console,'database':producer},
        guests={'console_guest':{'context':'selected','identity':{'vmid':808,'hostname':'console'}},
                'database_guest':{'context':'selected','identity':{'vmid':809,'hostname':'database'}}},
        site={'contexts':{'selected':{'node':'fixture-node'}}},
        endpoint=Mock(side_effect=AssertionError('Account binder consumes already resolved endpoints')),
        role_address=Mock(side_effect=AssertionError('Account binder consumes already resolved sources')))
    return resolver,{'database_account':account}


def mqtt_fixture():
    resolver,selected=database_fixture()
    value=selected['database_account'];value.update(adapter='mqtt-client',access='read-write-all',
        credential_id='explorer-broker',principal='explorer_client')
    value['target_endpoint'].update(protocol='tcp',port=1883,address='198.18.41.2')
    resolver.apps['database'].update(adapter='mqtt',guest='console_guest')
    consumer=resolver.apps['console'];consumer['adapter']='mqtt_explorer'
    consumer['settings']={'broker':{'name':'Saved broker','hostname':'broker.example.invalid','port':1883}}
    consumer['resolved_connections']={'broker':{'account':copy.deepcopy(value),'source_address':'198.18.41.2'}}
    return resolver,selected


class AccountBindingUnits(unittest.TestCase):
    def setUp(self):
        self.filename=self.enterContext(patch.object(accounts.managed_credentials,'input_name',
            side_effect=lambda name:'managed-'+name+'.json'))
        self.owner=self.enterContext(patch.object(accounts.database_admin,'owner',
            side_effect=lambda value:copy.deepcopy(value)))
        self.connections=self.enterContext(patch.object(accounts.database_admin,'connections',return_value={}))

    def expected_owner(self,engine='postgresql'):
        return {'node':'fixture-node','engine':engine,'database_vmid':809,'source_vmid':808,
            'server_address':'198.18.31.23','source_address':'198.18.31.32','username':'console_admin',
            'purpose':'database-administration'}

    def test_empty_selection_does_not_resolve_endpoints_or_generate_owners(self):
        resolver=SimpleNamespace(apps={})
        self.assertEqual(accounts.bind(resolver,{}),{})
        self.owner.assert_not_called();self.filename.assert_not_called();self.connections.assert_not_called()

    def test_postgresql_and_mariadb_dispatch_exact_canonical_owner_to_the_validator(self):
        for engine in ('postgresql','mariadb'):
            resolver,selected=database_fixture(engine);before=copy.deepcopy(selected)
            self.owner.reset_mock();self.filename.reset_mock();self.connections.reset_mock()
            result=accounts.bind(resolver,selected)
            self.owner.assert_called_once_with(self.expected_owner(engine))
            self.filename.assert_called_once_with('console-database')
            self.connections.assert_called_once_with(resolver.apps['console']['settings'])
            self.assertEqual(result['database_account']['canonical_owner'],self.expected_owner(engine))
            self.assertEqual(result['database_account']['input_filename'],'managed-console-database.json')
            self.assertEqual(selected,before)
            resolver.endpoint.assert_not_called();resolver.role_address.assert_not_called()

    def test_database_writer_and_client_slots_have_independent_app_namespaces_and_same_owner(self):
        resolver,selected=database_fixture();accounts.bind(resolver,selected)
        writer=resolver.apps['database']['database_administrators']['database_account']
        client=resolver.apps['console']['settings']['managed_connections']['administrator']
        self.assertEqual(writer,{'username':'console_admin','source_guest':'console_guest',
            'credential_id':'console-database','credential_file':'${inputs}/applications/database/managed-console-database.json',
            'access':'server-administration','transport':'tls','owner':self.expected_owner()})
        self.assertEqual(client['credential_file'],'${inputs}/applications/console/managed-console-database.json')
        self.assertEqual(client['account_id'],'database_account');self.assertEqual(client['transport'],'tls')
        self.assertEqual(client['owner'],writer['owner']);self.assertNotIn('account',client)
        self.assertEqual((client['name'],client['driver'],client['database']),('Database administrator','postgresql','postgres'))
        self.assertEqual((client['host'],client['port']),('198.18.31.23',5432))

    def test_metadata_and_unselected_resolved_connections_are_unchanged(self):
        resolver,selected=database_fixture();consumer=resolver.apps['console']
        consumer['resolved_connections']['metadata']={'target':{'address':'198.18.31.23'},'source_address':'198.18.31.32'}
        consumer['resolved_connections']['unrelated']={'account':{'owner':'other'},'source_address':'198.18.31.99'}
        before=copy.deepcopy(consumer['resolved_connections']);metadata=copy.deepcopy(consumer['settings']['connections'])
        accounts.bind(resolver,selected)
        self.assertEqual(consumer['resolved_connections'],before)
        self.assertEqual(consumer['settings']['connections'],metadata)

    def test_multiple_matching_roles_share_one_canonical_owner_without_revalidating_components(self):
        resolver,selected=database_fixture();consumer=resolver.apps['console']
        consumer['resolved_connections']['same_owner_alias']=copy.deepcopy(consumer['resolved_connections']['administrator'])
        consumer['settings']['managed_connections']['same_owner_alias']=copy.deepcopy(consumer['settings']['managed_connections']['administrator'])
        result=accounts.bind(resolver,selected)
        self.owner.assert_called_once();self.filename.assert_called_once()
        rows=consumer['settings']['managed_connections']
        self.assertEqual(rows['administrator']['owner'],rows['same_owner_alias']['owner'])
        self.assertEqual(rows['administrator']['credential_file'],rows['same_owner_alias']['credential_file'])
        rows['same_owner_alias']['owner']['username']='mutated'
        self.assertEqual(rows['administrator']['owner'],self.expected_owner())
        self.assertEqual(result['database_account']['canonical_owner'],self.expected_owner())

    def test_alias_spelling_does_not_replace_the_resolved_canonical_owner(self):
        owners=[]
        for endpoint in ('sql','sql_alias'):
            resolver,selected=database_fixture();value=selected['database_account'];value['target']['endpoint']=endpoint
            consumer=resolver.apps['console']
            consumer['resolved_connections']['administrator']['account']=copy.deepcopy(value)
            consumer['settings']['managed_connections']['administrator']['account']=copy.deepcopy(value)
            result=accounts.bind(resolver,selected);owners.append(result['database_account']['canonical_owner'])
        self.assertEqual(owners,[self.expected_owner(),self.expected_owner()])

    def test_same_display_name_or_address_on_another_server_cannot_reuse_canonical_owner(self):
        resolver,selected=database_fixture();one=accounts.bind(resolver,selected)['database_account']['canonical_owner']
        resolver,selected=database_fixture();resolver.guests['database_guest']['identity']['vmid']=810
        two=accounts.bind(resolver,selected)['database_account']['canonical_owner']
        self.assertNotEqual(one,two);self.assertEqual(one['database_vmid'],809);self.assertEqual(two['database_vmid'],810)

    def test_selected_app_key_renaming_does_not_change_guest_based_owner_but_rebinds_only_slots(self):
        resolver,selected=database_fixture();value=selected['database_account']
        resolver.apps['renamed_database']=resolver.apps.pop('database');resolver.apps['renamed_database']['id']='renamed_database'
        value['target_endpoint']['app']='renamed_database';value['target']['app']='renamed_database'
        resolver.apps['console']['resolved_connections']['administrator']['account']=copy.deepcopy(value)
        resolver.apps['console']['settings']['managed_connections']['administrator']['account']=copy.deepcopy(value)
        result=accounts.bind(resolver,selected)
        self.assertEqual(result['database_account']['canonical_owner'],self.expected_owner())
        self.assertEqual(resolver.apps['renamed_database']['database_administrators']['database_account']['credential_file'],
            '${inputs}/applications/renamed_database/managed-console-database.json')

    def test_returned_values_and_each_owner_copy_do_not_alias_source_or_producer(self):
        resolver,selected=database_fixture();before=copy.deepcopy(selected)
        result=accounts.bind(resolver,selected);value=result['database_account']
        value['target']['endpoint']='changed';value['target_endpoint']['address']='198.18.31.99'
        value['canonical_owner']['username']='changed'
        writer=resolver.apps['database']['database_administrators']['database_account'];writer['owner']['node']='changed'
        self.assertEqual(selected,before)
        self.assertEqual(resolver.apps['console']['settings']['managed_connections']['administrator']['owner'],self.expected_owner())

    def test_unknown_and_missing_normalized_component_references_are_redacted(self):
        mutations=[lambda r,v:v['database_account'].update(owner='missing'),
            lambda r,v:v['database_account']['target_endpoint'].update(app='missing'),
            lambda r,v:r.apps['console'].update(guest='missing'),
            lambda r,v:r.apps['database'].update(guest='missing'),
            lambda r,v:r.site['contexts'].pop('selected'),lambda r,v:r.site['contexts']['selected'].pop('node')]
        for index,mutate in enumerate(mutations):
            resolver,selected=database_fixture();mutate(resolver,selected)
            with self.subTest(case=index),self.assertRaises(ComponentError) as caught:accounts.bind(resolver,selected)
            self.assertEqual(caught.exception.code,'component.type')
            self.assertEqual(caught.exception.path,('accounts','database_account'))

    def test_missing_and_wrong_typed_required_normalized_fields_are_safe_refusals(self):
        mutations=[lambda r,v:v['database_account'].pop('owner'),
            lambda r,v:v['database_account'].pop('target_endpoint'),
            lambda r,v:v['database_account'].pop('credential_id'),
            lambda r,v:v['database_account'].pop('principal'),
            lambda r,v:v['database_account'].update(target_endpoint=None),
            lambda r,v:v['database_account'].update(owner=[]),
            lambda r,v:v.update(database_account=None)]
        for index,mutate in enumerate(mutations):
            resolver,selected=database_fixture();mutate(resolver,selected)
            with self.subTest(case=index),self.assertRaises(ComponentError) as caught:accounts.bind(resolver,selected)
            self.assertEqual(caught.exception.path,('accounts','database_account'))

    def test_context_placement_mismatch_refuses_before_credential_or_owner_binding(self):
        resolver,selected=database_fixture();resolver.guests['database_guest']['context']='another'
        with self.assertRaisesRegex(ComponentError,'account-placement-unsupported'):accounts.bind(resolver,selected)
        self.filename.assert_not_called();self.owner.assert_not_called()

    def test_no_match_nonaccount_or_foreign_normalized_selection_refuses(self):
        for variant in ('absent','scalar','foreign_owner','foreign_target','foreign_principal','foreign_credential'):
            resolver,selected=database_fixture();connection=resolver.apps['console']['resolved_connections']['administrator']
            if variant=='absent':connection.pop('account')
            elif variant=='scalar':connection['account']='not-a-normalized-account'
            elif variant=='foreign_target':connection['account']['target_endpoint']['app']='foreign'
            else:connection['account'][{'foreign_owner':'owner','foreign_principal':'principal','foreign_credential':'credential_id'}[variant]]='foreign'
            with self.subTest(variant=variant),self.assertRaisesRegex(ComponentError,'account-binding'):accounts.bind(resolver,selected)
        self.filename.assert_not_called();self.owner.assert_not_called()

    def test_one_account_cannot_bind_connections_with_distinct_source_addresses(self):
        resolver,selected=database_fixture();consumer=resolver.apps['console']
        consumer['resolved_connections']['other']=copy.deepcopy(consumer['resolved_connections']['administrator'])
        consumer['resolved_connections']['other']['source_address']='198.18.31.33'
        with self.assertRaisesRegex(ComponentError,'account-binding'):accounts.bind(resolver,selected)
        self.owner.assert_not_called()

    def test_missing_or_unhashable_selected_source_refuses(self):
        for change in ('missing','list'):
            resolver,selected=database_fixture();connection=resolver.apps['console']['resolved_connections']['administrator']
            if change=='missing':connection.pop('source_address')
            else:connection['source_address']=[]
            with self.subTest(change=change),self.assertRaises(ComponentError) as caught:accounts.bind(resolver,selected)
            self.assertEqual(caught.exception.code,'component.type')

    def test_database_account_cannot_bind_noncloud_consumer(self):
        for adapter in ('mqtt_explorer','node_red','unknown'):
            resolver,selected=database_fixture();resolver.apps['console']['adapter']=adapter
            with self.subTest(adapter=adapter),self.assertRaisesRegex(ComponentError,'account-binding'):accounts.bind(resolver,selected)
        self.owner.assert_not_called()

    def test_selected_managed_role_is_required_and_its_account_must_match(self):
        for variant in ('missing-role','missing-account','foreign-account','wrong-collection'):
            resolver,selected=database_fixture();managed=resolver.apps['console']['settings']['managed_connections']
            if variant=='missing-role':managed.clear()
            elif variant=='missing-account':managed['administrator'].pop('account')
            elif variant=='foreign-account':managed['administrator']['account']={'owner':'foreign'}
            else:resolver.apps['console']['settings']['managed_connections']=None
            with self.subTest(variant=variant),self.assertRaises(ComponentError):accounts.bind(resolver,selected)

    def test_owner_credential_and_final_connection_validation_are_delegated_without_raw_values(self):
        for target,code in ((self.owner,'component.account-owner'),(self.filename,'component.account-credential'),
                            (self.connections,'component.account-binding')):
            resolver,selected=database_fixture();target.side_effect=ComponentError(code)
            with self.subTest(code=code),self.assertRaises(ComponentError) as caught:accounts.bind(resolver,selected)
            self.assertEqual(caught.exception.code,code)
            self.assertNotIn('198.18.',str(caught.exception));self.assertNotIn('console_admin',str(caught.exception))
            target.side_effect=(lambda value:copy.deepcopy(value)) if target is self.owner else \
                (lambda name:'managed-'+name+'.json') if target is self.filename else None

    def test_mqtt_same_guest_account_uses_current_hostname_owner_and_only_explorer_slot(self):
        resolver,selected=mqtt_fixture();before=copy.deepcopy(selected)
        result=accounts.bind(resolver,selected);owner={'node':'fixture-node','vmid':808,'hostname':'console',
            'purpose':'mqtt-explorer','username':'explorer_client'}
        self.assertEqual(result['database_account']['canonical_owner'],owner)
        self.assertEqual(resolver.apps['console']['settings']['broker']['managed_credential'],{
            'credential_id':'explorer-broker','owner':owner,
            'credential_file':'${inputs}/applications/console/managed-explorer-broker.json'})
        self.assertNotIn('database_administrators',resolver.apps['database'])
        self.owner.assert_not_called();self.connections.assert_not_called()
        self.assertEqual(selected,before)

    def test_mqtt_account_refuses_other_guest_adapter_or_consumer_without_fallback(self):
        mutations=[lambda r:r.apps['database'].update(guest='database_guest'),
            lambda r:r.apps['database'].update(adapter='influxdb'),
            lambda r:r.apps['database'].update(adapter='unknown'),
            lambda r:r.apps['console'].update(adapter='cloudbeaver')]
        for index,mutate in enumerate(mutations):
            resolver,selected=mqtt_fixture();mutate(resolver)
            with self.subTest(case=index),self.assertRaisesRegex(ComponentError,'account-placement-unsupported'):accounts.bind(resolver,selected)
            self.assertNotIn('managed_credential',resolver.apps['console']['settings']['broker'])

    def test_no_private_material_or_password_field_is_produced(self):
        for factory in (database_fixture,mqtt_fixture):
            resolver,selected=factory();result=accounts.bind(resolver,selected)
            def keys(value):
                if isinstance(value,dict):
                    return set(value)|set().union(*(keys(item) for item in value.values()))
                if isinstance(value,list):return set().union(*(keys(item) for item in value))
                return set()
            self.assertTrue(keys(result).isdisjoint({'password','secret','content','material','environment','token'}))
            self.assertNotIn('read-write-all',json.dumps(result['database_account']['canonical_owner']))


if __name__=='__main__':unittest.main()
