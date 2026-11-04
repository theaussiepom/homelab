"""Finite R2 gaps at their real direct component boundaries; no whole plans."""
from contextlib import ExitStack
import copy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'proxmox/applications'))
import component_types as types
import component_connections as connections
import component_secrets as secrets
import component_monitoring as monitoring
import component_identity
import component_foundations
import component_properties
from component_errors import ComponentError
import test_component_monitoring as monitoring_cases


def app():
    return {'profile':'recursive','guest':'worker','lifecycle':'fresh',
        'interfaces':{'service':{'interface':'control'}}}


def profile(adapter='traefik'):
    return {'adapter':adapter,'display_name':'Synthetic app','interfaces':{},'properties':{}}


class TypeOptionalEdges(unittest.TestCase):
    def app_guards(self):
        stack=ExitStack();collaborators={}
        for name in ('role','admission','allocation'):
            collaborators[name]=stack.enter_context(patch.object(types,name))
        collaborators['directory']=stack.enter_context(patch.object(component_identity,'directory'))
        return stack,collaborators

    def profile_guards(self):
        stack=ExitStack();collaborators={}
        collaborators['adapter']=stack.enter_context(patch.object(types,'adapter',return_value={'services':(),'native':()}))
        collaborators['requirements']=stack.enter_context(patch.object(secrets,'requirements'))
        collaborators['foundation']=stack.enter_context(patch.object(component_foundations,'validate'))
        collaborators['properties']=stack.enter_context(patch.object(component_properties,'validate'))
        collaborators['monitoring']=stack.enter_context(patch.object(monitoring,'reference'))
        collaborators['health']=stack.enter_context(patch.object(types,'health'))
        return stack,collaborators

    def test_app_optional_identity_assets_allocations_secret_and_device_refs_are_forwarded_without_io(self):
        value=app();value.update(identity={'phase':'owned','runtime_id':'owned','project':'owned',
            'services':{'unbound':'owned-service'},'networks':{'private':'owned-key'},
            'runtime_directory':'/opt/homelab-app/runtime/owned','custody_directory':'/var/lib/owned-app'},
            storage={'config':{'asset':'packaged_config'},'root':{'root_path':'owned','subpath':'relative/sub'},
                     'data':{'volume':'data','subpath':''}},resources={'containers':{'unbound':{'memory_mib':128}}},
            secrets={'probe':'existing_input'},devices={'coordinator':'registered_device'})
        before=copy.deepcopy(value);stack,mocks=self.app_guards()
        with stack:types.app(value)
        mocks['directory'].assert_called_once_with('/opt/homelab-app/runtime/owned')
        mocks['allocation'].assert_called_once_with({'memory_mib':128})
        self.assertEqual(value,before)

    def test_app_optional_metadata_unknowns_types_and_reference_shapes_refuse(self):
        mutations=[lambda v:v.update(identity={'custody_directory':None}),
            lambda v:v.update(storage={'config':{'asset':'bad!PRIVATE_SENTINEL'}}),
            lambda v:v.update(storage={'config':{'asset':'config','path':'PRIVATE_SENTINEL'}}),
            lambda v:v.update(resources={'containers':{}}),
            lambda v:v.update(resources={'containers':{'service':{}},'extra':'PRIVATE_SENTINEL'}),
            lambda v:v.update(secrets={'probe':'bad!PRIVATE_SENTINEL'}),
            lambda v:v.update(devices={'coordinator':'../PRIVATE_SENTINEL'})]
        for index,mutate in enumerate(mutations):
            value=app();mutate(value);stack,_=self.app_guards()
            with self.subTest(case=index),stack,self.assertRaises(ComponentError) as caught:types.app(value)
            self.assertNotIn('PRIVATE_SENTINEL',str(caught.exception))

    def test_app_runtime_namespace_collaborator_refusal_is_not_replaced_with_a_fallback(self):
        value=app();value['identity']={'runtime_directory':'/opt/homelab-app/runtime/owned'}
        stack,mocks=self.app_guards();mocks['directory'].side_effect=ComponentError('component.runtime-directory')
        with stack,self.assertRaisesRegex(ComponentError,'runtime-directory'):types.app(value)

    def test_profile_internal_dashboard_monitoring_and_health_requirement_dispatch_are_closed(self):
        value=profile();value.update(endpoints={'dashboard':{'internal':'dashboard'}},
            monitoring={'profile':'linux'},health={'ready':{'profile':'ready'},'adapter':{'type':'adapter','check':'readiness'}})
        stack,mocks=self.profile_guards()
        with stack:types.profile(value)
        mocks['foundation'].assert_called_once_with('traefik',{},partial=True)
        mocks['properties'].assert_not_called();mocks['monitoring'].assert_called_once_with({'profile':'linux'})
        mocks['health'].assert_called_once_with({'type':'adapter','check':'readiness'})

    def test_profile_dashboard_and_health_reference_unknowns_do_not_become_ports_or_argv(self):
        mutations=[lambda v:v.update(adapter='unbound',endpoints={'dashboard':{'internal':'dashboard'}}),
            lambda v:v.update(endpoints={'dashboard':{'internal':'foreign'}}),
            lambda v:v.update(endpoints={'dashboard':{'internal':'dashboard','port':80}}),
            lambda v:v.update(health={'ready':{'profile':'bad!PRIVATE_SENTINEL'}}),
            lambda v:v.update(health={'ready':{'profile':'ready','source_interface':'missing'}}),
            lambda v:v.update(health={'ready':{'profile':'ready','argv':['PRIVATE_SENTINEL']}})]
        for index,mutate in enumerate(mutations):
            value=profile();mutate(value);stack,_=self.profile_guards()
            with self.subTest(case=index),stack,self.assertRaises(ComponentError) as caught:types.profile(value)
            self.assertNotIn('PRIVATE_SENTINEL',str(caught.exception))

    def test_nonfoundation_profile_uses_only_its_selected_property_validator(self):
        value=profile('node_red');stack,mocks=self.profile_guards()
        with stack:types.profile(value)
        mocks['properties'].assert_called_once_with('node_red',{},partial=True);mocks['foundation'].assert_not_called()
        stack,mocks=self.profile_guards();mocks['properties'].side_effect=ComponentError('component.property')
        with stack,self.assertRaisesRegex(ComponentError,'component.property'):types.profile(value)

    def test_network_policy_explicit_null_and_omitted_ports_keep_distinct_literal_intent(self):
        value={'rules':[{'direction':'out','proto':'tcp','comment':'explicit all ports','port':None},
            {'direction':'in','proto':'icmp','comment':'no port field'},
            {'direction':'out','proto':'udp','comment':'named listener','port':{'endpoint':'dns'}}]}
        before=copy.deepcopy(value);types.network_policy(value);self.assertEqual(value,before)
        self.assertIsNone(value['rules'][0]['port']);self.assertNotIn('port',value['rules'][1])
        for port in (False,[],{'endpoint':'bad!PRIVATE_SENTINEL'},{'endpoint':'dns','raw':'PRIVATE_SENTINEL'}):
            bad=copy.deepcopy(value);bad['rules'][0]['port']=port
            with self.subTest(kind=type(port).__name__),self.assertRaises(ComponentError):types.network_policy(bad)


def connection_fixture(*, managed=False, loopback=False):
    kind='dns' if loopback else 'mqtt';role='resolver' if loopback else 'broker'
    target={'app':'producer','endpoint':'service'} if managed or loopback else {'external':'broker'}
    owner={'id':'reader','guest':'reader_guest','adapter':'node_red','profile':'client',
           'interfaces':{role:{'scope':'guest-loopback'} if loopback else {'interface':'service'}}}
    site={'accounts':{},'secret_sources':{'existing':{'type':'environment','name':'EXISTING_BROKER_PASSWORD'}},
        'connections':{'selected':{'consumer':{'app':'reader','connection':role},'target':target,'source_interface':role}}}
    apps={'reader':owner};guests={'reader_guest':{}}
    endpoint={'protocol':'udp' if loopback else 'tcp','port':5335 if loopback else 1883,
              'address':'127.0.0.1' if loopback else '198.18.41.2'}
    if managed or loopback:
        apps['producer']={'id':'producer','guest':'reader_guest' if loopback else 'producer_guest',
                          'adapter':'unbound' if loopback else 'mqtt','profile':'server','interfaces':{}}
        guests[apps['producer']['guest']]={}
        endpoint.update(app='producer',guest=apps['producer']['guest'])
    resolver=SimpleNamespace(apps=apps,guests=guests,site=site,
        library={'app_profiles':{'client':{'connections':{role:{'type':kind,'required':True}}},'server':{}}},
        policy={'transport':{'selected':{}}},endpoint=Mock(side_effect=lambda ref:copy.deepcopy(endpoint)),
        role_address=Mock(return_value='127.0.0.1' if loopback else '198.18.41.8'))
    exposures=SimpleNamespace(hostname=Mock(return_value='broker.example.invalid'))
    return resolver,exposures,endpoint


class ConnectionOptionalEdges(unittest.TestCase):
    def test_external_file_and_environment_credentials_transport_and_saved_hostname_are_only_refs(self):
        for source in ({'type':'environment','name':'EXISTING_BROKER_PASSWORD'},
                       {'type':'file','path':'/selected/never-opened-credential'}):
            r,e,_=connection_fixture();r.site['secret_sources']['existing']=source
            row=r.site['connections']['selected'];row.update(credential={'principal':'existing_client','secret':'existing'},
                transport='selected',hostname={'domain':'saved_broker'})
            before=copy.deepcopy(r.site);result=connections.bind(r,e)
            selected=r.apps['reader']['resolved_connections']['broker']
            self.assertEqual(selected['credential'],{'principal':'existing_client','secret':'existing'})
            self.assertEqual(selected['hostname'],'broker.example.invalid');self.assertEqual(selected['transport'],'selected')
            self.assertEqual(result['guest_dependencies'],{'reader_guest':[]});self.assertEqual(result['accounts'],{})
            e.hostname.assert_called_once_with({'domain':'saved_broker'},selected['target'])
            self.assertEqual(r.site,before)

    def test_external_credential_unknown_type_reference_principal_and_account_conflicts_refuse(self):
        changes=[lambda r,v:v.update(credential={'principal':'client','secret':'missing'}),
            lambda r,v:r.site['secret_sources'].update(existing={'type':'generated','credential_id':'existing-account'}),
            lambda r,v:v.update(credential={'principal':'','secret':'existing'}),
            lambda r,v:v.update(credential={'principal':None,'secret':'existing'}),
            lambda r,v:v.update(credential={'principal':'client','secret':'existing','value':'PRIVATE_SENTINEL'}),
            lambda r,v:v.update(account='missing'),lambda r,v:v.update(transport='missing')]
        for index,change in enumerate(changes):
            r,e,_=connection_fixture();value=r.site['connections']['selected']
            value['credential']={'principal':'client','secret':'existing'};change(r,value)
            with self.subTest(case=index),self.assertRaises(ComponentError) as caught:connections.bind(r,e)
            self.assertEqual(caught.exception.path,('connections','selected'))
            self.assertNotIn('PRIVATE_SENTINEL',str(caught.exception))

    def test_same_guest_managed_mqtt_explicit_existing_credential_is_supported_without_account_creation(self):
        r,e,target=connection_fixture(managed=True);r.apps['producer']['guest']='reader_guest';target['guest']='reader_guest'
        r.guests.pop('producer_guest')
        r.library['app_profiles']['client']['connections']['broker']['readiness']=['start']
        r.site['connections']['selected']['readiness']='start'
        r.site['connections']['selected']['credential']={'principal':'client','secret':'existing'}
        result=connections.bind(r,e)
        self.assertEqual(result['accounts'],{});self.assertEqual(r.apps['reader']['resolved_connections']['broker']['credential']['secret'],'existing')
        self.assertEqual(result['app_dependencies'],{'reader':['producer'],'producer':[]})
        self.assertEqual(result['guest_dependencies'],{'reader_guest':[]})

    def test_managed_loopback_requires_exact_guest_loopback_source_and_never_adds_a_wait(self):
        r,e,target=connection_fixture(loopback=True);result=connections.bind(r,e)
        self.assertEqual(r.apps['reader']['resolved_connections']['resolver']['source_address'],'127.0.0.1')
        self.assertEqual(result['app_dependencies'],{'reader':[],'producer':[]})
        for change in ('foreign-guest','source-scope','other-loopback'):
            r,e,target=connection_fixture(loopback=True)
            if change=='foreign-guest':target['guest']='foreign'
            elif change=='source-scope':r.apps['reader']['interfaces']['resolver']={'scope':'app-network','network':'private'}
            else:target['address']='127.0.0.2'
            with self.subTest(case=change),self.assertRaises(ComponentError):connections.bind(r,e)

    def test_invalid_managed_endpoint_projection_is_a_defensive_scope_refusal_not_a_capability(self):
        r,e,target=connection_fixture(managed=True);target['address']='not-an-ip'
        with self.assertRaisesRegex(ComponentError,'connection-target-scope'):connections.bind(r,e)
        # A well-formed resolved target is the actual collaborator contract.
        r,e,target=connection_fixture(managed=True);target['address']='198.18.41.2'
        connections.bind(r,e)

    def test_hostname_resolution_refusal_is_propagated_without_echoing_reference_values(self):
        r,e,_=connection_fixture();r.site['connections']['selected']['hostname']={'domain':'declared'}
        e.hostname.side_effect=ComponentError('component.reference')
        with self.assertRaises(ComponentError) as caught:connections.bind(r,e)
        self.assertEqual(str(caught.exception),'component.reference at connections.selected')


class SecretActionOptionalEdges(unittest.TestCase):
    def resolver(self):
        return SimpleNamespace(apps={'explorer':{'adapter':'mqtt_explorer','settings':{'broker':{}}}},
            site={'secret_sources':{'existing':{'type':'environment','name':'BROKER_PASSWORD','workflow_secret':'EXISTING_BROKER_KEY'}}})

    def test_external_explorer_auth_forwards_its_single_named_scalar_slot_only(self):
        r=self.resolver();r.apps['explorer']['settings']['broker']['credential']={'principal':'client','secret':'existing'}
        self.assertEqual(secrets.action_inputs(r,'explorer'),{'mqtt_explorer_broker_password':{
            'environment':'BROKER_PASSWORD','workflow_secret':'EXISTING_BROKER_KEY'}})
        r.site['secret_sources']['existing']={'type':'file','path':'/selected/never-opened-credential'}
        self.assertEqual(secrets.action_inputs(r,'explorer'),{})

    def test_managed_or_unselected_explorer_and_missing_cloud_auth_emit_no_scalar(self):
        r=self.resolver();self.assertEqual(secrets.action_inputs(r,'explorer'),{})
        r.apps['explorer']['settings']['broker']['managed_credential']={'credential_id':'declared-account'}
        self.assertEqual(secrets.action_inputs(r,'explorer'),{})
        r.apps['cloud']={'adapter':'cloudbeaver'};self.assertEqual(secrets.action_inputs(r,'cloud'),{})

    def test_selected_explorer_source_validation_refusal_is_owned_by_the_source_component(self):
        r=self.resolver();r.apps['explorer']['settings']['broker']['credential']={'principal':'client','secret':'existing'}
        with patch.object(secrets,'source',side_effect=ComponentError('component.secret-source')) as validator:
            with self.assertRaisesRegex(ComponentError,'secret-source'):secrets.action_inputs(r,'explorer')
        validator.assert_called_once_with(r.site['secret_sources']['existing'])


class MonitoringOptionalEdges(unittest.TestCase):
    def test_source_selection_skips_manual_interfaces_and_preserves_connected_or_default_choice(self):
        guest={'provider_interfaces':[{'ipv4':'manual'},{'ipv4':'198.18.25.8/24','gateway':'198.18.25.1'},
                                      {'ipv4':'198.18.31.8/24'}]}
        before=copy.deepcopy(guest)
        self.assertEqual(monitoring.source_address(guest,'198.18.31.23'),'198.18.31.8')
        self.assertEqual(monitoring.source_address(guest,'203.0.113.20'),'198.18.25.8')
        self.assertEqual(guest,before)
        with self.assertRaisesRegex(ComponentError,'network-source'):monitoring.source_address({'provider_interfaces':[{'ipv4':'manual'}]},'198.18.31.23')

    def test_no_origin_or_metrics_selection_adds_neither_web_edge_nor_unselected_metrics_fields(self):
        r,e=monitoring_cases.fixture();r.apps['zabbix'].pop('origin')
        r.apps['zabbix']['resolved_connections'].pop('metrics')
        r.library['app_profiles']['influxdb'].pop('monitoring')
        monitoring.bind(r,e)
        self.assertEqual(r.guests['ingress']['rules'],[monitoring.rule('out','198.18.20.13','198.18.20.10',10051)])
        self.assertNotIn('influxdb_address',r.guests['server']['monitoring'])
        self.assertEqual(r.guests['metrics']['monitoring']['profiles'],['linux'])
        self.assertFalse(any(rule['port']=='8086' for guest in r.guests.values() for rule in guest['rules']))

    def test_separately_selected_profiles_deduplicate_workloads_in_declared_order(self):
        r,e=monitoring_cases.fixture();r.library['monitoring_profiles']['postgresql']['profiles']=['linux','postgresql']
        monitoring.bind(r,e)
        self.assertEqual(r.guests['database']['monitoring']['profiles'],['linux','postgresql'])


if __name__=='__main__':unittest.main()
