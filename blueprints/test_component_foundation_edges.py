"""Direct finite foundation capability units, separate from full plan tests."""
import copy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'proxmox/applications'))
import component_foundations as foundation
import component_monitoring
from component_errors import ComponentError
import test_component_foundations as original


def callback():
    return {'provider_id':1,'application_id':'22222222-2222-4222-8222-222222222222',
        **{key:'a'*64 for key in ('client_id_sha256','provider_metadata_sha256',
                                 'application_metadata_sha256','policy_metadata_sha256')},
        'existing_redirects':[{'matching_mode':'strict','url':'https://prior.example.invalid/old'}],
        'additions':['https://web.example.invalid/oauth2/callback']}


class FoundationValidatorEdges(unittest.TestCase):
    def test_direct_line_database_digest_and_physical_success_and_refusal_boundaries(self):
        self.assertEqual(foundation._line('metadata'), 'metadata')
        self.assertEqual(foundation._line('',empty=True), '')
        self.assertEqual(foundation._sql('owned_database'), 'owned_database')
        foundation._digest('a'*64);foundation.physical({'app':'owned','interface':'database_interface'})
        cases=[(foundation._line,value) for value in (None,False,'','x'*4097,'a\r','a\n','a\0')]
        cases += [(foundation._sql,value) for value in (None,'template0','template1','Upper','a-b','x'*64)]
        cases += [(foundation._digest,value) for value in (None,64,'A'*64,'a'*63)]
        cases += [(foundation.physical,value) for value in ({'app':'a'}, {'app':'a','interface':'x_interface','extra':True},
                     {'app':False,'interface':'x_interface'},{'app':'../escape','interface':'x_interface'})]
        for index,(check,value) in enumerate(cases):
            with self.subTest(case=index),self.assertRaises(ComponentError):check(value)

    def test_finite_scalar_types_bounds_and_partial_requirements_do_not_become_property_bags(self):
        for adapter in ('mqtt_explorer','authentik','zabbix','zigbee2mqtt'):
            foundation.validate(adapter,{},partial=True)
            with self.subTest(adapter=adapter),self.assertRaises(ComponentError):foundation.validate(adapter,{})
        cases=[('mqtt',{'password_file':value}) for value in (None,False,'/mosquitto/config/.','/mosquitto/config/','/mosquitto/config/'+'a'*101)]
        cases += [('mqtt_explorer',{'connection_name':value}) for value in (None,False,'a'*101)]
        cases += [('postgresql',{'client_access':value}) for value in ({},None,[{}]*129)]
        cases += [('zigbee2mqtt',{'adapter':'ember','mqtt_base_topic':value}) for value in (None,False,'','a'*129,'/prefix')]
        cases += [('zigbee2mqtt',{'adapter':value,'mqtt_base_topic':'owned/topic'}) for value in (None,True,'Upper')]
        for index,(adapter,value) in enumerate(cases):
            with self.subTest(case=index),self.assertRaises(ComponentError):foundation.validate(adapter,value)
        foundation.validate('mqtt',{'password_file':'/mosquitto/config/owned_passwords'})
        foundation.validate('zigbee2mqtt',{'adapter':'ember','mqtt_base_topic':'owned/topic_2'})
        for adapter in ('music_assistant','mariadb','influxdb','pihole'):
            foundation.validate(adapter,{})
            with self.subTest(adapter=adapter),self.assertRaises(ComponentError):foundation.validate(adapter,{'command':'foreign'})

    def test_callback_evidence_returns_exact_deep_copied_records_without_reformatting(self):
        value=callback();value['existing_redirects'].append({'matching_mode':'strict','url':'https://old.example.invalid:8443/other'})
        selected=foundation._callback_records([value]);self.assertEqual(selected,[value])
        selected[0]['existing_redirects'][0]['url']='changed'
        self.assertEqual(value['existing_redirects'][0]['url'],'https://prior.example.invalid/old')

    def test_optional_timeouts_and_discovery_omission_do_not_insert_values_or_scope(self):
        identity=copy.deepcopy(original.props()['authentik']);identity['smtp'].pop('timeout')
        ingress=copy.deepcopy(original.props()['traefik']);ingress['provider'].pop('discovery')
        ingress['acme'].pop('propagation_timeout_seconds')
        before=copy.deepcopy((identity,ingress))
        foundation.validate('authentik',identity);foundation.validate('traefik',ingress)
        self.assertEqual((identity,ingress),before)
        self.assertNotIn('timeout',identity['smtp']);self.assertNotIn('discovery',ingress['provider'])
        self.assertNotIn('propagation_timeout_seconds',ingress['acme'])

    def test_callback_collection_and_provider_uuid_digest_fields_are_closed(self):
        for values in (None,{},[],[callback()]*9,[callback(),callback()]):
            with self.subTest(kind=type(values).__name__),self.assertRaises(ComponentError):foundation._callback_records(values)
        mutations=[lambda r:r.update(unknown=True),lambda r:r.pop('provider_id'),lambda r:r.update(provider_id=True),
            lambda r:r.update(provider_id=0),lambda r:r.update(application_id=None),
            lambda r:r.update(application_id='not-a-uuid'),lambda r:r.update(application_id='22222222222242228222222222222222')]
        for field in ('client_id_sha256','provider_metadata_sha256','application_metadata_sha256','policy_metadata_sha256'):
            mutations.append(lambda r,field=field:r.update({field:'not-a-digest'}))
        for index,mutate in enumerate(mutations):
            row=callback();mutate(row)
            with self.subTest(case=index),self.assertRaises(ComponentError):foundation._callback_records([row])

    def test_callback_redirect_bounds_modes_duplicates_and_exact_https_uri_floor(self):
        mutations=[lambda r:r.update(existing_redirects=[]),lambda r:r.update(existing_redirects=[{}]*21),
            lambda r:r.update(additions=[]),lambda r:r.update(additions=['x']*5),
            lambda r:r['existing_redirects'][0].update(matching_mode='regex'),
            lambda r:r['existing_redirects'][0].update(extra='foreign'),
            lambda r:r.update(additions=[r['existing_redirects'][0]['url']])]
        for index,mutate in enumerate(mutations):
            row=callback();mutate(row)
            with self.subTest(case=index),self.assertRaises(ComponentError):foundation._callback_records([row])
        urls=(None,'','x'*2049,'https://web.example.invalid/oauth2/callback\n','http://web.example.invalid/oauth2/callback',
              'https:///oauth2/callback','https://user@web.example.invalid/oauth2/callback',
              'https://user:password@web.example.invalid/oauth2/callback','https://web.example.invalid/oauth2/callback?x=1',
              'https://web.example.invalid/oauth2/callback#x','https://web.example.invalid/oauth2/callback?',
              'https://web.example.invalid/oauth2/callback#','https://web.example.invalid/other',
              'https://web.example.invalid/oauth2/call\\back','https://web.example.invalid:bad/oauth2/callback',
              'https://web.example.invalid:0/oauth2/callback','https://web.example.invalid:65536/oauth2/callback')
        for index,url in enumerate(urls):
            row=callback();row['additions']=[url]
            with self.subTest(uri_case=index),self.assertRaises(ComponentError):foundation._callback_records([row])


def fixture(adapter):
    resolver=original.FoundationBindingTests().fixture(adapter)
    app=resolver.apps['application'];app['lifecycle']='retained'
    resolver.policy={'tls':{'public':{'resolver':'letsencrypt'}}}
    resolver.exposure_values={'routes':{},'dns_records':{}}
    resolver.authentication_values={'transports':{}}
    resolver.endpoint=Mock(side_effect=lambda ref: {
        'api':{'address':'198.18.20.2','protocol':'https','port':8006},
        'dns':{'address':'198.18.20.53','protocol':'udp','port':53},
        'dns_other':{'address':'198.18.20.54','protocol':'tcp','port':53}}[ref['external']])
    resolver.role_address=Mock(return_value='198.18.21.10')
    return resolver,app


def database(app):
    app['resolved_connections']['database']={'type':'postgresql','target':{'address':'198.18.31.23','port':5432}}


def explorer(*, managed=False):
    resolver,app=fixture('mqtt_explorer')
    app['resolved_connections']={'outpost':{'type':'http','target':{
        'protocol':'http','port':9000,'address':'198.18.30.20'}},
        'broker':{'type':'mqtt','target':{'app':'broker','protocol':'tcp','port':1883,'address':'198.18.41.2'},
                  'hostname':'broker.example.invalid'}}
    if managed:
        app['resolved_connections']['broker']['account']={'owner':'application'}
        resolver.apps['broker']={'id':'broker','adapter':'mqtt','properties':{'password_file':'/mosquitto/config/passwords'},
            'secret_bindings':{'probe':{'type':'file','path':'/selected/probe.json'}},
            'software_selection':{'images':{'mqtt':{'image':'example/mqtt@sha256:'+'a'*64}}}}
    else:app['resolved_connections']['broker']['credential']={'principal':'existing','secret':'declared-reference'}
    return resolver,app


class FoundationBindingEdges(unittest.TestCase):
    def setUp(self):
        self.validate=self.enterContext(patch.object(foundation,'validate'))
        self.monitoring=self.enterContext(patch.object(component_monitoring,'server',return_value=None))

    def test_unowned_adapters_are_untouched_and_owned_empty_adapters_use_the_validator(self):
        resolver,app=fixture('music_assistant');app['settings']={'old':'discarded'}
        resolver.apps['peer']={'adapter':'node_red','settings':{'other':'preserved'}}
        foundation.bind(resolver)
        self.validate.assert_called_once_with('music_assistant',{})
        self.assertEqual(app['settings'],{});self.assertEqual(resolver.apps['peer']['settings'],{'other':'preserved'})

    def test_binder_validator_refusal_propagates_safe_source_path_without_overwriting_settings(self):
        resolver,app=fixture('unbound');app['settings']={'old':'preserved'}
        self.validate.side_effect=ComponentError('component.property')
        with self.assertRaises(ComponentError) as caught:foundation.bind(resolver)
        self.assertEqual(caught.exception.path,('apps','application','properties'))
        self.assertEqual(app['settings'],{'old':'preserved'})

    def test_pihole_copies_only_declared_dns_records_and_omission_is_empty(self):
        resolver,app=fixture('pihole');selected={'web.example.invalid':'198.18.30.32'}
        resolver.exposure_values['dns_records']['application']=selected
        foundation.bind(resolver);self.assertEqual(app['settings'],{'dns_records':selected})
        app['settings']['dns_records']['new']='changed';self.assertNotIn('new',selected)
        del resolver.exposure_values;foundation.bind(resolver)
        self.assertEqual(app['settings'],{'dns_records':{}})

    def test_authentik_uses_only_declared_database_secret_floor_and_callback_evidence(self):
        resolver,app=fixture('authentik');database(app)
        app['secret_bindings']={'secret_key':{},'postgresql_password':{}}
        resolver.site['evidence']['callbacks']={'type':'identity-callbacks','document':[callback()]}
        expected=[{'bounded':'callback projection'}]
        with patch.object(foundation,'_callback_records',return_value=expected) as check:foundation.bind(resolver)
        check.assert_called_once_with([callback()])
        self.assertEqual(app['settings']['database'],{'name':'authentik','user':'authentik','host':'198.18.31.23','port':5432})
        self.assertIs(app['settings']['allowed_callback_additions'],expected)
        self.monitoring.assert_not_called()

    def test_identity_callback_missing_wrong_type_and_validator_refusal_are_closed(self):
        for case in ('missing','wrong-type','invalid-record'):
            resolver,app=fixture('authentik');database(app);app['secret_bindings']={'secret_key':{},'postgresql_password':{}}
            if case!='missing':resolver.site['evidence']['callbacks']={'type':'other' if case=='wrong-type' else 'identity-callbacks','document':[]}
            with self.subTest(case=case),self.assertRaisesRegex(ComponentError,'callback-evidence'):foundation.bind(resolver)

    def test_database_connection_type_port_and_required_secrets_are_not_inferred(self):
        for adapter in ('authentik','zabbix'):
            for case in ('missing','wrong-type','wrong-port','missing-secret'):
                resolver,app=fixture(adapter);database(app);app['properties'].pop('callbacks',None)
                app['secret_bindings']={'secret_key':{},'postgresql_password':{}} if adapter=='authentik' else {'database_password':{}}
                if case=='missing':app['resolved_connections'].clear()
                elif case=='wrong-type':app['resolved_connections']['database']['type']='mariadb'
                elif case=='wrong-port':app['resolved_connections']['database']['target']['port']=5433
                else:app['secret_bindings'].clear()
                with self.subTest(adapter=adapter,case=case),self.assertRaises(ComponentError):foundation.bind(resolver)

    def test_owned_monitoring_uses_existing_owned_credential_and_refuses_duplicate_secret(self):
        resolver,app=fixture('zabbix');database(app);self.monitoring.return_value='application'
        foundation.bind(resolver)
        self.monitoring.assert_called_once_with(resolver)
        self.assertEqual(app['settings']['database_credential'],{'type':'monitoring-owned','server':'application'})
        app['secret_bindings']['database_password']={}
        with self.assertRaisesRegex(ComponentError,'secret-conflict'):foundation.bind(resolver)

    def test_mqtt_requires_existing_file_probe_and_never_opens_it(self):
        for selected in ({},{'probe':{'type':'environment','name':'REFERENCE'}}):
            resolver,app=fixture('mqtt');app['secret_bindings']=selected
            with self.subTest(selected=bool(selected)),self.assertRaisesRegex(ComponentError,'secret-required'):foundation.bind(resolver)
        resolver,app=fixture('mqtt');app['secret_bindings']={'probe':{'type':'file','path':'/selected/probe.json'}}
        foundation.bind(resolver);self.assertEqual(app['settings'],{'probe_credential_file':'/selected/probe.json'})

    def test_explorer_preserves_external_credentials_or_managed_account_without_material(self):
        for managed in (False,True):
            resolver,app=explorer(managed=managed);before=copy.deepcopy(app['resolved_connections'])
            foundation.bind(resolver)
            self.assertEqual(app['settings']['authentik_outpost_url'],'http://198.18.30.20:9000')
            broker=app['settings']['broker'];self.assertEqual(broker['hostname'],'broker.example.invalid')
            self.assertEqual('password_file' in broker,managed);self.assertEqual('image' in broker,managed)
            self.assertEqual(app['resolved_connections'],before)
            broker['hostname']='changed';self.assertEqual(app['resolved_connections']['broker']['hostname'],'broker.example.invalid')

    def test_explorer_refuses_missing_origin_outpost_protocol_port_or_wrong_owned_provider(self):
        mutations=[lambda r,a:a.pop('origin_url'),lambda r,a:a['resolved_connections'].pop('outpost'),
            lambda r,a:a['resolved_connections']['outpost'].update(type='https'),
            lambda r,a:a['resolved_connections']['outpost']['target'].update(protocol='https'),
            lambda r,a:a['resolved_connections']['outpost']['target'].update(port=9001),
            lambda r,a:a['resolved_connections']['outpost']['target'].update(app='foreign')]
        for index,mutate in enumerate(mutations):
            resolver,app=explorer();resolver.apps['foreign']={'adapter':'node_red'};mutate(resolver,app)
            with self.subTest(case=index),self.assertRaises(ComponentError):foundation.bind(resolver)

    def test_explorer_owned_authentik_outpost_binds_same_fixed_endpoint(self):
        resolver,app=explorer();app['resolved_connections']['outpost']['target']['app']='identity'
        resolver.apps['identity']={'id':'identity','adapter':'authentik','properties':{'database':{'name':'identity','user':'identity'}},
            'secret_bindings':{'secret_key':{},'postgresql_password':{}},'resolved_connections':{}}
        database(resolver.apps['identity']);foundation.bind(resolver)
        self.assertEqual(app['settings']['authentik_outpost_url'],'http://198.18.30.20:9000')

    def test_explorer_broker_requires_declared_type_port_hostname_and_account_or_credential(self):
        mutations=[lambda r,a:a['resolved_connections'].pop('broker'),
            lambda r,a:a['resolved_connections']['broker'].update(type='http'),
            lambda r,a:a['resolved_connections']['broker']['target'].update(port=1884),
            lambda r,a:a['resolved_connections']['broker'].pop('hostname'),
            lambda r,a:a['resolved_connections']['broker'].pop('credential')]
        for index,mutate in enumerate(mutations):
            resolver,app=explorer();mutate(resolver,app)
            with self.subTest(case=index),self.assertRaisesRegex(ComponentError,'broker-binding'):foundation.bind(resolver)
        resolver,app=explorer(managed=True);resolver.apps['broker']['properties'].pop('password_file')
        with self.assertRaisesRegex(ComponentError,'broker-binding'):foundation.bind(resolver)

    def test_zigbee_requires_retained_registered_device_and_explicit_broker_web(self):
        resolver,app=fixture('zigbee2mqtt');app['devices']={'coordinator':'serial'}
        resolver.site['devices']={'serial':{'path':'/dev/serial/by-id/usb-synthetic'}}
        app['resolved_connections']['broker']={'type':'mqtt','target':{'port':1883,'address':'198.18.41.2'}}
        resolver.endpoint.return_value={'protocol':'http','address':'198.18.40.6','port':8099};resolver.endpoint.side_effect=None
        foundation.bind(resolver)
        self.assertEqual(app['settings'],{'serial_device':'/dev/serial/by-id/usb-synthetic',
            'bind_address':'198.18.40.6','frontend_port':8099,'adapter':'ember','mqtt_base_topic':'home',
            'mqtt_server':'mqtt://198.18.41.2:1883'})
        resolver.endpoint.assert_called_once_with({'app':'application','endpoint':'web_endpoint'})
        app['resolved_connections']['broker']['hostname']='broker.example.invalid';foundation.bind(resolver)
        self.assertEqual(app['settings']['mqtt_server'],'mqtt://broker.example.invalid:1883')
        for case in ('fresh','device','broker','type','port','web'):
            saved=copy.deepcopy(app);saved_endpoint=copy.deepcopy(resolver.endpoint.return_value)
            if case=='fresh':app['lifecycle']='fresh'
            elif case=='device':app.pop('devices')
            elif case=='broker':app['resolved_connections'].clear()
            elif case=='type':app['resolved_connections']['broker']['type']='http'
            elif case=='port':app['resolved_connections']['broker']['target']['port']=1884
            else:resolver.endpoint.return_value['protocol']='https'
            with self.subTest(case=case),self.assertRaises(ComponentError):foundation.bind(resolver)
            app.clear();app.update(saved);resolver.endpoint.return_value=saved_endpoint

    def test_traefik_required_capabilities_secrets_context_and_discovery_guests_are_explicit(self):
        for case in ('provider','acme','secret','context','discovery-missing','discovery-context'):
            resolver,app=fixture('traefik');app['secret_bindings']={'cloudflare_dns_token':{},'proxmox_token':{}}
            if case in ('provider','acme'):app['properties'].pop(case)
            elif case=='secret':app['secret_bindings'].pop('proxmox_token')
            elif case=='context':app['properties']['provider']['context']='other'
            elif case=='discovery-missing':resolver.guests.pop('application')
            else:resolver.guests['application']['context']='other'
            with self.subTest(case=case),self.assertRaises(ComponentError):foundation.bind(resolver)

    def test_traefik_dns_protocol_port_address_and_duplicate_aliases_refuse(self):
        for endpoint in ({'protocol':'https','port':53,'address':'198.18.20.53'},
                         {'protocol':'udp','port':5353,'address':'198.18.20.53'},
                         {'protocol':'udp','port':53,'address':'not-an-address'}):
            resolver,app=fixture('traefik');app['secret_bindings']={'cloudflare_dns_token':{},'proxmox_token':{}}
            app['properties']['provider'].pop('discovery');original_endpoint=resolver.endpoint.side_effect
            resolver.endpoint.side_effect=lambda ref:copy.deepcopy(endpoint) if ref['external']=='dns' else original_endpoint(ref)
            with self.subTest(endpoint=endpoint),self.assertRaises(ComponentError):foundation.bind(resolver)

    def test_traefik_copies_only_selected_trust_transport_files_in_stable_order(self):
        resolver,app=fixture('traefik');app['secret_bindings']={'cloudflare_dns_token':{},'proxmox_token':{}}
        resolver.exposure_values['routes']['application']={'b':{'tls':'public','transport':'zeta'},
            'a':{'tls':'public','transport':'alpha'},'none':{'tls':'public','transport':'plain'}}
        resolver.authentication_values['transports']={'zeta':{'ca_file':'/selected/zeta.pem'},
            'alpha':{'ca_file':'/selected/alpha.pem'},'plain':{},'unused':{'ca_file':'/never/read.pem'}}
        before=copy.deepcopy(app['properties']);foundation.bind(resolver)
        self.assertEqual(app['settings']['route_ca_files'],{
            'alpha':{'source':'/selected/alpha.pem','filename':'route-alpha.pem'},
            'zeta':{'source':'/selected/zeta.pem','filename':'route-zeta.pem'}})
        self.assertEqual(list(app['settings']['route_ca_files']),['alpha','zeta'])
        self.assertEqual(app['properties'],before)
        app['settings']['acme']['email']='changed';self.assertEqual(app['properties'],before)
        resolver.policy['tls']['public']['resolver']='other'
        with self.assertRaisesRegex(ComponentError,'tls-resolver-unsupported'):foundation.bind(resolver)
        resolver.policy['tls']['public']['resolver']='letsencrypt';resolver.authentication_values['transports'].pop('alpha')
        with self.assertRaisesRegex(ComponentError,'component.reference'):foundation.bind(resolver)

    def test_traefik_omitted_discovery_exposures_and_transports_do_not_invent_scope(self):
        resolver,app=fixture('traefik');app['secret_bindings']={'cloudflare_dns_token':{},'proxmox_token':{}}
        app['properties']['provider'].pop('discovery');del resolver.exposure_values;del resolver.authentication_values
        app['properties']['acme']['resolvers'].append({'external':'dns_other'})
        foundation.bind(resolver)
        self.assertNotIn('discovery',app['settings']['provider']);self.assertEqual(app['settings']['route_ca_files'],{})
        self.assertEqual(app['settings']['acme']['resolvers'],['198.18.20.53:53','198.18.20.54:53'])

    def test_traefik_binds_only_selected_inline_public_certificates_without_mutating_policy(self):
        resolver,app=fixture('traefik');app['secret_bindings']={'cloudflare_dns_token':{},'proxmox_token':{}}
        resolver.exposure_values['routes']['application']={
            'inline':{'tls':'public','transport':'selected'},
            'context':{'tls':'public','transport':'existing'}}
        resolver.authentication_values['transports']={
            'selected':{'certificate':'validated-public-pem'},
            'unused':{'certificate':'unused-public-pem'},'existing':{'ca_file':'/selected/context.pem'}}
        before=copy.deepcopy(resolver.authentication_values)
        foundation.bind(resolver)
        self.assertEqual(app['settings']['route_ca_certificates'],{
            'selected':{'certificate':'validated-public-pem','filename':'route-selected.pem'}})
        self.assertEqual(app['settings']['route_ca_files'],{
            'existing':{'source':'/selected/context.pem','filename':'route-existing.pem'}})
        self.assertEqual(resolver.authentication_values,before)

    def test_physical_address_resolution_refuses_unknown_nonphysical_or_unassigned_addresses(self):
        resolver,app=fixture('postgresql');app['properties']['client_access']=[]
        resolver.apps['peer']={'adapter':'node_red','interfaces':{'database_interface':{'interface':'backend'}}}
        ref={'app':'peer','interface':'database_interface'}
        self.assertEqual(foundation._address(resolver,ref),'198.18.21.10')
        for value in ('0.0.0.0','127.0.0.1','224.0.0.1','169.254.1.2','invalid'):
            resolver.role_address.return_value=value
            with self.subTest(address=value),self.assertRaises(ComponentError):foundation._address(resolver,ref)
        for value in ({'app':'missing','interface':'database_interface'},{'app':'peer','interface':'missing_interface'}):
            with self.subTest(reference=value),self.assertRaises(ComponentError):foundation._address(resolver,value)
        resolver.apps['peer']['interfaces']['database_interface']={'scope':'guest-loopback'}
        with self.assertRaisesRegex(ComponentError,'physical-role'):foundation._address(resolver,ref)


if __name__=='__main__':unittest.main()
