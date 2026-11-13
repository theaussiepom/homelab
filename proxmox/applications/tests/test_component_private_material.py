"""Private material component units and finite real-parser integrations only."""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

F=Path(os.environ.get('HOMELAB_FRAMEWORK',Path(__file__).resolve().parents[3]))
sys.path.insert(0,str(F/'proxmox/applications'))
import component_private_material as material


def scalar(adapter='authentik',role='secret_key',*,file=False):
    source={'type':'file','path':'/declared/private/input','source_id':'selected'}if file else{
        'type':'environment','name':'EXISTING_SECRET','workflow_secret':'EXISTING_WORKFLOW_SECRET','source_id':'selected'}
    return {'adapter':adapter,'input_sources':{role:source}}


def telemetry():
    app=scalar('winet','options',file=True)
    app['settings']={'configuration_file':'/declared/private/input','inverter_address':'198.18.80.9',
        'mqtt_server':'mqtt://broker.example.invalid:1883','mqtt_prefix':'fixture/telemetry'}
    values={'winet_host':'198.18.80.9','winet_user':'inverter-user','winet_pass':'inverter-value',
        'mqtt_url':'mqtt://mqtt-user:mqtt-value@broker.example.invalid:1883','mqtt_prefix':'fixture/telemetry',
        'poll_interval':30,'analytics':False,'ssl':True,'site_totals':False,'additional_winets':[]}
    return app,values


def provider():
    app=scalar('traefik','proxmox_token',file=True)
    app['settings']={'provider':{'token_id':'fixture@pve!discovery','url':'https://198.18.25.10:8006',
        'ca_file':'/public/context.pem','discovery':{'owner_sha256':'a'*64,'guests':[818,819]}}}
    record={'schema':'homelab-service-discovery-v1','identity':'fixture@pve!discovery',
            'token':'fixture@pve!discovery=synthetic-token'}
    return app,record


def raw(value,*,pretty=False):
    return json.dumps(value,indent=2 if pretty else None).encode()


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()


def selected_hash(app,role,value):
    return material.project(app,{role:value})[role]['material_sha256']


class ProjectorUnits(unittest.TestCase):
    def test_selected_role_contract_is_delegated_and_source_metadata_is_closed_copy(self):
        app=scalar();before=copy.deepcopy(app)
        with patch.object(material.component_input_secrets,'slots',return_value={'secret_key':'SLOT'})as slots:
            result=material.project(app,{'secret_key':b'synthetic-scalar'})
        slots.assert_called_once_with('authentik',app['input_sources'])
        self.assertEqual(result,{'secret_key':{'source':app['input_sources']['secret_key'],
            'material_sha256':hashlib.sha256(b'synthetic-scalar').hexdigest()}})
        result['secret_key']['source']['source_id']='renamed'
        self.assertEqual(app,before)

    def test_winet_app_wiring_delegates_existing_options_validator_once(self):
        app,options=telemetry();supplied=b'unit-supplied-only'
        with patch.object(material.winet,'options_bytes',return_value=options)as parser:
            actual=selected_hash(app,'options',supplied)
        parser.assert_called_once_with(supplied,app['settings'])
        self.assertEqual(actual,digest({'winet_user':'inverter-user','winet_pass':'inverter-value',
            'mqtt_username':'mqtt-user','mqtt_password':'mqtt-value'}))

    def test_probe_app_wiring_uses_duplicate_checked_parser_and_existing_validator(self):
        app=scalar('mqtt','probe',file=True);value={'username':'probe','password':'fixture-value'}
        with patch.object(material,'decode_json',return_value=value)as parser,patch.object(material.mqtt_runtime,'probe_files')as validate:
            result=selected_hash(app,'probe',b'unit-supplied-only')
        parser.assert_called_once_with(b'unit-supplied-only');validate.assert_called_once_with(value)
        self.assertEqual(result,digest(value))

    def test_provider_app_wiring_delegates_exact_expected_token_identity(self):
        app,_=provider()
        with patch.object(material.runtime_secrets,'retained_provider_token',return_value='synthetic-value')as parser:
            actual=selected_hash(app,'proxmox_token',b'unit-supplied-only')
        parser.assert_called_once_with(b'unit-supplied-only','fixture@pve!discovery')
        self.assertEqual(actual,digest({'identity':'fixture@pve!discovery','secret':'synthetic-value'}))

    def test_parser_failures_are_redacted_without_fallback_or_raw_fingerprint(self):
        app,_=telemetry()
        for error in (ValueError('private-value'),TypeError('private-value'),KeyError('private-value'),UnicodeError('private-value')):
            with self.subTest(kind=type(error).__name__),patch.object(material.winet,'options_bytes',side_effect=error),self.assertRaisesRegex(ValueError,'^Invalid selected private material$'):
                material.project(app,{'options':b'private-value'})

    def test_all_raw_roles_hash_exact_bytes_without_decoding_or_trimming(self):
        cases=[('authentik','secret_key'),('authentik','postgresql_password'),('authentik','smtp_password'),
               ('traefik','cloudflare_dns_token'),('node_red','api_token'),('cloudbeaver','client_secret'),
               ('mqtt_explorer','broker_password'),('zabbix','database_password'),
               ('bitwarden','runtime_environment'),('pegaprox','database_key')]
        for adapter,role in cases:
            app=scalar(adapter,role,file=True);value=b'\xff\x00opaque fixture\n '
            with self.subTest(adapter=adapter,role=role):
                self.assertEqual(selected_hash(app,role,value),hashlib.sha256(value).hexdigest())
                self.assertNotEqual(selected_hash(app,role,value+b' '),selected_hash(app,role,value))

    def test_plain_scalar_and_raw_bitwarden_public_field_changes_are_not_normalized(self):
        for app,role in ((scalar(),'secret_key'),(scalar('bitwarden','runtime_environment',file=True),'runtime_environment')):
            with self.subTest(role=role):
                self.assertNotEqual(selected_hash(app,role,b'{"public":"one","secret":"same"}'),
                                    selected_hash(app,role,b'{"public":"two","secret":"same"}'))

    def test_source_id_rename_never_changes_role_or_material_hash(self):
        app=scalar();first=material.project(app,{'secret_key':b'unchanged'})
        app['input_sources']['secret_key']['source_id']='renamed';app['input_sources']['secret_key']['name']='RENAMED_EXISTING'
        second=material.project(app,{'secret_key':b'unchanged'})
        self.assertEqual(set(first),set(second));self.assertEqual(first['secret_key']['material_sha256'],second['secret_key']['material_sha256'])
        self.assertNotEqual(first['secret_key']['source'],second['secret_key']['source'])
        self.assertNotEqual(second['secret_key']['material_sha256'],selected_hash(app,'secret_key',b'changed'))

    def test_no_path_reads_selection_reader_or_output(self):
        app,options=telemetry();out=io.StringIO();err=io.StringIO()
        with (patch('builtins.open',side_effect=AssertionError('No path read')),patch('pathlib.Path.open',side_effect=AssertionError('No path read')),
              patch.object(material.component_input_secrets,'selected',side_effect=AssertionError('No selection read')),
              contextlib.redirect_stdout(out),contextlib.redirect_stderr(err)):
            material.project(app,{'options':raw(options)})
        self.assertEqual((out.getvalue(),err.getvalue()),('',''))

    def test_empty_selected_roles_produce_no_invented_material(self):
        self.assertEqual(material.project({'adapter':'unbound'},{}),{})
        self.assertEqual(material.project({'adapter':'authentik','input_sources':{}},{}),{})


class ProjectorRefusalUnits(unittest.TestCase):
    def test_missing_extra_foreign_roles_and_bad_app_shapes_refuse(self):
        cases=[(None,{}),([],{}),({},{}),({'adapter':None},{}),({'adapter':'mqtt','input_sources':None},{}),
            (scalar(),None),(scalar(),{}),(scalar(),{'secret_key':b'one','smtp_password':b'peer'}),
            (scalar('authentik','foreign'),{'foreign':b'value'}),(scalar('unknown','secret_key'),{'secret_key':b'value'})]
        for app,values in cases:
            with self.subTest(app_type=type(app).__name__),self.assertRaises(ValueError):material.project(app,values)

    def test_nonbytes_empty_and_existing_environment_file_bounds_refuse(self):
        for file,limit in ((False,65536),(True,1024*1024)):
            app=scalar(file=file)
            self.assertEqual(len(selected_hash(app,'secret_key',b'x'*limit)),64)
            for value in ('text',bytearray(b'x'),b'',b'x'*(limit+1)):
                with self.subTest(file=file,kind=type(value).__name__),self.assertRaises(ValueError):material.project(app,{'secret_key':value})

    def test_source_metadata_cannot_be_a_generic_bag_or_unbounded_identity(self):
        sources=[None,{'type':'generated'},{'type':'environment','name':'bad-name'},
            {'type':'environment','name':'VALUE','value':'private'},
            {'type':'file','path':'relative'},{'type':'file','path':'/controller/../outside'},
            {'type':'file','path':'/controller/input','workflow_secret':'VALUE'},
            {'type':'environment','name':'VALUE','source_id':[]},
            {'type':'environment','name':'VALUE','source_id':'bad/id'},
            {'type':'environment','name':'VALUE','workflow_secret':None},
            {'type':'file','path':'/controller/value\n'},
            {'type':'file','path':'/controller/input','source_id':'x'*64}]
        for source in sources:
            with self.subTest(source_type=type(source).__name__),self.assertRaises(ValueError):
                material.project({'adapter':'authentik','input_sources':{'secret_key':source}},{'secret_key':b'input'})


class CompoundParserIntegration(unittest.TestCase):
    def test_winet_public_endpoint_options_and_source_properties_can_evolve_without_credential_hash_change(self):
        app,value=telemetry();first=selected_hash(app,'options',raw(value));before=copy.deepcopy((app,value))
        app['settings'].update(inverter_address='198.18.80.10',mqtt_server='mqtt://other.example.invalid:1883',
                               mqtt_prefix='updated/prefix',configuration_file='/declared/renamed/input')
        app['input_sources']['options'].update(path='/declared/renamed/input',source_id='renamed')
        value.update(winet_host='198.18.80.10',mqtt_url='mqtt://mqtt-user:mqtt-value@other.example.invalid:1883',
                     mqtt_prefix='updated/prefix',poll_interval=60,analytics=True,site_totals=True)
        self.assertEqual(selected_hash(app,'options',raw(value,pretty=True)),first)
        unchanged_app,unchanged_value=before
        self.assertEqual(selected_hash(unchanged_app,'options',raw(unchanged_value)),first)

    def test_each_winet_or_mqtt_credential_change_changes_projection(self):
        app,original=telemetry();first=selected_hash(app,'options',raw(original))
        for changes in ({'winet_user':'changed'},{'winet_pass':'changed'},
                        {'mqtt_url':'mqtt://changed:mqtt-value@broker.example.invalid:1883'},
                        {'mqtt_url':'mqtt://mqtt-user:changed@broker.example.invalid:1883'}):
            value=dict(original,**changes)
            with self.subTest(keys=list(changes)):self.assertNotEqual(selected_hash(app,'options',raw(value)),first)

    def test_winet_missing_empty_and_percent_encoded_credentials_remain_distinct(self):
        app,value=telemetry();urls=['mqtt://broker.example.invalid:1883','mqtt://@broker.example.invalid:1883',
            'mqtt://user@broker.example.invalid:1883','mqtt://user:@broker.example.invalid:1883',
            'mqtt://user:value@broker.example.invalid:1883','mqtt://%75ser:value@broker.example.invalid:1883']
        self.assertEqual(len({selected_hash(app,'options',raw(dict(value,mqtt_url=url)))for url in urls}),len(urls))

    def test_winet_existing_validator_and_duplicate_json_failures_are_not_ignored(self):
        app,value=telemetry()
        cases=[b'not-json',b'{"winet_pass":"first","winet_pass":"second"}',
            raw(dict(value,ssl=False)),raw(dict(value,winet_user='')),raw(dict(value,winet_pass='private\nvalue')),
            raw(dict(value,mqtt_url='mqtt://private-user:private-value@foreign.example.invalid:1883')),
            raw(dict(value,poll_interval=True)),raw(dict(value,custom_ca='private-value'))]
        for raw_ in cases:
            with self.subTest(length=len(raw_)),self.assertRaises(ValueError)as error:material.project(app,{'options':raw_})
            self.assertEqual(str(error.exception),'Invalid selected private material')

    def test_probe_hash_is_canonical_and_each_credential_remains_bound(self):
        app=scalar('mqtt','probe',file=True);value={'username':'probe','password':'value'}
        first=selected_hash(app,'probe',raw(value));self.assertEqual(first,digest(value))
        self.assertEqual(selected_hash(app,'probe',b'{ "password" : "value", "username":"probe" }'),first)
        for change in ({'username':'changed'},{'password':'changed'}):
            self.assertNotEqual(selected_hash(app,'probe',raw(dict(value,**change))),first)
        for raw_ in (b'[]',b'{}',b'{"username":"probe","password":"first","password":"second"}',
                     raw(dict(value,extra='private-value')),raw(dict(value,password='private\nvalue'))):
            with self.assertRaisesRegex(ValueError,'^Invalid selected private material$'):material.project(app,{'probe':raw_})

    def test_provider_projection_excludes_public_scope_trust_and_owner_metadata_but_keeps_identity_and_secret(self):
        app,record=provider();first=selected_hash(app,'proxmox_token',raw(record))
        self.assertEqual(first,digest({'identity':'fixture@pve!discovery','secret':'synthetic-token'}))
        app['settings']['provider'].update(url='https://198.18.25.11:8006',ca_file='/public/renamed.pem',
            discovery={'owner_sha256':'b'*64,'guests':[818,819,820]})
        self.assertEqual(selected_hash(app,'proxmox_token',raw(record,pretty=True)),first)
        record['token']='fixture@pve!discovery=changed'
        self.assertNotEqual(selected_hash(app,'proxmox_token',raw(record)),first)
        app['settings']['provider']['token_id']='other@pve!discovery'
        record.update(identity='other@pve!discovery',token='other@pve!discovery=synthetic-token')
        self.assertNotEqual(selected_hash(app,'proxmox_token',raw(record)),first)

    def test_provider_closed_record_rejects_credential_substitution_or_embedded_owner_catalog(self):
        app,record=provider()
        cases=[b'raw-private-token',raw(dict(record,identity='foreign@pve!discovery')),
            raw(dict(record,token='fixture@pve!discovery=private value')),raw(dict(record,owner={})),
            raw(dict(record,READY={})),b'{"identity":"first","identity":"second"}']
        for raw_ in cases:
            with self.subTest(length=len(raw_)),self.assertRaises(ValueError)as error:material.project(app,{'proxmox_token':raw_})
            self.assertNotIn('private',str(error.exception).replace('private material',''))

    def test_projections_do_not_mutate_app_values_or_parsed_inputs(self):
        app,value=telemetry();values={'options':raw(value)};before=copy.deepcopy((app,values))
        material.project(app,values);self.assertEqual((app,values),before)


if __name__=='__main__':unittest.main()
