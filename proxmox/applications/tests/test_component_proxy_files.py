"""App-owned file units mock shared builders; one legacy byte contract per app."""
import ast
import hashlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

FRAMEWORK=Path(os.environ.get('HOMELAB_FRAMEWORK',Path(__file__).resolve().parents[3])).resolve()
sys.path.insert(0,str(FRAMEWORK/'proxmox/applications'))
import cloudbeaver as c
import database_admin as original_database
import monitoring
import mqtt_explorer as e
import component_proxy_files as m
d=original_database


def cloud():
    value={'bind_address':'198.18.30.32','public_url':'https://database.example.invalid',
        'server_name':'Database Tools','recovery_admin':'recovery_admin','heap_mib':1024,
        'auth_headers':{'user':'X-User','team':'X-Team'},
        'connections':{'postgresql':{'name':'PostgreSQL','driver':'postgresql','database':'postgres',
            'sslmode':'prefer','host':'198.18.31.23','port':5432}}}
    auth={'version':1,'oidc_issuer':'https://sso.example.invalid/application/o/database/',
        'oauth_client_id':'fixture-client','oauth_name':'Sign in','user_claim':'preferred_username',
        'secret_files':{'oauth_client_secret':'/never-read/oauth'}}
    return {'id':'tools','adapter':'cloudbeaver','identity':{'services':{'cloudbeaver':'cloudbeaver','auth_gateway':'auth_gateway'},
        'runtime_directory':m.RUNTIME},'project_name':'homelab-db-tools','settings':value,
        'authentication_resolved':auth,'storage_paths':{'workspace':{'source':c.WORKSPACE}},
        'software_selection':{'images':{name:{'image':'example.invalid/'+name+'@sha256:'+'b'*64}
                                      for name in ('cloudbeaver','auth_gateway')}}}


def managed(app):
    value=app['settings']; records={}
    value['managed_connections']={}
    for driver,host,port in [('postgresql','198.18.31.23',5432),('mariadb','198.18.32.24',3306)]:
        owner={'node':'example-node','engine':driver,'database_vmid':810 if driver=='postgresql' else 811,
            'source_vmid':812,'server_address':host,'source_address':'198.18.31.32' if driver=='postgresql' else '198.18.32.32',
            'username':'fixture_admin','purpose':'database-administration'}
        credential='fixture-'+driver
        value['managed_connections'][driver+'-admin']={'name':driver+' Admin','driver':driver,
            'database':'postgres' if driver=='postgresql' else '', 'account_id':driver+'-admin','host':host,'port':port,
            'username':'fixture_admin','credential_id':credential,'credential_file':'${inputs}/managed-'+credential+'.json',
            'transport':'tls','owner':owner}
        records[credential]={'schema':'homelab-application-account-v1','owner':owner,'password':'c'*64}
    value['mariadb_jdbc']={'version':'3.5.11','sha256':'42604178b9e57ec08ee0035079961516f086e455d0141f0b22c6eff29fb2fff4',
                         'image_filename':'mariadb-java-client-3.5.10.jar'}
    return records


def explorer():
    owner={'node':'example-node','vmid':817,'hostname':'example-broker','purpose':'mqtt-explorer','username':'fixture_gui'}
    credential={'credential_id':'fixture-gui','owner':owner,'credential_file':'${inputs}/managed-fixture-gui.json'}
    broker={'type':'mqtt','hostname':'broker.example.invalid','target':{'address':'198.18.31.19','port':1883},
        'account':{'principal':'fixture_gui','access':'read-write-all'},'managed_credential':credential,
        'password_file':'/mosquitto/config/selected_passwords','image':'example.invalid/mqtt@sha256:'+'b'*64}
    return {'id':'browser','adapter':'mqtt_explorer','identity':{'services':{'mqtt_explorer':'mqtt_explorer','explorer_gateway':'explorer_gateway'},
        'runtime_directory':m.RUNTIME},'project_name':'homelab-mqtt','origin_url':'https://explorer.example.invalid',
        'role_addresses':{'web':'198.18.30.37'},'properties':{'connection_name':'Broker'},
        'settings':{'authentik_outpost_url':'http://198.18.30.20:9000','broker':broker},
        'storage_paths':{'data':{'source':e.DATA}},'software_selection':{'images':{name:{'image':'example.invalid/'+name+'@sha256:'+'a'*64}
                for name in ('mqtt_explorer','explorer_gateway')}}}, {'fixture-gui':{'schema':'homelab-application-account-v1','owner':owner,'password':'d'*64}}


def zabbix():
    return {'id':'monitor','adapter':'zabbix','identity':{'services':{'zabbix_server':'zabbix_server','zabbix_web':'zabbix_web'},
        'runtime_directory':m.RUNTIME},'project_name':'homelab-monitoring','settings':{'database':{'name':'zabbix','user':'zabbix','host':'198.18.31.23'}}}


class ProxyFileTests(unittest.TestCase):
    def test_cloud_unit_delegates_configuration_and_gateway_to_owned_service(self):
        app=cloud();app['identity']['services']={'cloudbeaver':'community2','auth_gateway':'gateway2'}
        app['identity']['runtime_directory']=m.RUNTIME+'/tools';app['project_name']='tools-project'
        app['storage_paths']['workspace']['source']='/srv/example/tools'
        with patch.object(m,'_context',return_value=(app['identity']['services'],app['identity']['runtime_directory'],app['project_name'])), \
             patch.object(c,'gateway',return_value=({'fixture':'alpha'},'fixture-options\n')) as gateway, \
             patch.object(c,'configuration',return_value={'fixture':'configuration'}), \
             patch.object(c,'connection_document',return_value={'connections':{}}),patch.object(m,'_public_source',return_value='source\n'), \
             patch.object(Path,'open',side_effect=AssertionError('private read forbidden')):
            rows=m.files(app,secrets={'client_secret':b'synthetic-oauth-only-unit-value-0'*2},records={},public_ca=None)
        gateway.assert_called_once_with(app['settings'],app['authentication_resolved'],b'synthetic-oauth-only-unit-value-0'*2,server_service='community2')
        values={row['path']:row for row in rows};self.assertEqual(len(values),8)
        public=json.loads(values['cloudbeaver-public.json']['content'])
        self.assertEqual((public['workspace'],public['project'],public['runtime_directory']),('/srv/example/tools','tools-project',m.RUNTIME+'/tools'))
        self.assertEqual(public['services'],app['identity']['services']);self.assertNotIn(('synthetic-oauth-only-unit-value-0'*2),values['cloudbeaver-public.json']['content'])
        self.assertTrue(all(row['mode']=='0400' for row in rows))
        self.assertEqual(values['oauth2.cfg']['content'],'fixture-options\n\n')

    def test_managed_cloud_uses_records_and_preserves_native_flags_and_driver_slot(self):
        app=cloud();records=managed(app);app['settings']['connections']={}
        app['identity']['runtime_directory']=m.RUNTIME+'/admin'
        with patch.object(m,'_public_source',return_value='source\n'),patch.object(Path,'open',side_effect=AssertionError('private read forbidden')):
            values={r['path']:r for r in m.files(app,secrets={'client_secret':b'a'*64},records=records,public_ca=None)}
        self.assertEqual(len(values),10)
        config=json.loads(values['cloudbeaver.conf']['content'])
        self.assertTrue(config['app']['adminCredentialsSaveEnabled']);self.assertTrue(config['app']['secretManagerEnabled'])
        self.assertNotIn('resourceManagerEnabled',config['app'])
        doc=json.loads(values['cloudbeaver-admin-connections.json']['content'])
        self.assertEqual(doc['connections']['postgresql-admin']['configuration']['properties'],
            {'sslmode':'require','channelBinding':'require','requireAuth':'scram-sha-256'})
        self.assertEqual(doc['connections']['mariadb-admin']['configuration']['properties'],{'sslMode':'verify-full'})
        public=json.loads(values['cloudbeaver-public.json']['content'])
        self.assertEqual(public['mariadb_jdbc']['source'],m.RUNTIME+'/admin/mariadb-java-client-3.5.11.jar')
        self.assertNotIn('c'*64,values['cloudbeaver-public.json']['content'])
        self.assertIn('c'*64,values['cloudbeaver-admin-connections.json']['content'])
        self.assertEqual(values['cloudbeaver-admin-connections.json']['uid'],0)

    def test_cloud_inputs_refuse_extra_missing_invalid_or_unused_sources(self):
        app=cloud()
        for secrets,records,ca in [({}, {},None),({'client_secret':b'a'*64,'foreign':b'x'}, {},None),
                ({'client_secret':'text'},{},None),({'client_secret':b'\xff'*64},{},None),
                ({'client_secret':b'a'*64},{'foreign':{}},None),({'client_secret':b'a'*64},{},b'ca')]:
            with self.subTest(secrets=list(secrets)),self.assertRaises(ValueError):m.files(app,secrets=secrets,records=records,public_ca=ca)
        app.pop('authentication_resolved')
        with self.assertRaises((ValueError,KeyError)):m.files(app,secrets={'client_secret':b'a'*64},records={},public_ca=None)

    def test_database_document_from_supplied_records_matches_frozen_wrapper_bytes(self):
        app=cloud();records=managed(app)
        baseline=json.loads(Path(__file__).with_name('proxy-file-wrapper-baseline.json').read_text())
        with patch.object(Path,'open',side_effect=AssertionError('Pure builder cannot open private records')):
            current=d.document_from_records(app['settings'],records)
        self.assertEqual(type(current).__name__,baseline['database_document_type'])
        self.assertEqual(hashlib.sha256(current).hexdigest(),baseline['database_document_sha256'])
        self.assertEqual(json.loads(current)['connections']['postgresql-admin']['configuration']['auth-properties']['userPassword'],'c'*64)

    def test_database_records_refuse_missing_foreign_owner_schema_and_password(self):
        app=cloud();records=managed(app)
        cases=[{},dict(records,foreign={})]
        for field,value in [('schema','foreign'),('owner',{}),('password','wrong'),('password',False),('extra',True)]:
            row=copy.deepcopy(records);row['fixture-postgresql'][field]=value;cases.append(row)
        for rows in cases:
            with self.subTest(keys=list(rows)),self.assertRaises(ValueError):d.document_from_records(app['settings'],rows)

    def test_explorer_unit_uses_owned_service_and_retains_only_selected_account(self):
        app,records=explorer();app['identity']['services']={'mqtt_explorer':'browser2','explorer_gateway':'gate2'}
        app['identity']['runtime_directory']=m.RUNTIME+'/gui';app['project_name']='gui-project';app['storage_paths']['data']['source']='/srv/example/gui'
        with patch.object(m,'_context',return_value=(app['identity']['services'],app['identity']['runtime_directory'],app['project_name'])), \
             patch.object(e,'configuration',return_value=({'static':True},{'dynamic':True})) as configuration, \
             patch.object(Path,'open',side_effect=AssertionError('private read forbidden')):
            rows=m.files(app,secrets={},records=records,public_ca=None)
        self.assertEqual(configuration.call_args.kwargs,{'explorer_service':'browser2'})
        values={r['path']:r for r in rows};self.assertEqual(len(values),4)
        account=json.loads(values['mqtt-explorer-account.json']['content'])
        self.assertEqual(account['image'],app['settings']['broker']['image']);self.assertEqual(account['credential'],records['fixture-gui'])
        self.assertNotIn('credential_file',account['connection']);self.assertEqual(values['mqtt-explorer-account.json']['mode'],'0600')
        public=json.loads(values['mqtt-explorer-public.json']['content'])
        self.assertEqual(public['broker_address'],'198.18.31.19');self.assertEqual(public['data_path'],'/srv/example/gui')
        self.assertEqual(public['project'],'gui-project');self.assertEqual(public['services'],app['identity']['services'])
        self.assertNotIn('d'*64,values['mqtt-explorer-public.json']['content'])

    def test_explorer_refuses_record_drift_unknown_inputs_and_missing_broker_image(self):
        for mutate in (lambda a,r:a['settings']['broker'].pop('image'),lambda a,r:a['settings']['broker'].update(image='latest'),
                       lambda a,r:r['fixture-gui'].update(owner={}),lambda a,r:r['fixture-gui'].update(password='changed')):
            app,records=explorer();mutate(app,records)
            with self.subTest(mutation=repr(mutate)),self.assertRaises(ValueError):m.files(app,secrets={},records=records,public_ca=None)
        app,records=explorer()
        with self.assertRaises(ValueError):m.files(app,secrets={'client_secret':b'x'},records=records,public_ca=None)
        app['settings']['broker'].pop('managed_credential')
        with self.assertRaises(ValueError):m.files(app,secrets={'broker_password':b'x'},records={},public_ca=None)

    def test_zabbix_unit_uses_supplied_owned_password_and_public_ca_only(self):
        app=zabbix();app['authentication_resolved']={'default_login':'saml'}
        ca=b'-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n'
        with patch.object(m,'_context',return_value=({},m.RUNTIME,'example')),patch.object(monitoring,'saml_settings',return_value={}) as saml, \
             patch.object(m,'_public_source',return_value='php\n') as source,patch.object(Path,'open',side_effect=AssertionError('private read forbidden')):
            rows=m.files(app,secrets={'database_password':b'fixture\n'},records={},public_ca=ca)
        saml.assert_called_once_with(app['authentication_resolved']);source.assert_called_once_with('saml-login.php')
        self.assertEqual([r['content'] for r in rows],['fixture\n',ca.decode(),'php\n'])
        self.assertTrue(all((r['uid'],r['gid'],r['mode'])==(1997,1995,'0400') for r in rows))
        app.pop('authentication_resolved')
        self.assertEqual(len(m.files(app,secrets={'database_password':b'fixture'},records={},public_ca=ca)),2)

    def test_zabbix_rejects_missing_or_overbroad_or_non_public_input(self):
        ca=b'-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n'
        for secrets,records,cert in [({}, {},ca),({'database_password':b'\n'}, {},ca),
            ({'database_password':b'a\nb'}, {},ca),({'database_password':b'a','foreign':b'b'}, {},ca),
            ({'database_password':b'a'}, {'foreign':{}},ca),({'database_password':b'a'}, {},None),
            ({'database_password':b'a'}, {},b'PRIVATE KEY'),({'database_password':b'\xff'}, {},ca)]:
            with self.subTest(secrets=list(secrets)),self.assertRaises(ValueError):m.files(zabbix(),secrets=secrets,records=records,public_ca=cert)

    def test_runtime_source_and_identity_paths_are_closed(self):
        for path in ('/etc','/opt/homelab-app/runtime/../other',m.RUNTIME+'//other',m.RUNTIME+'/bad\n',
                     m.RUNTIME+'/${INTERPOLATE}',m.RUNTIME+'/colon:path',m.RUNTIME+'/back\\slash'):
            app=cloud();app['identity']['runtime_directory']=path
            with self.subTest(path=path),self.assertRaises(ValueError):m.files(app,secrets={},records={},public_ca=None)
        with self.assertRaises(ValueError):m._public_source('../../private')
        app=cloud();app['identity']['services']['cloudbeaver']='bad/value'
        with self.assertRaises(ValueError):m.files(app,secrets={},records={},public_ca=None)
        app['adapter']='foreign'
        with self.assertRaises(ValueError):m.files(app,secrets={},records={},public_ca=None)

    def test_public_synthetic_rows_match_frozen_pre_removal_wrapper_hashes_and_metadata(self):
        baseline=json.loads(Path(__file__).with_name('proxy-file-wrapper-baseline.json').read_text())
        secret=b'fixture-entropy-not-production'*2
        app=cloud();records=managed(app)
        actual={'cloudbeaver':m.files(app,secrets={'client_secret':secret},records=records,public_ca=None)}
        app,records=explorer()
        actual['mqtt_explorer']=m.files(app,secrets={},records=records,public_ca=None)
        actual['monitoring']=m.files(zabbix(),secrets={'database_password':b'fixture-password\n'},records={},
            public_ca=b'-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n')
        for adapter,rows in actual.items():
            with self.subTest(adapter=adapter):
                self.assertEqual([row['path']for row in rows],list(baseline['rows'][adapter]))
                projected={row['path']:{'sha256':hashlib.sha256(row['content'].encode()if isinstance(row['content'],str)else row['content']).hexdigest(),
                    'content_type':type(row['content']).__name__,'uid':row['uid'],'gid':row['gid'],'mode':row['mode']}for row in rows}
                expected=copy.deepcopy(baseline['rows'][adapter])
                if adapter=='cloudbeaver':
                    # Expected bytes derive from the immutable old public DTO
                    # by removing only the retired image field.
                    public=json.loads(next(row['content']for row in rows if row['path']=='cloudbeaver-public.json'))
                    self.assertNotIn('retained_pgadmin_image',public)
                    spec=importlib.util.spec_from_file_location('normal_proxy_context',FRAMEWORK/'proxmox/applications/cloudbeaver-runtime.py')
                    helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
                    context=helper.context(public)
                    self.assertEqual((context.workspace,context.project),(Path(c.WORKSPACE),'homelab-db-tools'))
                self.assertEqual(projected,expected)


if __name__=='__main__':unittest.main()
