"""Current component account/connection integration and pure native HBA guards.

Public synthetic component collaborators supply endpoint/role metadata.  There
is no fixed guest compiler, legacy Cloud fixture, private parser or target call.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

F=Path(os.environ.get('HOMELAB_FRAMEWORK',Path(__file__).resolve().parents[3]))
sys.path[:0]=[str(F/'proxmox/applications'),str(F/'blueprints')]
import cloudbeaver
import component_accounts
import component_connections
from component_errors import ComponentError
import component_prepare
import component_properties
import component_proxy_files
import component_runtime
from component_sources import named
import database_admin as m
import database_hba
import managed_credentials
from private_io import encoded
from protocol_component_fixtures import cloudbeaver_app,document


def source():
    cloud=cloudbeaver_app({'oidc_issuer':'https://sso.example.invalid/oidc/',
        'oauth_client_id':'fixture-client','oauth_name':'Synthetic SSO','user_claim':'preferred_username'},
        {'public_url':'https://db.example.invalid'},image='example/cloud@sha256:'+'b'*64,
        gateway_image='example/gateway@sha256:'+'b'*64)
    cloud.update(id='cloud',guest='client',profile='cloud',origin_url=cloud['settings']['public_url'],interfaces={key+'_interface':{'interface':key}
        for key in ('web','postgresql','mariadb')},role_addresses={'web_interface':'198.18.30.32',
            'postgresql_interface':'198.18.11.81','mariadb_interface':'198.19.12.83'})
    cloud['properties']={'server_name':'Database Tools','recovery_admin':'local-recovery','heap_mib':1024,
        'auth_headers':{'user':'X-User','team':'X-Team'},
        'connections':{'postgresql':{'name':'PostgreSQL','database':'postgres','sslmode':'prefer'},
            'mariadb':{'name':'MariaDB','database':''},'postgresql-admin':{'name':'postgresql administrator','database':'postgres'},
            'mariadb-admin':{'name':'mariadb administrator','database':''}},
        'mariadb_jdbc':{'version':'3.5.11','sha256':'b'*64,'image_filename':'mariadb-java-client-3.5.10.jar'}}
    apps={'cloud':cloud};guests={'client':{'context':'primary','identity':{'vmid':902,'hostname':'client'}}}
    site={'contexts':{'primary':{'node':'fixture-node'}},'accounts':{},'connections':{},'secret_sources':{}}
    declarations={};addresses={'postgresql':'198.18.11.80','mariadb':'198.19.12.82'}
    for engine,vmid in (('postgresql',901),('mariadb',903)):
        apps[engine]={'id':engine,'adapter':engine,'guest':engine,'profile':'native','interfaces':{}}
        guests[engine]={'context':'primary','identity':{'vmid':vmid,'hostname':engine}}
        site['secret_sources'][engine]={'type':'generated','credential_id':'fixture-'+engine}
        site['accounts'][engine]={'adapter':engine+'-admin','owner':'cloud','target':{'app':engine,'endpoint':'sql_endpoint'},
            'principal':engine+'_administrator','credential':engine,'access':'server-administration','lifecycle':'create-once'}
        for suffix in ('','-admin'):
            role=engine+suffix
            declarations[role]={'type':engine,'required':True,'accounts':[engine+'-admin'],'readiness':['start']}
            site['connections'][role]={'consumer':{'app':'cloud','connection':role},'target':{'app':engine,'endpoint':'sql_endpoint'},
                'source_interface':engine+'_interface','readiness':'start'}
            if suffix:site['connections'][role]['account']=engine
    def endpoint(ref):
        if set(ref)!={'app','endpoint'}or ref['app']not in addresses or ref['endpoint']!='sql_endpoint':raise ComponentError('component.reference')
        engine=ref['app']
        return {'app':engine,'guest':engine,'protocol':'tcp','port':m.KINDS[engine],'address':addresses[engine]}
    resolver=SimpleNamespace(apps=apps,guests=guests,site=site,library={'app_profiles':{
        'cloud':{'connections':declarations},'native':{}}},policy={'transport':{}},endpoint=endpoint,
        role_address=lambda app,role:app['role_addresses'][role],
        image_values=lambda:{'old-client':{'image':'dpage/pgadmin4@sha256:'+'a'*64}})
    return resolver,SimpleNamespace(hostname=lambda reference,target:'database.example.invalid')


def bind(resolver,exposures):
    connections=component_connections.bind(resolver,exposures)
    settings=component_properties.bind(resolver)
    resolver.apps['cloud']['settings']=settings['cloud']
    accounts=component_accounts.bind(resolver,connections['accounts'])
    return connections,accounts


def composition():
    resolver,exposures=source();bind(resolver,exposures);return resolver


class DatabaseAdministratorTests(unittest.TestCase):
    def test_postgresql_hba_wildcard_and_reserved_roles_refuse_before_configuration(self):
        for username in ('all','public','none','pg_','pg_fixture'):
            resolver,exposures=source();resolver.site['accounts']['postgresql']['principal']=username
            before=copy.deepcopy(resolver.site)
            with self.subTest(username=username),self.assertRaises(ComponentError):bind(resolver,exposures)
            self.assertEqual(resolver.site,before)
            self.assertNotIn('database_administrators',resolver.apps['postgresql'])

    def test_role_refusal_preserves_literal_postgresql_names_and_other_engine_accounts(self):
        for engine,names in (('postgresql',('fixture_admin','pgadmin','all_admin','current_user','current_role','session_user')),
                             ('mariadb',('all','public','none','pg_fixture'))):
            for username in names:
                resolver,exposures=source();resolver.site['accounts'][engine]['principal']=username
                with self.subTest(engine=engine,username=username):
                    bind(resolver,exposures)
                    self.assertEqual(resolver.apps[engine]['database_administrators'][engine]['username'],username)

    def test_managed_maria_driver_is_one_closed_official_artifact_with_exact_readonly_mount(self):
        resolver=composition();app=resolver.apps['cloud'];value=app['settings'];artifact=cloudbeaver.jdbc(value)
        self.assertEqual(artifact['url'],'https://repo.maven.apache.org/maven2/org/mariadb/jdbc/mariadb-java-client/3.5.11/mariadb-java-client-3.5.11.jar')
        self.assertEqual(artifact['source'],'/opt/homelab-app/runtime/mariadb-java-client-3.5.11.jar')
        service=document(app)['services']['cloudbeaver']
        self.assertEqual([row for row in service['volumes']if row['target'].startswith('/opt/cloudbeaver/drivers/mariadb/')],
            [{'type':'bind','source':artifact['source'],'target':artifact['target'],'read_only':True,'bind':{'create_host_path':False}}])
        self.assertEqual(service['healthcheck']['test'][-4:],['--postgresql',artifact['version'],artifact['sha256'],artifact['image_filename']])
        for key,bad in (('version','3.5.10'),('version','latest'),('version',True),('sha256','short'),('sha256',None),
                        ('image_filename','../foreign.jar'),('image_filename','other.jar'),('url','https://foreign.invalid/driver.jar')):
            changed=copy.deepcopy(value);changed['mariadb_jdbc'][key]=bad
            with self.subTest(key=key,bad=bad),self.assertRaises(ValueError):cloudbeaver.jdbc(changed)
        missing=copy.deepcopy(value);missing.pop('mariadb_jdbc')
        with self.assertRaises(ValueError):cloudbeaver.jdbc(missing)
        app=copy.deepcopy(app);app['settings']['managed_connections'].pop('mariadb-admin')
        with self.assertRaises(ValueError):cloudbeaver.jdbc(app['settings'])
        app['settings'].pop('mariadb_jdbc')
        self.assertIsNone(cloudbeaver.jdbc(app['settings']))
        self.assertEqual(document(app)['services']['cloudbeaver']['healthcheck']['test'][-1],'--postgresql')
        app['settings']['managed_connections']={}
        self.assertNotIn('--postgresql',document(app)['services']['cloudbeaver']['healthcheck']['test'])

    def test_resolved_topology_links_only_new_ids_and_preserves_metadata_policies(self):
        resolver,exposures=source();metadata=copy.deepcopy(resolver.apps['cloud']['properties']['connections'])
        result,accounts=bind(resolver,exposures);cloud=resolver.apps['cloud']['settings']
        self.assertEqual(set(cloud['connections']),{'postgresql','mariadb'})
        self.assertEqual(set(cloud['managed_connections']),{'postgresql-admin','mariadb-admin'})
        for engine in m.KINDS:
            item=resolver.apps[engine]['database_administrators'][engine]
            connection=m.connections(cloud)[engine+'-admin']
            self.assertEqual(item['owner'],connection['owner'])
            self.assertEqual(connection['owner']['source_vmid'],902)
            self.assertEqual(connection['owner']['database_vmid'],resolver.guests[engine]['identity']['vmid'])
            self.assertEqual(connection['username'],item['username']);self.assertEqual(connection['port'],m.KINDS[engine])
            self.assertEqual(item['credential_file'],'${inputs}/applications/'+engine+'/managed-fixture-'+engine+'.json')
            self.assertEqual(connection['credential_file'],'${inputs}/applications/cloud/managed-fixture-'+engine+'.json')
            self.assertEqual({key:cloud['connections'][engine][key]for key in metadata[engine]},metadata[engine])
        self.assertEqual(len(resolver.apps['cloud']['resolved_connections']),4)
        self.assertEqual(result['guest_dependencies']['client'],['postgresql','mariadb'])

    def test_cross_guest_orphan_duplicate_and_wrong_engine_bindings_refuse(self):
        changes=[lambda r:r.site['accounts']['postgresql'].update(owner='missing'),
            lambda r:r.site['accounts']['postgresql'].update(owner='mariadb'),
            lambda r:r.site['secret_sources']['mariadb'].update(credential_id='fixture-postgresql'),
            lambda r:r.site['connections']['postgresql-admin'].update(account='missing'),
            lambda r:r.site['connections']['postgresql-admin'].update(target={'app':'mariadb','endpoint':'sql_endpoint'}),
            lambda r:r.site['connections'].pop('mariadb-admin'),
            lambda r:r.guests['postgresql'].update(context='foreign')]
        for change in changes:
            resolver,exposures=source();change(resolver)
            with self.subTest(change=change),self.assertRaises((ValueError,KeyError)):bind(resolver,exposures)
        resolver,exposures=source();endpoint=resolver.endpoint
        resolver.endpoint=lambda ref:dict(endpoint(ref),port=3306)if ref['app']=='postgresql'else endpoint(ref)
        with self.assertRaises(ValueError):bind(resolver,exposures)

    def test_private_credentials_are_independent_but_exactly_shared_with_their_declared_client(self):
        resolver=composition();cloud=resolver.apps['cloud']
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);root.chmod(0o700);producer={}
            for engine in m.KINDS:
                item=resolver.apps[engine]['database_administrators'][engine]
                _,producer[engine]=managed_credentials.payload(root,item['credential_id'],item['owner'],root/engine)
            payload={};records=component_prepare.account_records({'paths':{'state_root':str(root)}},cloud,payload)
            for engine in m.KINDS:
                filename='managed-fixture-'+engine+'.json';self.assertEqual(payload[filename],producer[engine][filename])
            self.assertNotEqual(records['fixture-postgresql']['password'],records['fixture-mariadb']['password'])
            rows=component_proxy_files.files(cloud,secrets={'client_secret':b'synthetic-oidc-client-secret-'*2},records=records,public_ca=None)
            by_name={row['path']:row for row in rows};native=by_name['cloudbeaver-admin-connections.json']
            public=json.loads(by_name['cloudbeaver-public.json']['content']);document_=json.loads(native['content'])
            self.assertEqual(document_['connections']['postgresql-admin']['configuration']['properties'],{'sslmode':'require','channelBinding':'require','requireAuth':'scram-sha-256'})
            self.assertEqual(document_['connections']['mariadb-admin']['configuration']['properties'],{'sslMode':'verify-full'})
            self.assertEqual(public['managed_sha256'],hashlib.sha256(native['content'].encode()).hexdigest())
            self.assertEqual(public['cloudbeaver_image'],cloud['software_selection']['images']['cloudbeaver']['image'])
            self.assertEqual((native['uid'],native['mode']),(0,'0400'))
            repeated={};self.assertEqual(component_prepare.account_records({'paths':{'state_root':str(root)}},cloud,repeated),records)
            self.assertEqual(repeated,payload)
            foreign=copy.deepcopy(cloud);foreign['settings']['managed_connections']['postgresql-admin']['owner']['username']='foreign'
            with self.assertRaises(ValueError):component_prepare.account_records({'paths':{'state_root':str(root)}},foreign,{})
            with tempfile.TemporaryDirectory()as absent:
                with self.assertRaises((ValueError,OSError)):component_prepare.account_records({'paths':{'state_root':absent}},cloud,{})

    def test_hba_is_a_finite_source_prefix_and_original_tail_is_byte_exact(self):
        resolver=composition();values=resolver.apps['postgresql']['database_administrators']
        old='local all postgres peer\nhost all all 127.0.0.1/32 scram-sha-256\n';before=copy.deepcopy(values)
        current=database_hba.administrators(old,values)
        prefix=('# homelab managed administrator accounts\n'
            'hostssl all,replication postgresql_administrator 198.18.11.81/32 scram-sha-256\n'
            'local all,replication postgresql_administrator reject\n'
            'host all,replication postgresql_administrator 0.0.0.0/0 reject\n'
            'host all,replication postgresql_administrator ::/0 reject\n')
        self.assertEqual(current,prefix+old);self.assertEqual(values,before)
        with self.assertRaises(ValueError):database_hba.administrators(current,values)
        self.assertEqual(database_hba.administrators(old,{}),old)

    def test_closed_account_connection_ownership_and_input_contracts(self):
        for changes in ({'principal':"bad'"},{'access':'read-only'},{'lifecycle':'rotate'},
                        {'credential_file':'/foreign/input'},{'transport':'plaintext'}):
            resolver,exposures=source();resolver.site['accounts']['postgresql'].update(changes)
            with self.subTest(changes=changes),self.assertRaises(ValueError):bind(resolver,exposures)
        for credential in ('../key','bad/key',''):
            resolver,exposures=source();resolver.site['secret_sources']['postgresql']['credential_id']=credential
            with self.subTest(credential=credential),self.assertRaises(ValueError):bind(resolver,exposures)
        for collection in (None,[],{'bad id':{}}):
            with self.subTest(collection=type(collection).__name__),self.assertRaises(ComponentError):named(collection)
        for duplicate in (False,True):
            resolver,exposures=source()
            if duplicate:resolver.site['accounts']['duplicate']=copy.deepcopy(resolver.site['accounts']['postgresql'])
            else:resolver.site['accounts']={}
            with self.assertRaises(ValueError):bind(resolver,exposures)
        value=composition().apps['cloud']['settings'];original=copy.deepcopy(value)
        for key,bad in (('host','198.18.11.99'),('port',3306),('username','foreign'),('transport','plaintext')):
            changed=copy.deepcopy(original);changed['managed_connections']['postgresql-admin'][key]=bad
            with self.subTest(key=key),self.assertRaises(ValueError):m.connections(changed)
        account=original['managed_connections']['postgresql-admin']
        for field,bad in (('database_vmid',True),('source_vmid',1),('source_address','127.0.0.1'),
                ('source_address','invalid-address'),('source_address',False),('engine',[]),('purpose','other')):
            own=copy.deepcopy(account['owner']);own[field]=bad
            with self.subTest(field=field),self.assertRaises(ValueError):m.owner(own)
        duplicate=copy.deepcopy(original);duplicate['managed_connections']['postgresql']=duplicate['managed_connections'].pop('postgresql-admin')
        with self.assertRaises(ValueError):m.connections(duplicate)
        self.assertEqual(m.connections({'connections':{}}),{})


if __name__=='__main__':unittest.main()
