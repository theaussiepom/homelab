"""Selected file ownership units and actual immutable-payload integrations."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import application_contract as contract
import component_prepare as prepare
import component_payload
import managed_credentials
from private_io import encoded,read_json,write_new
from test_component_proxy_files import cloud,managed,zabbix,explorer


def reserve(app):
    app.setdefault('id','selected');app.setdefault('guest','example')
    app['runtime_files']={'app':app['id'],'guest':app['guest'],
        'directory':app['identity']['runtime_directory'],
        'files':sorted(contract.runtime_files(app)),'directory_mounts':[]}
    return app


class RuntimeFileOwnershipTests(unittest.TestCase):
    def test_pega_existing_key_parity_runs_before_any_generic_copy_or_start(self):
        import yaml
        tasks=yaml.safe_load((Path(prepare.__file__).parent/'ansible/tasks/component-compose.yml').read_text())
        guard=next(i for i,row in enumerate(tasks) if row.get('ansible.builtin.include_tasks')=='pegaprox-runtime.yml')
        copies=[i for i,row in enumerate(tasks) if row.get('register')=='component_runtime_install']
        starts=[i for i,row in enumerate(tasks) if row.get('register')=='component_start']
        self.assertLess(guard,min(copies+starts))
        self.assertEqual(tasks[guard]['when'],"component_application.adapter == 'pegaprox'")
    def test_real_proxy_builders_emit_only_reserved_selected_leaves(self):
        app=cloud();records=managed(app)
        ca=b'-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n'
        choices=[(app,{'client_secret':b'synthetic-client-entropy'*3},records,None),
                 (explorer()[0],{},explorer()[1],None),
                 (zabbix(),{'database_password':b'fixture-password\n'},{},ca)]
        for app,values,records,ca in choices:
            with self.subTest(adapter=app['adapter']),patch.object(prepare.component_proxy_files,
                    '_public_source',return_value='fixed-source\n'):
                reserve(app);payload={}
                rows=prepare.component_proxy_files.files(app,secrets=values,records=records,public_ca=ca)
                installed=prepare.install_rows(app,rows,payload)
                artifact={'mariadb-java-client-3.5.11.jar'} if app['adapter']=='cloudbeaver' else set()
                self.assertEqual(set(payload)|artifact,contract.runtime_files(app))
                self.assertEqual({r['destination'] for r in installed},
                    {app['identity']['runtime_directory']+'/'+name for name in payload})
                self.assertTrue(all(isinstance(raw,bytes) for raw in payload.values()))

    def test_registry_covers_dynamic_driver_and_route_ca_leaves_without_directory_grants(self):
        app=cloud();managed(app);files=contract.runtime_files(app)
        self.assertIn('CloudBeaverDatabaseHealth.java',files)
        self.assertIn('cloudbeaver-admin-connections.json',files)
        self.assertIn('mariadb-java-client-3.5.11.jar',files)
        del app['settings']['managed_connections'];del app['settings']['mariadb_jdbc']
        self.assertNotIn('CloudBeaverDatabaseHealth.java',contract.runtime_files(app))
        route={'adapter':'traefik','settings':{'route_ca_files':{
            'selected':{'filename':'route-selected.pem','source':'/never-read/ca'}}}}
        self.assertIn('route-selected.pem',contract.runtime_files(route))
        monitor=zabbix();monitor['authentication_resolved']={'default_login':'saml'}
        self.assertIn('saml-login.php',contract.runtime_files(monitor))

    def test_foreign_duplicate_drift_and_invalid_row_metadata_refuse(self):
        app=reserve(cloud());row={'path':'cloudbeaver.conf','content':b'fixed','uid':8978,'gid':8978,'mode':'0400'}
        complete=[dict(row,path=name) for name in sorted(contract.runtime_files(app))]
        for change in ({'path':'peer-secret'},{'path':'../peer'}, {'uid':True},{'gid':-1},
                       {'mode':'0644'},{'content':None},{'extra':True}):
            with self.subTest(fields=list(change)),self.assertRaises(ValueError):
                prepare.install_rows(app,[dict(complete[0],**change),*complete[1:]],{})
        with self.assertRaises(ValueError):prepare.install_rows(app,[*complete,complete[0]],{})
        with self.assertRaises(ValueError):prepare.install_rows(app,complete[:-1],{})
        for field,value in [('app','peer'),('directory','/opt/homelab-app/runtime/peer'),('files',[])]:
            selected=copy.deepcopy(app);selected['runtime_files'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                prepare.install_rows(selected,[row],{})


class SelectedPreparationTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o700)
        continuity=patch.object(prepare.component_continuity,'verify')
        continuity.start();self.addCleanup(continuity.stop)
        self.inputs=self.root/'inputs';self.inputs.mkdir(mode=0o700)
        self.state=self.root/'state';self.state.mkdir(mode=0o700)
        self.runtime=self.inputs/'component-runtime.json'
        self.cfg={'app':{},'paths':{'state_root':str(self.state)},'deployment':{
            'runtime_file':str(self.runtime),'input_directory':str(self.inputs),'input_identity':'a'*64}}

    def save(self,apps):
        write_new(self.runtime,encoded({'applications':apps}))

    def test_two_same_adapter_inputs_remain_scoped_and_dollars_literal(self):
        apps={}
        for name,value in [('first',b'first-$literal'),('second',b'peer-$value')]:
            source=self.root/(name+'-token');write_new(source,value)
            apps[name]={'id':name,'adapter':'node_red','input_sources':{
                'api_token':{'type':'file','path':str(source)}},'project_file':'compose.yml',
                'identity':{'services':{'node_red':name}}}
        write_new(self.inputs/'compose.yml',encoded({'services':{'first':{},'second':{}}}))
        self.save(apps)
        # The peer's invalid private permissions cannot affect this phase.
        (self.root/'second-token').chmod(0o644)
        first=prepare.prepare(self.cfg,'first',{},attempt=object())
        raw=(first.directory/'environment.yml').read_bytes()
        self.assertEqual(json.loads(raw)['services'],{'first':{'environment':{'NODE_RED_API_TOKEN':'first-$$literal'}}})
        self.assertNotIn(b'peer-',raw)
        before={p.name:(p.stat().st_ino,p.read_bytes()) for p in first.directory.iterdir()}
        self.assertEqual(prepare.prepare(self.cfg,'first',{},attempt=object()).check(),first.check())
        self.assertEqual(before,{p.name:(p.stat().st_ino,p.read_bytes()) for p in first.directory.iterdir()})
        (self.root/'second-token').chmod(0o600)
        second=prepare.prepare(self.cfg,'second',{},attempt=object())
        self.assertIn(b'peer-$$value',(second.directory/'environment.yml').read_bytes())
        self.assertNotIn(b'first-',(second.directory/'environment.yml').read_bytes())

    def test_shared_base_peer_env_requirement_and_multiline_values_refuse(self):
        with self.assertRaises(ValueError):prepare.overlay({'adapter':'bitwarden'}, {'KEY':'line\nbreak'})
        source=self.root/'token';write_new(source,b'fixture')
        app={'id':'first','adapter':'node_red','input_sources':{'api_token':{'type':'file','path':str(source)}},
             'identity':{'services':{'node_red':'first'}},'project_file':'compose.yml'}
        self.save({'first':app});write_new(self.inputs/'compose.yml',encoded({'services':{
            'first':{},'peer':{'env_file':'/never-read-peer'}}}))
        with self.assertRaisesRegex(ValueError,'peer late environment'):prepare.prepare(self.cfg,'first',{},attempt=object())
        self.assertFalse((self.inputs/'applications/first').exists())

    def test_consumer_cannot_create_missing_producer_credential_or_rebind_owner(self):
        app=cloud();records=managed(app);payload={}
        before=list(self.state.iterdir())
        with self.assertRaises((ValueError,OSError)):prepare.account_records(self.cfg,app,payload)
        self.assertEqual(before,list(self.state.iterdir()));self.assertEqual(payload,{})
        for name,row in records.items():managed_credentials.credential(self.state,name,row['owner'])
        actual=prepare.account_records(self.cfg,app,payload)
        self.assertEqual(set(actual),set(records));self.assertEqual(len(payload),2)
        selected=copy.deepcopy(app);selected['settings']['managed_connections']['postgresql-admin']['owner']['username']='different'
        with self.assertRaises(ValueError):prepare.account_records(self.cfg,selected,{})

    def test_real_cloud_files_include_uppercase_owned_sources_in_immutable_payload(self):
        app=reserve(cloud());app['input_sources']={'client_secret':{'type':'environment','name':'ORIGINAL'}}
        self.save({'selected':app})
        with patch.object(prepare.component_proxy_files,'_public_source',return_value='fixed source\n'):
            selected=prepare.prepare(self.cfg,'selected',{'HOMELAB_APP_SECRET_CLOUDBEAVER_CLIENT_SECRET':'synthetic-client-secret'*3},attempt=object())
        selected.check()
        self.assertEqual((selected.directory/'CloudBeaverHealth.java').read_bytes(),b'fixed source\n\n')
        rows=read_json(selected.directory/'runtime-files.json',private=True)
        self.assertEqual({row['source'] for row in rows},contract.runtime_files(app))
        self.assertFalse(any('content' in row for row in rows))

    def test_retained_vault_has_no_runtime_leaf_requirement_and_preserves_exact_environment_bytes(self):
        from test_component_private_inputs import vault
        app,raw,_=vault();source=self.root/'vault-environment.json';write_new(source,raw)
        app.update(id='vault',identity={'services':{'bitwarden':'vault'}},project_file='compose.yml',
                   input_sources={'runtime_environment':{'type':'file','path':str(source)}})
        self.save({'vault':app});write_new(self.inputs/'compose.yml',encoded({'services':{'vault':{'environment':{}}}}))
        selected=prepare.prepare(self.cfg,'vault',{},attempt=object())
        self.assertEqual((selected.directory/'bitwarden-environment.json').read_bytes(),raw)
        self.assertEqual(read_json(selected.directory/'runtime-files.json',private=True),[])
        self.assertIn('BW_DB_PASSWORD',read_json(selected.directory/'environment.yml',private=True)['services']['vault']['environment'])


if __name__=='__main__':unittest.main()
