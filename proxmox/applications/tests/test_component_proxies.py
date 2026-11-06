"""App-specific units with common helpers mocked; three actual baseline renders."""
import copy
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
F = Path(Path(__file__).resolve().parents[3]).resolve()
sys.path[:0] = [str(F/'proxmox/applications'), str(F/'blueprints')]


import cloudbeaver as community
import mqtt_explorer as explorer
import monitoring
import component_runtime as core
BASELINE = json.loads((HERE/'proxy-compose-baseline.json').read_text())


def listener(service, port, address=None, published=None):
    value = {'service':service,'port':port,'protocol':'tcp','namespace':'app-network',
             'interface':'private','bind':'wildcard','actual_bind':'0.0.0.0'}
    if address is not None:
        value.update(publication_address=address, publish={'port':published or port,
            'scope':'guest-loopback' if address=='127.0.0.1' else 'guest-interface',
            **({} if address=='127.0.0.1' else {'interface':'web'})})
    return value


def descriptor(adapter):
    baseline = BASELINE[adapter]
    app = {'id':'instance-a','adapter':adapter,'lifecycle':'retained','project_name':baseline['name'],
           'identity':{'runtime_directory':'/opt/homelab-app/runtime',
             'services':{key:key for key in baseline['services']},
             'networks':{'default':'default'} if adapter=='zabbix' else
                 {'database_tools':'database_tools'} if adapter=='cloudbeaver' else {'explorer':'explorer'}},
           'containers':{},'software_selection':{'images':{}},'role_addresses':{},
           'properties':{},'resolved_connections':{},'storage_paths':{},'settings':{}}
    for name, service in baseline['services'].items():
        app['containers'][name] = {'memory_mib':int(service['mem_limit'][:-1]),
            'cpu_limit':service['cpus'],'pids_limit':service['pids_limit']}
        for key in ('user','cap_drop','read_only'):
            if key in service:app['containers'][name][key] = service[key]
        if 'security_opt' in service:app['containers'][name]['no_new_privileges']=True
        app['software_selection']['images'][name]={'image':service['image']}
    if adapter=='cloudbeaver':
        app['authentication_resolved']={'version':1}
        app['settings']={'heap_mib':1024, 'connections':{'metadata-pg':{'driver':'postgresql'}},
            'managed_connections':{'pg-admin':{'driver':'postgresql'},'maria-admin':{'driver':'mariadb'}},
            'mariadb_jdbc':{'version':'3.5.11','sha256':'42604178b9e57ec08ee0035079961516f086e455d0141f0b22c6eff29fb2fff4',
                'image_filename':'mariadb-java-client-3.5.10.jar'}}
        app['storage_paths']={'workspace':{'source':'/srv/homelab/data/cloudbeaver','target':'/opt/cloudbeaver/workspace','kind':'directory','read_only':False}}
        app['listeners']={'web':listener('auth_gateway',4180,'198.18.30.32',80),
                          'community':listener('cloudbeaver',8978)}
    elif adapter=='mqtt_explorer':
        app['origin_url']='https://mqtt-ui-a.example.invalid'
        app['settings']={'authentik_outpost_url':'http://198.18.30.25:9000','broker':{'type':'mqtt',
            'target':{'port':1883,'address':'198.18.30.37'},'hostname':'broker.mqtt',
            'account':{'credential_id':'synthetic-only'}}}
        app['storage_paths']={'data':{'source':'/srv/homelab/data/mqtt-explorer','target':'/app/data','kind':'directory','read_only':False}}
        app['listeners']={'web':listener('explorer_gateway',4180,'198.18.30.37',80),
                          'explorer':listener('mqtt_explorer',3000)}
    else:
        app['settings']={'database':{'host':'198.18.31.23','name':'zabbix','user':'zabbix'},
                         'database_credential':{'type':'monitoring-owned','server':'instance-a'}}
        app['listeners']={'server':listener('zabbix_server',10051,'198.18.25.36'),
            'web':listener('zabbix_web',8080,'198.18.25.36'),
            'local-web':listener('zabbix_web',8080,'127.0.0.1',8081)}
    return app


def guest(adapter):
    return {'timezone':'Australia/Brisbane' if adapter=='zabbix' else 'Etc/UTC',
            'memory_mib':4096,'os_reserve_mib':256}


def units(app):
    stack = ExitStack()
    stack.enter_context(mock.patch.object(core,'_service',side_effect=lambda a,name,g:{'environment':{},'volumes':[]}))
    # Shared socket/ownership/path validators are independently tested by F.
    stack.enter_context(mock.patch.object(core,'_ports',side_effect=lambda a,name:[
        row['publication_address']+':'+str(row['publish']['port'])+':'+str(row['port'])+'/tcp'
        for row in a['listeners'].values() if row['service']==name and 'publish'in row]))
    stack.enter_context(mock.patch.object(core,'_mounts',return_value=[]))
    stack.enter_context(mock.patch.object(core,'_runtime_mount',side_effect=lambda a,name,target:{
        'type':'bind','source':a['identity']['runtime_directory']+'/'+name,'target':target,'read_only':True,
        'bind':{'create_host_path':False}}))
    return stack


class CommunityTests(unittest.TestCase):
    def test_security_memory_health_and_owned_peer_name(self):
        app=descriptor('cloudbeaver');app['identity']['services']['cloudbeaver']='db_a'
        app['identity']['runtime_directory']='/opt/homelab-app/runtime/db-a'
        with units(app): result=core._cloudbeaver(app,guest('cloudbeaver'))
        self.assertEqual(result['auth_gateway']['depends_on'],{'db_a':{'condition':'service_healthy'}})
        self.assertEqual(result['cloudbeaver']['user'],'8978:8978')
        self.assertEqual(result['auth_gateway']['user'],'65532:65532')
        self.assertTrue(result['auth_gateway']['read_only'])
        self.assertEqual(result['cloudbeaver']['cap_drop'],['ALL'])
        health=result['cloudbeaver']['healthcheck']['test']
        self.assertIn('--postgresql',health);self.assertEqual(health[-3:],['3.5.11',app['settings']['mariadb_jdbc']['sha256'],'mariadb-java-client-3.5.10.jar'])
        jdbc=[row for row in result['cloudbeaver']['volumes'] if row['target'].startswith('/opt/cloudbeaver/drivers/')]
        self.assertEqual(jdbc[0]['source'],'/opt/homelab-app/runtime/db-a/mariadb-java-client-3.5.11.jar')
        self.assertNotIn('ports',result['cloudbeaver'])

    def test_fresh_managed_only_needs_no_retired_pgadmin_metadata(self):
        app=descriptor('cloudbeaver');app['lifecycle']='fresh';app['settings']['connections']={}
        with units(app):result=core._cloudbeaver(app,guest('cloudbeaver'))
        self.assertIn('healthcheck',result['cloudbeaver'])
        app['settings']['managed_connections']={};app['settings'].pop('mariadb_jdbc')
        with units(app),self.assertRaises(ValueError):core._cloudbeaver(app,guest('cloudbeaver'))

    def test_metadata_only_and_managed_pg_only_omit_unselected_maria_driver(self):
        for managed in ({}, {'pg-admin': {'driver': 'postgresql'}}):
            app=descriptor('cloudbeaver');app['settings']['managed_connections']=managed
            app['settings'].pop('mariadb_jdbc')
            with self.subTest(managed=bool(managed)),units(app):
                result=core._cloudbeaver(app,guest('cloudbeaver'))
            server=result['cloudbeaver'];health=server['healthcheck']['test']
            self.assertEqual('--postgresql' in health,bool(managed))
            self.assertFalse(any(row['target'].startswith('/opt/cloudbeaver/drivers/') for row in server['volumes']))
            self.assertEqual(any(row['target'].endswith('CloudBeaverDatabaseHealth.java') for row in server['volumes']),bool(managed))

    def test_app_auth_memory_workspace_and_process_failures(self):
        changes=[lambda a:a.pop('authentication_resolved'),lambda a:a['settings'].update(heap_mib=1536),
            lambda a:a['storage_paths']['workspace'].update(read_only=True),
            lambda a:a.update(storage_paths={}),lambda a:a['containers']['auth_gateway'].update(user='root'),
            lambda a:a['containers']['cloudbeaver'].update(cap_add=['NET_ADMIN']),
            lambda a:a['listeners'].pop('web'),lambda a:a['listeners']['community'].update(port=8080),
            lambda a:a['listeners']['community'].update(publication_address='198.18.30.32',publish={'port':8978})]
        for change in changes:
            app=descriptor('cloudbeaver');change(app)
            with self.subTest(change=change),units(app),self.assertRaises(ValueError):core._cloudbeaver(app,guest('cloudbeaver'))

    def test_oidc_upstream_names_are_explicit_with_unchanged_default(self):
        value={'auth_headers':{'user':'X-User','team':'X-Team'},'public_url':'https://db.example.invalid'}
        foundation={'user_claim':'preferred_username','oauth_name':'SSO','oauth_client_id':'client',
                    'oidc_issuer':'https://sso.example.invalid/application/o/db/'}
        default,_=community.gateway(value,foundation,b'x'*32)
        custom,_=community.gateway(value,foundation,b'x'*32,server_service='db_a')
        self.assertEqual(default['upstreamConfig']['upstreams'][0]['uri'],'http://cloudbeaver:8978')
        self.assertEqual(custom['upstreamConfig']['upstreams'][0]['uri'],'http://db_a:8978')
        self.assertFalse(custom['providers'][0]['oidcConfig']['insecureSkipNonce'])
        with self.assertRaises(ValueError):community.gateway(value,foundation,b'x'*32,server_service='outside/peer')


class ExplorerTests(unittest.TestCase):
    def test_selected_backend_alias_not_gateway_address_and_log_suppression(self):
        app=descriptor('mqtt_explorer');app['settings']['broker']['target']['address']='198.19.99.9'
        app['identity']['services']['mqtt_explorer']='client_a'
        with units(app):result=core._mqtt_explorer(app,guest('mqtt_explorer'))
        self.assertEqual(result['mqtt_explorer']['extra_hosts'],{'broker.mqtt':'198.19.99.9'})
        self.assertNotIn('extra_hosts',result['explorer_gateway'])
        self.assertEqual(result['explorer_gateway']['depends_on'],{'client_a':{'condition':'service_healthy'}})
        self.assertEqual(result['mqtt_explorer']['command'],BASELINE['mqtt_explorer']['services']['mqtt_explorer']['command'])
        self.assertNotIn('ports',result['mqtt_explorer'])
        self.assertTrue(result['mqtt_explorer']['read_only'])
        self.assertEqual(result['mqtt_explorer']['environment']['ALLOWED_ORIGINS'],app['origin_url'])

    def test_external_credential_source_is_explicit_without_an_account_inference(self):
        app=descriptor('mqtt_explorer');app['settings']['broker'].pop('account')
        app['settings']['broker']['credential']={'principal':'external_user','secret':'external-secret'}
        with units(app):result=core._mqtt_explorer(app,guest('mqtt_explorer'))
        self.assertEqual(result['mqtt_explorer']['extra_hosts'],{'broker.mqtt':'198.18.30.37'})

    def test_auth_backend_data_and_process_boundaries_refuse(self):
        changes=[lambda a:a.pop('origin_url'),lambda a:a.update(origin_url='http://ui.example.invalid'),
            lambda a:a['settings'].pop('authentik_outpost_url'),lambda a:a['settings']['broker'].pop('hostname'),
            lambda a:a['settings']['broker'].pop('account'),lambda a:a['settings']['broker']['target'].update(port=8883),
            lambda a:a['storage_paths']['data'].update(read_only=True),lambda a:a['listeners'].pop('web'),
            lambda a:a['containers']['mqtt_explorer'].update(user='root'),
            lambda a:a['listeners']['explorer'].update(publication_address='198.18.30.37',publish={'port':3000})]
        for change in changes:
            app=descriptor('mqtt_explorer');change(app)
            with self.subTest(change=change),units(app),self.assertRaises(ValueError):core._mqtt_explorer(app,guest('mqtt_explorer'))

    def test_file_provider_backend_uses_the_same_owned_instance_name(self):
        value={'public_url':'https://mqtt-ui.example.invalid','authentik_outpost_url':'http://198.18.30.25:9000'}
        _,default=explorer.configuration(value);_,custom=explorer.configuration(value,explorer_service='client_a')
        self.assertEqual(default['http']['services']['explorer']['loadBalancer']['servers'],[{'url':'http://mqtt_explorer:3000'}])
        self.assertEqual(custom['http']['services']['explorer']['loadBalancer']['servers'],[{'url':'http://client_a:3000'}])
        self.assertIn('authentik',custom['http']['routers']['explorer']['middlewares'])
        with self.assertRaises(ValueError):explorer.configuration(value,explorer_service='outside/peer')


class ZabbixTests(unittest.TestCase):
    def test_owned_credential_peer_names_tls_and_default_image_identity(self):
        app=descriptor('zabbix');app['identity']['services']['zabbix_server']='server_a'
        with units(app):result=core._zabbix(app,guest('zabbix'))
        self.assertEqual(result['zabbix_web']['depends_on'],{'server_a':{'condition':'service_started'}})
        self.assertEqual(result['zabbix_web']['environment']['ZBX_SERVER_HOST'],'server_a')
        self.assertEqual(result['zabbix_server']['environment']['ZBX_DBTLSCONNECT'],'required')
        self.assertEqual(result['zabbix_web']['environment']['ZBX_DB_ENCRYPTION'],'true')
        self.assertEqual(result['zabbix_server']['environment']['POSTGRES_PASSWORD_FILE'],'/run/secrets/database-password')
        self.assertNotIn('user',result['zabbix_server'])
        self.assertEqual(result['zabbix_web']['ports'],['198.18.25.36:8080:8080','127.0.0.1:8081:8080'])

    def test_selected_saml_preserves_strict_settings_and_owned_login_mount(self):
        app=descriptor('zabbix');app['authentication_resolved']={'default_login':'saml'}
        with units(app),mock.patch.object(monitoring,'saml_settings',return_value={'strict':True}) as saml:
            result=core._zabbix(app,guest('zabbix'))
        saml.assert_called_once_with(app['authentication_resolved'])
        self.assertEqual(result['zabbix_web']['environment']['ZBX_SSO_SETTINGS'],'{"strict":true}')
        self.assertEqual(result['zabbix_web']['volumes'][-1]['target'],'/usr/share/zabbix/local/app/views/general.login.php')

    def test_credential_scope_unselected_file_mount_and_image_process_drift_refuse(self):
        changes=[lambda a:a['settings'].pop('database_credential'),
            lambda a:a['settings']['database_credential'].update(server='peer'),
            lambda a:a.update(secret_bindings={'database_password':{}}),lambda a:a['listeners'].pop('server'),
            lambda a:a['settings']['database'].update(user='postgres'),
            lambda a:a.update(storage_paths={'unexpected':{}}),
            lambda a:a['containers']['zabbix_server'].update(user='root'),
            lambda a:a['software_selection']['images']['zabbix_web'].update(image='example/foreign@sha256:'+'a'*64),
            lambda a:a['listeners']['web'].update(port=443)]
        for change in changes:
            app=descriptor('zabbix');change(app)
            with self.subTest(change=change),units(app),self.assertRaises(ValueError):core._zabbix(app,guest('zabbix'))
        app=descriptor('zabbix');app['settings'].pop('database_credential');app['secret_bindings']={'database_password':{'type':'file','path':'/run/synthetic/password'}}
        with units(app):self.assertIn('zabbix_web',core._zabbix(app,guest('zabbix')))


class BaselineIntegrationTests(unittest.TestCase):
    def test_each_real_handler_and_shared_helpers_equal_complete_immutable_service_fields(self):
        for adapter,expected in BASELINE.items():
            with self.subTest(adapter=adapter):
                app=descriptor(adapter)
                cfg={'schema':'homelab-component-runtime-v1','guest':guest(adapter),'applications':{'instance-a':app}}
                actual=next(iter(core.compositions(cfg).values()))
                self.assertEqual(actual,expected)

    def test_two_instances_share_neither_helper_names_nor_runtime_leaf_paths(self):
        for adapter in BASELINE:
            app=descriptor(adapter);app['lifecycle']='fresh';app['project_name']='project-a'
            app['identity']['runtime_directory']='/opt/homelab-app/runtime/app-a'
            app['identity']['services']={key:'a_'+key for key in app['identity']['services']}
            other=copy.deepcopy(app);other['id']='instance-b';other['project_name']='project-b'
            other['identity']['runtime_directory']='/opt/homelab-app/runtime/app-b'
            other['identity']['services']={key:'b_'+key for key in other['identity']['services']}
            if adapter=='zabbix':other['settings']['database_credential']['server']='instance-b'
            cfg={'schema':'homelab-component-runtime-v1','guest':dict(guest(adapter),memory_mib=8192),
                 'applications':{'a':app,'b':other}}
            documents=core.compositions(cfg)
            self.assertEqual(set(documents),{'project-a','project-b'})
            for project,prefix in [('project-a','a_'),('project-b','b_')]:
                for service in documents[project]['services'].values():
                    self.assertTrue(all(name.startswith(prefix) for name in service.get('depends_on',{})))
                    self.assertTrue(all(row['source'].startswith('/opt/homelab-app/runtime/app-'+prefix[0])
                        for row in service['volumes'] if row['source'].startswith('/opt/homelab-app/runtime/')))


if __name__=='__main__':unittest.main()
