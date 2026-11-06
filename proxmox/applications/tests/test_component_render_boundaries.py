"""Pure app units with mocked common builders and finite real render integrations."""
import copy
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

F=Path(os.environ.get('HOMELAB_FRAMEWORK',Path(__file__).resolve().parents[3])).resolve()
sys.path[:0]=[str(F/'blueprints'),str(F/'proxmox/applications'),str(F/'proxmox/applications/tests')]
import component_checks as checks
import component_foundation_files as foundation_files
import component_proxy_files as proxy_files
import component_runtime as runtime
import database_hba
import discovery
from component_errors import ComponentError
import test_component_checks as check_fixtures
import test_component_foundation_files as foundation_fixtures
import test_component_handlers as app_fixtures
import test_component_native_namespace as native_fixtures
import test_component_proxies as proxy_fixtures
import test_component_proxy_files as file_fixtures


class CheckAndFileBoundaries(unittest.TestCase):
    def test_invalid_native_and_http_addresses_refuse_with_component_error_not_raw_input(self):
        for address in (None,'not-an-address-PRIVATE','127.0.0.1'):
            item=check_fixtures.case('postgresql');item['app']['role_addresses']={'service':address}
            with self.subTest(address_type=type(address).__name__),self.assertRaises(ComponentError) as raised:
                checks.checks(item['app'],item['guest'],compose_file=None)
            self.assertNotIn('PRIVATE',str(raised.exception))
        for address in (None,'invalid-PRIVATE','198.018.1.1','::1'):
            with self.subTest(kind=type(address).__name__),self.assertRaises(ComponentError) as raised:
                checks._ipv4(address)
            self.assertNotIn('PRIVATE',str(raised.exception))
        self.assertEqual(checks._ipv4('198.18.25.90'),'198.18.25.90')

    def test_invalid_selected_scalar_encoding_is_redacted_before_any_file_rows_escape(self):
        app,values=foundation_fixtures.auth();values['secret_key']=b'\xffPRIVATE'
        before=copy.deepcopy((app,values))
        with self.assertRaisesRegex(ValueError,'^Supply UTF-8 selected scalar bytes$'):
            foundation_files.files(app,secrets=values)
        self.assertEqual((app,values),before)

    def test_named_header_profile_and_explicit_aliases_keep_route_auth_and_inputs(self):
        app,_,_,_,plan=foundation_fixtures.ingress()
        plan['middlewares']['selected-headers']={'type':'default-headers'}
        route=plan['routes']['external'];route['hosts'].append('alternate-host.example.invalid')
        route['middlewares']=['selected-headers','admins']
        before=copy.deepcopy(plan);result=foundation_files.routing(app,plan)
        self.assertEqual(result['routes']['external']['aliases'],['alternate-host.example.invalid'])
        self.assertEqual(result['routes']['external']['middlewares'],['selected-headers','admins'])
        self.assertEqual(result['middlewares']['selected-headers'],discovery.DEFAULT_MIDDLEWARES['security-headers'])
        self.assertEqual(plan,before)
        result['middlewares']['selected-headers']['headers']['frameDeny']=False
        self.assertNotEqual(result['middlewares']['selected-headers'],discovery.DEFAULT_MIDDLEWARES['security-headers'])
        invalid=copy.deepcopy(plan);invalid['routes']['external']['middlewares'].append('foreign')
        with self.assertRaisesRegex(ValueError,'defined middleware'):foundation_files.routing(app,invalid)

    def test_managed_explorer_uses_only_compiled_broker_runtime_without_peer_or_record_drift(self):
        app,records=file_fixtures.explorer()
        selected={'project':'owned-broker-project','service':'owned-broker',
                  'config_path':'/srv/example/broker/config'}
        app['settings']['broker']['runtime']=selected
        before=copy.deepcopy((app,records))
        rows={row['path']:row for row in proxy_files.files(app,secrets={},records=records,public_ca=None)}
        document=json.loads(rows['mqtt-explorer-account.json']['content'])
        self.assertEqual(document['broker_runtime'],selected)
        self.assertEqual(document['credential'],records['fixture-gui'])
        self.assertEqual(document['connection']['hostname'],app['settings']['broker']['hostname'])
        self.assertNotIn('broker_runtime',json.loads(rows['mqtt-explorer-public.json']['content']))
        document['broker_runtime']['service']='peer';self.assertEqual((app,records),before)
        for value in ({'project':'only'},{**selected,'extra':'peer'}):
            broken=copy.deepcopy(app);broken['settings']['broker']['runtime']=value
            with self.subTest(keys=sorted(value)),self.assertRaisesRegex(ValueError,'compiled broker runtime'):
                proxy_files.files(broken,secrets={},records=records,public_ca=None)


class OwnedRuntimeBranches(unittest.TestCase):
    def test_same_owned_socket_publication_is_emitted_once_and_other_service_is_ignored(self):
        row={'service':'owned','protocol':'tcp','port':1883,
             'publication_address':'198.18.30.37','publish':{'port':1883}}
        app={'listeners':{'a':row,'same-owned-socket':copy.deepcopy(row),
                          'peer':dict(row,service='peer')}}
        before=copy.deepcopy(app)
        self.assertEqual(runtime._ports(app,'owned'),['198.18.30.37:1883:1883/tcp'])
        self.assertEqual(app,before)
        app['listeners']['udp']=dict(row,protocol='udp')
        self.assertEqual(runtime._ports(app,'owned'),['198.18.30.37:1883:1883/tcp','198.18.30.37:1883:1883/udp'])

    def test_retained_homeassistant_mdns_is_explicit_and_alias_is_selected(self):
        app={'adapter':'homeassistant','lifecycle':'retained',
             'properties':{'mdns':{'interface':'home','startup':'startup'}},
             'role_addresses':{'home':'198.18.100.20'},
             'storage_paths':{'startup':{'target':'/startup','read_only':True}}}
        base=lambda:{'environment':{},'volumes':[],'cap_add':['NET_ADMIN']}
        before=copy.deepcopy(app)
        with patch.object(runtime,'_service',side_effect=lambda *a:base()) as service, \
             patch.object(runtime,'_mounts',return_value=['owned-startup:ro']), \
             patch.object(runtime,'_aliases',return_value={'database.example.invalid':'198.18.31.10'}):
            result=runtime._homeassistant(app,{'timezone':'Etc/UTC'})['homeassistant']
        service.assert_called_once_with(app,'homeassistant',{'timezone':'Etc/UTC'})
        self.assertEqual(result['extra_hosts'],{'database.example.invalid':'198.18.31.10'})
        self.assertEqual(result['environment']['HOMELAB_HA_IPV4'],'198.18.100.20')
        self.assertEqual(result['entrypoint'],['/bin/sh','-c','/startup/mdns-route.sh && exec /init'])
        self.assertIsNone(result['command']);self.assertEqual(app,before)
        for change in ('fresh','writeable-startup','wrong-role','missing-capability'):
            selected=copy.deepcopy(app);service_value=base()
            if change=='fresh':selected['lifecycle']='fresh'
            elif change=='writeable-startup':selected['storage_paths']['startup']['read_only']=False
            elif change=='wrong-role':selected['properties']['mdns']['interface']='peer'
            else:service_value.pop('cap_add')
            with self.subTest(change=change),patch.object(runtime,'_service',return_value=service_value), \
                 patch.object(runtime,'_mounts',return_value=[]),patch.object(runtime,'_aliases',return_value={}), \
                 self.assertRaisesRegex(ValueError,'retained mDNS'):runtime._homeassistant(selected,{})

    def test_authentik_without_optional_smtp_keeps_only_required_secret_mounts_and_owned_redis(self):
        app={'secret_bindings':{'secret_key':{},'postgresql_password':{}},'properties':{},
             'settings':{'database':{'host':'198.18.31.10','user':'identity_user','name':'identity_db'}},
             'identity':{'services':{'redis':'owned-redis','server':'owned-server','worker':'owned-worker'}},
             'containers':{'server':{},'worker':{},'redis':{}},
             'storage_paths':{key:{'source':'/srv/example/'+key} for key in ('media','templates','certs','redis')}}
        def mount(a,name,target):return {'source':'owned-runtime/'+name,'target':target}
        with patch.object(runtime,'_service',side_effect=lambda *a:{'environment':{},'volumes':[]}), \
             patch.object(runtime,'_mounts',return_value=[]),patch.object(runtime,'_runtime_mount',side_effect=mount), \
             patch.object(runtime,'_ports',return_value=['198.18.30.20:9000:9000/tcp']):
            rows=runtime._authentik(app,{})
        for name in ('server','worker'):
            self.assertFalse(any(key.startswith('AUTHENTIK_EMAIL__') for key in rows[name]['environment']))
            self.assertEqual(rows[name]['depends_on'],{'owned-redis':{'condition':'service_healthy'}})
            self.assertEqual({r['target'] for r in rows[name]['volumes']},
                             {'/run/secrets/authentik-secret-key','/run/secrets/postgresql-password'})
        self.assertEqual(rows['redis']['command'],['--save','60','1','--loglevel','warning'])
        invalid=copy.deepcopy(app);invalid['secret_bindings'].pop('secret_key')
        with patch.object(runtime,'_service') as service,self.assertRaises(ValueError):runtime._authentik(invalid,{})
        service.assert_not_called()

    def test_winet_with_no_named_endpoint_does_not_invent_host_alias(self):
        item=app_fixtures.case('winet');app=item['app']
        with patch.object(runtime,'_service',return_value=app_fixtures.base_service()), \
             patch.object(runtime,'_runtime_mount',return_value={'source':'selected-options'}), \
             patch.object(runtime,'_aliases',return_value={}):
            result=runtime._winet(app,item['guest'])['winet']
        self.assertNotIn('extra_hosts',result);self.assertEqual(result['volumes'],[{'source':'selected-options'}])
        self.assertEqual(result['network_mode'],'host');self.assertNotIn('command',result)


class PureRenderIntegration(unittest.TestCase):
    def test_selected_monitoring_hba_prefix_keeps_original_tail_and_no_admin_inference(self):
        cfg=native_fixtures.configuration('postgresql');app=cfg['applications']['postgresql']
        app['monitoring_hba_source']='198.18.31.90'
        original=runtime.component_native.render(app)['files']['pg_hba.conf'];before=copy.deepcopy(cfg)
        with patch.object(database_hba,'monitoring',wraps=database_hba.monitoring) as monitoring, \
             patch.object(database_hba,'administrators',wraps=database_hba.administrators) as administrators:
            result=runtime.artifacts(cfg)
        monitoring.assert_called_once_with(original,'198.18.31.90')
        text=result['native-postgresql-pg_hba.conf'].decode()
        self.assertTrue(text.endswith(original));self.assertIn('hostssl zabbix zabbix 198.18.31.90/32 scram-sha-256\n',text)
        self.assertIn('hostnossl zabbix zabbix 198.18.31.90/32 reject\n',text)
        self.assertNotIn('managed administrator',text);administrators.assert_called_once_with(text,{})
        self.assertEqual(cfg,before)

    def test_project_composition_is_the_single_network_owner_for_each_proxy_pair(self):
        for adapter,network in [('cloudbeaver','database_tools'),('mqtt_explorer','explorer')]:
            app=proxy_fixtures.descriptor(adapter)
            app['identity']['networks']={network:'owned-private-network'}
            cfg={'schema':runtime.SCHEMA,'guest':proxy_fixtures.guest(adapter),'applications':{'selected':app}}
            before=copy.deepcopy(cfg);result=runtime.compositions(cfg)[app['project_name']]
            self.assertEqual(result['networks'],{'owned-private-network':{}})
            self.assertTrue(all(row['networks']==['owned-private-network'] for row in result['services'].values()))
            self.assertEqual(cfg,before)
            if adapter=='mqtt_explorer':
                browser=result['services']['mqtt_explorer'];gateway=result['services']['explorer_gateway']
                self.assertEqual(browser['extra_hosts'],{'broker.mqtt':'198.18.30.37'})
                self.assertNotIn('extra_hosts',gateway)


if __name__=='__main__':unittest.main()
