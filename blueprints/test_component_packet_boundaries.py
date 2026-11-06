"""Packet boundary tests; validated component outputs stub unrelated adapters.

The source plan fixture is real. Renderer/check outputs are explicit
collaborator fixtures here; native validity is tested by its owners.
"""
from contextlib import ExitStack
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

import test_component_packet as integration
import component_packet as packet
from component_lower import runtime_config
from component_errors import ComponentError
from private_io import encoded


class PacketComponentBoundaryTests(unittest.TestCase):
    def setUp(self):
        source=integration.PacketIntegrationTests();source.setUp();self.addCleanup(source.doCleanups)
        real=source.resolve()
        self.plan=SimpleNamespace(check=Mock(),library=copy.deepcopy(real.library),
            site=copy.deepcopy(real.site),resolved=copy.deepcopy(real.resolved))
        self.runtime=runtime_config(real,'resolver');self.files={'owned-config.txt':b'fixed bytes\n'}
        stack=ExitStack();self.addCleanup(stack.close)
        stack.enter_context(patch.object(packet,'runtime_config',side_effect=lambda *args:copy.deepcopy(self.runtime)))
        stack.enter_context(patch.object(packet.component_runtime,'artifacts',side_effect=lambda value:copy.deepcopy(self.files)))
        self.checks=stack.enter_context(patch.object(packet.component_checks,'checks',return_value=[{
            'name':'owned-ready','argv':['true'],'expect':''}]))
        stack.enter_context(patch.object(packet,'application_order',side_effect=lambda *args:list(self.runtime['applications'])))

    def lower(self):return packet.lower_guest(self.plan,'resolver',inputs=Path('/controller/inputs'))
    def config(self):return json.loads(self.lower()['files']['site.json'])

    def test_repositories_preserve_public_asset_bytes_and_named_input_slots(self):
        guest=self.plan.resolved['guests']['resolver']
        text='-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic-public-key\n\n'
        self.plan.library['assets']['vendor']={'type':'raw-utf8','text':text,'sha256':hashlib.sha256(text.encode()).hexdigest()}
        guest['software_selection']['repositories']=[{'name':'vendor','source':'deb https://vendor.example.invalid stable main','key_asset':'vendor'}]
        guest['frontend_routing']={'address':'198.18.20.10','gateway':'198.18.20.1','interface':'eth0','table':100,'priority':100}
        before=copy.deepcopy(self.plan.library['assets']);result=self.lower();cfg=json.loads(result['files']['site.json'])
        self.assertEqual(result['files']['repository-vendor.asc'],text)
        self.assertEqual(cfg['app']['repositories'][0]['key_path'],cfg['deployment']['input_directory']+'/repository-vendor.asc')
        self.assertEqual(cfg['app']['frontend_routing'],guest['frontend_routing'])
        self.assertEqual(self.plan.library['assets'],before)

    def test_repository_asset_collisions_and_missing_health_refuse(self):
        self.plan.resolved['guests']['resolver']['software_selection']['repositories']=[{
            'name':'vendor','source':'fixed source','key_asset':'vendor'}]
        self.plan.library['assets']['vendor']={'type':'json','text':'not a raw key','sha256':'a'*64}
        with self.assertRaisesRegex(ComponentError,'component.artifact-conflict'):self.lower()
        self.plan.library['assets']['vendor']['type']='raw-utf8';self.files['repository-vendor.asc']=b'existing'
        with self.assertRaisesRegex(ComponentError,'component.artifact-conflict'):self.lower()
        self.plan.resolved['guests']['resolver']['software_selection']['repositories']=[]
        self.checks.return_value=[]
        with self.assertRaisesRegex(ComponentError,'component.health-required'):self.lower()

    def test_serial_credential_is_named_file_only_and_qualification_never_opens_device(self):
        original=packet.provider_config(self.plan,'resolver')
        original['guest']['serial_device']={'path':'/dev/serial/by-id/usb-synthetic'}
        self.plan.resolved['apps']['recursive_a']['devices']={'coordinator':'serial'}
        self.plan.site['devices']['serial']={'capability':'coordinator','path':'/dev/serial/by-id/usb-synthetic'}
        context=self.plan.resolved['contexts']['lab']
        context['capabilities']={'coordinator':{'type':'serial-device','ssh_private_key':'device-key','known_hosts':'/controller/device-hosts'}}
        self.plan.site['secret_sources']['device-key']={'type':'file','path':'/controller/device-key'}
        with patch.object(packet,'provider_config',return_value=original):
            cfg=self.config()
            self.assertEqual(cfg['paths']['host_device_key'],'/controller/device-key')
            self.assertEqual(cfg['paths']['host_known_hosts'],'/controller/device-hosts')
            self.plan.site['secret_sources']['device-key']={'type':'environment','name':'FOREIGN'}
            with self.assertRaisesRegex(ComponentError,'component.context-file-credential'):self.lower()
        source=context['credentials']['api_token']
        self.plan.site['secret_sources'][source]={'type':'environment','name':'FOREIGN'}
        with self.assertRaisesRegex(ComponentError,'component.context-file-credential'):self.lower()

    def test_monitoring_roles_bind_only_their_compiled_app_and_agent_slots(self):
        guest=self.plan.resolved['guests']['resolver']
        guest['monitoring']={key:'${inputs}/'+name for key,name in (
            ('credential_file','monitoring-agent.json'),('database_password_file','monitoring-database-password'),
            ('storage_password_file','monitoring-storage-password'),('server_file','monitoring-server.json'))}
        storage=copy.deepcopy(self.runtime['applications']['recursive_a'])
        storage.update(id='storage',adapter='postgresql',monitoring_hba_source='198.18.20.20')
        storage.pop('project_file');storage.pop('project_name')
        storage['identity']={'phase':'storage','runtime_id':'storage','services':{},'networks':{}}
        storage.update(role_addresses={'service':'198.18.31.20'},properties={},
            software_selection={'packages':['postgresql-16=16.10-1.pgdg13+1']},
            storage_paths={'data':{'source':'/var/lib/postgresql','target':'/var/lib/postgresql',
                                   'kind':'directory','read_only':False}})
        self.runtime['applications']['storage']=storage
        native=packet.component_native.render(storage)
        self.files['component-native.json']=encoded({'storage':{'identity':native['identity'],'services':native['services']}})
        for name,text in native['files'].items():self.files[name]=text.encode()
        observer=self.runtime['applications']['recursive_a'];observer['adapter']='zabbix'
        observer['identity']['services']={role:'owned-'+role for role in packet.adapter('zabbix')['services']}
        self.plan.resolved['apps']['recursive_a']['adapter']='zabbix'
        self.plan.resolved['monitoring']={'server':'recursive_a'}
        cfg=self.config();root=cfg['deployment']['input_directory']+'/applications/'
        self.assertEqual(cfg['app']['monitoring'],{'credential_file':root+'agent/monitoring-agent.json',
            'database_password_file':root+'agent/monitoring-database-password',
            'storage_password_file':root+'storage/monitoring-storage-password',
            'server_file':root+'recursive_a/monitoring-server.json'})
        self.assertEqual(cfg['deployment']['payload_phases']['zabbix-agent'],'agent')
        for field in ('credential_file','server_file'):
            previous=guest['monitoring'][field];guest['monitoring'][field]='${inputs}/nested/foreign'
            with self.subTest(field=field),self.assertRaisesRegex(ComponentError,'component.monitoring-input-slot'):self.lower()
            guest['monitoring'][field]=previous
        storage.pop('monitoring_hba_source')
        with self.assertRaisesRegex(ComponentError,'component.monitoring-input-owner'):self.lower()
        storage['monitoring_hba_source']='198.18.20.20';self.plan.resolved['monitoring']['server']='foreign'
        with self.assertRaisesRegex(ComponentError,'component.monitoring-input-owner'):self.lower()

    def test_account_slots_bind_sql_consumer_and_broker_without_generic_interpolation(self):
        directory=Path('/controller/inputs/fixed')
        applications={}
        for app_id,adapter in [('server','postgresql'),('client','cloudbeaver'),('explorer','mqtt_explorer')]:
            row={'credential_id':app_id,'credential_file':'${inputs}/applications/'+app_id+'/managed-'+app_id+'.json'}
            selected={'adapter':adapter,'settings':{}}
            if adapter=='postgresql':selected['database_administrators']={'owned':row}
            elif adapter=='cloudbeaver':selected['settings']['managed_connections']={'owned':row}
            else:selected['settings']['broker']={'managed_credential':row}
            applications[app_id]=selected
        runtime={'applications':applications};packet._account_paths(runtime,directory)
        for app_id,selected in applications.items():
            text=json.dumps(selected);self.assertIn(str(directory/'applications'/app_id/('managed-'+app_id+'.json')),text)
        with self.assertRaisesRegex(ComponentError,'component.credential-slot'):packet._account_paths(runtime,directory)


if __name__=='__main__':unittest.main()
