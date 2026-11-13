"""Closed compiled metadata, mocked agent formatter, and real old-byte parity."""
import copy
import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
F=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(F/'proxmox/applications'),str(F/'proxmox/applications/tests')]
import monitoring_agent as old
import test_monitoring_agent as legacy
agent=old


def component(kind='dns',docker=False):
    value=legacy.cfg(kind,docker);value['schema']='homelab-component-guest-v1';value['app'].pop('kind')
    value['app']['monitoring']['server_hostname']='zabbix'
    value['deployment']['contract']=3;value['deployment']['applications']={'app':{'id':'owned','adapter':{'automation':'node_red','dns':'pihole','monitoring':'zabbix'}.get(kind,kind)}}
    # Existing legacy test intentionally had an unqualified DHCP placeholder;
    # the component path consumes only the explicit qualified endpoint form.
    value['guest']['interfaces'][-1]={'ipv4':'dhcp','ipv4_endpoint':'198.18.25.33/24','gateway':None}
    if kind=='monitoring':value['guest']['hostname']='zabbix'
    return value


class ComponentAgentTests(unittest.TestCase):
    def test_component_unit_formats_only_selected_metadata_without_kind_reconstruction(self):
        value=component()
        with patch.object(agent.monitoring,'agent_config',return_value='synthetic-config\n')as formatter:
            self.assertEqual(agent.configuration(value),'synthetic-config\n')
        formatter.assert_called_once_with({'hostname':'fixture-208','server_active':'198.18.25.36:10051','psk_identity':'fixture-208','psk_path':'/etc/zabbix/agent.psk'})
        self.assertNotIn('kind',value['app'])
    def test_requested_workload_uses_explicit_selected_native_adapter(self):
        for kind,profile,port in [('postgresql','postgresql',5432),('mariadb','mysql',3306)]:
            value=component(kind)
            text=agent.configuration(value,'a'*64);self.assertIn('User=zbx_monitor',text);self.assertIn(':'+str(port),text)
            for adapters in ({},{'app':{'adapter':'pihole'}},{'a':{'adapter':kind},'b':{'adapter':kind}}):
                bad=copy.deepcopy(value);bad['deployment']['applications']=adapters
                with self.subTest(kind=kind,adapters=len(adapters)),self.assertRaises(ValueError):agent.configuration(bad,'a'*64)
    def test_native_application_without_requested_workload_does_not_infer_session(self):
        value=component();value['deployment']['applications']={'db':{'adapter':'postgresql'}}
        self.assertNotIn('Plugins.PostgreSQL',agent.configuration(value))
    def test_profiles_unknown_duplicate_unordered_and_nonstring_refuse(self):
        for profiles in ([],['docker'],['linux','foreign'],['linux','linux'],['linux',None],'linux'):
            value=component();value['app']['monitoring']['profiles']=profiles
            with self.subTest(shape=type(profiles).__name__),self.assertRaises(ValueError):agent.configuration(value)
    def test_docker_profile_requires_capability_without_adding_socket_or_profile(self):
        value=component('automation',True);self.assertIn('Plugins.Docker.Endpoint=unix:///var/run/docker.sock\n',agent.configuration(value))
        value['deployment']['capabilities']=['linux']
        with self.assertRaises(ValueError):agent.configuration(value)
    def test_multiple_requested_database_sessions_refuse_instead_of_picking_one(self):
        value=component('postgresql');value['deployment']['applications']['maria']={'adapter':'mariadb'};value['app']['monitoring']['profiles'].append('mysql')
        with self.assertRaises(ValueError):agent.configuration(value,'a'*64)
    def test_database_uri_preserves_local_protocol_port_and_credential_boundary(self):
        uris=['tcp://198.18.99.1:5432','tcp://127.0.0.1:3306','http://127.0.0.1:5432','tcp://user:pass@127.0.0.1:5432','tcp://127.0.0.1:5432/path','tcp://127.0.0.1:5432?q=1','tcp://127.0.0.1:5432#x']
        for uri in uris:
            value=component('postgresql');value['app']['monitoring']['database_uri']=uri
            with self.subTest(uri_shape=uri.split(':',1)[0]),self.assertRaises(ValueError):agent.configuration(value,'a'*64)
        for password in (None,'','a'*63,'x'*64):
            with self.subTest(password_type=type(password).__name__),self.assertRaises(ValueError):agent.configuration(component('postgresql'),password)
    def test_database_fields_cannot_be_missing_or_appear_without_selected_workload(self):
        for key in ('database_uri','database_password_file'):
            value=component('postgresql');value['app']['monitoring'].pop(key)
            with self.subTest(key=key),self.assertRaises(ValueError):agent.configuration(value,'a'*64)
        value=component();value['app']['monitoring']['database_uri']='tcp://127.0.0.1:5432'
        with self.assertRaises(ValueError):agent.configuration(value)
    def test_qualified_dhcp_is_an_owned_address_and_unqualified_or_foreign_refuses(self):
        value=component('mariadb');value['app']['monitoring']['database_uri']='tcp://198.18.25.33:3306'
        self.assertIn('Uri=tcp://198.18.25.33:3306',agent.configuration(value,'a'*64))
        value['guest']['interfaces'][-1].pop('ipv4_endpoint')
        with self.assertRaises(ValueError):agent.configuration(value,'a'*64)
    def test_identity_server_endpoint_path_and_foreign_extra_fields_refuse(self):
        for field,v in [('extra',True),('hostname','foreign'),('psk_identity','foreign'),('server_vmid',True),('server_hostname','bad host'),('server_active','8.8.8.8:10051'),('server_active','127.0.0.1:10051'),('server_active','198.18.25.36:10050'),('credential_file','relative')]:
            value=component();value['app']['monitoring'][field]=v
            with self.subTest(field=field),self.assertRaises(ValueError):agent.configuration(value)
    def test_storage_password_is_explicit_and_owned_by_selected_postgresql_only(self):
        value=component('postgresql');self.assertIn('storage_password_file',agent.validate(value))
        value=component();value['app']['monitoring']['storage_password_file']='/payload/monitoring-storage-password'
        with self.assertRaises(ValueError):agent.validate(value)
    def test_root_metadata_is_bound_to_actual_server_guest_and_context(self):
        good=component('monitoring',True);self.assertEqual(agent.validate(good),good['app']['monitoring'])
        mutations=[lambda v:v['guest'].update(hostname='foreign'),lambda v:v['deployment'].update(applications={}),lambda v:v['app']['monitoring']['proxmox'].update(endpoint='https://foreign.invalid/'),lambda v:v['app']['monitoring'].update(server_vmid=999),lambda v:v['app']['monitoring'].pop('server_file')]
        for mutate in mutations:
            value=copy.deepcopy(good);mutate(value)
            with self.subTest(case=mutations.index(mutate)),self.assertRaises(ValueError):agent.validate(value)
    def test_root_members_unknown_duplicate_and_wrong_influx_endpoint_refuse(self):
        good=component('monitoring',True)
        mutations=[lambda m:m['members'].append(copy.deepcopy(m['members'][0])),lambda m:m['members'][0].update(extra='foreign'),lambda m:m['members'][0].update(profiles=['linux','unknown']),lambda m:m['members'][1].update(url='http://198.18.99.1:8086'),lambda m:m.update(influxdb_address='8.8.8.8')]
        for mutate in mutations:
            value=copy.deepcopy(good);mutate(value['app']['monitoring'])
            with self.subTest(case=mutations.index(mutate)),self.assertRaises(ValueError):agent.validate(value)
    def test_real_same_retained_metadata_produces_exact_old_configuration_bytes(self):
        for kind,docker in [('dns',False),('automation',True),('postgresql',False),('mariadb',False),('monitoring',True)]:
            with self.subTest(kind=kind):self.assertEqual(agent.configuration(component(kind,docker),'a'*64),old.configuration(legacy.cfg(kind,docker),'a'*64))
    def test_old_source_validator_and_configuration_unit_suite_remain_separate(self):
        with patch.object(legacy,'agent',agent):
            result=unittest.TestResult();unittest.defaultTestLoader.loadTestsFromTestCase(legacy.AgentTests).run(result)
        self.assertEqual(result.testsRun,3);self.assertFalse(result.errors,result.errors);self.assertFalse(result.failures,result.failures)

if __name__=='__main__':unittest.main()
