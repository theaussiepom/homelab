"""Real compiler integration: explicit phases survive canonical packet serialization."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import component_plan
import component_packet
import component_workflows
from test_component_plan import library, site


class PacketIntegrationTests(unittest.TestCase):

    def native(self,adapter):
        settings={'postgresql':('postgresql-16=16.10-1.pgdg13+1',1792,'/var/lib/postgresql',5432),
                  'influxdb':('influxdb2=2.7.12-1',1792,'/var/lib/influxdb',8086)}
        package,memory,path,port=settings[adapter]
        self.spec['software'][adapter]={'packages':[package]}
        self.spec['runtime_profiles'][adapter]={'native':{'memory_mib':memory}}
        self.spec['app_profiles'][adapter]={'adapter':adapter,'display_name':adapter,
            'interfaces':{'service_interface':{'required':True,'accepts':['guest-interface']}},
            'listeners':{'service_listener':{'service':adapter,'namespace':'host','interface':'service_interface',
                'bind':'interface','protocol':'tcp','port':port}},
            'endpoints':{'service_endpoint':{'listener':'service_listener','protocol':'tcp','via':'service_interface'}},
            'storage':{'data':{'required':True,'target':path,'kind':'directory','read_only':False}},
            'software':[adapter],'runtime':[adapter],'health':{'ready':{'type':'adapter','check':'readiness'}}}
        guest=self.site['guests']['resolver'];guest['resources']={'memory_mib':8192}
        guest.setdefault('volumes',{})[adapter]={'slot':len(guest.get('volumes',{})),
            'path':path,'size_gib':4,'storage':'local'}
        self.site['apps'][adapter]={'profile':adapter,'guest':'resolver','lifecycle':'fresh',
            'interfaces':{'service_interface':{'interface':'backend'}},
            'storage':{'data':{'volume':adapter,'subpath':''}}}

    def test_real_compiler_mixes_a_native_server_with_a_container_without_native_project_identity(self):
        self.native('postgresql')
        packet=component_packet.lower_plan(self.resolve())['resolver']
        runtime=json.loads(packet['files']['component-runtime.json'])
        self.assertNotIn('project_name',runtime['applications']['postgresql'])
        manifest=json.loads(packet['files']['component-projects.json'])
        self.assertEqual(len(manifest),1)
        self.assertEqual(next(iter(manifest.values()))['applications'],{'recursive_a':['recursive_a_unbound']})
        self.assertIn('postgresql',json.loads(packet['files']['component-native.json']))

    def test_real_compiler_refuses_conflicting_native_numeric_group_owners_before_packet_emission(self):
        self.native('postgresql');self.native('influxdb')
        with self.assertRaisesRegex(ValueError,'namespace'):
            component_packet.lower_plan(self.resolve())

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.stack = self.root/'stack'; self.stack.mkdir()
        self.consumer = self.root/'consumer'; self.consumer.mkdir()
        self.spec, self.site = library(), site()
        self.spec['software'] = {'resolver': {'images': {'unbound': 'unbound'}}}
        self.spec['runtime_profiles'] = {'resolver': {'containers': {'unbound': {
            'memory_mib': 256, 'cpu_limit': 1, 'pids_limit': 128}}}}
        self.spec['app_profiles']['recursive'].update(software=['resolver'], runtime=['resolver'],
            health={'ready': {'type': 'adapter', 'check': 'readiness'}})
        (self.stack/'images.json').write_text(json.dumps({'unbound': {
            'repository': 'example/unbound', 'tag': '1', 'digest': 'sha256:'+'a'*64}}))

    def resolve(self, *, disabled=None):
        (self.stack/'stack.json').write_text(json.dumps(self.spec))
        self.source = self.consumer/'site.json'
        self.source.write_text(json.dumps(self.site))
        return component_plan.resolve(self.stack, self.source, disabled)

    def test_actual_packet_carries_engines_and_exact_explicit_phase_order_after_json_roundtrip(self):
        self.site['guests']['resolver']['resources'] = {'memory_mib': 1024}
        first = self.site['apps'].pop('recursive_a')
        first['display_name'] = 'literal ${inputs} is not a template'
        self.site['apps'] = {'zeta': first, 'alpha': copy.deepcopy(first)}
        self.site['apps']['alpha']['properties'] = {'publish_port': 5336}
        plan = self.resolve()
        packet = json.loads(json.dumps(component_packet.lower_plan(plan)['resolver'], sort_keys=True))
        cfg = json.loads(packet['files']['site.json'])
        runtime = json.loads(packet['files']['component-runtime.json'])
        self.assertEqual(cfg['deployment']['phases'], ['preparation', 'zeta', 'alpha'])
        self.assertEqual(list(cfg['deployment']['applications']), ['alpha', 'zeta'])
        self.assertEqual(cfg['deployment']['payload_phases'], {'zeta': 'zeta', 'alpha': 'alpha'})
        self.assertEqual(runtime['applications']['zeta']['display_name'], 'literal ${inputs} is not a template')
        self.assertEqual(cfg['app']['address'], '198.18.20.10')
        self.assertEqual(cfg['app']['mac'], '02:00:00:20:00:10')
        self.assertEqual(cfg['deployment']['protected_guests'], [9900, 9914, 9915, 9920])
        self.assertEqual(component_workflows.model(plan)['guests']['resolver']['phases'][2:][0]['id'], 'zeta')
        self.assertIn('compose-zeta.yml', packet['files'])
        self.assertIn('compose-alpha.yml', packet['files'])

    def test_readiness_reorders_real_apps_without_adding_value_only_waits(self):
        self.site['guests']['resolver']['resources'] = {'memory_mib': 1024}
        first = self.site['apps'].pop('recursive_a')
        self.site['apps'] = {'zeta': first, 'alpha': copy.deepcopy(first)}
        self.site['apps']['alpha']['properties'] = {'publish_port': 5336}
        self.spec['app_profiles']['recursive']['connections'] = {'upstream': {
            'type': 'dns', 'required': False, 'readiness': ['start']}}
        self.site['connections'] = {'upstream': {'consumer': {'app': 'zeta', 'connection': 'upstream'},
            'target': {'app': 'alpha', 'endpoint': 'dns_endpoint'}, 'source_interface': 'local_interface'}}
        plan = self.resolve()
        self.assertEqual(component_packet.application_order(plan, 'resolver'), ['zeta', 'alpha'])
        self.site['connections']['upstream']['readiness'] = 'start'
        plan = self.resolve()
        cfg = json.loads(component_packet.lower_plan(plan)['resolver']['files']['site.json'])
        self.assertEqual(cfg['deployment']['phases'], ['preparation', 'alpha', 'zeta'])
        self.assertEqual(plan.resolved['guest_dependencies'], {'resolver': []})

    def test_compilation_does_not_read_secret_files_generate_credentials_or_execute_commands(self):
        plan = self.resolve()
        with patch('private_io.regular', side_effect=AssertionError('no private input reads')), \
             patch('managed_credentials.credential', side_effect=AssertionError('no credential generation')), \
             patch('subprocess.run', side_effect=AssertionError('no execution')), \
             patch('socket.create_connection', side_effect=AssertionError('no network')):
            packet = component_packet.lower_plan(plan)['resolver']
        self.assertTrue(packet['enabled'])
        self.assertEqual(packet['schema'], component_packet.PACKET_SCHEMA)
        self.assertEqual(json.loads(packet['files']['site.json'])['deployment']['contract'], 3)
        self.assertFalse(component_packet.lower_plan(self.resolve(disabled=['resolver']))['resolver']['enabled'])

    def test_real_cli_uses_arbitrary_guest_ids_and_private_create_only_packet(self):
        self.resolve()
        output = self.root/'packet.json'
        compiler = Path(__file__).with_name('compile.py')
        command = [sys.executable, str(compiler), '--stack', str(self.stack), '--site', str(self.source),
                   '--guest', 'resolver', '--output', str(output)]
        completed = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual((completed.returncode, completed.stdout, completed.stderr), (0, '', ''))
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        before = output.read_bytes()
        completed = subprocess.run(command, capture_output=True, text=True)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(output.read_bytes(), before)
        self.source.write_text(json.dumps({'schema': 'homelab-site-v3', 'values': {}}))
        completed = subprocess.run(command[:-2] + ['--check'], capture_output=True, text=True)
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn('Traceback', completed.stderr)

    def test_real_fresh_ha_composition_carries_declared_storage_initialization_to_ansible(self):
        import component_guest,component_inputs,component_prepare,component_ansible
        from private_io import encoded,write_new
        self.spec['software']['ha']={'images':{'homeassistant':'ha'}}
        self.spec['runtime_profiles']['ha']={'containers':{'homeassistant':{
            'memory_mib':256,'cpu_limit':1,'pids_limit':128}}}
        self.spec['app_profiles']['ha']={'adapter':'homeassistant','display_name':'Home Assistant',
            'interfaces':{'web_interface':{'required':True,'accepts':['guest-interface']}},
            'listeners':{'web_listener':{'service':'homeassistant','namespace':'host','interface':'web_interface',
                'bind':'interface','protocol':'tcp','port':8123}},
            'storage':{'config':{'target':'/config','kind':'directory','read_only':False,'required':True,
                'initialize':{'type':'directory','uid':0,'gid':0,'mode':'0700'}}},
            'software':['ha'],'runtime':['ha'],'health':{'ready':{'type':'adapter','check':'readiness'}}}
        (self.stack/'images.json').write_text(json.dumps({'unbound':{'repository':'example/unbound',
            'tag':'1','digest':'sha256:'+'a'*64},'ha':{'repository':'example/homeassistant',
            'tag':'1','digest':'sha256:'+'b'*64}}))
        self.site['guests']['resolver']['volumes']={'apps':{'storage':'local','slot':0,
            'path':'/srv/example/apps','size_gib':8}}
        self.site['apps']={'ha':{'profile':'ha','guest':'resolver','lifecycle':'fresh',
            'interfaces':{'web_interface':{'interface':'backend'}},'storage':{'config':{'volume':'apps','subpath':'homeassistant'}}}}
        plan=self.resolve();root=self.root/'inputs'
        packet=component_packet.lower_plan(plan,inputs=root)['resolver']
        path=self.root/'packet.json';write_new(path,encoded(packet))
        cfg,site_path=component_inputs.prepare(path,root,create=True)
        self.assertEqual(cfg['app']['required_paths'],[])
        from types import SimpleNamespace
        payload=component_prepare.prepare(cfg,'ha',{},attempt=SimpleNamespace(receipt=self.root/'absent-receipt'))
        values=component_ansible.variables(cfg,'ha',payload=payload)
        self.assertEqual(values['component_fresh_directories'],{'previously_owned':False,
            'directories':[{'root':'/srv/example/apps','path':'/srv/example/apps/homeassistant',
                            'uid':0,'gid':0,'mode':'0700'}]})
        self.assertEqual(values['app']['required_paths'],[
            {'path':'/srv/example/apps/homeassistant','type':'directory'}])
        runtime=json.loads(packet['files']['component-runtime.json'])
        self.assertEqual(runtime['applications']['ha']['storage_paths']['config']['volume_root'],'/srv/example/apps')
        self.site['guests']['resolver'].pop('volumes')
        self.site['guests']['resolver']['root_paths']={'apps':{'path':'/srv/example/apps'}}
        self.site['apps']['ha']['storage']['config']={'root_path':'apps','subpath':'homeassistant'}
        with self.assertRaisesRegex(ValueError,'storage-initialization-volume'):
            component_packet.lower_plan(self.resolve())


if __name__ == '__main__':
    unittest.main()
