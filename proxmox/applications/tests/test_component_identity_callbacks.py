"""Selected callback bytes reach the retained guard through the component caller."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import application_contract as contract
import component_ansible
import component_foundation_files
import component_inputs
import component_prepare
import component_runtime
import identity_callbacks
from private_io import encoded,write_bytes,write_new
from test_identity_callbacks_contract import fixture as callback_fixture
import test_component_inputs as input_fixtures


class ComponentCallbackTests(unittest.TestCase):
    def test_reviewed_declaration_is_an_owned_private_leaf_and_invalid_records_refuse(self):
        record=callback_fixture()[0]
        app={'adapter':'authentik','settings':{'allowed_callback_additions':[record]},
             'secret_bindings':{'secret_key':{},'postgresql_password':{}},
             'input_sources':{'secret_key':{},'postgresql_password':{}}}
        values={'secret_key':b'synthetic-secret','postgresql_password':b'synthetic-password'}
        before=copy.deepcopy((app,values))
        rows=component_foundation_files.files(app,secrets=values)
        self.assertEqual({row['path']for row in rows},contract.runtime_files(app))
        row=rows[-1]
        self.assertEqual((row['path'],row['uid'],row['gid'],row['mode']),
                         ('identity-callbacks.json',0,0,'0600'))
        self.assertEqual(json.loads(row['content']),[record]);self.assertEqual((app,values),before)
        for value in ([],[dict(record,allow_all=True)],[dict(record,additions=['https://bad.example.invalid/'])]):
            with self.subTest(value=value),self.assertRaises(ValueError):
                component_foundation_files.files(dict(app,settings={'allowed_callback_additions':value}),secrets=values)

    def test_real_selected_payload_installs_only_reviewed_callbacks_and_selected_server(self):
        fixture=input_fixtures.StaticInputTests('test_create_once_repeat_verify_and_separate_app_directory_do_not_rebind_static_inputs')
        fixture.setUp();self.addCleanup(fixture.doCleanups)
        record=callback_fixture()[0];runtime_root='/opt/homelab-app/runtime/identity_a'
        sources={}
        for role in ('secret_key','postgresql_password'):
            path=fixture.root/(role+'.txt');write_new(path,('synthetic-'+role).encode())
            sources[role]={'type':'file','path':str(path)}
        roles=contract.ADAPTERS['authentik']['services']
        app={'id':'identity_a','adapter':'authentik','lifecycle':'retained',
             'identity':{'phase':'identity_a','runtime_id':'identity_a',
                'services':{role:'owned_'+role for role in roles},'runtime_directory':runtime_root},
             'settings':{'allowed_callback_additions':[record]},'secret_bindings':sources,
             'input_sources':sources,'storage_paths':{},'project_name':'owned-project','project_file':'compose-owned.yml',
             'software_selection':{'images':{role:{'image':'example/'+role+'@sha256:'+'b'*64}for role in roles}}}
        app['runtime_files']={'app':app['id'],'directory':runtime_root,'files':sorted(contract.runtime_files(app))}
        runtime={'schema':component_runtime.SCHEMA,'guest':{'id':'example'},'applications':{app['id']:app}}
        with patch.object(component_runtime,'compositions',return_value={'owned-project':{
                'name':'owned-project','services':{app['identity']['services'][role]:{
                    'image':app['software_selection']['images'][role]['image']}for role in roles}}}):
            artifacts=component_runtime.artifacts(runtime)
        cfg=fixture.cfg;cfg['deployment'].update(lifecycle='retained',phases=['preparation','identity_a'],
            payload_phases={'identity_a':'identity_a'},applications={'identity_a':{'id':'identity_a',
            'adapter':'authentik','lifecycle':'retained','runtime_id':'identity_a','project':'owned-project',
            'compose_file':'compose-owned.yml','services':contract.ordered_services(app)}})
        cfg['app'].update(exclusive_writer_confirmed=True,service_health_checks={'identity_a':[{'name':'owned-ready','argv':['true'],'expect':''}]})
        fixture.packet['files']={'site.json':encoded(cfg).decode(),'component-runtime.json':encoded(runtime).decode(),
            **{name:raw.decode()for name,raw in artifacts.items()}}
        write_bytes(fixture.path,encoded(fixture.packet))
        selected,_=component_inputs.prepare(fixture.path,fixture.inputs,create=True)
        with patch.object(component_prepare.component_continuity,'verify'):
            payload=component_prepare.prepare(selected,'identity_a',{},attempt=object())
        variables=component_ansible.variables(selected,'identity_a',payload=payload)
        self.assertEqual(json.loads((payload.directory/'identity-callbacks.json').read_bytes()),[record])
        self.assertEqual(variables['component_identity_callbacks'],{
            'config':runtime_root+'/identity-callbacks.json','service':'owned_server'})
        self.assertIn({'source':'identity_callbacks.py','destination':'/opt/homelab-app/identity_callbacks.py',
                       'mode':'0700'},variables['component_helpers'])
        row=next(row for row in variables['component_runtime_files']if row['source']=='identity-callbacks.json')
        self.assertEqual(row['destination'],runtime_root+'/identity-callbacks.json')
        self.assertNotIn('stack',variables)

    def test_helper_preserves_default_command_and_accepts_only_owned_service_identity(self):
        record=callback_fixture()[0]
        result=subprocess.CompletedProcess([],0,json.dumps({'callbacks':'verified','providers':1,'changed':0})+'\n','')
        for service in ('server','identity_server'):
            with patch.object(identity_callbacks.subprocess,'run',return_value=result)as native:
                self.assertEqual(identity_callbacks.run([record],Path('/opt/homelab-app/compose-owned.yml'),service),
                                 {'callbacks':'verified','providers':1,'changed':0})
            argv=native.call_args.args[0]
            self.assertEqual(argv[argv.index('PGOPTIONS=-c default_transaction_read_only=on')+1],service)
            self.assertEqual(json.loads(native.call_args.kwargs['input'])['configuration'],[record])
            self.assertEqual(native.call_args.kwargs['timeout'],60)
        for service in ('--option','other/name','${ENV}','x\nforeign',None):
            with self.subTest(service=service),patch.object(identity_callbacks.subprocess,'run')as native,self.assertRaises(ValueError):
                identity_callbacks.run([record],Path('/opt/homelab-app/compose-owned.yml'),service)
            native.assert_not_called()

    def test_guard_runs_after_owned_start_before_peer_verification_without_new_authored_hook(self):
        import yaml
        tasks=yaml.safe_load((Path(__file__).resolve().parents[1]/'ansible/tasks/component-compose.yml').read_text())
        start=next(i for i,row in enumerate(tasks)if row['name']=="Start only this application's owned services")
        guard=next(i for i,row in enumerate(tasks)if row['name']=='Maintain only the reviewed identity callbacks')
        peers=next(i for i,row in enumerate(tasks)if row['name']=='Verify peer continuity')
        self.assertLess(start,guard);self.assertLess(guard,peers)
        task=tasks[guard]
        self.assertEqual(task['when'],'component_identity_callbacks is defined and not ansible_check_mode')
        self.assertTrue(task['no_log']);self.assertFalse(task['changed_when'])
        self.assertIn('component_identity_callbacks.config',task['ansible.builtin.command']['argv'])
        self.assertIn('component_compose_file',task['ansible.builtin.command']['argv'])


if __name__=='__main__':unittest.main()
