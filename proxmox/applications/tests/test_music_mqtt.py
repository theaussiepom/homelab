"""Dedicated services preserve credentials/data and refuse unsupported runtime changes."""
import copy
import importlib.util
import io
import json
import os
import runpy
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import guest_contract
import music_assistant as music
import mqtt_runtime
import render
import deployment_inputs
import test_composition_boundaries as composition
from test_render import fixture

HEALTH_PATH = Path(__file__).resolve().parents[1] / 'automation-health.py'
spec = importlib.util.spec_from_file_location('dedicated_mqtt_health', HEALTH_PATH)
health = importlib.util.module_from_spec(spec); spec.loader.exec_module(health)


def music_stack():
    service = copy.deepcopy(fixture('automation')['services']['homeassistant'])
    for key in ('command', 'entrypoint', 'user', 'extra_mounts', 'cap_add', 'extra_hosts'):
        service.pop(key, None)
    service.update(image='ghcr.io/music-assistant/server:latest', memory_mib=1536,
                   environment={})
    return {'kind': 'music', 'guest_memory_mib': 2048, 'music_bind_address': '198.18.100.241',
            'services': {'music_assistant': service}}


def settings():
    return {'server_id':'retained-synthetic-id', 'onboard_done':True,
            'core':{'webserver':{'values':{'bind_ip':'198.18.100.241'}},
                    'streams':{'values':{'bind_ip':'198.18.100.241', 'publish_ip':'198.18.100.241'}}},
            'providers':{'original-provider':{'domain':'spotify','values':{'token':'never-output'}}}}


class MusicTests(unittest.TestCase):
    def test_cli_entry_refuses_unprepared_state_without_printing_values(self):
        with patch('pathlib.Path.is_symlink',return_value=True),patch('sys.argv',['music_assistant.py','--address','198.18.100.241']),patch('sys.stdout',new_callable=io.StringIO) as output:
            with self.assertRaises(SystemExit) as result:runpy.run_path(music.__file__,run_name='__main__')
            self.assertEqual(result.exception.code,1)
            self.assertEqual(output.getvalue(),'Music Assistant startup held; inspect retained state privately\n')
    def test_dedicated_contract_binds_selected_player_interface_and_service_health(self):
        with tempfile.TemporaryDirectory() as directory:
            helper=composition.CompositionTests();helper.root=Path(directory)
            stack=music_stack();cfg=helper.configuration('music',stack,stack['music_bind_address'])
            self.assertEqual(guest_contract.validate(cfg,stack),cfg['guest']['vmid'])
            stack['music_bind_address']='198.18.100.242'
            with self.assertRaisesRegex(ValueError,'assigned player-facing'):guest_contract.validate(cfg,stack)
            stack['music_bind_address']=cfg['app']['address']
            cfg['app']['service_health_checks']['foreign']=[{'name':'foreign','argv':['true']}]
            with self.assertRaises(ValueError):guest_contract.validate(cfg,stack)

    def test_vendor_image_state_mount_identity_and_listeners_are_exact(self):
        stack=music_stack(); result=render.compose(stack); service=result['services']['music_assistant']
        self.assertEqual(service['image'],'ghcr.io/music-assistant/server:latest')
        self.assertEqual(service['pull_policy'],'always')
        self.assertEqual(service['network_mode'],'host')
        self.assertEqual(service['volumes'],[{'type':'bind','source':str(music.DATA),
                         'target':'/data','bind':{'create_host_path':False}}])
        self.assertNotIn('privileged',service); self.assertNotIn('cap_add',service)
        self.assertIn('198.18.100.241',service['healthcheck']['test'][-1])
        self.assertIn('8095/info',service['healthcheck']['test'][-1])
        self.assertIn('8097',service['healthcheck']['test'][-1])
        self.assertEqual(music.configure({'kind':'other'},{}),{})
        for key,value in [('cap_add',[]),('user','0'),('environment',{'UNREVIEWED':'value'})]:
            changed=copy.deepcopy(stack);changed['services']['music_assistant'][key]=value
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'upstream'):
                render.compose(changed)
        with self.assertRaisesRegex(ValueError,'dedicated'):
            music.validate({'kind':'other','music_bind_address':'198.18.100.241'})
        for value in ['0.0.0.0','127.0.0.1','224.0.0.1','169.254.1.1','invalid']:
            with self.subTest(address=value),self.assertRaises(ValueError):music.address(value)
        changed=copy.deepcopy(stack);changed['services']['music_assistant']['image']='other/image:latest'
        with self.assertRaisesRegex(ValueError,'Pin each image'):render.compose(changed)

    def test_retained_settings_refuse_fresh_onboarding_wrong_listeners_or_new_capabilities(self):
        original=settings();music.validate_settings(original,'198.18.100.241')
        for transform in [lambda v:None,lambda v:v.update(server_id=None),lambda v:v.update(server_id=''),
                lambda v:v.update(onboard_done=False),
                lambda v:v['core']['webserver']['values'].update(bind_ip='172.20.0.10'),
                lambda v:v['core']['streams']['values'].update(publish_ip='198.18.25.31'),
                lambda v:v.update(providers=[]),lambda v:v.update(providers={}),
                lambda v:v.update(providers={str(i):{'domain':'spotify'}for i in range(129)}),
                lambda v:v.update(providers={'bad':None}),
                lambda v:v.update(providers={'bad':{'domain':'filesystem'}})]:
            value=copy.deepcopy(original);result=transform(value)
            with self.subTest(change=str(transform)),self.assertRaises(ValueError):
                music.validate_settings(None if result is None and value==original else value,'198.18.100.241')
        value=copy.deepcopy(original);value['providers']['disabled']={'domain':'filesystem','enabled':False}
        music.validate_settings(value,'198.18.100.241')

    def test_readonly_data_verification_never_changes_retained_private_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'playlists').mkdir()
            (root/'settings.json').write_text(json.dumps(settings()))
            for name in ('library.db','auth.db'):(root/name).write_bytes(b'SQLite format 3\x00synthetic')
            original={p:p.read_bytes()for p in root.iterdir()if p.is_file()}
            music.check_directory(root,'198.18.100.241')
            for path,raw in original.items():self.assertEqual(path.read_bytes(),raw)
            with patch.object(music,'DATA',root),patch('sys.stdout',new_callable=io.StringIO)as output:
                self.assertEqual(music.main(['--address','198.18.100.241']),0)
                self.assertNotIn('never-output',output.getvalue())
            for name in ('library.db','auth.db'):
                (root/name).write_bytes(b'not SQLite')
                with self.assertRaisesRegex(ValueError,'databases'):music.check_directory(root,'198.18.100.241')
                (root/name).write_bytes(original[root/name])
            (root/'playlists').rmdir()
            with self.assertRaisesRegex(ValueError,'playlists'):music.check_directory(root,'198.18.100.241')
            (root/'playlists').symlink_to(root,target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'playlists'):music.check_directory(root,'198.18.100.241')
            with patch.object(music,'DATA',root),patch('sys.stdout',new_callable=io.StringIO)as output:
                self.assertEqual(music.main(['--address','198.18.100.241']),1)
                self.assertNotIn('never-output',output.getvalue())
            with self.assertRaisesRegex(ValueError,'separately prepared'):
                music.check_directory(root/'absent','198.18.100.241')
            link=root/'alias';link.symlink_to(root,target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'separately prepared'):music.check_directory(link,'198.18.100.241')

    def test_bounded_state_reader_refuses_links_size_and_races(self):
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'state';path.write_bytes(b'private')
            with self.assertRaisesRegex(ValueError,'bounded'):music.read_file(path,1)
            link=path.with_name('hardlink');os.link(path,link)
            with self.assertRaisesRegex(ValueError,'bounded'):music.read_file(path,100)
            link.unlink()
            first=SimpleNamespace(st_mode=stat.S_IFREG,st_nlink=1,st_size=7)
            after=SimpleNamespace(st_mode=stat.S_IFREG,st_nlink=1,st_size=8)
            with patch.object(music.os,'fstat',side_effect=[first,after]),self.assertRaisesRegex(ValueError,'changed'):
                music.read_file(path,100)
            with patch.object(music.os,'fstat',return_value=after),self.assertRaisesRegex(ValueError,'changed'):
                music.read_file(path,100)
            not_regular=SimpleNamespace(st_mode=stat.S_IFIFO,st_nlink=1,st_size=7)
            with patch.object(music.os,'fstat',return_value=not_regular),self.assertRaisesRegex(ValueError,'bounded'):
                music.read_file(path,100)


class BrokerTests(unittest.TestCase):
    def test_renderer_delivers_only_the_private_bound_probe_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o700)
            account=root/'account.json';account.write_text(json.dumps({'username':'retained','password':'private'}));account.chmod(0o600)
            stack={'kind':'mqtt','guest_memory_mib':4096,'services':{'mqtt':fixture('automation')['services']['mqtt']},
                   'mqtt':{'credential_file':str(account)}}
            config=root/'stack.json';config.write_text(json.dumps(stack));config.chmod(0o600)
            ca=root/'ca';ca.write_text('synthetic ca')
            cfg={'paths':{'ca_file':str(ca)},'guest':{},'app':{'kind':'mqtt','stack_config':str(config)}}
            before=deployment_inputs.input_hashes(cfg)
            self.assertIn(str(account),before)
            with patch('sys.argv',['render.py','--config',str(config),'--output',str(root/'rendered')]):render.main()
            manifest=json.loads((root/'rendered/runtime-files.json').read_text())
            self.assertEqual(manifest,[{'path':'mqtt-probe.json','uid':0,'gid':0,'mode':'0600'}])
            self.assertEqual((root/'rendered/mqtt-probe.json').read_bytes(),mqtt_runtime.files(stack)[0]['content'].encode())
            account.write_text(json.dumps({'username':'retained','password':'different'}))
            self.assertNotEqual(deployment_inputs.input_hashes(cfg)[str(account)],before[str(account)])

    def test_private_probe_input_is_exact_bound_and_not_shared_ha_configuration(self):
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'account';path.write_text(json.dumps({'username':'retained','password':'never-output'}));path.chmod(0o600)
            cfg={'kind':'mqtt','mqtt':{'credential_file':str(path)}}
            self.assertEqual(mqtt_runtime.source_files(cfg),[str(path)])
            value=mqtt_runtime.files(cfg)[0]
            self.assertEqual({k:value[k]for k in ['path','uid','gid','mode']},
                             {'path':'mqtt-probe.json','uid':0,'gid':0,'mode':'0600'})
            self.assertEqual(json.loads(value['content']),json.loads(path.read_text()))
            for value in ({}, {'username':'retained','password':''}, {'username':'retained','password':'x\n'},
                          {'username':'retained','password':'x'*65536},{'username':None,'password':'x'},
                          {'username':'retained','password':'x','extra':'not allowed'}):
                path.write_text(json.dumps(value))
                with self.subTest(value_type=type(value).__name__),self.assertRaises(ValueError):mqtt_runtime.files(cfg)
        for cfg in ({'kind':'mqtt'}, {'kind':'other','mqtt':{}},
                    {'kind':'mqtt','mqtt':{'credential_file':'relative'}},
                    {'kind':'mqtt','mqtt':{'credential_file':'/private/../invalid'}}):
            with self.assertRaises(ValueError):mqtt_runtime.validate(cfg)
        self.assertEqual(mqtt_runtime.source_files({'kind':'other'}),[])

    def test_probe_authenticates_one_account_and_rejects_anonymous_without_publishing(self):
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'account';path.write_text(json.dumps({'username':'retained','password':'private'}))
            with patch.object(health,'connect',side_effect=[0,5])as connection:
                health.mqtt(path,standalone=True)
                self.assertEqual([c.args for c in connection.call_args_list],[('retained','private'),()])
            for value in (None,{}, {'data':{'entries':[]}}):
                path.write_text(json.dumps(value))
                with self.assertRaisesRegex(ValueError,'probe account'):health.mqtt(path,standalone=True)
        with patch.object(health,'mqtt')as probe:
            health.probe('mqtt-broker')
            probe.assert_called_once_with(Path(mqtt_runtime.RUNTIME),standalone=True)

    def test_optional_shared_broker_keeps_original_order_and_data_requirements(self):
        cfg={'app':{'kind':'automation','service_health_checks':{'homeassistant':[], 'node_red':[]}}}
        self.assertEqual(guest_contract.applications(cfg),['homeassistant','node_red'])
        self.assertFalse(any('/mqtt/'in x['path']for x in guest_contract.required_paths(cfg)))
        cfg['app']['service_health_checks']['mqtt']=[]
        self.assertEqual(guest_contract.applications(cfg),['mqtt','homeassistant','node_red'])
        self.assertTrue(any('/mqtt/'in x['path']for x in guest_contract.required_paths(cfg)))
        for order in (None,['homeassistant'],['mqtt','mqtt','homeassistant','node_red']):
            selected=copy.deepcopy(guest_contract.BLUEPRINTS['automation']);selected['application_order']=order
            with self.assertRaisesRegex(ValueError,'exactly once'):guest_contract.application_order(selected,[])


if __name__=='__main__':unittest.main()
