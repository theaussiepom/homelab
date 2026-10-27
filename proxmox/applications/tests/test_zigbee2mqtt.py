"""Synthetic radio deployment checks; never open a coordinator or MQTT connection."""
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import render
import deploy
from test_deploy import fixture as site_fixture
from unittest.mock import patch

DEVICE = '/dev/serial/by-id/usb-Example_Radio_123-if00'

def fixture():
    return {'kind': 'zigbee2mqtt', 'guest_memory_mib': 768, 'timezone': 'Etc/UTC',
            'zigbee': {'serial_device': DEVICE, 'bind_address': '198.18.30.22',
                       'frontend_port': 8080, 'adapter': 'ember',
                       'mqtt_server': 'mqtt://broker.example.invalid:1883',
                       'mqtt_base_topic': 'zigbee2mqtt',
                       'state_sha256': {name: '1' * 64 for name in
                         ('configuration.yaml', 'database.db', 'coordinator_backup.json')}},
            'services': {'zigbee2mqtt': {'image': 'example.invalid/zigbee2mqtt@sha256:' + '2'*64,
                        'memory_mib': 256, 'cpus': 1, 'pids_limit': 128, 'restart': 'unless-stopped'}}}


def state():
    return {'configuration.yaml': b"serial:\n  port: /dev/ttyACM0\n  adapter: ember\nmqtt:\n  server: mqtt://broker.example.invalid:1883\n  base_topic: zigbee2mqtt\nfrontend:\n  enabled: true\n  host: 0.0.0.0\n  port: 8080\nadvanced:\n  network_key: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]\n  pan_id: 1234\n  ext_pan_id: [1, 2, 3, 4, 5, 6, 7, 8]\n",
            'database.db': b'{"id":1,"type":"Coordinator"}\n',
            'coordinator_backup.json': b'{"metadata":{"format":"synthetic-only"}}'}


class ZigbeeTests(unittest.TestCase):
    def test_invalid_radio_capture_cannot_create_a_guest_in_either_entry_point(self):
        from test_rollout import RolloutTests
        for action in ('deploy', 'apply'):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                cfg, site, work, plan=RolloutTests().prepare(root)
                stack=fixture(); stack['zigbee']['bind_address']=cfg['app']['address']
                stack_path=root/'stack.json'; stack_path.write_text(json.dumps(stack))
                cfg['guest']['serial_device']={'path':DEVICE}
                cfg['guest']['interfaces'][0]['role']='backend'
                cfg['app'].update(kind='zigbee2mqtt',stack_config=str(stack_path))
                site.write_text(json.dumps(cfg))
                receipt=json.loads((work/'plan.json').read_text())
                receipt.update(site_sha256=deploy.sha(site), input_hashes=deploy.input_hashes(cfg))
                deploy.write(work/'plan.json',receipt)
                with patch.object(deploy,'_execute_step') as execute_step, self.assertRaises(ValueError):
                    deploy.execute(action,site,plan)
                execute_step.assert_not_called()

    def test_radio_uses_one_exact_device_and_one_existing_data_tree(self):
        cfg=fixture(); svc=render.compose(cfg)['services']['zigbee2mqtt']
        self.assertEqual(svc['devices'], [DEVICE + ':/dev/ttyACM0:rw'])
        self.assertNotIn('network_mode', svc)
        self.assertEqual(svc['ports'], ['198.18.30.22:8080:8080'])
        self.assertEqual(svc['volumes'], [{'type':'bind', 'source':'/srv/homelab/data/zigbee2mqtt',
             'target':'/app/data', 'bind': {'create_host_path':False}}])
        for field in ('privileged', 'cap_add', 'device_cgroup_rules'):
            self.assertNotIn(field,svc)

    def test_radio_rejects_unstable_devices_and_config_overrides(self):
        for device in ('/dev/ttyACM0', '/dev/*', '/dev/sda', '/dev/serial/by-id/../other'):
            cfg=fixture(); cfg['zigbee']['serial_device']=device
            with self.subTest(device=device), self.assertRaises(ValueError): render.compose(cfg)
        for key, value in [('environment', {'ZIGBEE2MQTT_CONFIG_ADVANCED_NETWORK_KEY':'GENERATE'}),
                           ('extra_mounts',[{'source':'/srv/homelab/data/other','target':'/app/data'}]),
                           ('command',['anything']), ('entrypoint',['anything']), ('user','0:0')]:
            cfg=fixture(); cfg['services']['zigbee2mqtt'][key]=value
            with self.subTest(key=key), self.assertRaises(ValueError): render.compose(cfg)

    def test_radio_needs_matching_guest_device_and_listener(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); cfg=site_fixture(root); stack=fixture()
            stack['zigbee']['bind_address']=cfg['app']['address']
            path=root/'stack.json'; path.write_text(json.dumps(stack))
            cfg['app'].update(kind='zigbee2mqtt', stack_config=str(path))
            cfg['guest']['serial_device']={'path':DEVICE}
            cfg['guest']['interfaces'][0]['role']='backend'
            self.assertEqual(deploy.validate(cfg),6101)
            for wrong in ({'path':DEVICE+'-other'}, None):
                bad=copy.deepcopy(cfg); bad['guest']['serial_device']=wrong
                with self.assertRaises(ValueError): deploy.validate(bad)
            cfg['app']['kind']='dns'
            with self.assertRaises(ValueError): deploy.validate(cfg)

    def test_radio_listener_requires_one_explicit_backend_interface(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); cfg=site_fixture(root); stack=fixture()
            cfg['guest']['interfaces'][0]['role']='management'
            backend={'role':'backend', 'ipv4':'198.18.30.22/24', 'mac':'02:00:00:00:61:02'}
            cfg['guest']['interfaces'].append(backend)
            cfg['guest']['serial_device']={'path':DEVICE}
            path=root/'stack.json'; path.write_text(json.dumps(stack))
            cfg['app'].update(kind='zigbee2mqtt', stack_config=str(path))
            self.assertEqual(deploy.validate(cfg),6101)
            for mode in ('management-listener','missing-role','duplicate-role'):
                bad=copy.deepcopy(cfg)
                if mode=='management-listener':
                    stack['zigbee']['bind_address']=cfg['app']['address']
                elif mode=='missing-role':
                    bad['guest']['interfaces'][1].pop('role')
                else:
                    bad['guest']['interfaces'][0]['role']='backend'
                path.write_text(json.dumps(stack))
                with self.subTest(mode=mode), self.assertRaises(ValueError): deploy.validate(bad)
                stack['zigbee']['bind_address']='198.18.30.22'

    def test_preserved_network_identity_rejects_malformed_values(self):
        import yaml
        import zigbee2mqtt
        for key, invalid in (
                ('network_key', [[], [1]*15, [1]*17, [True]*16, [1.5]*16, [-1]*16,
                                 [256]*16, {}, 'not-a-key', '!secret.yaml', '!secret.yaml ']),
                ('pan_id', [True, 0, -1, 65535, 1.5, [], {}, '1234', '!secret.yaml pan_id']),
                ('ext_pan_id', [[], [1]*7, [1]*9, [True]*8, [1.5]*8, [-1]*8,
                                [256]*8, {}, 1234, '!secret.yaml ext_pan_id'])):
            for selected in invalid:
                value=yaml.safe_load(state()['configuration.yaml'])
                value['advanced'][key]=selected
                with self.subTest(key=key,selected=selected), self.assertRaises(ValueError):
                    zigbee2mqtt.check_configuration(yaml.safe_dump(value),fixture()['zigbee'])

    def test_preserved_network_identity_accepts_boundaries_and_key_reference(self):
        import yaml
        import zigbee2mqtt
        for key in ([0]*16, [255]*16, '!secret.yaml network_key', '!secret network_key'):
            for pan_id in (1,65534):
                value=yaml.safe_load(state()['configuration.yaml'])
                value['advanced'].update(network_key=key,pan_id=pan_id,ext_pan_id=[0,255]*4)
                zigbee2mqtt.check_configuration(yaml.safe_dump(value),fixture()['zigbee'])

    def test_archive_and_restored_state_are_checked_without_modification(self):
        import zigbee2mqtt
        files=state(); cfg=fixture()['zigbee']
        cfg['state_sha256']={name:hashlib.sha256(value).hexdigest() for name,value in files.items()}
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); archive=root/'capture.tar'
            with tarfile.open(archive,'w') as tar:
                for name,value in files.items():
                    member=tarfile.TarInfo('zigbee2mqtt/'+name); member.size=len(value)
                    tar.addfile(member,io.BytesIO(value))
            zigbee2mqtt.check_archive(archive,cfg)
            data=root/'data'; data.mkdir()
            for name,value in files.items(): (data/name).write_bytes(value)
            before={p.name:p.read_bytes() for p in data.iterdir()}
            zigbee2mqtt.check_directory(data,cfg)
            self.assertEqual(before,{p.name:p.read_bytes() for p in data.iterdir()})
            (data/'database.db').write_bytes(b'other state')
            with self.assertRaises(ValueError): zigbee2mqtt.check_directory(data,cfg)

    def test_missing_or_generated_network_identity_is_held(self):
        import zigbee2mqtt
        cfg=fixture()['zigbee']; original=state()['configuration.yaml']
        for data in (b'', original.replace(b'pan_id: 1234',b'pan_id: GENERATE'),
                     original.replace(b'port: /dev/ttyACM0',b'port: /dev/ttyUSB0'),
                     original.replace(b'base_topic: zigbee2mqtt',b'base_topic: other'),
                     original.replace(b'host: 0.0.0.0',b'host: 127.0.0.1')):
            with self.subTest(data=data), self.assertRaises(ValueError): zigbee2mqtt.check_configuration(data,cfg)

    def test_missing_or_duplicate_archive_state_and_links_are_held(self):
        import zigbee2mqtt
        files=state(); cfg=fixture()['zigbee']
        cfg['state_sha256']={name:hashlib.sha256(value).hexdigest() for name,value in files.items()}
        for mode in ('missing','duplicate','link','other-service'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                archive=Path(tmp)/'capture.tar'
                with tarfile.open(archive,'w') as tar:
                    for name,value in files.items():
                        if mode=='missing' and name=='database.db': continue
                        member=tarfile.TarInfo('zigbee2mqtt/'+name); member.size=len(value)
                        if mode=='link' and name=='database.db':
                            member.type=tarfile.SYMTYPE; member.linkname='configuration.yaml'; member.size=0
                            tar.addfile(member)
                        else: tar.addfile(member,io.BytesIO(value))
                    if mode in ('duplicate','other-service'):
                        member=tarfile.TarInfo('zigbee2mqtt/database.db' if mode=='duplicate' else 'homeassistant/configuration.yaml')
                        member.size=1; tar.addfile(member,io.BytesIO(b'x'))
                with self.assertRaises(ValueError): zigbee2mqtt.check_archive(archive,cfg)
