"""Split web sockets preserve native data APIs and retained player state."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3]/'blueprints'))
import component_native as native
import component_runtime as runtime
import component_checks as checks
import component_app_hooks as hooks
import music_assistant as music
from test_component_native import app as native_app
from test_component_music import descriptor, settings, make_data


def influx():
    value = native_app('influxdb')
    value['role_addresses']['web'] = '198.18.40.26'
    value['listeners'] = {
        name: {'service': 'influxdb', 'namespace': 'host', 'interface': role,
               'bind': 'interface', 'protocol': 'tcp', 'port': 8086,
               'actual_bind': value['role_addresses'][role]}
        for name, role in [('web', 'web'), ('backend', 'service')]}
    return value


class InfluxFrontendTests(unittest.TestCase):
    def test_real_ansible_ownership_guard_refuses_foreign_or_writable_unit_paths(self):
        import yaml
        from ansible.parsing.dataloader import DataLoader
        from ansible.template import Templar,trust_as_template
        tasks=yaml.safe_load((Path(__file__).resolve().parents[1]/'ansible/tasks/influxdb-web-frontend.yml').read_text())
        guard=next(task for task in tasks if task['name']=='Preserve foreign or unexpected frontend unit paths')
        expression=guard['ansible.builtin.assert']['that'][0]
        owned={'exists':True,'isreg':True,'uid':0,'gid':0,'nlink':1,'mode':'0644','size':200}
        cases=[({'exists':False},True),(owned,True)]
        cases += [(dict(owned,**change),False)for change in (
            {'isreg':False},{'uid':1000},{'gid':1000},{'nlink':2},{'mode':'0666'},{'size':16384})]
        for observed,expected in cases:
            with self.subTest(observed=observed):
                templar=Templar(loader=DataLoader(),variables={'item':{'stat':observed}})
                self.assertEqual(templar.evaluate_expression(trust_as_template(expression)),expected)

    def test_health_uses_each_explicit_listener_without_a_setup_or_data_query(self):
        rows=checks._influxdb(influx(),None)
        self.assertEqual(len(rows),5)
        self.assertIn('198.18.33.26:8086/health',rows[1]['argv'][-1])
        self.assertIn('198.18.40.26:8086/health',rows[-1]['argv'][-1])
        self.assertNotIn('Authorization',repr(rows))

    def test_optional_frontend_keeps_every_native_file_data_path_and_identity_exact(self):
        original = native_app('influxdb')
        self.assertEqual(native.web_frontend(original), {'enabled': False, 'files': []})
        value = influx(); before = copy.deepcopy(value)
        self.assertEqual(native.render(value), native.render(original))
        self.assertEqual(value, before)
        result = native.web_frontend(value)
        self.assertTrue(result['enabled'])
        units = {row['name']: row['content'] for row in result['files']}
        self.assertEqual(set(units), {'homelab-influxdb-web.socket', 'homelab-influxdb-web.service'})
        socket = units['homelab-influxdb-web.socket']
        self.assertIn('ListenStream=198.18.40.26:8086\n', socket)
        # Default sockets.target ordering precedes basic/network startup. This
        # explicit late socket must not create a cycle with network-ready.
        self.assertIn('DefaultDependencies=no\n', socket)
        self.assertIn('WantedBy=multi-user.target\n', socket)
        self.assertIn('Requires=homelab-network-ready.service influxdb.service\n', socket)
        self.assertIn('systemd-socket-proxyd 198.18.33.26:8086\n', units['homelab-influxdb-web.service'])
        self.assertNotIn('0.0.0.0', ''.join(units.values()))

    def test_wrong_owner_addresses_protocols_names_and_publications_refuse(self):
        changes = [lambda v: v.update(adapter='postgresql'),
                   lambda v: v['role_addresses'].update(web='0.0.0.0'),
                   lambda v: v['role_addresses'].update(web=v['role_addresses']['service']),
                   lambda v: v['listeners'].pop('backend')]
        changes += [lambda v, k=k, x=x: v['listeners']['web'].update({k: x})
                    for k, x in [('service', 'other'), ('namespace', 'app-network'),
                                 ('interface', 'service'), ('bind', 'all'),
                                 ('protocol', 'udp'), ('port', 8087),
                                 ('actual_bind', '198.18.40.27'), ('publish', {})]]
        for change in changes:
            value = influx(); change(value)
            with self.subTest(change=change), self.assertRaises(ValueError):
                native.web_frontend(value)


class MusicSplitTests(unittest.TestCase):
    def test_split_hook_and_cli_preserve_default_compatibility_and_pass_the_stream_role(self):
        import io
        from contextlib import redirect_stdout
        from test_component_app_hooks import app,describe
        value=app('music_assistant');value['role_addresses']['stream']='198.18.100.40'
        argv=describe(value)['music_state']['argv']
        self.assertEqual(argv[-2:],['--stream-address','198.18.100.40'])
        with patch.object(music,'check_directory')as verify,redirect_stdout(io.StringIO()):
            self.assertEqual(music.main(argv[2:]),0)
        verify.assert_called_once_with(music.DATA,'198.18.41.9','198.18.100.40')

    def test_split_composition_keeps_owned_service_except_probes_and_stream_address(self):
        value = descriptor(); value['role_addresses']['stream'] = '198.18.100.40'
        value['listeners']['8097'].update(interface='stream', actual_bind='198.18.100.40')
        with patch.object(runtime, '_service', return_value={}) as builder:
            service = runtime._music_assistant(value, {})['music_assistant']
        builder.assert_called_once()
        probe = service['healthcheck']['test'][-1]
        self.assertIn("http://198.19.100.241:8095/info", probe)
        self.assertIn("'198.18.100.40',8097", probe)
        value['listeners']['8097']['actual_bind'] = value['role_addresses']['web']
        with self.assertRaises(ValueError): runtime._music_assistant(value, {})

    def test_retained_split_settings_validate_without_rewriting_any_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); make_data(root)
            value = settings(); value['core']['streams']['values'].update(
                bind_ip='198.18.100.40', publish_ip='198.18.100.40')
            (root/'settings.json').write_text(json.dumps(value))
            before = {p.name: p.read_bytes() for p in root.iterdir() if p.is_file()}
            music.check_bound_directory(str(root), '198.19.100.241', '198.18.100.40')
            self.assertEqual(before, {p.name: p.read_bytes() for p in root.iterdir() if p.is_file()})
            with self.assertRaises(ValueError): music.validate_settings(value, '198.19.100.241')
            with self.assertRaises(ValueError): music.validate_settings(value, '198.19.100.241', '198.18.100.41')


class BoundAutomationTests(unittest.TestCase):
    def test_node_retained_interface_becomes_owned_nonsecret_environment_and_fresh_refuses(self):
        from test_component_handlers import case,base_service
        value=case('node_red');app=value['app'];app['listeners']['web']['bind']='interface'
        app['role_addresses']={'web':'198.18.40.21'}
        app['listeners']['web']['actual_bind']='198.18.40.21'
        with patch.object(runtime,'_service',return_value=base_service()):
            service=runtime._node_red(app,value['guest'])['node_red']
        self.assertEqual(service['environment']['NODE_RED_WEB_ADDRESS'],app['role_addresses']['web'])
        app['lifecycle']='fresh'
        with self.assertRaises(ValueError):runtime._node_red(app,value['guest'])

    def test_bound_web_contract_rejects_an_actual_wildcard_or_legacy_socket(self):
        import io
        from contextlib import redirect_stdout
        for port in (8123,1880):
            app={'role_addresses':{'web':'198.18.40.21'},'listeners':{'web':{'bind':'interface'}}}
            row=checks._bound_web_checks(app,port)[0]
            for sockets,passed in [(['198.18.40.21', '127.0.0.1'],True),(['0.0.0.0'],False),
                                   (['198.18.40.21','198.18.30.21'],False),(['127.0.0.1'],False)]:
                text='\n'.join('LISTEN 0 128 '+ip+':'+str(port)+' 0.0.0.0:*'for ip in sockets)
                with patch('subprocess.check_output',return_value=text),redirect_stdout(io.StringIO()):
                    if passed:exec(row['argv'][-1],{})
                    else:
                        with self.assertRaises(AssertionError):exec(row['argv'][-1],{})

    def test_bound_health_uses_the_exact_node_address_and_keeps_ha_loopback_probe(self):
        from test_component_checks import case
        for adapter in ('homeassistant','node_red'):
            app=case(adapter)['app'];app['listeners']['web']['bind']='interface'
            app['role_addresses']={'web':'198.18.40.21'}
            app['listeners']['web']['actual_bind']='198.18.40.21'
            rows=getattr(checks,'_'+adapter)(app,None)
            self.assertEqual(len(rows),2)
            if adapter=='node_red':self.assertEqual(rows[0]['argv'][-2:],['--address',app['role_addresses']['web']])
            else:self.assertEqual(rows[0]['argv'][-1],'homeassistant')


if __name__ == '__main__': unittest.main()
