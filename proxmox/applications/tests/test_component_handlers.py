"""Independent adapter units mock helpers; each legacy comparison integrates once."""
import copy
from fixture_network_names import modernize
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import component_runtime as runtime

FIXTURE = modernize(json.loads(Path(__file__).with_name('public-synthetic-retained-services.json').read_text()))


def case(name):
    return modernize(FIXTURE['cases'][name])


def base_service():
    return {'environment': {'TZ': 'Etc/UTC'}, 'volumes': []}


class NodeUnitTests(unittest.TestCase):
    def test_retained_strategy_storage_process_and_aliases_use_component_boundaries(self):
        item = case('node_red');app, guest = item['app'], item['guest']
        with patch.object(runtime, '_service', return_value=base_service()) as service, \
             patch.object(runtime, '_mounts', return_value=['selected-data', 'selected-config']) as mounts, \
             patch.object(runtime, '_aliases', return_value={'broker.example.invalid': '198.18.30.21'}) as aliases:
            selected = runtime._node_red(app, guest)['node_red']
        service.assert_called_once_with(app, 'node_red', guest)
        mounts.assert_called_once()
        aliases.assert_called_once_with(app)
        self.assertEqual(selected['network_mode'], 'host')
        self.assertEqual(selected['entrypoint'], ['./entrypoint.sh'])
        self.assertEqual(selected['command'], ['--settings', '/runtime-settings.js'])
        self.assertEqual(selected['user'], 'node-red')
        self.assertEqual(selected['environment']['FLOWS'], '/config/flows.json')
        self.assertEqual(selected['environment']['NODE_RED_OIDC_CLIENT_ID'], app['authentication_resolved']['client_id'])
        self.assertNotIn('NODE_RED_API_TOKEN', selected['environment'])

    def test_retained_wrappers_and_process_identity_cannot_disappear_or_change(self):
        for mutate in (lambda a: a['storage_paths'].pop('settings'),
                       lambda a: a['storage_paths']['healthcheck'].update(read_only=False),
                       lambda a: a.pop('authentication_resolved'),
                       lambda a: a['listeners']['web_listener'].update(port=1881)):
            with self.subTest(mutate=mutate):
                item = case('node_red');mutate(item['app'])
                with patch.object(runtime, '_service', return_value=base_service()):
                    with self.assertRaises(ValueError):runtime._node_red(item['app'], item['guest'])
        item = case('node_red')
        with patch.object(runtime, '_service', return_value=dict(base_service(), user='root')):
            with self.assertRaises(ValueError):runtime._node_red(item['app'], item['guest'])

    def test_public_fresh_node_has_no_retained_wrapper_strategy_or_flows_override(self):
        item = case('node_red');app = item['app'];app['lifecycle'] = 'fresh';app.pop('authentication_resolved')
        app['storage_paths'] = {'data': app['storage_paths']['data']}
        with patch.object(runtime, '_service', return_value=base_service()), \
             patch.object(runtime, '_mounts', return_value=['data:/data']), \
             patch.object(runtime, '_aliases', return_value={}):
            selected = runtime._node_red(app, item['guest'])['node_red']
        self.assertNotIn('command', selected);self.assertNotIn('entrypoint', selected)
        self.assertNotIn('FLOWS', selected['environment'])
        self.assertFalse(any(k.startswith('NODE_RED_OIDC') for k in selected['environment']))

    def test_fresh_node_cannot_silently_select_a_retained_strategy_or_wrapper(self):
        item = case('node_red');item['app']['lifecycle'] = 'fresh'
        with patch.object(runtime, '_service', return_value=base_service()):
            with self.assertRaises(ValueError):runtime._node_red(item['app'], item['guest'])

    def test_fresh_node_rejects_unselected_retained_config_even_without_auth(self):
        item = case('node_red');app = item['app'];app['lifecycle'] = 'fresh';app.pop('authentication_resolved')
        app['storage_paths'] = {key:value for key,value in app['storage_paths'].items() if key in ('data', 'config')}
        with patch.object(runtime, '_service', return_value=base_service()):
            with self.assertRaises(ValueError):runtime._node_red(app, item['guest'])


class WinetUnitTests(unittest.TestCase):
    def test_existing_owned_options_health_and_aliases_are_fixed_without_options_read(self):
        item = case('winet');app, guest = item['app'], item['guest'];mount = {'source': 'selected-owned-runtime'}
        with patch.object(runtime, '_service', return_value=base_service()) as service, \
             patch.object(runtime, '_runtime_mount', return_value=mount) as runtime_mount, \
             patch.object(runtime, '_aliases', return_value={'broker.example.invalid': '198.18.30.21'}), \
             patch('builtins.open', side_effect=AssertionError('No private options reads')):
            selected = runtime._winet(app, guest)['winet']
        service.assert_called_once_with(app, 'winet', guest)
        runtime_mount.assert_called_once_with(app, 'winet-options.json', '/data/options.json')
        self.assertEqual(selected['volumes'], [mount])
        self.assertEqual(selected['network_mode'], 'host')
        self.assertEqual(selected['healthcheck']['test'][:3], ['CMD', 'node', '-e'])
        self.assertEqual(selected['healthcheck']['interval'], '30s')
        self.assertEqual(set(selected['environment']), {'TZ'})

    def test_custom_mount_listener_prefix_drift_or_process_override_refuses(self):
        for mutate in (lambda a: a.update(storage_paths={'custom': {}}),
                       lambda a: a.update(listeners={'web_listener': {}}),
                       lambda a: a['settings'].update(mqtt_prefix='foreign-prefix')):
            with self.subTest(mutate=mutate):
                item = case('winet');mutate(item['app'])
                with self.assertRaises(ValueError):runtime._winet(item['app'], item['guest'])
        for key in ('user', 'command', 'entrypoint', 'cap_add'):
            with self.subTest(key=key):
                item = case('winet')
                with patch.object(runtime, '_service', return_value=dict(base_service(), **{key: 'override'})):
                    with self.assertRaises(ValueError):runtime._winet(item['app'], item['guest'])


class ZigbeeUnitTests(unittest.TestCase):
    def test_registered_OCI_device_and_retained_alias_are_both_preserved(self):
        item = case('zigbee2mqtt');app, guest = item['app'], item['guest'];settings = app['settings']
        with patch.object(runtime.zigbee_runtime, 'validate', return_value=settings) as validated, \
             patch.object(runtime, '_service', return_value=base_service()), \
             patch.object(runtime, '_mounts', return_value=[app['storage_paths']['data']['source']+':/app/data']) as mounts, \
             patch.object(runtime, '_ports', return_value=item['expected_service']['ports']) as ports, \
             patch.object(runtime, '_aliases', return_value={}):
            selected = runtime._zigbee2mqtt(app, guest)['zigbee2mqtt']
        validated.assert_called_once_with(settings);mounts.assert_called_once();ports.assert_called_once()
        device = settings['serial_device']
        self.assertEqual(selected['devices'], [device+':'+device+':rw'])
        self.assertEqual(selected['volumes'][1], {'type': 'bind', 'source': device, 'target': '/dev/ttyACM0',
                        'read_only': False, 'bind': {'create_host_path': False}})
        self.assertFalse(selected['volumes'][0]['bind']['create_host_path'])
        self.assertNotIn('network_mode', selected)
        self.assertEqual(selected['healthcheck']['retries'], 30)

    def test_fresh_or_readonly_data_refuses_before_any_runtime_access(self):
        for mutate in (lambda a: a.update(lifecycle='fresh'),
                       lambda a: a['storage_paths']['data'].update(read_only=True),
                       lambda a: a['storage_paths'].clear()):
            with self.subTest(mutate=mutate):
                item = case('zigbee2mqtt');mutate(item['app'])
                with self.assertRaises(ValueError):runtime._zigbee2mqtt(item['app'], item['guest'])

    def test_port_namespace_and_process_identity_cannot_diverge_from_retained_config(self):
        item = case('zigbee2mqtt');item['app']['listeners']['web_listener']['namespace'] = 'host'
        with self.assertRaises(ValueError):runtime._zigbee2mqtt(item['app'], item['guest'])
        item = case('zigbee2mqtt')
        with patch.object(runtime, '_ports', return_value=['0.0.0.0:8099:8099/tcp']):
            with self.assertRaises(ValueError):runtime._zigbee2mqtt(item['app'], item['guest'])
        with patch.object(runtime, '_service', return_value=dict(base_service(), user='root')):
            with self.assertRaises(ValueError):runtime._zigbee2mqtt(item['app'], item['guest'])

    def test_upstream_settings_refusal_propagates_before_service_materialization(self):
        item = case('zigbee2mqtt')
        with patch.object(runtime.zigbee_runtime, 'validate', side_effect=ValueError('fixed settings refusal')), \
             patch.object(runtime, '_service') as service:
            with self.assertRaisesRegex(ValueError, 'fixed settings refusal'):
                runtime._zigbee2mqtt(item['app'], item['guest'])
        service.assert_not_called()


class PublicBaselineIntegrationTests(unittest.TestCase):
    def check_service(self, name):
        item = case(name)
        value = getattr(runtime, '_'+name)(item['app'], item['guest'])[name]
        self.assertEqual(json.dumps(value, sort_keys=True, separators=(',', ':')),
                         json.dumps(item['expected_service'], sort_keys=True, separators=(',', ':')))

    def test_retained_node_red_matches_actual_f287_70d_public_compilation(self):
        self.check_service('node_red')

    def test_winet_matches_actual_f287_70d_public_compilation(self):
        self.check_service('winet')

    def test_retained_zigbee_matches_actual_f287_70d_public_compilation(self):
        self.check_service('zigbee2mqtt')


if __name__ == '__main__':unittest.main()
