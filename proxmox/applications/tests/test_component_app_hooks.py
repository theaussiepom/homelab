"""Owned app hook units mock common contracts; one legacy descriptor comparison."""
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

FRAMEWORK = Path(Path(__file__).resolve().parents[3])
sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(FRAMEWORK / 'blueprints'),
                str(FRAMEWORK / 'proxmox/applications')]
import component_app_hooks as hooks
import dns_records
import music_assistant
import zigbee2mqtt

BASELINE = json.loads(Path(__file__).with_name('public-retained-app-hooks.json').read_text())
COMPOSE = '/opt/homelab-app/compose.yml'


def app(adapter, *, source=None):
    value = {'adapter': adapter, 'lifecycle': 'retained',
             'identity': {'runtime_id': adapter, 'services': {adapter: adapter}},
             'settings': {}, 'role_addresses': {}, 'storage_paths': {}}
    if adapter == 'pihole':
        value['settings'] = {'dns_records': {'broker.example.invalid': '198.18.41.8'}}
    elif adapter == 'music_assistant':
        value['role_addresses'] = {'web': '198.18.41.9'}
        value['storage_paths'] = {'data': {'source': source or str(music_assistant.DATA),
            'target': '/data', 'kind': 'directory', 'read_only': False}}
    elif adapter == 'zigbee2mqtt':
        value['settings'] = copy.deepcopy(BASELINE['settings'])
        value['storage_paths'] = {'data': {'source': source or hooks.ZIGBEE_DATA,
            'target': '/app/data', 'kind': 'directory', 'read_only': False}}
    return value


def describe(value, compose=COMPOSE):
    return hooks.descriptors(value, compose_file=compose)


class PiholeHookUnits(unittest.TestCase):
    def test_selected_service_only_is_reconciled_then_restarted_without_dependencies(self):
        value = app('pihole'); value['identity']['services']['pihole'] = 'resolver-a'
        with patch.object(hooks.dns_records, 'validate') as records, \
             patch.object(hooks, '_mount_path', return_value='/opt/homelab-app/compose-a.yml') as path, \
             patch.object(hooks, '_name', return_value='resolver-a') as service:
            result = describe(value, '/opt/homelab-app/compose-a.yml')
        records.assert_called_once_with(value['settings']['dns_records'])
        path.assert_called_once_with('/opt/homelab-app/compose-a.yml')
        service.assert_called_once_with('resolver-a')
        row = result['pihole_records']
        self.assertEqual(row['reconcile_argv'][-2:], ['--service', 'resolver-a'])
        self.assertEqual(row['restart_argv'], ['docker', 'compose', '-f',
            '/opt/homelab-app/compose-a.yml', 'restart', '--no-deps', 'resolver-a'])
        self.assertEqual(set(result), {'helpers', 'pihole_records'})

    def test_optional_service_parameter_reaches_only_the_bounded_ftl_command(self):
        values = ['[ 198.18.41.7 retained.example.invalid ]', '',
                  '[ 198.18.41.7 retained.example.invalid, 198.18.41.8 broker.example.invalid ]']
        with patch.object(dns_records.subprocess, 'run',
                          side_effect=[SimpleNamespace(stdout=value) for value in values]) as run:
            self.assertTrue(dns_records.reconcile({'broker.example.invalid': '198.18.41.8'},
                                                 Path(COMPOSE), service='resolver-a'))
        self.assertEqual(run.call_count, 3)
        for call in run.call_args_list:
            self.assertEqual(call.args[0][4:8], ['exec', '-T', 'resolver-a', 'pihole-FTL'])
            self.assertEqual(call.kwargs['timeout'], 30)
            self.assertTrue(call.kwargs['capture_output'])
        self.assertEqual(json.loads(run.call_args_list[1].args[0][-1]),
                         ['198.18.41.7 retained.example.invalid', '198.18.41.8 broker.example.invalid'])

    def test_literal_service_guard_refuses_options_expressions_controls_before_docker(self):
        for name in ('', '--all', 'other service', '${NAME}', 'a\nb', None, 42, 'x' * 129):
            with self.subTest(name=name), patch.object(dns_records.subprocess, 'run') as run, \
                 self.assertRaises(ValueError):
                dns_records.reconcile({}, Path(COMPOSE), service=name)
            run.assert_not_called()

    def test_cli_forwards_optional_service_and_emits_only_changed_status(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'records.json'; source.write_text(json.dumps(dns_records.document({},{})))
            for extra, selected in (([], 'pihole'), (['--service', 'resolver-a'], 'resolver-a')):
                argv = ['dns_records.py', 'reconcile', '--records', str(source), '--compose', COMPOSE, *extra]
                with self.subTest(service=selected), patch.object(sys, 'argv', argv), \
                     patch.object(dns_records, 'reconcile', return_value=False) as reconcile, \
                     patch('sys.stdout', new_callable=io.StringIO) as output:
                    dns_records.main()
                reconcile.assert_called_once_with({}, Path(COMPOSE), service=selected, previous={})
                self.assertEqual(output.getvalue(), '{"changed": false}\n')


class MusicHookUnits(unittest.TestCase):
    def test_role_and_data_bindings_use_the_existing_common_contracts(self):
        value = app('music_assistant', source='/srv/example/music/data')
        with patch.object(hooks.music_assistant, 'address', return_value='198.18.42.9') as address, \
             patch.object(hooks.music_assistant, 'data_path', return_value=Path('/srv/example/music/data')) as data, \
             patch.object(hooks, '_mount_path', return_value='/srv/example/music/data') as mount:
            row = describe(value)['music_state']
        address.assert_called_once_with('198.18.41.9')
        mount.assert_called_once_with('/srv/example/music/data')
        data.assert_called_once_with('/srv/example/music/data')
        self.assertEqual(row['argv'], ['python3', '/opt/homelab-app/music_assistant.py',
            '--address', '198.18.42.9', '--data-root', '/srv/example/music/data'])

    def test_generated_default_and_bound_argv_reach_the_existing_read_only_helper_paths(self):
        for source, selected in ((None, 'legacy'), ('/srv/example/music/data', 'bound')):
            argv = describe(app('music_assistant', source=source))['music_state']['argv']
            with self.subTest(selected=selected), patch.object(music_assistant, 'check_directory') as old, \
                 patch.object(music_assistant, 'check_bound_directory') as bound, \
                 patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(music_assistant.main(argv[2:]), 0)
            if selected == 'legacy':
                old.assert_called_once_with(music_assistant.DATA, '198.18.41.9'); bound.assert_not_called()
            else:
                bound.assert_called_once_with(source, '198.18.41.9'); old.assert_not_called()

    def test_fresh_commissioning_and_shadow_data_roles_remain_unsupported(self):
        value = app('music_assistant'); value['lifecycle'] = 'fresh'
        with self.assertRaises(ValueError): describe(value)
        for changes in ({'read_only': True}, {'kind': 'file'}, {'target': '/another'}, {'source': '/'}):
            value = app('music_assistant'); value['storage_paths']['data'].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError): describe(value)
        value = app('music_assistant'); value['storage_paths']['shadow'] = copy.deepcopy(value['storage_paths']['data'])
        with self.assertRaises(ValueError): describe(value)


class ZigbeeHookUnits(unittest.TestCase):
    def test_validation_and_health_share_selected_data_and_fixed_single_coordinator_receipt(self):
        value = app('zigbee2mqtt', source='/srv/example/radio/data')
        value['identity'] = {'runtime_id': 'radio-a', 'services': {'zigbee2mqtt': 'coordinator-a'}}
        original = copy.deepcopy(value)
        with patch.object(hooks.zigbee2mqtt, 'validate', return_value=value['settings']) as validate:
            row = describe(value)['zigbee_state']
        validate.assert_called_once_with(value['settings'])
        self.assertTrue(row['single_coordinator_per_guest'])
        self.assertEqual(row['identity_file'], '/opt/homelab-app/zigbee-network.json')
        for mode in ('validate', 'health'):
            self.assertEqual(row[mode + '_argv'], ['python3', '/opt/homelab-app/zigbee2mqtt.py', mode,
                '--settings', '/opt/homelab-app/zigbee-settings.json', '--data', '/srv/example/radio/data'])
        self.assertEqual(value, original)
        self.assertNotIn('initialize', repr(row))

    def test_cli_uses_existing_data_option_and_default_receipt_without_opening_radio(self):
        value = app('zigbee2mqtt', source='/srv/example/radio/data')
        for mode in ('validate', 'health'):
            argv = hooks.zigbee_argv(value, mode)
            with self.subTest(mode=mode), patch.object(sys, 'argv', argv[1:]), \
                 patch.object(zigbee2mqtt, 'read', return_value=json.dumps(value['settings']).encode()) as read, \
                 patch.object(zigbee2mqtt, 'check', return_value={'healthy': True, 'radio_opened': False}) as check, \
                 patch('sys.stdout', new_callable=io.StringIO) as output:
                zigbee2mqtt.main()
            read.assert_called_once_with(Path('/opt/homelab-app/zigbee-settings.json'))
            check.assert_called_once_with(Path('/srv/example/radio/data'), value['settings'],
                                          Path('/opt/homelab-app/zigbee-network.json'), mode == 'health')
            self.assertFalse(json.loads(output.getvalue())['radio_opened'])

    def test_settings_validation_errors_are_propagated_without_new_initialization(self):
        with patch.object(hooks.zigbee2mqtt, 'validate', side_effect=ValueError('rejected')) as validate, \
             self.assertRaisesRegex(ValueError, 'rejected'):
            describe(app('zigbee2mqtt'))
        validate.assert_called_once()
        for mode in ('initialize', 'repair', ''):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                hooks.zigbee_argv(app('zigbee2mqtt'), mode)
        value = app('zigbee2mqtt'); value['lifecycle'] = 'fresh'
        with self.assertRaises(ValueError): hooks.zigbee_argv(value, 'validate')


class SharedHookContractUnits(unittest.TestCase):
    def test_only_named_owned_adapters_and_literal_paths_are_admitted(self):
        for value in (None, {}, {'adapter': 'arbitrary', 'argv': ['injected']}):
            with self.subTest(value=value), self.assertRaises(ValueError): describe(value)
        for path in ('relative.yml', '/opt/homelab-app/${NAME}.yml', '/srv/../outside'):
            with self.subTest(path=path), self.assertRaises(ValueError): describe(app('pihole'), path)
        for path in ('relative', '/srv/../outside', '/srv/${ENV}', '/'):
            for adapter in ('music_assistant', 'zigbee2mqtt'):
                with self.subTest(path=path, adapter=adapter), self.assertRaises(ValueError):
                    describe(app(adapter, source=path))

    def test_fixed_installer_metadata_has_no_authored_hook_or_permissions_override(self):
        for adapter, name in (('pihole', 'dns_records.py'), ('music_assistant', 'music_assistant.py'),
                              ('zigbee2mqtt', 'zigbee2mqtt.py')):
            value = app(adapter); value['hooks'] = {'argv': ['ignored']}
            row = describe(value)
            self.assertEqual(row['helpers'], [{'source': name, 'destination': '/opt/homelab-app/' + name,
                                               'uid': 0, 'gid': 0, 'mode': '0700'}])
            self.assertNotIn('ignored', repr(row))
        settings = describe(app('zigbee2mqtt'))['zigbee_state']['settings_file']
        self.assertEqual({key: settings[key] for key in ('path', 'uid', 'gid', 'mode')},
                         {'path': '/opt/homelab-app/zigbee-settings.json', 'uid': 0, 'gid': 0, 'mode': '0600'})


class LegacyDescriptorIntegration(unittest.TestCase):
    def test_three_public_retained_descriptors_match_actual_old_task_argv_and_settings_bytes(self):
        self.assertTrue(BASELINE['source_is_public_synthetic'])
        self.assertEqual(BASELINE['framework_commit'], 'f28725b1e8334a0baba26dfc2fa623cb3a63cdf5')
        self.assertEqual(describe(app('pihole'))['pihole_records'], BASELINE['pihole'])
        self.assertEqual(describe(app('music_assistant'))['music_state'], BASELINE['music_assistant'])
        row = describe(app('zigbee2mqtt'))['zigbee_state']
        self.assertEqual(row['validate_argv'], BASELINE['zigbee2mqtt']['validate_argv'])
        self.assertEqual(row['health_argv'], BASELINE['zigbee2mqtt']['health_argv'])
        self.assertEqual(row['settings_file']['content'].encode(),
                         BASELINE['zigbee2mqtt']['settings_json'].encode())


if __name__ == '__main__':
    unittest.main()
