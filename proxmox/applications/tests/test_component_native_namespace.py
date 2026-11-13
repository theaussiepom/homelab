"""Pure native namespace units; actual renderer integration, never guest operations."""
import copy
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

F = Path(os.environ.get('HOMELAB_FRAMEWORK', Path(__file__).resolve().parents[3])).resolve()
sys.path[:0] = [str(F / 'proxmox/applications'), str(F / 'blueprints'),
                str(F / 'proxmox/applications/tests')]
import component_native as native
import component_runtime as runtime
from test_component_native import app
import test_component_runtime as runtime_cases


def fake(name, **identity):
    return {'files': {'settings.conf': 'synthetic\n'}, 'services': [name],
            'identity': {'user': name, 'group': name, 'home': '/srv/example/' + name,
                         'config_files': [{'source': '${inputs}/settings.conf',
                                           'destination': '/etc/example/' + name + '.conf'}], **identity}}


def configuration(*adapters):
    return {'schema': runtime.SCHEMA, 'guest': {'timezone': 'UTC', 'memory_mib': 8192,
                                             'os_reserve_mib': 128},
            'applications': {name: dict(app(name), native_requirements={'memory_mib': 256})
                             for name in adapters}}


class NativeNamespaceUnits(unittest.TestCase):
    def test_empty_single_and_package_unknown_numbers_do_not_invent_identity(self):
        native.namespace({})
        rows = {'server': fake('server', uid=70, gid=1000), 'package': fake('package')}
        before = copy.deepcopy(rows); native.namespace(rows); self.assertEqual(rows, before)
        rows = {'a': fake('a', uid=70, gid=1000, group='shared'),
                'b': fake('b', uid=71, gid=1000, group='shared')}
        native.namespace(rows)

    def test_uid_and_gid_are_separate_numeric_namespaces(self):
        native.namespace({'a': fake('a', uid=70, gid=1000), 'b': fake('b', uid=1000, gid=70)})

    def test_numeric_principal_conflicts_refuse_in_both_directions(self):
        for fields in ({'uid': 70, 'gid': 1001}, {'uid': 71, 'gid': 1000},
                       {'uid': 71, 'gid': 1001, 'user': 'a'},
                       {'uid': 71, 'gid': 1001, 'group': 'a'}):
            rows = {'a': fake('a', uid=70, gid=1000), 'b': fake('b', **fields)}
            before = copy.deepcopy(rows)
            with self.subTest(fields=fields), self.assertRaisesRegex(ValueError, 'Unix account'):
                native.namespace(rows)
            self.assertEqual(rows, before)

    def test_units_config_files_and_data_paths_cannot_have_competing_owners(self):
        for kind in ('unit', 'config', 'data', 'nested-data', 'config-in-data', 'data-around-config',
                     'own-duplicate-config', 'own-file-directory'):
            rows = {'a': fake('a'), 'b': fake('b')}
            first, second = rows['a'], rows['b']
            if kind == 'unit': second['services'] = first['services'][:]
            elif kind == 'config': second['identity']['config_files'][0]['destination'] = first['identity']['config_files'][0]['destination']
            elif kind == 'data': second['identity']['home'] = first['identity']['home']
            elif kind == 'nested-data': second['identity']['home'] = first['identity']['home'] + '/nested'
            elif kind == 'config-in-data': second['identity']['config_files'][0]['destination'] = first['identity']['home'] + '/settings.conf'
            elif kind == 'data-around-config': second['identity']['home'] = '/etc/example'
            elif kind == 'own-duplicate-config': second['identity']['config_files'] *= 2
            else: second['identity']['config_files'][0]['destination'] = second['identity']['home']
            with self.subTest(kind=kind), self.assertRaises(ValueError): native.namespace(rows)
        # A component may own configuration below its own data directory.
        row = fake('owned'); row['identity']['config_files'][0]['destination'] = row['identity']['home'] + '/settings.conf'
        native.namespace({'owned': row})

    def test_declared_identity_and_path_shapes_are_closed_at_the_component_boundary(self):
        for value in (None, [], {'bad': {}}, {'bad': {'identity': {}, 'services': []}}):
            with self.subTest(value=value), self.assertRaises(ValueError): native.namespace(value)
        for fields in ({'uid': True}, {'gid': -1}, {'uid': 1.5}, {'uid': 7, 'user': ''},
                       {'gid': 7, 'group': None}, {'config_files': {}}, {'config_files': [None]},
                       {'home': None}, {'home': '/'}, {'home': 'relative'}, {'home': '/srv/../outside'},
                       {'home': '/srv//double'}, {'home': '/srv/unsafe\n'}, {'home': '/srv/back\\slash'}):
            with self.subTest(fields=fields), self.assertRaises(ValueError): native.namespace({'bad': fake('bad', **fields)})
        for services in ([None], [''], ['duplicate', 'duplicate']):
            value = fake('bad'); value['services'] = services
            with self.subTest(services=services), self.assertRaises(ValueError): native.namespace({'bad': value})


class NativeNamespaceRendererIntegration(unittest.TestCase):
    def test_actual_compatible_pg_maria_renders_once_each_and_preserves_budget_owner(self):
        cfg = configuration('postgresql', 'mariadb'); before = copy.deepcopy(cfg)
        with patch.object(native, 'render', wraps=native.render) as render:
            files = runtime.artifacts(cfg)
        self.assertEqual(render.call_count, 2)
        self.assertIn('component-native.json', files)
        self.assertEqual(cfg, before)
        cfg['guest']['memory_mib'] = 512
        with patch.object(native, 'namespace') as check, self.assertRaises(ValueError): runtime.artifacts(cfg)
        check.assert_not_called()

    def test_actual_pg_influx_fixed_gid_conflict_refuses_before_owned_hba_hooks(self):
        cfg = configuration('postgresql', 'influxdb'); before = copy.deepcopy(cfg)
        with patch.object(native, 'render', wraps=native.render) as render, \
             patch('database_hba.administrators', side_effect=AssertionError('No owned hook before namespace admission')):
            with self.assertRaisesRegex(ValueError, 'Unix account'): runtime.artifacts(cfg)
        self.assertEqual(render.call_count, 2)
        self.assertEqual(cfg, before)

    def test_native_and_actual_selected_container_remain_independent(self):
        fixture = runtime_cases.RuntimeTests(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        cfg = fixture.compile(); cfg['guest']['memory_mib'] = 1024
        cfg['applications']['postgresql'] = dict(app('postgresql'), native_requirements={'memory_mib': 256})
        with patch.object(native, 'render', wraps=native.render) as render:
            files = runtime.artifacts(cfg)
        self.assertEqual(render.call_count, 1)
        self.assertTrue(any(name.startswith('compose-') for name in files))
        self.assertIn('component-native.json', files)


if __name__ == '__main__':
    unittest.main()
