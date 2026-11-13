"""Native adapter units plus one actual baseline-file integration.

Shared binding validators have one matrix; per-app units use conforming resolved
bindings and mock those shared helpers. No database, service or filesystem state
is changed by this suite.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(Path(__file__).resolve().parents[3])
sys.path[:0] = [str(ROOT / 'proxmox/applications'), str(ROOT / 'blueprints')]
import component_native as m
FIXTURE = Path(__file__).with_name('native-baseline.json')


def app(adapter):
    packages = {
        'postgresql': ['postgresql-16=16.10-1.pgdg13+1', 'postgresql-client-16=16.10-1.pgdg13+1',
                       'libpq5=16.10-1.pgdg13+1'],
        'mariadb': ['mariadb-server=1:12.3.3+maria~deb13', 'mariadb-client=1:12.3.3+maria~deb13'],
        'influxdb': ['influxdb2=2.7.12-1', 'influxdb2-cli=2.7.5-1']}[adapter]
    root = {'postgresql': '/var/lib/postgresql', 'mariadb': '/var/lib/mysql',
            'influxdb': '/var/lib/influxdb'}[adapter]
    address = {'postgresql': '198.18.31.23', 'mariadb': '198.18.32.24',
               'influxdb': '198.18.33.26'}[adapter]
    return {'adapter': adapter, 'properties': {}, 'role_addresses': {'service_interface': address},
            'storage_paths': {'data': {'source': root, 'target': root, 'read_only': False,
                                       'kind': 'directory'}},
            'software_selection': {'packages': packages}}


def allowance(address):
    return {'source_address': address, 'database': 'all', 'user': 'all', 'method': 'scram-sha-256'}


class ResolvedBindingTests(unittest.TestCase):
    def test_native_address_binding_success_and_unsafe_shapes(self):
        self.assertEqual(m._address('198.18.31.23'), '198.18.31.23')
        for value in (None, True, 1, '::1', '127.0.0.1', '0.0.0.0', '224.0.0.1',
                      '169.254.1.2', '240.0.0.1', '198.18.31.23/32',
                      "198.18.31.23'\nssl=off", '198.018.31.23'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                m._address(value)

    def test_explicit_native_data_role_and_no_relocation_inference(self):
        for adapter in ('postgresql', 'mariadb', 'influxdb'):
            value = app(adapter)
            self.assertEqual(m._data(value), value['storage_paths']['data']['source'])
        base = app('influxdb')
        for change in (
            lambda v: v.update(storage_paths={}),
            lambda v: v['storage_paths'].update(extra=copy.deepcopy(v['storage_paths']['data'])),
            lambda v: v['storage_paths']['data'].update(target='/other'),
            lambda v: v['storage_paths']['data'].update(read_only=True),
            lambda v: v['storage_paths']['data'].update(read_only=0),
            lambda v: v['storage_paths']['data'].update(kind='file')):
            value = copy.deepcopy(base); change(value)
            with self.subTest(change=change), self.assertRaises(ValueError): m._data(value)
        for source in ('/', 'relative', '/tmp/../outside', '/tmp/./data', '//tmp/data',
                       '/tmp/data/', '/tmp/data\nsetting=bad', '/tmp/\\data',
                       '/tmp/${unresolved}', 'x' * 4097, None):
            value = app('influxdb'); value['storage_paths']['data']['source'] = source
            with self.subTest(source=source), self.assertRaises(ValueError): m._data(value)
        for adapter in ('postgresql', 'mariadb'):
            value = app(adapter); value['storage_paths']['data']['source'] = '/srv/example/relocated'
            with self.subTest(adapter=adapter), self.assertRaises(ValueError): m._data(value)
        value = app('influxdb'); value['storage_paths']['data']['source'] = '/srv/example/metrics'
        self.assertEqual(m._data(value), '/srv/example/metrics')

    def test_version_metadata_derives_exact_selected_server_not_other_packages(self):
        for adapter, expected in [('postgresql', ('16.10', '16')), ('mariadb', ('12.3.3', None)),
                                  ('influxdb', ('2.7.12', None))]:
            value = app(adapter)
            value['software_selection']['packages'].append('curl=8.14.1-2')
            self.assertEqual(m._version(value), expected)
        for adapter in ('postgresql', 'mariadb', 'influxdb'):
            for packages in (None, [], [True], [app(adapter)['software_selection']['packages'][0]] * 2,
                             ['postgresql-16=latest', 'mariadb-server=latest', 'influxdb2=latest']):
                value = app(adapter); value['software_selection']['packages'] = packages
                with self.subTest(adapter=adapter, packages=packages), self.assertRaises(ValueError):
                    m._version(value)
        value = app('postgresql'); value['software_selection']['packages'][0] = 'postgresql-17=16.10-1'
        with self.assertRaises(ValueError): m._version(value)

    def test_runtime_descriptor_boundary_rejects_unknown_adapter_property_and_missing_role(self):
        for value in (None, {}, {'adapter': 'mysql'}, {'adapter': ['postgresql']}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                m.render(value)
        for adapter in ('postgresql', 'mariadb', 'influxdb'):
            for change in (lambda v: v.update(properties={'raw_config': 'listen=*'}),
                           lambda v: v.update(role_addresses={})):
                value = app(adapter); change(value)
                with self.subTest(adapter=adapter, change=change), self.assertRaises(ValueError):
                    m.render(value)


class PostgreSQLTests(unittest.TestCase):
    def test_owned_config_fixed_main_paths_identity_and_ordered_explicit_allowances(self):
        value = app('postgresql'); before = copy.deepcopy(value)
        rows = [allowance('198.18.31.32'), allowance('198.18.31.20')]
        with patch.object(m, '_address', side_effect=lambda v: v), \
             patch.object(m, '_data', return_value='/var/lib/postgresql'), \
             patch.object(m, '_version', return_value=('16.10', '16')):
            result = m.render(value, clients=rows)
        self.assertEqual(value, before)
        self.assertEqual(result['services'], ['postgresql'])
        self.assertEqual(result['files']['homelab.conf'],
            "listen_addresses = '127.0.0.1,198.18.31.23'\npassword_encryption = 'scram-sha-256'\n"
            "shared_buffers = '256MB'\nmax_connections = 100\n")
        self.assertEqual(result['files']['pg_hba.conf'],
            'local all postgres peer\nlocal all all peer\n'
            'host all all 127.0.0.1/32 scram-sha-256\nhost all all ::1/128 scram-sha-256\n'
            'host all all 198.18.31.32/32 scram-sha-256\nhost all all 198.18.31.20/32 scram-sha-256\n')
        self.assertEqual(result['identity']['config_files'], [
            {'source': '${inputs}/homelab.conf', 'destination': '/etc/postgresql/16/main/conf.d/homelab.conf'},
            {'source': '${inputs}/pg_hba.conf', 'destination': '/etc/postgresql/16/main/pg_hba.conf'}])
        self.assertEqual((result['identity']['uid'], result['identity']['gid']), (70, 1000))
        self.assertNotIn('ssl=off', ''.join(result['files'].values()))
        self.assertNotIn('CREATE', ''.join(result['files'].values()))

    def test_standalone_has_no_inferred_remote_grants_or_monitoring_admin_prefix(self):
        result = m.render(app('postgresql'))
        rows = result['files']['pg_hba.conf'].splitlines()
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[-1], 'host all all ::1/128 scram-sha-256')
        self.assertNotIn('#', result['files']['pg_hba.conf'])

    def test_client_scope_is_closed_and_auth_method_cannot_downgrade(self):
        baseline = allowance('198.18.31.32')
        for row in (None, {}, dict(baseline, database='replication'), dict(baseline, user='postgres'),
                    dict(baseline, method='trust'), dict(baseline, method='md5'),
                    dict(baseline, connection='implied'),
                    dict(baseline, source_address='198.18.31.32/24')):
            with self.subTest(row=row), self.assertRaises(ValueError):
                m.render(app('postgresql'), clients=[row])
        for rows in ({'implicit': baseline}, None, [baseline] * 129):
            with self.subTest(rows_type=type(rows).__name__), self.assertRaises(ValueError):
                m.render(app('postgresql'), clients=rows)


class MariaDBTests(unittest.TestCase):
    def test_package_account_is_retained_without_numeric_identity_or_new_server_settings(self):
        with patch.object(m, '_address', return_value='198.18.32.24'), \
             patch.object(m, '_data', return_value='/var/lib/mysql'), \
             patch.object(m, '_version', return_value=('12.3.3', None)):
            result = m.render(app('mariadb'))
        self.assertEqual(result['files'], {'homelab.cnf': '[mysqld]\nbind-address = 198.18.32.24\n'
                         'skip-name-resolve\nmax_connections = 100\ninnodb_buffer_pool_size = 256M\n'})
        self.assertEqual(result['identity']['account_mode'], 'package')
        self.assertFalse({'uid', 'gid'} & set(result['identity']))
        self.assertEqual(result['identity']['config_files'][0]['destination'],
                         '/etc/mysql/mariadb.conf.d/99-homelab.cnf')
        self.assertNotIn('server_id', result['files']['homelab.cnf'])
        self.assertNotIn('ssl', result['files']['homelab.cnf'])
        self.assertEqual(result['services'], ['mariadb'])

    def test_no_unselected_server_id_or_postgresql_client_policy(self):
        value = app('mariadb'); value['properties'] = {'server_id': 1}
        with self.assertRaises(ValueError): m.render(value)
        with self.assertRaises(ValueError): m.render(app('mariadb'), clients=[allowance('198.18.32.32')])


class InfluxDBTests(unittest.TestCase):
    def test_explicit_data_root_and_bind_without_bootstrap_reporting_or_auth_changes(self):
        value = app('influxdb')
        value['storage_paths']['data']['source'] = '/srv/example/influx'
        with patch.object(m, '_address', return_value='198.18.33.26'), \
             patch.object(m, '_version', return_value=('2.7.12', None)):
            result = m.render(value)
        self.assertEqual(result['files'], {'config.toml': 'bolt-path = "/srv/example/influx/influxd.bolt"\n'
            'engine-path = "/srv/example/influx/engine"\nhttp-bind-address = "198.18.33.26:8086"\n'
            'reporting-disabled = true\n'})
        self.assertEqual(result['identity']['home'], '/srv/example/influx')
        self.assertEqual((result['identity']['uid'], result['identity']['gid']), (1000, 1000))
        self.assertEqual(result['services'], ['influxdb'])
        self.assertNotIn('token', ''.join(result['files'].values()))
        self.assertNotIn('setup', ''.join(result['files'].values()))

    def test_auth_or_engine_escape_properties_and_postgresql_allowances_refuse(self):
        for properties in ({'token': 'unused'}, {'raw_config': 'http-bind-address=:8086'},
                           {'reporting_disabled': False}):
            value = app('influxdb'); value['properties'] = properties
            with self.subTest(properties=properties), self.assertRaises(ValueError): m.render(value)
        with self.assertRaises(ValueError): m.render(app('influxdb'), clients=[allowance('198.18.33.32')])


class BaselineIntegrationTests(unittest.TestCase):
    def test_actual_base_renderer_existing_owned_hba_hooks_equal_all_four_baseline_files(self):
        import database_hba
        expected = json.loads(FIXTURE.read_text())
        for adapter in ('postgresql', 'mariadb', 'influxdb'):
            clients = [allowance('198.18.31.32'), allowance('198.18.31.20')] if adapter == 'postgresql' else ()
            result = m.render(app(adapter), clients=clients)
            self.assertEqual(result['identity'], expected[adapter]['database'])
            files = result['files']
            if adapter == 'postgresql':
                files['pg_hba.conf'] = database_hba.monitoring(files['pg_hba.conf'], '198.18.31.36')
                owner = {'node': 'example-pve', 'engine': 'postgresql', 'database_vmid': 208,
                    'source_vmid': 202, 'server_address': '198.18.31.23', 'source_address': '198.18.31.32',
                    'username': 'fixture_pg_admin_a', 'purpose': 'database-administration'}
                cfg = {'site': {'node': 'example-pve'}, 'guest': {'vmid': 208}, 'app': {
                    'kind': 'postgresql', 'database': result['identity'], 'database_administrators': {
                        'server-admin': {'username': 'fixture_pg_admin_a', 'source_guest': 'db-tools',
                            'credential_id': 'example-pg-admin-a',
                            'credential_file': '${inputs}/managed-example-pg-admin-a.json',
                            'access': 'server-administration', 'transport': 'tls', 'owner': owner}}}}
                files['pg_hba.conf']=database_hba.administrators(files['pg_hba.conf'],
                    cfg['app']['database_administrators'])
            self.assertEqual({name: value.encode() for name, value in files.items()},
                             {name: value.encode() for name, value in expected[adapter]['files'].items()})


if __name__ == '__main__':
    unittest.main()
