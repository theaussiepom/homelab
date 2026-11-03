"""Typed ownership, real immutable credentials and preserved native HBA inputs."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.append(str(Path(__file__).resolve().parents[3]/'blueprints'))
import database_admin as m
import service_bindings
import cloudbeaver
from test_cloudbeaver import fixture


def composition():
    cloud = fixture()
    cloud['cloudbeaver']['managed_connections'] = {engine+'-admin': {'name': engine+' administrator',
        'driver': engine, 'database': 'postgres' if engine == 'postgresql' else '', 'account_id': 'server-admin'}
        for engine in m.KINDS}
    source = {'guest': {'vmid': 902, 'interfaces': [{'ipv4': '198.18.11.81/25'}, {'ipv4': '198.19.12.83/25'}]},
        'site': {'node': 'fixture-node'}, 'paths': {'state_root': '/synthetic/state'}, 'app': {'kind': 'db-tools', 'service_health_checks': {'cloudbeaver': [{}]},
            'service_connections': {'cloudbeaver.'+name: {'service': engine+'.'+engine, 'address': 'backend'}
                for engine in m.KINDS for name in (engine, engine+'-admin')}}}
    resolved = {'db-tools': (source, cloud, {})}
    for engine, vmid, address in [('postgresql', 901, '198.18.11.80'), ('mariadb', 903, '198.19.12.82')]:
        cfg = {'guest': {'vmid': vmid, 'interfaces': [{'ipv4': address+'/25'}]}, 'site': {'node': 'fixture-node'}, 'paths': {'state_root': '/synthetic/state'},
            'app': {'kind': engine, 'service_health_checks': {engine: [{}]}, 'published_services': {engine: {
                'hostname': engine+'.example.invalid', 'addresses': {'backend': address}, 'dns_address': 'backend',
                'protocol': 'tcp', 'port': m.KINDS[engine]}}, 'database_administrators': {'server-admin': {
                    'username': engine+'_administrator', 'source_guest': 'db-tools', 'credential_id': 'fixture-'+engine,
                    'credential_file': '${inputs}/managed-fixture-'+engine+'.json', 'access': 'server-administration',
                    'transport': 'tls'}}, 'database': {'config_files': [{'source': '${inputs}/pg_hba.conf',
                        'destination': '/etc/postgresql/16/main/pg_hba.conf'}]}}}
        resolved[engine] = (cfg, None, {'pg_hba.conf': 'local all postgres peer\nhost all all 127.0.0.1/32 scram-sha-256\n'})
    return resolved


class DatabaseAdministratorTests(unittest.TestCase):
    def test_resolved_topology_links_only_new_ids_and_preserves_metadata_policies(self):
        resolved = composition(); original = copy.deepcopy(resolved['db-tools'][1]['cloudbeaver']['connections'])
        endpoints = service_bindings.bind(resolved)
        source, cloud, _ = resolved['db-tools']
        self.assertEqual(set(endpoints), {'postgresql.postgresql', 'mariadb.mariadb'})
        for engine in m.KINDS:
            cfg = resolved[engine][0]; item = m.accounts(cfg, compiled=True)['server-admin']
            connection = m.connections(cloud['cloudbeaver'], compiled=True)[engine+'-admin']
            self.assertEqual(item['owner'], connection['owner'])
            self.assertEqual(connection['owner']['source_vmid'], 902)
            self.assertEqual(connection['owner']['database_vmid'], cfg['guest']['vmid'])
            self.assertEqual(connection['username'], item['username'])
            self.assertEqual(connection['port'], m.KINDS[engine])
            self.assertEqual(set(cloud['cloudbeaver']['connections'][engine]), set(original[engine]) | {'host', 'port'})
        self.assertEqual(cloud['cloudbeaver']['connections']['postgresql']['sslmode'], original['postgresql']['sslmode'])
        edges = list(service_bindings.connections_for({k: v[0] for k, v in resolved.items()}))
        self.assertEqual(len(edges), 4)
        self.assertEqual({edge.source for edge in edges}, {'db-tools'})

    def test_cross_guest_orphan_duplicate_and_wrong_engine_bindings_refuse(self):
        changes = [lambda r: r['postgresql'][0]['app']['database_administrators']['server-admin'].update(source_guest='missing'),
            lambda r: r['postgresql'][0]['app']['database_administrators']['server-admin'].update(source_guest='mariadb'),
            lambda r: r['mariadb'][0]['app']['database_administrators']['server-admin'].update(credential_id='fixture-postgresql',credential_file='${inputs}/managed-fixture-postgresql.json'),
            lambda r: r['db-tools'][1]['cloudbeaver']['managed_connections']['postgresql-admin'].update(account_id='missing'),
            lambda r: r['db-tools'][0]['app']['service_connections']['cloudbeaver.postgresql-admin'].update(service='mariadb.mariadb'),
            lambda r: r['db-tools'][0]['app']['service_connections'].pop('cloudbeaver.mariadb-admin'),
            lambda r: r['postgresql'][0]['paths'].update(state_root='/foreign/state'),
            lambda r: r['postgresql'][0]['app']['published_services']['postgresql'].update(port=3306)]
        for change in changes:
            resolved = composition(); change(resolved)
            with self.subTest(change=change), self.assertRaises(ValueError):service_bindings.bind(resolved)
        resolved = composition(); resolved['db-tools'][1]['cloudbeaver']['managed_connections'].pop('postgresql-admin')
        resolved['db-tools'][0]['app']['service_connections'].pop('cloudbeaver.postgresql-admin')
        with self.assertRaises(ValueError):service_bindings.bind(resolved)

    def test_private_credentials_are_independent_but_exactly_shared_with_their_declared_client(self):
        resolved = composition(); service_bindings.bind(resolved)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700)
            packets = {}
            for engine in m.KINDS:
                cfg = resolved[engine][0]; cfg['paths'] = {'state_root': str(root)}
                item = cfg['app']['database_administrators']['server-admin']
                item['credential_file'] = str(root/engine/Path(item['credential_file']).name)
                packets[engine] = m.prepare(cfg, None, root/engine)
            cfg, cloud, _ = resolved['db-tools']; cfg['paths'] = {'state_root': str(root)}
            for item in cloud['cloudbeaver']['managed_connections'].values():
                item['credential_file'] = str(root/'cloud'/Path(item['credential_file']).name)
            payload = m.prepare(cfg, cloud, root/'cloud')
            for engine in m.KINDS:
                filename = 'managed-fixture-'+engine+'.json'
                self.assertEqual(payload[filename], packets[engine][filename])
                path = root/'cloud'/filename; path.parent.mkdir(mode=0o700, exist_ok=True); path.write_bytes(payload[filename]); path.chmod(0o600)
            self.assertNotEqual(json.loads(next(iter(packets['postgresql'].values())))['password'],
                                json.loads(next(iter(packets['mariadb'].values())))['password'])
            document = json.loads(m.document(cloud['cloudbeaver']))
            self.assertEqual(set(document['connections']), {'postgresql-admin', 'mariadb-admin'})
            self.assertEqual(document['connections']['postgresql-admin']['configuration']['properties'], {'sslmode': 'require'})
            self.assertEqual(document['connections']['mariadb-admin']['configuration']['properties'], {'sslMode': 'trust'})
            before = cloudbeaver.configuration(fixture()['cloudbeaver'])
            after = cloudbeaver.configuration(cloud['cloudbeaver'])
            self.assertFalse(before['app']['adminCredentialsSaveEnabled'])
            self.assertTrue(after['app']['adminCredentialsSaveEnabled']); self.assertTrue(after['app']['secretManagerEnabled'])
            self.assertEqual(cloud['cloudbeaver']['connections'].keys(), {'postgresql', 'mariadb'})
            rows = cloudbeaver.files(cloud, b'synthetic-oidc-client-secret-'*2)
            public = json.loads(next(row['content'] for row in rows if row['path'] == 'cloudbeaver-public.json'))
            native = next(row for row in rows if row['path'] == 'cloudbeaver-admin-connections.json')
            import hashlib
            self.assertEqual(public['managed_sha256'], hashlib.sha256(native['content'].encode()).hexdigest())
            self.assertEqual(public['cloudbeaver_image'], cloud['services']['cloudbeaver']['image'])
            self.assertEqual(native['uid'], 0); self.assertEqual(native['mode'], '0400')
            import render
            service = render.compose(cloud)['services']['cloudbeaver']
            self.assertTrue(any(row['target'].endswith('/CloudBeaverDatabaseHealth.java') and row['read_only']
                                for row in service['volumes']))
            cfg['paths']['state_root'] = str(root)
            cloud['cloudbeaver']['managed_connections']['postgresql-admin']['credential_file'] = '/foreign/managed-fixture-postgresql.json'
            with self.assertRaises(ValueError):m.prepare(cfg, cloud, root/'cloud')

    def test_hba_is_a_finite_source_prefix_and_original_tail_is_byte_exact(self):
        resolved = composition(); service_bindings.bind(resolved)
        cfg, _, files = resolved['postgresql']; old = files['pg_hba.conf']; before = copy.deepcopy(cfg)
        m.hba(cfg, files)
        self.assertEqual(cfg, before); self.assertTrue(files['pg_hba.conf'].endswith(old))
        self.assertIn('hostssl all,replication postgresql_administrator 198.18.11.81/32 scram-sha-256\n', files['pg_hba.conf'])
        self.assertIn('local all,replication postgresql_administrator reject\n', files['pg_hba.conf'])
        self.assertIn('host all,replication postgresql_administrator ::/0 reject\n', files['pg_hba.conf'])
        with self.assertRaises(ValueError):m.hba(cfg, files)
        cfg['app']['database']['config_files'] = []
        with self.assertRaises(ValueError):m.hba(cfg, {'pg_hba.conf': old})
        self.assertIsNone(m.hba(resolved['mariadb'][0], {}))

    def test_closed_account_connection_ownership_and_input_contracts(self):
        resolved = composition(); account = resolved['postgresql'][0]['app']['database_administrators']['server-admin']
        for key, value in [('username', "bad'"), ('credential_id', '../key'), ('credential_file', 'relative'),
                           ('credential_file', '/synthetic/other.json'), ('access', 'read-only'), ('transport', 'plaintext')]:
            cfg = copy.deepcopy(resolved['postgresql'][0]); cfg['app']['database_administrators']['server-admin'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):m.accounts(cfg)
        for values in ([], {}, None, {'bad id': account}, {'one': account, 'two': account}):
            cfg = copy.deepcopy(resolved['postgresql'][0]); cfg['app']['database_administrators'] = values
            with self.assertRaises(ValueError):m.accounts(cfg)
        self.assertEqual(m.accounts({'app': {'kind': 'music'}}), {})
        service_bindings.bind(resolved); value = resolved['db-tools'][1]['cloudbeaver']; original = copy.deepcopy(value)
        for key, bad in [('host', '198.18.11.99'), ('port', 3306), ('username', 'foreign'), ('transport', 'plaintext')]:
            row = copy.deepcopy(original); row['managed_connections']['postgresql-admin'][key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):m.connections(row, compiled=True)
        for field, bad in [('database_vmid', True), ('source_vmid', 1), ('source_address', '127.0.0.1'),
                           ('source_address', 'invalid-address'), ('source_address', False), ('engine', []), ('purpose', 'other')]:
            own = copy.deepcopy(account['owner']); own[field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError):m.owner(own)
        row = copy.deepcopy(original); row['managed_connections']['postgresql'] = row['managed_connections'].pop('postgresql-admin')
        with self.assertRaises(ValueError):m.connections(row, compiled=True)
        self.assertEqual(m.connections({'connections': {}}), {})


if __name__ == '__main__':
    unittest.main()
