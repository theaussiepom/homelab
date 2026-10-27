"""Pure additive DB listener candidates; never read or contact a target."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import database_network_server as server
import database_networks as networks


def contract():
    return json.loads((networks.ROOT / 'examples/database-networks.example.json').read_text())


def postgres():
    return {'homelab.conf': "# keep this comment\nlisten_addresses = '127.0.0.1,10.88.30.23' # old backend\npassword_encryption = 'scram-sha-256'\nshared_buffers = '256MB'\n",
            'pg_hba.conf': 'local all postgres peer\nlocal all all peer\nhost all all 127.0.0.1/32 scram-sha-256\nhost all all ::1/128 scram-sha-256\nhost all all 10.88.30.0/24 scram-sha-256\n'}


class DatabaseNetworkServerTests(unittest.TestCase):
    def test_postgres_adds_new_listener_and_exact_clients_without_removing_legacy(self):
        value = contract(); original = postgres()
        result = server.render(value, 'postgresql', original)
        self.assertEqual(result['activation'], 'restart')
        self.assertEqual(result['endpoint'], networks.endpoint(value, 'postgresql'))
        self.assertEqual(result['files']['homelab.conf'], original['homelab.conf'].replace(
            "127.0.0.1,10.88.30.23'", "127.0.0.1,10.88.30.23,10.88.31.23'"))
        self.assertTrue(result['files']['pg_hba.conf'].startswith(original['pg_hba.conf']))
        added = result['files']['pg_hba.conf'][len(original['pg_hba.conf']):].splitlines()
        expected = ['host all all ' + client['address'] + '/32 scram-sha-256'
                    for client in value['networks']['postgresql']['clients']]
        self.assertEqual(added, expected)
        self.assertTrue(all('/24' not in line for line in added))

    def test_repeated_render_has_no_changes_or_service_activation(self):
        first = server.render(contract(), 'postgresql', postgres())
        repeated = server.render(contract(), 'postgresql', first['files'])
        self.assertEqual(repeated['files'], first['files'])
        self.assertEqual(repeated['activation'], 'none')

    def test_existing_wildcard_needs_only_hba_reload(self):
        for address in ('*', '0.0.0.0'):
            source = postgres(); source['homelab.conf'] = "listen_addresses = '" + address + "'\n"
            result = server.render(contract(), 'postgresql', source)
            self.assertEqual(result['files']['homelab.conf'], source['homelab.conf'])
            self.assertEqual(result['activation'], 'reload')

    def test_existing_client_row_with_comments_and_spacing_is_not_duplicated(self):
        source = postgres()
        source['pg_hba.conf'] += 'host  all  all  10.88.31.20/32  scram-sha-256 # existing\n'
        result = server.render(contract(), 'postgresql', source)
        self.assertEqual(result['files']['pg_hba.conf'].count('10.88.31.20/32'), 1)

    def test_missing_or_ambiguous_postgres_listener_is_held(self):
        for text in ('# no active listener\n', "listen_addresses = ''\n",
                     "listen_addresses = '127.0.0.1'\nlisten_addresses = '*'\n",
                     "listen_addresses = 'unreviewed.example.invalid'\n"):
            source = postgres(); source['homelab.conf'] = text
            with self.subTest(text=text), self.assertRaises(ValueError):
                server.render(contract(), 'postgresql', source)

    def test_other_postgres_authentication_policy_requires_explicit_review(self):
        for line in ('host all all 10.88.31.0/24 reject', 'hostssl all all 10.88.31.0/24 scram-sha-256',
                     'host all all 10.88.31.0/24 md5', 'include additional.conf',
                     'host app selected_user 10.88.31.0/24 scram-sha-256'):
            source = postgres(); source['pg_hba.conf'] += line + '\n'
            with self.subTest(line=line), self.assertRaises(ValueError):
                server.render(contract(), 'postgresql', source)

    def test_current_mariadb_and_influx_wildcard_configs_are_kept_byte_for_byte(self):
        sources = {'mariadb': {'homelab.cnf': '[mysqld]\nbind-address = 0.0.0.0\nskip-name-resolve\nmax_connections = 100\n'},
                   'influxdb': {'config.toml': 'bolt-path = "/var/lib/influxdb/influxd.bolt"\nhttp-bind-address = ":8086"\nreporting-disabled = true\n'}}
        for engine, source in sources.items():
            result = server.render(contract(), engine, source)
            self.assertEqual(result['files'], source)
            self.assertEqual(result['activation'], 'none')
            self.assertEqual(result['endpoint'], networks.endpoint(contract(), engine))

    def test_specific_mariadb_or_influx_listener_is_not_silently_broadened(self):
        cases = [('mariadb', {'homelab.cnf': '[mysqld]\nbind-address = 10.88.30.24\n'}),
                 ('influxdb', {'config.toml': 'http-bind-address = "10.88.30.26:8086"\n'})]
        for engine, source in cases:
            with self.subTest(engine=engine), self.assertRaises(ValueError):
                server.render(contract(), engine, source)

    def test_nonstandard_ports_or_disabled_mariadb_tcp_are_held(self):
        cases = [('mariadb', {'homelab.cnf': '[mysqld]\nbind-address = 0.0.0.0\nport = 3307\n'}),
                 ('mariadb', {'homelab.cnf': '[mysqld]\nbind-address = 0.0.0.0\nskip-networking\n'}),
                 ('influxdb', {'config.toml': 'http-bind-address = ":8087"\n'}),
                 ('postgresql', dict(postgres(), **{'homelab.conf': "listen_addresses = '127.0.0.1'\nport = 5433\n"}))]
        for engine, source in cases:
            with self.subTest(engine=engine), self.assertRaises(ValueError):
                server.render(contract(), engine, source)

    def test_input_contracts_and_sources_are_not_mutated(self):
        value = contract(); original = copy.deepcopy(value); source = postgres(); before = dict(source)
        result = server.render(value, 'postgresql', source)
        self.assertEqual(value, original); self.assertEqual(source, before)
        result['files']['homelab.conf'] = 'caller change'
        self.assertEqual(source, before)

    def test_closed_source_names_and_catalogue_validation_are_used(self):
        for engine, source in [('unknown', postgres()), ('postgresql', {}),
                               ('postgresql', dict(postgres(), **{'../other.conf': 'must not render'})),
                               ('postgresql', dict(postgres(), **{'homelab.conf': b'not text'}))]:
            with self.subTest(engine=engine), self.assertRaises(ValueError):
                server.render(contract(), engine, source)
        value = contract(); value['networks']['postgresql']['clients'][0]['address'] = '192.0.2.1'
        with self.assertRaises(ValueError):
            server.render(value, 'postgresql', postgres())


if __name__ == '__main__':
    unittest.main()
