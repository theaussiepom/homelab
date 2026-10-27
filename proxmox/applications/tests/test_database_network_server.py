"""Source-only database listener cutover tests; no target is contacted."""
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
    return {'homelab.conf': "# keep this comment\nlisten_addresses = '127.0.0.1,10.88.30.23' # backend\npassword_encryption = 'scram-sha-256'\nshared_buffers = '256MB'\n",
            'pg_hba.conf': '# local maintenance\nlocal all postgres peer\nlocal all all peer\nhost all all 127.0.0.1/32 scram-sha-256\nhost all all ::1/128 scram-sha-256\nhost all all 10.88.30.0/24 scram-sha-256\n'}


def cutover(value=None, sources=None, **kwargs):
    return server.render(value or contract(), 'postgresql', sources or postgres(),
                         phase='cutover', client_vmids=kwargs.pop('client_vmids', [211, 202]), **kwargs)


class DatabaseNetworkServerTests(unittest.TestCase):
    def test_postgres_replaces_old_listener_and_remote_policy_with_selected_clients(self):
        original = postgres(); result = cutover(sources=original)
        self.assertEqual(result['activation'], 'restart')
        self.assertEqual(result['phase'], 'cutover')
        self.assertEqual(result['client_vmids'], [202, 211])
        self.assertEqual(result['endpoint'], networks.endpoint(contract(), 'postgresql'))
        self.assertEqual(result['files']['homelab.conf'], original['homelab.conf'].replace('10.88.30.23', '10.88.31.23'))
        self.assertEqual(result['files']['pg_hba.conf'], original['pg_hba.conf'].replace(
            'host all all 10.88.30.0/24 scram-sha-256\n',
            'host all all 10.88.31.32/32 scram-sha-256\nhost all all 10.88.31.20/32 scram-sha-256\n'))
        self.assertNotIn('10.88.30.', str(result['files']))
        self.assertNotIn('10.88.31.27', str(result['files']))  # Planned Zabbix is not admitted.

    def test_repeated_cutover_has_no_change_or_activation(self):
        first = cutover(); repeated = cutover(sources=first['files'])
        self.assertEqual(repeated['files'], first['files'])
        self.assertEqual(repeated['activation'], 'none')

    def test_existing_wildcards_are_replaced_not_retained(self):
        for address in ('*', '0.0.0.0', '::', 'localhost,10.88.30.23'):
            source = postgres(); source['homelab.conf'] = "listen_addresses = '" + address + "'\n"
            result = cutover(sources=source)
            self.assertEqual(result['files']['homelab.conf'], "listen_addresses = '127.0.0.1,10.88.31.23'\n")
            self.assertEqual(result['activation'], 'restart')

    def test_hba_only_difference_requires_reload_and_drops_other_remote_rows(self):
        source = postgres(); source['homelab.conf'] = "listen_addresses = '127.0.0.1,10.88.31.23'\n"
        source['pg_hba.conf'] += 'host all all 10.88.31.27/32 scram-sha-256 # future\n'
        result = cutover(sources=source)
        self.assertEqual(result['activation'], 'reload')
        self.assertNotIn('10.88.31.27', result['files']['pg_hba.conf'])
        self.assertNotIn('/24', result['files']['pg_hba.conf'])

    def test_explicit_phase_and_finite_client_subset_are_required(self):
        for args in ({}, {'phase': 'additive', 'client_vmids': [211, 202]},
                     {'phase': 'cutover'}, {'phase': 'cutover', 'client_vmids': []},
                     {'phase': 'cutover', 'client_vmids': [211, 211]},
                     {'phase': 'cutover', 'client_vmids': [999]},
                     {'phase': 'cutover', 'client_vmids': [True]},
                     {'phase': 'cutover', 'client_vmids': 'all'}):
            with self.subTest(args=args), self.assertRaises(ValueError):
                server.render(contract(), 'postgresql', postgres(), **args)

    def test_missing_or_ambiguous_postgres_listener_is_held(self):
        for text in ('# no active listener\n', "listen_addresses = ''\n",
                     "listen_addresses = '127.0.0.1'\nlisten_addresses = '*'\n",
                     "listen_addresses = 'unreviewed.example.invalid'\n"):
            source = postgres(); source['homelab.conf'] = text
            with self.subTest(text=text), self.assertRaises(ValueError):
                cutover(sources=source)

    def test_other_postgres_authentication_policy_requires_review(self):
        for line in ('host all all 10.88.31.0/24 reject', 'hostssl all all 10.88.31.0/24 scram-sha-256',
                     'host all all 10.88.31.0/24 md5', 'include additional.conf',
                     'host app selected_user 10.88.31.0/24 scram-sha-256'):
            source = postgres(); source['pg_hba.conf'] += line + '\n'
            with self.subTest(line=line), self.assertRaises(ValueError):
                cutover(sources=source)

    def test_current_mariadb_and_influx_wildcard_configs_are_unchanged(self):
        sources = {'mariadb': {'homelab.cnf': '[mysqld]\nbind-address = 0.0.0.0\nskip-name-resolve\nmax_connections = 100\n'},
                   'influxdb': {'config.toml': 'bolt-path = "/var/lib/influxdb/influxd.bolt"\nhttp-bind-address = ":8086"\nreporting-disabled = true\n'}}
        for engine, source in sources.items():
            result = server.render(contract(), engine, source)
            self.assertEqual(result['files'], source)
            self.assertEqual(result['activation'], 'none')
            self.assertEqual(result['phase'], 'additive')
            with self.assertRaises(ValueError):
                server.render(contract(), engine, source, phase='cutover')

    def test_specific_mariadb_or_influx_listener_is_not_broadened(self):
        for engine, source in [('mariadb', {'homelab.cnf': '[mysqld]\nbind-address = 10.88.30.24\n'}),
                               ('influxdb', {'config.toml': 'http-bind-address = "10.88.30.26:8086"\n'})]:
            with self.subTest(engine=engine), self.assertRaises(ValueError):
                server.render(contract(), engine, source)

    def test_nonstandard_ports_and_disabled_tcp_are_held(self):
        cases = [('mariadb', {'homelab.cnf': '[mysqld]\nbind-address = 0.0.0.0\nport = 3307\n'}),
                 ('mariadb', {'homelab.cnf': '[mysqld]\nbind-address = 0.0.0.0\nskip-networking\n'}),
                 ('influxdb', {'config.toml': 'http-bind-address = ":8087"\n'})]
        for engine, source in cases:
            with self.subTest(engine=engine), self.assertRaises(ValueError):
                server.render(contract(), engine, source)
        source = postgres(); source['homelab.conf'] += 'port = 5433\n'
        with self.assertRaises(ValueError):
            cutover(sources=source)

    def test_inputs_and_sources_are_not_mutated(self):
        value = contract(); original = copy.deepcopy(value); source = postgres(); before = dict(source)
        result = cutover(value, source)
        self.assertEqual(value, original); self.assertEqual(source, before)
        result['files']['homelab.conf'] = 'caller change'
        self.assertEqual(source, before)

    def test_closed_source_names_and_catalogue_validation(self):
        for engine, source in [('unknown', postgres()), ('postgresql', {}),
                               ('postgresql', dict(postgres(), **{'../other.conf': 'must not render'})),
                               ('postgresql', dict(postgres(), **{'homelab.conf': b'not text'}))]:
            with self.subTest(engine=engine), self.assertRaises(ValueError):
                server.render(contract(), engine, source, phase='cutover', client_vmids=[211, 202])
        value = contract(); value['networks']['postgresql']['clients'][0]['address'] = '192.0.2.1'
        with self.assertRaises(ValueError):
            cutover(value)


if __name__ == '__main__':
    unittest.main()
