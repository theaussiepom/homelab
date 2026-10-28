"""Non-PG server cutovers: source-only regressions, no native commands."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import database_network_maintenance as maintenance
import database_network_server as server
from test_database_network_server import contract
from test_database_network_maintenance import cfg, raw_container, raw_rules


SOURCES = {
    'mariadb': {'homelab.cnf': '[mysqld]\nbind-address = 0.0.0.0\nskip-name-resolve\nmax_connections = 100\n'},
    'influxdb': {'config.toml': 'bolt-path = "/var/lib/influxdb/influxd.bolt"\nengine-path = "/var/lib/influxdb/engine"\nhttp-bind-address = ":8086"\nreporting-disabled = true\n'},
}


def installed(engine):
    c = cfg(); n = contract()['networks'][engine]
    c['app']['kind'] = engine
    c['guest'].update(vmid=n['server']['vmid'], hostname=n['server']['hostname'])
    end = n['server']['address'].split('.')[-1]
    c['guest']['interfaces'][0]['ipv4'] = '10.88.25.' + end + '/24'
    c['guest']['interfaces'][1]['ipv4'] = '10.88.30.' + end + '/24'
    c['guest']['rules'][1].update(port=str({'mariadb': 3306, 'influxdb': 8086}[engine]),
                                 destination='10.88.30.' + end + '/32')
    return c


class ServerCutoverTests(unittest.TestCase):
    def test_listener_cutover_changes_only_the_bound_address(self):
        for engine, source in SOURCES.items():
            with self.subTest(engine=engine):
                net = contract()['networks'][engine]
                result = server.render(contract(), engine, source, phase='cutover',
                                       client_vmids=[c['vmid'] for c in net['clients']])
                old = '0.0.0.0' if engine == 'mariadb' else ':8086'
                new = net['server']['address'] + (':8086' if engine == 'influxdb' else '')
                self.assertEqual(result['files'], {k: v.replace(old, new) for k, v in source.items()})
                self.assertEqual(result['activation'], 'restart')
                repeated = server.render(contract(), engine, result['files'], phase='cutover',
                                         client_vmids=[c['vmid'] for c in net['clients']])
                self.assertEqual(repeated['activation'], 'none')
                self.assertEqual(repeated['files'], result['files'])

    def test_cutover_requires_an_explicit_catalogue_client_selection(self):
        for engine, source in SOURCES.items():
            for ids in (None, [], [True], [999], [200, 200]):
                with self.subTest(engine=engine, ids=ids), self.assertRaises(ValueError):
                    server.render(contract(), engine, source, phase='cutover', client_vmids=ids)

    def test_server_replaces_old_nic_and_rule_without_touching_management_or_data(self):
        for engine in SOURCES:
            with self.subTest(engine=engine):
                original = installed(engine); before = copy.deepcopy(original)
                net = contract()['networks'][engine]
                guest = maintenance.candidate_guest(original['guest'], contract(), engine,
                    phase='cutover', client_vmids=[c['vmid'] for c in net['clients']],
                    legacy_server_address=original['guest']['interfaces'][1]['ipv4'].split('/')[0])
                self.assertEqual(original, before)
                self.assertEqual(len(guest['interfaces']), 2)
                self.assertEqual(guest['interfaces'][0], original['guest']['interfaces'][0])
                self.assertEqual(guest['interfaces'][1]['bridge'], net['bridge'])
                self.assertEqual(guest['interfaces'][1]['ipv4'], net['server']['address'] + '/24')
                self.assertEqual(guest['volumes'], original['guest']['volumes'])
                self.assertNotIn('10.88.30.', str(guest['rules']))
                self.assertEqual([r for r in guest['rules'] if r['port'] != str({'mariadb': 3306, 'influxdb': 8086}[engine])],
                                 [r for r in original['guest']['rules'] if r['port'] != str({'mariadb': 3306, 'influxdb': 8086}[engine])])

    def test_missing_legacy_address_and_material_nic_change_are_held(self):
        for engine in SOURCES:
            for legacy in (None, '10.88.30.199'):
                with self.subTest(engine=engine, legacy=legacy), self.assertRaises((ValueError, TypeError)):
                    maintenance.candidate_guest(installed(engine)['guest'], contract(), engine,
                        phase='cutover', client_vmids=[200], legacy_server_address=legacy)

    def test_other_or_ambiguous_listener_settings_are_not_silently_rewritten(self):
        cases = [
            ('mariadb', {'homelab.cnf': '[mysqld]\nbind-address = 0.0.0.0\nbind_address = 192.0.2.1\n'}),
            ('mariadb', {'homelab.cnf': '[mysqld]\nbind-address = 0.0.0.0\nskip-networking\n'}),
            ('mariadb', {'homelab.cnf': '[mysqld]\nbind-address = 0.0.0.0\nport = 3307\n'}),
            ('mariadb', {'homelab.cnf': '[mysqld]\nbind-address = 192.0.2.1\n'}),
            ('mariadb', {'homelab.cnf': '!include /tmp/other\n[mysqld]\nbind-address = 0.0.0.0\n'}),
            ('influxdb', {'config.toml': 'http-bind-address = ":8087"\n'}),
            ('influxdb', {'config.toml': 'http-bind-address = "192.0.2.1:8086"\n'}),
            ('influxdb', {'config.toml': 'http-bind-address = ":8086"\nhttp-bind-address = ":8086"\n'}),
        ]
        for engine, source in cases:
            with self.subTest(engine=engine, source=source), self.assertRaises(ValueError):
                server.render(contract(), engine, source, phase='cutover', client_vmids=[200])


if __name__ == '__main__':
    unittest.main()
