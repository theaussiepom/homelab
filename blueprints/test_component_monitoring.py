"""Root monitoring component expansion with conforming app/guest collaborators."""
import copy
from types import SimpleNamespace
import unittest

import component_monitoring as monitoring
from component_errors import ComponentError


def fixture():
    """Build synthetic monitoring collaborators with distinct guest identities."""
    guests = {}
    for index, key in enumerate(('server', 'database', 'metrics', 'ingress')):
        guests[key] = {'context': 'lab', 'identity': {'vmid': 610 + index, 'hostname': key}, 'rules': [],
            'monitoring_profile': {'profile': 'linux'}, 'provider_interfaces': [
                {'ipv4': '198.18.20.' + str(10 + index) + '/24', 'gateway': '198.18.20.1'}]}
    apps = {}
    for key, adapter, profile in [('zabbix', 'zabbix', 'docker'), ('sql', 'postgresql', 'postgresql'),
                                  ('metrics', 'influxdb', 'influxdb'), ('proxy', 'traefik', 'docker')]:
        guest = {'zabbix': 'server', 'sql': 'database', 'metrics': 'metrics', 'proxy': 'ingress'}[key]
        apps[key] = {'id': key, 'guest': guest, 'adapter': adapter, 'profile': profile,
                     'role_addresses': {'service_interface': '198.18.20.11'}, 'resolved_connections': {}}
    apps['zabbix']['origin'] = {'exposure': 'monitoring'}
    apps['zabbix']['resolved_connections'] = {
        'database': {'type': 'postgresql', 'source_address': '198.18.20.10',
                     'target': {'app': 'sql', 'address': '198.18.20.11', 'port': 5432}},
        'metrics': {'type': 'influxdb', 'source_address': '198.18.20.10',
                    'target': {'app': 'metrics', 'address': '198.18.20.12', 'port': 8086}}}
    values = {key: {'type': 'zabbix-agent', 'profiles': [key]} for key in
              ('linux', 'docker', 'postgresql', 'influxdb')}
    resolver = SimpleNamespace(site={'zabbix': None, 'contexts': {'lab': {'node': 'example-node',
        'api_endpoint': {'external': 'api'}, 'trust': {'ca_file': '/example/ca.pem'}}}},
        apps=apps, guests=guests, library={'monitoring_profiles': values,
            'app_profiles': {key: {'monitoring': {'profile': key}} for key in values}},
        endpoint=lambda ref: {'protocol': 'tcp', 'port': 10051, 'address': '198.18.20.10'}
            if 'app' in ref else {'address': '198.18.20.2'})
    exposures = SimpleNamespace(resolved={'monitoring': {'ingress_target': {'app': 'proxy'},
        'target': {'address': '198.18.20.10', 'port': 8080}}})
    return resolver, exposures


class MonitoringTests(unittest.TestCase):
    def test_web_grant_follows_the_web_endpoint_without_moving_agent_transport(self):
        """Vary both web address and port while preserving the agent endpoint."""
        resolver, exposures = fixture()
        resolver.guests['ingress']['provider_interfaces'].append({'ipv4': '198.18.40.13/24'})
        exposures.resolved['monitoring']['target']['address'] = '198.18.40.10'
        exposures.resolved['monitoring']['target']['port'] = 8081
        monitoring.bind(resolver, exposures)
        self.assertEqual(resolver.guests['ingress']['rules'][0], monitoring.rule(
            'out', '198.18.40.13', '198.18.40.10', 8081))
        self.assertEqual(resolver.guests['database']['monitoring']['server_active'], '198.18.20.10:10051')

    def test_profile_and_reference_are_closed_without_commands_or_secrets(self):
        monitoring.profile({'type': 'zabbix-agent', 'profiles': ['linux', 'docker']})
        monitoring.reference({'profile': 'linux'})
        for value in ({'type': 'zabbix-agent', 'profiles': []},
                      {'type': 'zabbix-agent', 'profiles': ['linux', 'linux']},
                      {'type': 'zabbix-agent', 'profiles': ['shell']},
                      {'type': 'agent', 'profiles': ['linux']},
                      {'type': 'zabbix-agent', 'profiles': ['linux'], 'token': 'PRIVATE_SENTINEL'}):
            with self.subTest(case=value), self.assertRaises(ComponentError) as caught:
                monitoring.profile(value)
            self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))

    def test_root_selector_is_explicit_and_ambiguous_or_wrong_server_refuses(self):
        resolver, _ = fixture()
        self.assertEqual(monitoring.server(resolver), 'zabbix')
        resolver.apps['second'] = dict(resolver.apps['zabbix'])
        with self.assertRaisesRegex(ComponentError, 'monitoring-server'):
            monitoring.server(resolver)
        resolver.site['zabbix'] = {'server': 'zabbix'}
        self.assertEqual(monitoring.server(resolver), 'zabbix')
        resolver.site['zabbix'] = {'server': 'sql'}
        with self.assertRaisesRegex(ComponentError, 'monitoring-server'):
            monitoring.server(resolver)

    def test_expansion_adds_only_the_explicit_root_capability_edges_and_owned_metadata(self):
        resolver, exposures = fixture()
        result = monitoring.bind(resolver, exposures)
        self.assertEqual(result, {'server': 'zabbix', 'guest': 'server'})
        self.assertEqual(sum(len(row['rules']) for row in resolver.guests.values()), 11)
        self.assertEqual(resolver.guests['ingress']['rules'][0], monitoring.rule('out',
            '198.18.20.13', '198.18.20.10', 8080))
        selected = resolver.guests['server']['monitoring']
        self.assertEqual([row['guest'] for row in selected['members']], list(resolver.guests))
        self.assertEqual(selected['server_hostname'], 'server')
        self.assertEqual(resolver.guests['database']['monitoring']['profiles'], ['linux', 'postgresql'])
        self.assertEqual(resolver.guests['database']['monitoring']['database_uri'], 'tcp://127.0.0.1:5432')
        self.assertEqual(resolver.apps['sql']['monitoring_hba_source'], '198.18.20.10')
        self.assertEqual(selected['members'][2]['url'], 'http://198.18.20.12:8086')
        self.assertNotIn('password', str(selected))

    def test_omission_does_not_add_rules_waits_agents_or_credential_metadata(self):
        resolver, exposures = fixture()
        resolver.site.pop('zabbix')
        before = copy.deepcopy(resolver.guests)
        self.assertIsNone(monitoring.bind(resolver, exposures))
        self.assertEqual(resolver.guests, before)

    def test_invalid_bindings_fail_without_guessing_an_app_or_source(self):
        changes = [
            lambda r: r.guests['database'].update(monitoring_profile={'profile': 'missing'}),
            lambda r: r.guests['database'].pop('monitoring_profile'),
            lambda r: r.apps['zabbix']['resolved_connections']['metrics']['target'].update(port=443),
            lambda r: r.apps['zabbix']['resolved_connections']['database'].update(source_address='198.18.20.99'),
            lambda r: r.apps['zabbix']['resolved_connections']['metrics'].update(type='http'),
        ]
        for change in changes:
            resolver, exposures = fixture(); change(resolver)
            with self.subTest(case=changes.index(change)), self.assertRaises(ComponentError):
                monitoring.bind(resolver, exposures)

    def test_source_selection_uses_declared_route_not_interface_order_or_control_name(self):
        guest = {'provider_interfaces': [{'ipv4': '198.18.20.10/24', 'gateway': '198.18.20.1'},
                                         {'ipv4': '198.18.31.10/24'}]}
        self.assertEqual(monitoring.source_address(guest, '198.18.31.23'), '198.18.31.10')
        self.assertEqual(monitoring.source_address(guest, '203.0.113.10'), '198.18.20.10')
        guest['provider_interfaces'].append({'ipv4': '198.18.31.11/24'})
        with self.assertRaisesRegex(ComponentError, 'network-source'):
            monitoring.source_address(guest, '198.18.31.23')
        guest['provider_interfaces'] = [{'ipv4': 'dhcp', 'ipv4_endpoint': '198.18.20.10/24', 'gateway': None}]
        self.assertEqual(monitoring.source_address(guest, '203.0.113.10'), '198.18.20.10')


if __name__ == '__main__':
    unittest.main()
