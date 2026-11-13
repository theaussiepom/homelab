"""Connection/account component units with interface-conforming app/guest fakes."""
import copy
import unittest
from types import SimpleNamespace

import component_connections as connections
from component_errors import ComponentError


def fixture(*, separate=False, alias=False):
    apps = {}
    for name, adapter in (('client_a', 'cloudbeaver'), ('client_b', 'cloudbeaver'),
                           ('db_a', 'postgresql'), ('db_b', 'postgresql')):
        apps[name] = {'id': name, 'guest': name, 'adapter': adapter,
                      'profile': 'client' if adapter == 'cloudbeaver' else 'server',
                      'interfaces': {'database_interface': {'interface': 'backend'}}}
    site = {'accounts': {}, 'secret_sources': {}, 'connections': {}}
    for suffix in ('a', 'b'):
        target = {'app': 'db_b' if separate and suffix == 'b' else 'db_a',
                  'endpoint': 'alias' if alias and suffix == 'b' else 'sql'}
        site['secret_sources']['secret_' + suffix] = {'type': 'generated', 'credential_id': 'owned-' + suffix}
        site['accounts']['account_' + suffix] = {'adapter': 'postgresql-admin', 'owner': 'client_' + suffix,
            'target': target, 'principal': 'shared_admin', 'credential': 'secret_' + suffix,
            'access': 'server-administration', 'lifecycle': 'create-once'}
        site['connections']['database_' + suffix] = {'consumer': {'app': 'client_' + suffix, 'connection': 'database'},
            'target': target, 'source_interface': 'database_interface', 'account': 'account_' + suffix}

    def endpoint(ref):
        name = ref['app']
        return {'app': name, 'guest': name, 'protocol': 'tcp', 'port': 5432,
                'address': '198.18.31.23' if name == 'db_a' else '198.18.31.24'}
    resolver = SimpleNamespace(apps=apps, site=site, guests={key: {} for key in apps},
        library={'app_profiles': {'client': {'connections': {'database': {
            'type': 'postgresql', 'required': True, 'accounts': ['postgresql-admin'], 'readiness': ['start']}}},
            'server': {}}}, policy={'transport': {}}, endpoint=endpoint,
        role_address=lambda app, role: '198.18.31.10' if app['id'] == 'client_a' else '198.18.31.11')
    exposures = SimpleNamespace(hostname=lambda reference, target: 'db.example.invalid')
    return resolver, exposures


class ConnectionComponentTests(unittest.TestCase):
    def test_influx_api_uses_the_real_http_endpoint_and_refuses_transport_mismatch(self):
        resolver, exposures = fixture(separate=True)
        resolver.site['accounts'] = {}
        for row in resolver.site['connections'].values():
            row.pop('account')
        resolver.library['app_profiles']['client']['connections']['database'] = {
            'type': 'influxdb', 'required': True}
        resolver.apps['db_a']['adapter'] = resolver.apps['db_b']['adapter'] = 'influxdb'
        old = resolver.endpoint
        resolver.endpoint = lambda ref: dict(old(ref), protocol='http', port=8086)
        result = connections.bind(resolver, exposures)
        self.assertEqual(resolver.apps['client_a']['resolved_connections']['database']['target']['protocol'], 'http')
        self.assertTrue(all(not row for row in result['guest_dependencies'].values()))
        for protocol in ('tcp', 'udp', 'https'):
            resolver.endpoint = lambda ref, protocol=protocol: dict(old(ref), protocol=protocol, port=8086)
            with self.subTest(protocol=protocol), self.assertRaisesRegex(ComponentError, 'connection-target'):
                connections.bind(resolver, exposures)

    def test_same_target_principal_refuses_distinct_credential_owners_and_aliases(self):
        for alias in (False, True):
            with self.subTest(alias=alias), self.assertRaisesRegex(ComponentError, 'component.account-principal-conflict'):
                connections.bind(*fixture(alias=alias))

    def test_same_principal_on_distinct_servers_is_a_valid_component(self):
        resolver, exposures = fixture(separate=True)
        result = connections.bind(resolver, exposures)
        self.assertEqual(set(result['accounts']), {'account_a', 'account_b'})
        self.assertEqual(result['accounts']['account_a']['principal'], result['accounts']['account_b']['principal'])
        self.assertNotEqual(result['accounts']['account_a']['target_endpoint']['app'],
                            result['accounts']['account_b']['target_endpoint']['app'])
        self.assertTrue(all(not row for row in result['guest_dependencies'].values()))

    def test_account_component_failures_do_not_need_real_app_or_guest_validation(self):
        mutations = [
            lambda r: r.site['accounts']['account_a'].update(owner='client_b'),
            lambda r: r.site['accounts']['account_a'].update(principal='all'),
            lambda r: r.site['accounts']['account_a'].update(principal='pg_owned'),
            lambda r: r.site['accounts']['account_a'].update(lifecycle='rotate'),
            lambda r: r.site['secret_sources']['secret_a'].update(type='file'),
            lambda r: r.site['secret_sources']['secret_b'].update(credential_id='owned-a'),
            lambda r: r.site['connections']['database_a'].update(target={'app': 'db_b', 'endpoint': 'sql_endpoint'}),
            lambda r: r.site['connections']['database_a'].update(source_interface='missing_interface'),
            lambda r: r.site['connections']['database_a'].update(readiness='configure'),
            lambda r: r.site['connections']['database_a'].update(credential={'principal': 'user', 'secret': 'secret_a'}),
        ]
        for index, mutate in enumerate(mutations):
            resolver, exposures = fixture(separate=True)
            mutate(resolver)
            with self.subTest(case=index), self.assertRaises(ComponentError):
                connections.bind(resolver, exposures)

    def test_requested_readiness_and_guest_stage_are_explicit_edges(self):
        resolver, exposures = fixture(separate=True)
        resolver.site['connections']['database_a']['readiness'] = 'start'
        resolver.guests['client_b']['readiness'] = [{'stage': 'preparation',
                                                   'target': {'app': 'db_a', 'endpoint': 'sql_endpoint'}}]
        result = connections.bind(resolver, exposures)
        self.assertEqual(result['guest_dependencies']['client_a'], ['db_a'])
        self.assertEqual(result['guest_dependencies']['client_b'], ['db_a'])
        self.assertEqual(result['app_dependencies']['client_a'], ['db_a'])
        self.assertEqual(result['app_dependencies']['client_b'], [])
        resolver.guests['db_a']['readiness'] = [{'stage': 'preparation',
                                              'target': {'app': 'client_a', 'endpoint': 'web_endpoint'}}]
        with self.assertRaisesRegex(ComponentError, 'component.readiness-cycle'):
            connections.bind(resolver, exposures)


if __name__ == '__main__':
    unittest.main()
