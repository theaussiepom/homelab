"""Closed foundation component units; app/reference collaborators are fakes."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import component_foundations as settings
from component_errors import ComponentError


def props():
    return {
        'unbound': {'publish_port': 5336}, 'pihole': {}, 'homeassistant': {'mdns': {'interface': 'home', 'startup': 'startup'}},
        'mqtt': {'password_file': '/mosquitto/config/passwords'},
        'mqtt_explorer': {'connection_name': 'Broker'},
        'authentik': {'database': {'name': 'authentik', 'user': 'authentik'}, 'smtp': {
            'host': 'smtp.example.invalid', 'port': 587, 'use_tls': True, 'use_ssl': False,
            'from': 'sso@example.invalid', 'username': '', 'timeout': 30}, 'callbacks': {'evidence': 'callbacks'}},
        'zabbix': {'database': {'name': 'zabbix', 'user': 'zabbix'}},
        'postgresql': {'client_access': [{'source': {'app': 'identity', 'interface': 'database'},
            'database': 'all', 'user': 'all', 'method': 'scram-sha-256'}]},
        'mariadb': {}, 'influxdb': {}, 'music_assistant': {},
        'zigbee2mqtt': {'adapter': 'ember', 'mqtt_base_topic': 'home'},
        'traefik': {'dashboard': True, 'provider': {'context': 'lab', 'token_id': 'reader@pve!routes',
            'discovery': {'local_directory': '/example/local/service-discovery',
                          'mirror_directory': '/example/mirror/service-discovery', 'owner_sha256': 'a' * 64,
                          'guests': ['application']}},
            'acme': {'email': 'operator@example.invalid', 'resolvers': [{'external': 'dns'}],
                     'propagation_timeout_seconds': 2100}}}


class FoundationPropertyTests(unittest.TestCase):
    def test_each_supported_adapter_component_accepts_closed_source_types(self):
        for adapter, value in props().items():
            with self.subTest(adapter=adapter):
                settings.validate(adapter, value)
                settings.validate(adapter, {}, partial=True)
                with self.assertRaisesRegex(ComponentError, 'component.fields'):
                    settings.validate(adapter, dict(value, arbitrary='PRIVATE_SENTINEL'))
        with self.assertRaisesRegex(ComponentError, 'component.adapter'):
            settings.validate('unregistered', {})

    def test_scalar_property_negatives_are_not_generic_environment_or_command_bags(self):
        values = [
            ('unbound', {'publish_port': True}), ('unbound', {'publish_port': 65536}),
            ('homeassistant', {'mdns': {'interface': 'home'}}),
            ('homeassistant', {'mdns': {'interface': '../outside', 'startup': 'startup'}}),
            ('mqtt', {'password_file': '/mosquitto/config/..'}),
            ('mqtt', {'password_file': '/other/passwords'}),
            ('mqtt_explorer', {'connection_name': 'Broker\nPRIVATE_SENTINEL'}),
            ('mqtt_explorer', {'connection_name': ''}), ('zabbix', {}),
            ('zabbix', {'database': {'name': 'postgres', 'user': 'zabbix'}}),
            ('zabbix', {'database': {'name': 'zabbix', 'user': "user'"}}),
            ('traefik', {'dashboard': 1}),
            ('zigbee2mqtt', {}), ('zigbee2mqtt', {'adapter': 'PRIVATE_SENTINEL\n', 'mqtt_base_topic': 'home'}),
            ('zigbee2mqtt', {'adapter': 'ember', 'mqtt_base_topic': 'home/#'}),
        ]
        for adapter, value in values:
            with self.subTest(adapter=adapter, case=values.index((adapter, value))):
                with self.assertRaises(ComponentError) as caught:
                    settings.validate(adapter, value)
                self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))

    def test_smtp_has_finite_fields_typed_flags_and_no_secret_value(self):
        base = props()['authentik']
        for key, value in [('port', 0), ('use_tls', 1), ('use_ssl', True), ('timeout', 301),
                           ('password', 'PRIVATE_SENTINEL'), ('host', 'host\nPRIVATE_SENTINEL')]:
            selected = copy.deepcopy(base)
            selected['smtp'][key] = value
            with self.subTest(key=key), self.assertRaises(ComponentError):
                settings.validate('authentik', selected)
        base.pop('smtp'); base.pop('callbacks')
        settings.validate('authentik', base)

    def test_hba_intent_is_explicit_and_never_derived_from_a_connection(self):
        base = props()['postgresql']
        for key, value in [('database', 'application'), ('user', 'different'), ('method', 'trust'),
                           ('source', {'external': 'database'}), ('port', '5432')]:
            selected = copy.deepcopy(base)
            selected['client_access'][0][key] = value
            with self.subTest(key=key), self.assertRaises(ComponentError):
                settings.validate('postgresql', selected)
        settings.validate('postgresql', {})

    def test_provider_and_acme_negative_components(self):
        changes = [
            lambda v: v['provider'].update(token_id='PRIVATE_SENTINEL'),
            lambda v: v['provider'].update(context='../outside'),
            lambda v: v['provider']['discovery'].update(owner_sha256='z' * 64),
            lambda v: v['provider']['discovery'].update(guests=['application', 'application']),
            lambda v: v['provider']['discovery'].update(guests=[]),
            lambda v: v['provider']['discovery'].update(mirror_directory='/example/local/service-discovery'),
            lambda v: v['provider']['discovery'].update(local_directory='/example/wrong'),
            lambda v: v['acme'].update(email='invalid'),
            lambda v: v['acme'].update(resolvers=[]),
            lambda v: v['acme'].update(propagation_timeout_seconds=2101),
            lambda v: v['acme'].update(resolvers=[{'external': 'dns', 'port': 53}]),
        ]
        for change in changes:
            value = copy.deepcopy(props()['traefik']); change(value)
            with self.subTest(case=changes.index(change)), self.assertRaises(ComponentError):
                settings.validate('traefik', value)


class FoundationBindingTests(unittest.TestCase):
    def fixture(self, adapter):
        app = {'id': 'application', 'guest': 'host', 'adapter': adapter, 'properties': props()[adapter],
               'interfaces': {'database': {'interface': 'database'}, 'web': {'interface': 'web'}},
               'secret_bindings': {}, 'resolved_connections': {}, 'origin_url': 'https://app.example.invalid'}
        endpoints = {'dns': {'address': '198.18.20.53', 'protocol': 'udp', 'port': 53},
                     'api': {'address': '198.18.20.2', 'protocol': 'https', 'port': 8006}}
        return SimpleNamespace(apps={'application': app}, guests={'host': {'context': 'lab', 'identity': {'vmid': 610}},
                'application': {'context': 'lab', 'identity': {'vmid': 611}}},
            site={'contexts': {'lab': {'api_endpoint': {'external': 'api'}, 'trust': {'ca_file': '/example/ca.pem'}}},
                  'evidence': {}}, endpoint=lambda ref: endpoints[ref['external']],
            role_address=lambda app, role: '198.18.21.10')

    def test_explicit_physical_client_policy_binds_no_other_incoming_connections(self):
        resolver = self.fixture('postgresql')
        resolver.apps['identity'] = {'id': 'identity', 'adapter': 'node_red',
                                     'interfaces': {'database': {'interface': 'database'}}}
        with patch.object(settings, 'validate') as check:
            settings.bind(resolver)
        check.assert_called_once()
        self.assertEqual(resolver.apps['application']['settings']['client_access'], [
            {'source_address': '198.18.21.10', 'database': 'all', 'user': 'all', 'method': 'scram-sha-256'}])
        resolver.apps['application']['properties']['client_access'].append(
            copy.deepcopy(resolver.apps['application']['properties']['client_access'][0]))
        with self.assertRaisesRegex(ComponentError, 'database-access'):
            settings.bind(resolver)
        resolver.apps['identity']['interfaces']['database'] = {'scope': 'app-network', 'network': 'private'}
        with self.assertRaisesRegex(ComponentError, 'physical-role'):
            settings.bind(resolver)

    def test_provider_uses_context_authority_and_explicit_finite_guest_refs(self):
        resolver = self.fixture('traefik')
        resolver.apps['application']['secret_bindings'] = {'cloudflare_dns_token': {}, 'proxmox_token': {}}
        settings.bind(resolver)
        selected = resolver.apps['application']['settings']
        self.assertEqual(selected['provider']['url'], 'https://198.18.20.2:8006')
        self.assertEqual(selected['provider']['discovery']['guests'], [611])
        self.assertEqual(selected['acme']['resolvers'], ['198.18.20.53:53'])
        resolver.apps['application']['properties']['acme']['resolvers'].append({'external': 'dns'})
        with self.assertRaisesRegex(ComponentError, 'dns-endpoint'):
            settings.bind(resolver)

    def test_cloudflare_route_requires_its_own_origin_secret_and_selects_runtime(self):
        resolver = self.fixture('traefik')
        app = resolver.apps['application']
        app['secret_bindings'] = {'cloudflare_dns_token': {}, 'proxmox_token': {}}
        resolver.exposure_values = {'routes': {'application': {'web': {'tls': 'public', 'middlewares': ['cloud']}}},
                                    'middlewares': {'cloud': {'type': 'cloudflare-source'}}}
        resolver.policy = {'tls': {'public': {'resolver': 'letsencrypt'}}}
        with self.assertRaisesRegex(ComponentError, 'secret-required'): settings.bind(resolver)
        app['secret_bindings']['cloudflare_origin_token'] = {'type': 'file'}
        settings.bind(resolver)
        self.assertIs(app['settings']['cloudflare'], True)

    def test_database_binding_checks_separate_secret_and_named_connection_contracts(self):
        resolver = self.fixture('zabbix')
        resolver.apps['application']['resolved_connections']['database'] = {
            'type': 'postgresql', 'target': {'address': '198.18.31.23', 'port': 5432}}
        with self.assertRaisesRegex(ComponentError, 'secret-required'):
            settings.bind(resolver)
        resolver.apps['application']['secret_bindings']['database_password'] = {'type': 'file'}
        settings.bind(resolver)
        self.assertEqual(resolver.apps['application']['settings']['database'], {
            'name': 'zabbix', 'user': 'zabbix', 'host': '198.18.31.23', 'port': 5432})
        resolver.apps['application']['resolved_connections']['database']['target']['port'] = 5433
        with self.assertRaisesRegex(ComponentError, 'database-binding'):
            settings.bind(resolver)


if __name__ == '__main__':
    unittest.main()
