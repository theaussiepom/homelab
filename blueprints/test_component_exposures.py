"""Exposure/alias components validate namespace semantics with app collaborators mocked."""
import copy
from types import SimpleNamespace
import unittest

import component_exposures as exposures
from component_errors import ComponentError


class ExposureComponentTests(unittest.TestCase):
    def resolver(self):
        return SimpleNamespace(site={'domains': {'web': 'App.example.invalid'},
            'host_aliases': {'database': {'hostname': 'mariadb.db_hass'}}, 'exposures': {}},
            policy={'tls': {}, 'middlewares': {}}, apps={})

    def test_compose_only_alias_preserves_underscore_without_dns_routes_or_waits(self):
        resolver = self.resolver()
        selected = exposures.Exposures(resolver)
        selected.validate_policies()
        self.assertEqual(selected.hostname({'alias': 'database'}, {'address': '198.18.31.21'}),
                         'mariadb.db_hass')
        self.assertEqual(selected.hostname({'domain': 'web'}, {}), 'App.example.invalid')
        self.assertEqual((selected.records, selected.routes, selected.resolved), ({}, {}, {}))
        self.assertEqual(resolver.site['exposures'], {})

    def test_alias_cannot_be_used_as_a_domain_or_origin_and_malformed_refs_are_closed(self):
        resolver = self.resolver()
        selected = exposures.Exposures(resolver)
        for value in ({'alias': 'database'}, {'alias': 'database', 'domain': 'web'}):
            with self.subTest(value=value), self.assertRaises(ComponentError):
                exposures.origin_reference(value)
        resolver.site['domains']['bad'] = 'mariadb.db_hass'
        with self.assertRaisesRegex(ComponentError, 'hostname'):
            selected.validate_policies()
        resolver.site['domains'].pop('bad')
        for value in ({'alias': 'missing'}, {'alias': 'database', 'port': 3306}, {'alias': '../database'}):
            with self.subTest(value=value), self.assertRaises(ComponentError):
                selected.hostname(value, {})

    def test_alias_metadata_rejects_unsafe_syntax_and_unrecognized_fields(self):
        for value in ('db:3306', '${SOURCE}', 'user@db', 'db/path', 'db\nname', '-db', 'db..local', 'a'*64):
            resolver = self.resolver()
            resolver.site['host_aliases']['database']['hostname'] = value
            with self.subTest(value=value), self.assertRaisesRegex(ComponentError, 'hostname'):
                exposures.Exposures(resolver).validate_policies()
        resolver = self.resolver()
        resolver.site['host_aliases']['database']['address'] = '198.18.31.21'
        with self.assertRaises(ComponentError):
            exposures.Exposures(resolver).validate_policies()


if __name__ == '__main__':
    unittest.main()
