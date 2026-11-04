"""Selected source and traffic projections with peer contracts mocked explicitly."""
import copy
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import call, patch

import component_properties as properties
import component_sources as sources
import component_traffic as traffic
from component_errors import ComponentError
from test_component_properties import fixture


class SourceReadFailures(unittest.TestCase):
    def test_anchored_open_errors_are_value_free_and_never_pin_a_partial_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / 'asset.txt').write_text('synthetic private source detail')
            selected = sources.Sources(root)
            original = sources.os.open
            for unavailable_name in ('/', 'asset.txt'):
                def unavailable(name, flags, *args, **kwargs):
                    if name == unavailable_name:
                        raise OSError('synthetic private source detail')
                    return original(name, flags, *args, **kwargs)
                with self.subTest(name=unavailable_name), patch.object(sources.os, 'open', side_effect=unavailable), \
                     self.assertRaises(ComponentError) as caught:
                    selected.raw('asset.txt')
                self.assertEqual(str(caught.exception), 'component.source')
                self.assertEqual(selected.pins, {})

    def test_hash_valid_non_utf8_asset_refuses_as_source_without_decoder_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); raw = b'\xffsynthetic-private-marker'
            (root / 'asset.txt').write_bytes(raw)
            selected = sources.Sources(root)
            with self.assertRaises(ComponentError) as caught:
                selected.asset({'type': 'raw-utf8', 'source': 'asset.txt',
                    'sha256': hashlib.sha256(raw).hexdigest()})
            self.assertEqual(str(caught.exception), 'component.source')


class TrafficProjectionTests(unittest.TestCase):
    def fixture(self):
        guests = {name: {'context': 'context', 'control': {'address': address},
            'provider_interfaces': [{'ipv4': address + '/24', 'gateway': None}], 'rules': []}
            for name, address in [('client', '198.18.20.10'), ('server', '198.18.20.11')]}
        apps = {'browser': {'guest': 'client', 'resolved_connections': {}},
                'dns': {'guest': 'server', 'adapter': 'unbound', 'resolved_connections': {}}}
        target = {'app': 'dns', 'address': '198.18.20.11', 'protocol': 'udp', 'port': 53}
        resolver = SimpleNamespace(guests=guests, apps=apps,
            site={'guests': {key: {} for key in guests}, 'contexts': {'context': {'dns_servers': []}}},
            endpoint=lambda reference: copy.deepcopy(target))
        exposures = SimpleNamespace(routes={}, middlewares={})
        return resolver, exposures, target

    def test_context_dns_projects_both_protocols_and_named_app_owner_without_grants(self):
        resolver, exposures, _ = self.fixture()
        resolver.site['contexts']['context']['dns_servers'] = [{'app': 'dns', 'endpoint': 'dns'}]
        before = copy.deepcopy(resolver.guests)
        with patch.object(traffic, 'source_address', return_value='198.18.20.10') as address, \
             patch.object(traffic, 'check') as check:
            traffic.bind(resolver, exposures)
        address.assert_called_once_with(resolver.guests['client'], '198.18.20.11')
        self.assertEqual(check.call_args_list, [
            call(resolver.guests, 'client', 'server', '198.18.20.10', '198.18.20.11', protocol, 53)
            for protocol in ('tcp', 'udp')])
        self.assertEqual(resolver.guests, before)

    def test_internal_route_and_non_auth_middleware_add_no_connection(self):
        resolver, exposures, _ = self.fixture()
        exposures.routes = {'browser': {'dashboard': {'target': {'internal': 'dashboard'},
            'middlewares': ['restricted', 'headers']}}}
        exposures.middlewares = {'restricted': {'type': 'ip-allow-list'}, 'headers': {'type': 'headers'}}
        with patch.object(traffic, 'check') as check, patch.object(traffic, 'source_address') as source:
            traffic.bind(resolver, exposures)
        check.assert_not_called(); source.assert_not_called()


class OptionalDriverProjection(unittest.TestCase):
    def test_managed_postgres_only_never_introduces_a_mariadb_driver(self):
        selected = fixture()
        cloud = selected.apps['cloud']
        cloud['properties']['connections'] = {'postgresql-admin': cloud['properties']['connections']['postgresql-admin']}
        del cloud['properties']['mariadb_jdbc']
        cloud['resolved_connections'] = {'postgresql-admin': cloud['resolved_connections']['postgresql-admin']}
        result = properties.bind(selected)['cloud']
        self.assertEqual(result['connections'], {})
        self.assertEqual(set(result['managed_connections']), {'postgresql-admin'})
        self.assertNotIn('mariadb_jdbc', result)
        self.assertEqual(result['managed_connections']['postgresql-admin']['account'],
                         cloud['resolved_connections']['postgresql-admin']['account'])


if __name__ == '__main__':
    unittest.main()
