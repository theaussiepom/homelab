"""Container DNS selection, narrow grants and unchanged host provisioning."""
import copy
from types import SimpleNamespace
import unittest

import component_runtime_dns as dns
import component_types as types
from component_errors import ComponentError
from test_component_plan import site, library
import test_component_runtime as runtime_tests


def fixture():
    def guest(address):
        return {'context': 'lab', 'dns_servers': ['198.18.99.1'], 'rules': [],
                'provider_interfaces': [{'ipv4': address + '/24', 'gateway': '198.18.40.1'}]}
    endpoints = {'primary': {'guest': 'dns', 'address': '198.18.40.2', 'port': 53, 'protocol': 'udp'},
                 'secondary': {'address': '198.18.40.4', 'port': 53, 'protocol': 'udp'}}
    result = SimpleNamespace(
        site={'contexts': {'lab': {'runtime_dns_servers': [
            {'external': 'primary'}, {'external': 'secondary'}]}}},
        guests={'app': guest('198.18.40.21'), 'dns': guest('198.18.40.2')},
        apps={'app': {'profile': 'normal', 'guest': 'app', 'containers': {'one': {}, 'two': {}}}},
        library={'app_profiles': {'normal': {}, 'resolver': {'runtime_dns': 'host'}}},
        endpoint=lambda reference: endpoints[reference['external']])
    return result, endpoints


class RuntimeDnsTests(unittest.TestCase):
    def test_two_resolvers_and_only_dns_grants_leave_host_dns_unchanged(self):
        r, _ = fixture()
        before = copy.deepcopy(r.guests['app']['dns_servers'])
        dns.bind(r)
        self.assertEqual(r.apps['app']['runtime_dns_servers'], ['198.18.40.2', '198.18.40.4'])
        self.assertEqual(r.guests['app']['dns_servers'], before)
        self.assertEqual(len(r.guests['app']['rules']), 4)
        self.assertEqual(len(r.guests['dns']['rules']), 2)
        for row in r.guests['app']['rules'] + r.guests['dns']['rules']:
            self.assertEqual(row['port'], '53')
            self.assertEqual(row['source'], '198.18.40.21/32')
            self.assertEqual(row['interface'], 'net0')

    def test_duplicate_servers_and_apps_do_not_duplicate_grants(self):
        r, _ = fixture()
        r.site['contexts']['lab']['runtime_dns_servers'].append({'external': 'primary'})
        r.apps['second'] = copy.deepcopy(r.apps['app'])
        dns.bind(r)
        self.assertEqual(len(r.apps['second']['runtime_dns_servers']), 2)
        self.assertEqual(len(r.guests['app']['rules']), 4)
        self.assertEqual(len(r.guests['dns']['rules']), 2)

    def test_host_profile_exception_and_explicit_application_override(self):
        r, _ = fixture()
        r.apps['app']['profile'] = 'resolver'
        dns.bind(r)
        self.assertNotIn('runtime_dns_servers', r.apps['app'])
        r.apps['app']['runtime_dns'] = 'context'
        dns.bind(r)
        self.assertEqual(len(r.apps['app']['runtime_dns_servers']), 2)

    def test_host_app_native_service_and_unselected_context_keep_existing_behavior(self):
        for change in ('host', 'native', 'absent'):
            with self.subTest(change=change):
                r, _ = fixture()
                if change == 'host': r.apps['app']['runtime_dns'] = 'host'
                elif change == 'native': r.apps['app']['containers'] = {}
                else: r.site['contexts']['lab'].clear()
                before = copy.deepcopy(r.guests)
                dns.bind(r)
                self.assertEqual(r.guests, before)
                self.assertNotIn('runtime_dns_servers', r.apps['app'])

    def test_same_guest_resolver_does_not_add_guest_firewall_rules(self):
        r, _ = fixture()
        r.apps['app']['guest'] = 'dns'
        r.site['contexts']['lab']['runtime_dns_servers'] = [{'external': 'primary'}]
        dns.bind(r)
        self.assertEqual(r.guests['dns']['rules'], [])
        self.assertEqual(r.apps['app']['runtime_dns_servers'], ['198.18.40.2'])

    def test_tcp_dns_endpoint_is_supported(self):
        r, endpoints = fixture()
        endpoints['primary']['protocol'] = 'tcp'
        dns.bind(r)
        self.assertEqual(len(r.guests['app']['rules']), 4)

    def test_invalid_endpoint_and_unroutable_addresses_refuse(self):
        for field, value in [('port', 5353), ('protocol', 'http'), ('address', 'dns.example.invalid'),
                             ('address', '::1'), ('address', '127.0.0.1'), ('address', '0.0.0.0'),
                             ('address', '224.0.0.1'), ('address', '169.254.1.1')]:
            with self.subTest(field=field, value=value):
                r, endpoints = fixture()
                endpoints['primary'][field] = value
                with self.assertRaises(ComponentError): dns.bind(r)

    def test_closed_source_fields(self):
        context = site()['contexts']['lab']
        for invalid in (None, [], 'dns', [{}], [{'external': 'bad!'}]):
            with self.subTest(invalid=invalid), self.assertRaises(ComponentError):
                types.context(dict(context, runtime_dns_servers=invalid))
        types.context(dict(context, runtime_dns_servers=[{'external': 'dns'}]))
        profile = library()['app_profiles']['recursive']
        app = site()['apps']['recursive_a']
        for value in ('host', 'context'):
            types.profile(dict(profile, runtime_dns=value))
            types.app(dict(app, runtime_dns=value))
        for value in (None, False, 'public', [], {}):
            for validator, source in ((types.profile, profile), (types.app, app)):
                with self.subTest(value=value, validator=validator), self.assertRaises(ComponentError):
                    validator(dict(source, runtime_dns=value))

    def test_real_compiler_and_renderer_preserve_provider_dns(self):
        case = runtime_tests.RuntimeTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        selected = site()
        selected['contexts']['lab']['runtime_dns_servers'] = [{'external': 'dns'}]
        cfg = case.compile(selected)
        import render
        services = render.compose(cfg)['services']
        self.assertEqual(services['recursive_a_unbound']['dns'], ['198.18.21.53'])
        selected['apps']['recursive_a']['runtime_dns'] = 'host'
        cfg = case.compile(selected)
        self.assertNotIn('dns', render.compose(cfg)['services']['recursive_a_unbound'])


if __name__ == '__main__':
    unittest.main()
