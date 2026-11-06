"""Plan reference units over conforming source fixtures and mocked peer contracts."""
import copy
from contextlib import ExitStack
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import component_plan as plan
from component_errors import ComponentError
from test_component_plan import library, site


def resolver(*, guests=True, apps=False):
    r = object.__new__(plan.Resolver)
    r.library, r.site = library(), site()
    for key in ('software', 'runtime_profiles', 'health_profiles', 'monitoring_profiles', 'assets'):
        r.library.setdefault(key, {})
    for key in ('devices', 'evidence', 'images', 'domains', 'exposures', 'accounts', 'address_groups'):
        r.site.setdefault(key, {})
    r.policy = {kind: {} for kind in plan.sources.POLICIES}
    r.library['policies'] = copy.deepcopy(r.policy); r.site['policies'] = copy.deepcopy(r.policy)
    r.library_sources = SimpleNamespace(pins={}); r.site_sources = SimpleNamespace(pins={})
    r.guests, r.apps, r.endpoints, r.sockets = {}, {}, {}, []
    if guests:
        r.external_values(); r.guest_values()
    if apps:
        with patch.object(plan.component_foundations, 'validate'), patch.object(plan.component_properties, 'validate'):
            r.app_values()
    return r


class PlanSourceReferenceReview(unittest.TestCase):
    def test_constructor_merges_disjoint_policies_and_refuses_shadowing(self):
        r = resolver(guests=False)
        r.library['policies']['network']['library'] = {'rules': []}
        r.site['policies']['network']['consumer'] = {'rules': []}
        with patch.object(plan.sources, 'library', return_value=(r.library, r.library_sources)), \
             patch.object(plan.sources, 'site', return_value=(r.site, r.site_sources)):
            result = plan.Resolver('never-read-library', 'never-read-site')
            self.assertEqual(set(result.policy['network']), {'library', 'consumer'})
            r.site['policies']['network']['library'] = {'rules': []}
            with self.assertRaises(ComponentError): plan.Resolver('never-read-library', 'never-read-site')

    def test_device_context_and_capability_are_explicit_after_peer_validation(self):
        for kind in ('valid', 'context', 'capability'):
            r = resolver(guests=False)
            r.site['contexts']['lab']['capabilities'] = {'usb': {'type': 'serial-device', 'ssh_private_key': 'ssh', 'known_hosts': '/example/known_hosts'}}
            r.site['devices']['coordinator'] = {'type': 'serial', 'context': 'lab', 'capability': 'usb',
                                                 'path': '/dev/serial/by-id/usb-synthetic'}
            if kind == 'context': r.site['devices']['coordinator']['context'] = 'missing'
            if kind == 'capability': r.site['devices']['coordinator']['capability'] = 'missing'
            # Raw schemas belong to their component tests; this unit owns cross-reference closure.
            with self.subTest(kind=kind), patch.object(plan, 'checked') as validators:
                if kind == 'valid': r.validate(); self.assertTrue(validators.called)
                else:
                    with self.assertRaisesRegex(ComponentError, 'reference'): r.validate()

    def test_external_aliases_resolve_once_without_dns_and_cycles_or_urls_refuse(self):
        r = resolver(guests=False)
        r.site['external_endpoints'] = {'alias': {'protocol': 'http', 'address': {'external': 'origin'}, 'port': 9000},
                                        'origin': {'protocol': 'https', 'address': 'origin.example.invalid', 'port': 8006}}
        r.external_values()
        self.assertEqual(r.endpoint({'external': 'alias'})['address'], 'origin.example.invalid')
        self.assertEqual(r.endpoint({'external': 'alias'})['port'], 9000)
        for kind in ('cycle', 'missing', 'url', 'extra-address-field'):
            bad = resolver(guests=False)
            bad.site['external_endpoints'] = {'one': {'protocol': 'http', 'address': {'external': 'one'}, 'port': 9000}}
            if kind == 'missing': bad.site['external_endpoints']['one']['address'] = {'external': 'absent'}
            if kind == 'url': bad.site['external_endpoints']['one']['address'] = 'https://host.invalid/path'
            if kind == 'extra-address-field': bad.site['external_endpoints']['one']['address'] = {'external': 'one', 'port': 1}
            with self.subTest(kind=kind), self.assertRaises(ComponentError): bad.external_values()

    def test_guest_monitoring_override_and_secondary_dhcp_endpoint_are_preserved(self):
        r = resolver(guests=False); r.external_values()
        r.library['guest_templates']['base']['monitoring'] = 'base-monitoring'
        guest = r.site['guests']['resolver']; guest['monitoring'] = 'guest-monitoring'
        guest['interfaces']['backend']['address'] = {'mode': 'dhcp', 'endpoint': '198.18.21.10'}
        r.guest_values(); selected = r.guests['resolver']
        self.assertEqual(selected['monitoring_profile'], 'guest-monitoring')
        self.assertNotIn('monitoring', selected)
        self.assertEqual(selected['provider_interfaces'][1]['gateway'], None)
        self.assertEqual(selected['provider_interfaces'][1]['ipv4_endpoint'], '198.18.21.10/24')
        r = resolver(guests=False); r.external_values()
        r.site['guests']['resolver']['interfaces']['backend']['address'] = {'mode': 'manual'}
        r.site['guests']['resolver']['interfaces']['backend'].pop('ipv6')
        r.guest_values()
        self.assertEqual(r.guests['resolver']['provider_interfaces'][1]['ipv4'], 'manual')
        self.assertNotIn('ipv4_endpoint', r.guests['resolver']['provider_interfaces'][1])
        self.assertNotIn('ipv6', r.guests['resolver']['provider_interfaces'][1])
        self.assertIsNone(r.guests['resolver']['interface_addresses']['backend'])

    def test_asset_and_health_references_are_selected_without_reading_assets_or_rendering(self):
        r = resolver(); profile = r.library['app_profiles']['recursive']; app = r.site['apps']['recursive_a']
        profile['storage'] = {'config': {'target': '/opt/unbound/etc/unbound', 'kind': 'file', 'read_only': True, 'required': False}}
        profile['interfaces']['control'] = {'required': False, 'accepts': ['guest-interface']}
        app['interfaces']['control'] = {'interface': 'management'}
        app['storage'] = {'config': {'asset': 'selected'}}
        r.library['assets']['selected'] = {'format': 'raw', 'text': 'synthetic-public-configuration'}
        r.library['health_profiles']['readiness'] = {'type': 'adapter', 'check': 'readiness'}
        profile['health'] = {'ready': {'profile': 'readiness', 'source_interface': 'control'}}
        with patch.object(plan.component_foundations, 'validate') as validator:
            r.app_values()
        validator.assert_called_once_with('unbound', {})
        self.assertEqual(r.apps['recursive_a']['health']['ready'], {'type': 'adapter', 'check': 'readiness', 'source_interface': 'control'})
        self.assertEqual(r.apps['recursive_a']['storage'], {'config': {'asset': 'selected'}})
        for kind in ('missing-asset', 'writable-asset', 'missing-health', 'nonphysical-health'):
            bad = resolver(); bad.library = copy.deepcopy(r.library); bad.site = copy.deepcopy(r.site)
            if kind == 'missing-asset': bad.site['apps']['recursive_a']['storage']['config']['asset'] = 'missing'
            if kind == 'writable-asset': bad.library['app_profiles']['recursive']['storage']['config']['read_only'] = False
            if kind == 'missing-health': bad.library['app_profiles']['recursive']['health']['ready']['profile'] = 'missing'
            if kind == 'nonphysical-health': bad.library['app_profiles']['recursive']['health']['ready']['source_interface'] = 'local'
            with self.subTest(kind=kind), patch.object(plan.component_foundations, 'validate'), self.assertRaises(ComponentError): bad.app_values()

    def test_device_roles_bind_context_and_refuse_aliases_of_one_physical_device(self):
        def selected():
            r = resolver(); p = r.library['app_profiles']['recursive']; p.update(adapter='zigbee2mqtt', listeners={}, endpoints={},
                properties={'adapter': 'zstack', 'mqtt_base_topic': 'fixture'}, devices={'coordinator': {'type': 'serial', 'required': True}})
            r.site['devices']['usb'] = {'type': 'serial', 'context': 'lab', 'path': '/dev/serial/by-id/usb-synthetic'}
            r.site['apps']['recursive_a']['devices'] = {'coordinator': 'usb'}
            return r
        r = selected()
        with patch.object(plan.component_foundations, 'validate'): r.app_values()
        self.assertEqual(r.apps['recursive_a']['devices'], {'coordinator': 'usb'})
        for kind in ('missing', 'other-context', 'wrong-type', 'same-physical-device'):
            r = selected()
            if kind == 'missing': r.site['apps']['recursive_a']['devices']['coordinator'] = 'absent'
            elif kind == 'other-context': r.site['devices']['usb']['context'] = 'other'
            elif kind == 'wrong-type': r.site['devices']['usb']['type'] = 'other'
            else:
                r.site['devices']['alias'] = copy.deepcopy(r.site['devices']['usb'])
                r.site['apps']['recursive_b'] = copy.deepcopy(r.site['apps']['recursive_a'])
                r.site['apps']['recursive_b']['devices']['coordinator'] = 'alias'
            with self.subTest(kind=kind), patch.object(plan.component_foundations, 'validate'), self.assertRaises(ComponentError): r.app_values()
        r = resolver()
        r.library['app_profiles']['recursive']['devices'] = {'optional': {'type': 'serial', 'required': False}}
        with patch.object(plan.component_foundations, 'validate'): r.app_values()
        self.assertNotIn('devices', r.apps['recursive_a'])

    def test_nonfoundation_property_contract_and_physical_role_address_are_delegated(self):
        r = resolver(); r.library['app_profiles']['recursive'].update(adapter='node_red', listeners={}, endpoints={})
        r.library['app_profiles']['recursive']['interfaces'] = {'control': {'required': True, 'accepts': ['guest-interface']}}
        r.site['apps']['recursive_a']['interfaces'] = {'control': {'interface': 'management'}}
        with patch.object(plan.component_properties, 'validate') as validator: r.app_values()
        validator.assert_called_once_with('node_red', {})
        app = r.apps['recursive_a']; app['interfaces']['control'] = {'interface': 'management'}
        self.assertEqual(r.role_address(app, 'control'), '198.18.20.10')
        r.guests['resolver']['interface_addresses']['management'] = None
        with self.assertRaises(ComponentError): r.role_address(app, 'control')

    def test_context_dns_deduplicates_only_equal_addresses_and_validates_api_credentials(self):
        r = resolver(); context = r.site['contexts']['lab']
        context['dns_servers'] += [copy.deepcopy(context['dns_servers'][0])]
        result = r.context_values()
        self.assertEqual(result['lab']['api_endpoint'], 'https://192.0.2.10:8006')
        self.assertEqual(r.guests['resolver']['dns_servers'], ['198.18.21.53'])
        for kind in ('credential', 'api-protocol', 'api-port', 'dns-protocol', 'dns-port'):
            r = resolver()
            if kind == 'credential': r.site['contexts']['lab']['credentials']['api_token'] = 'missing'
            else:
                key = ('external', 'api' if kind.startswith('api') else 'dns')
                r.endpoints[key].update({('protocol' if kind.endswith('protocol') else 'port'): ('tcp' if kind.startswith('api') else 'http') if kind.endswith('protocol') else 8000})
            with self.subTest(kind=kind), self.assertRaises(ComponentError): r.context_values()

    def test_internal_dashboard_and_private_service_endpoints_do_not_invent_host_publications(self):
        for enabled in (False, True):
            r = resolver(apps=True); profile = r.library['app_profiles']['recursive']
            profile.update(adapter='traefik', interfaces={}, listeners={}, endpoints={'dashboard': {'internal': 'dashboard'}})
            r.apps['recursive_a'].update(adapter='traefik', interfaces={}, properties={'dashboard': enabled})
            r.apps['recursive_a']['identity'].update(services={'traefik': 'proxy'}, networks={})
            r.endpoint_values(); key = ('app', 'recursive_a', 'dashboard')
            with self.subTest(dashboard=enabled):
                self.assertEqual(key in r.endpoints, enabled)
                if enabled: self.assertEqual(r.endpoints[key]['service'], 'api@internal')
        r = resolver(apps=True); profile = r.library['app_profiles']['recursive']
        profile['listeners']['udp'].pop('publish'); profile['endpoints']['dns']['via'] = 'private'
        r.endpoint_values(); endpoint = r.endpoint({'app': 'recursive_a', 'endpoint': 'dns'})
        self.assertEqual(endpoint['address'], 'recursive_a_unbound'); self.assertEqual(endpoint['port'], 53)
        self.assertNotIn('publication_address', r.apps['recursive_a']['listeners']['udp'])

    def test_host_endpoint_uses_the_declared_physical_role_and_transport(self):
        def selected():
            r = resolver(apps=True); profile = r.library['app_profiles']['recursive']
            profile.update(adapter='homeassistant', listeners={'web': {'service': 'homeassistant', 'namespace': 'host',
                'interface': 'web', 'bind': 'wildcard', 'protocol': 'tcp', 'port': 8123}},
                endpoints={'web': {'listener': 'web', 'protocol': 'http', 'via': 'web'}},
                interfaces={'web': {'required': True, 'accepts': ['guest-interface']}})
            r.apps['recursive_a'].update(adapter='homeassistant', interfaces={'web': {'interface': 'management'}})
            r.apps['recursive_a']['identity']['services'] = {'homeassistant': 'homeassistant'}
            return r
        r = selected(); r.endpoint_values()
        self.assertEqual(r.endpoint({'app': 'recursive_a', 'endpoint': 'web'})['address'], '198.18.20.10')
        for kind in ('loopback-only', 'protocol'):
            r = selected()
            if kind == 'loopback-only': r.library['app_profiles']['recursive']['listeners']['web']['bind'] = 'loopback'
            else: r.library['app_profiles']['recursive']['endpoints']['web']['protocol'] = 'udp'
            with self.subTest(kind=kind), self.assertRaises(ComponentError): r.endpoint_values()

    def test_network_rule_app_roles_are_explicit_physical_references_not_implicit_grants(self):
        r = resolver(apps=True); guest = r.guests['resolver']
        r.apps['recursive_a']['interfaces']['control'] = {'interface': 'management'}
        r.policy['network']['access'] = {'rules': [{'direction': 'out', 'action': 'ACCEPT', 'proto': 'tcp',
            'source': {'interface': 'client'}, 'destination': {'endpoint': 'server'}, 'port': {'endpoint': 'server'}}]}
        guest['network_policy'] = [{'policy': 'access', 'interfaces': {'client': {'app': 'recursive_a', 'interface': 'control'}},
                                    'endpoints': {'server': {'external': 'api'}}}]
        before = copy.deepcopy(guest['network_policy']); rules = r.policy_values(guest)
        self.assertEqual(rules, [{'direction': 'out', 'action': 'ACCEPT', 'proto': 'tcp', 'source': '198.18.20.10/32',
                                 'destination': '192.0.2.10/32', 'port': '8006'}])
        self.assertEqual(guest['network_policy'], before)
        for kind in ('missing-app', 'missing-role', 'loopback-role', 'unused-binding'):
            old = copy.deepcopy(r.apps); bindings = copy.deepcopy(guest['network_policy'])
            if kind == 'missing-app': guest['network_policy'][0]['interfaces']['client']['app'] = 'missing'
            elif kind == 'missing-role': guest['network_policy'][0]['interfaces']['client']['interface'] = 'missing'
            elif kind == 'loopback-role': r.apps['recursive_a']['interfaces']['control'] = {'scope': 'guest-loopback'}
            else: guest['network_policy'][0]['interfaces']['unused'] = 'management'
            with self.subTest(kind=kind), self.assertRaises(ComponentError): r.policy_values(guest)
            r.apps = old; guest['network_policy'] = bindings
        r.policy['network']['access']['rules'][0]['source'] = {'network': 'clients'}
        guest['network_policy'] = [{'policy': 'access', 'networks': {'clients': 'secondary'},
                                    'endpoints': {'server': {'external': 'api'}}}]
        self.assertEqual(r.policy_values(guest)[0]['source'], '198.18.21.0/24')
        r.site['networks']['secondary']['context'] = 'other'
        with self.assertRaises(ComponentError): r.policy_values(guest)


class PlanRuntimeReview(unittest.TestCase):

    def runtime(self):
        r = resolver(apps=True)
        r.library['app_profiles']['recursive'].update(runtime=['base'], software=['dns'])
        r.library['runtime_profiles']['base'] = {'containers': {'unbound': {'memory_mib': 256, 'cpu_limit': 1, 'pids_limit': 128}},
            'requirements': {'os_reserve_mib': 256}, 'minimums': {'containers': {'unbound': {'memory_mib': 128}}}}
        r.library['software']['dns'] = {'images': {'unbound': 'image'}, 'packages': ['resolver-tools=1']}
        return r, {'image': {'image': 'example/unbound@sha256:' + 'a' * 64}}

    def test_runtime_merges_equal_limits_and_minimums_but_refuses_conflicting_security_or_budget(self):
        r, images = self.runtime(); r.library['app_profiles']['recursive']['runtime'] += ['same']
        r.library['runtime_profiles']['same'] = copy.deepcopy(r.library['runtime_profiles']['base'])
        r.execution_values(images)
        self.assertEqual(r.guests['resolver']['software_selection']['packages'], ['resolver-tools=1'])
        self.assertEqual(r.apps['recursive_a']['containers']['unbound']['memory_mib'], 256)
        for kind in ('limits', 'minimum', 'security', 'scope', 'incomplete', 'memory', 'foreign-override', 'capability'):
            r, images = self.runtime(); base = r.library['runtime_profiles']['base']
            if kind == 'limits':
                r.library['runtime_profiles']['conflict'] = {'containers': {'unbound': {'memory_mib': 300}}}
                r.apps['recursive_a']['runtime'] = ['conflict']
            elif kind == 'minimum': r.apps['recursive_a']['resources'] = {'containers': {'unbound': {'memory_mib': 64}}}
            elif kind == 'security': base['requirements']['nesting'] = True; r.guests['resolver']['security']['nesting'] = False
            elif kind == 'scope': r.guests['resolver']['runtime'] = ['base']
            elif kind == 'incomplete': del base['containers']['unbound']['pids_limit']
            elif kind == 'memory': r.guests['resolver']['resources']['memory_mib'] = 400
            elif kind == 'foreign-override': r.apps['recursive_a']['resources'] = {'containers': {'foreign': {'memory_mib': 1}}}
            else: base['containers']['unbound']['cap_add'] = ['NET_ADMIN']
            with self.subTest(kind=kind), self.assertRaises(ComponentError): r.execution_values(images)

    def test_software_repository_identity_and_image_roles_refuse_ambiguous_owners(self):
        r, images = self.runtime(); r.library['assets']['key'] = {'format': 'raw', 'text': 'synthetic-public-key'}
        repository = {'name': 'selected', 'key_asset': 'key', 'source': 'deb https://packages.example.invalid stable main'}
        r.library['software']['dns']['repositories'] = [repository]
        r.apps['recursive_a']['software'] = ['dns']; r.execution_values(images)
        self.assertEqual(r.guests['resolver']['software_selection']['repositories'], [repository])
        for kind in ('package', 'repository', 'missing-key', 'image'):
            r, images = self.runtime(); r.library['assets']['key'] = {'format': 'raw', 'text': 'synthetic-public-key'}
            r.library['software']['dns']['repositories'] = [copy.deepcopy(repository)]
            r.library['software']['other'] = {}
            r.apps['recursive_a']['software'] = ['other']
            if kind == 'package': r.library['software']['other']['packages'] = ['resolver-tools=2']
            elif kind == 'repository': r.library['software']['other']['repositories'] = [dict(repository, source='deb https://other.example.invalid stable main')]
            elif kind == 'missing-key': r.library['software']['dns']['repositories'][0]['key_asset'] = 'missing'
            else:
                r.library['software']['other']['images'] = {'unbound': 'other'}
                images['other'] = {'image': 'example/unbound@sha256:' + 'b' * 64}
            with self.subTest(kind=kind), self.assertRaises(ComponentError): r.execution_values(images)

    def test_native_budget_and_cross_guest_app_selection_are_explicit(self):
        r = resolver()
        r.library['app_profiles']['native'] = {'runtime': ['native'], 'software': []}
        r.library['runtime_profiles']['native'] = {'native': {'memory_mib': 256}}
        r.apps = {'database': {'id': 'database', 'guest': 'resolver', 'adapter': 'postgresql', 'profile': 'native', 'properties': {}}}
        r.execution_values({}); self.assertEqual(r.apps['database']['native_requirements'], {'memory_mib': 256})
        r.guests['other'] = copy.deepcopy(r.guests['resolver'])
        r.guests['other']['identity']['vmid'] = 611
        r.apps['foreign'] = dict(copy.deepcopy(r.apps['database']), guest='other')
        r.execution_values({})
        r.library['runtime_profiles']['other'] = {'native': {'memory_mib': 300}}
        r.apps['database']['runtime'] = ['other']
        with self.assertRaisesRegex(ComponentError, 'runtime-conflict'): r.execution_values({})

    def test_mdns_capability_requires_its_physical_interface_and_readonly_startup_owner(self):
        def selected():
            r, images = self.runtime(); profile = r.library['app_profiles']['recursive']; app = r.apps['recursive_a']
            app.update(adapter='homeassistant', interfaces={'control': {'interface': 'management'}},
                storage={'startup': {'asset': 'mdns'}}, properties={'mdns': {'interface': 'control', 'startup': 'startup'}})
            profile.update(adapter='homeassistant', interfaces={'control': {'required': True, 'accepts': ['guest-interface']}})
            app['identity']['services'] = {'homeassistant': 'homeassistant'}
            r.library['assets']['mdns'] = {'format': 'raw', 'text': 'synthetic-startup-hook'}
            profile['storage'] = {'startup': {'target': '/startup', 'read_only': True, 'kind': 'directory', 'required': True}}
            r.library['runtime_profiles']['base']['containers'] = {'homeassistant': {'memory_mib': 256, 'cpu_limit': 1, 'pids_limit': 128, 'cap_add': ['NET_ADMIN']}}
            r.library['runtime_profiles']['base']['minimums'] = {'containers': {'homeassistant': {'memory_mib': 128}}}
            r.library['software']['dns']['images'] = {'homeassistant': 'image'}
            return r, images
        r, images = selected(); r.execution_values(images)
        self.assertEqual(r.apps['recursive_a']['containers']['homeassistant']['cap_add'], ['NET_ADMIN'])
        for kind in ('loopback', 'startup', 'target', 'writable', 'capability'):
            r, images = selected(); app = r.apps['recursive_a']
            if kind == 'loopback': app['interfaces']['control'] = {'scope': 'guest-loopback'}
            elif kind == 'startup': app['storage'] = {}
            elif kind == 'target': r.library['app_profiles']['recursive']['storage']['startup']['target'] = '/elsewhere'
            elif kind == 'writable': r.library['app_profiles']['recursive']['storage']['startup']['read_only'] = False
            else: r.library['runtime_profiles']['base']['containers']['homeassistant']['cap_add'] = []
            with self.subTest(kind=kind), self.assertRaisesRegex(ComponentError, 'runtime-capability'): r.execution_values(images)


class PlanCompilerWiringReview(unittest.TestCase):
    """Only output stitching/selection is real; each producing component is a mock."""
    def compile(self, *, disabled=None, dependency=False, monitoring_guest='resolver', admit=True):
        r = resolver()
        r.guests['backend'] = copy.deepcopy(r.guests['resolver'])
        r.guests['backend']['identity'].update(vmid=611, hostname='example-backend')
        r.apps = {'browser': {'id': 'browser', 'guest': 'resolver'}}
        authentication = {'oidc_issuer': 'https://identity.example.invalid/application/o/browser/'}
        settings = {'bind_address': '198.18.20.10'}
        dependencies = {'guest_dependencies': {'resolver': ['backend'] if dependency else [], 'backend': []},
                        'app_dependencies': {'browser': []}, 'accounts': {}}
        with ExitStack() as stack:
            stack.enter_context(patch.object(plan.component_addresses, 'resolve', return_value={}))
            for method, returned in {'validate': None, 'image_values': {}, 'external_values': None,
                'guest_values': None, 'app_values': None, 'endpoint_values': None,
                'context_values': {'lab': {'node': 'example-node'}}, 'policy_values': [],
                'execution_values': None}.items():
                stack.enter_context(patch.object(r, method, return_value=returned))
            exposure = stack.enter_context(patch.object(plan.component_exposures, 'Exposures')).return_value
            exposure.bind.return_value = {'exposures': {}, 'dns_records': {}, 'routes': {}, 'middlewares': {}}
            stack.enter_context(patch.object(plan.component_auth, 'bind', return_value={
                'authentication': {'browser': authentication}, 'identity_providers': {},
                'transports': {}, 'canonical_middlewares': {}}))
            stack.enter_context(patch.object(plan.component_connections, 'bind', return_value=dependencies))
            stack.enter_context(patch.object(plan.component_properties, 'bind', return_value={'browser': settings}))
            stack.enter_context(patch.object(plan.component_accounts, 'bind', return_value={}))
            stack.enter_context(patch.object(plan.component_monitoring, 'bind', return_value={'guest': monitoring_guest}))
            admission = stack.enter_context(patch.object(plan.component_admission, 'admit'))
            for owner in (plan.component_secrets, plan.component_foundations, plan.component_identity, plan.component_traffic):
                stack.enter_context(patch.object(owner, 'bind'))
            result = r.resolve(disabled, admit=admit)
            return result, admission, authentication, settings

    def test_validated_component_outputs_are_stitched_without_retesting_producers(self):
        result, admission, authentication, settings = self.compile(disabled=['backend'])
        self.assertEqual(result.resolved['apps']['browser']['authentication_resolved'], authentication)
        self.assertEqual(result.resolved['apps']['browser']['settings'], settings)
        self.assertEqual(result.resolved['monitoring'], {'guest': 'resolver'})
        self.assertEqual(result.resolved['enabled'], ['resolver'])
        admission.assert_called_once(); self.assertEqual(admission.call_args.args[1], ['resolver'])
        result.check()

    def test_disabled_dependency_monitoring_owner_and_admission_flags_remain_closed(self):
        for arguments in ({'disabled': 'backend'}, {'disabled': ['unknown']},
                          {'disabled': ['backend', 'backend']}, {'disabled': ['backend'], 'dependency': True},
                          {'disabled': ['backend'], 'monitoring_guest': 'backend'}, {'admit': 1}):
            with self.subTest(arguments=arguments), self.assertRaises(ComponentError): self.compile(**arguments)


if __name__ == '__main__':
    unittest.main()
