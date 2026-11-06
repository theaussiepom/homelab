"""Finite firewall values and real compiler/packet propagation; no target access."""
import copy
import json
from pathlib import Path
import traceback
import unittest
from unittest.mock import patch

import component_addresses as addresses
import component_exposures
import component_lower
import component_packet
import component_traffic as traffic
import component_types as types
from component_errors import ComponentError
from test_component_exposure_policy import fixture as exposure_fixture
import test_component_packet as fixtures


def rule(proto='udp', **values):
    return dict(direction='out', proto=proto, destination='ff02::fb/128',
                port='5353', comment='Explicit synthetic discovery', **values)


class FirewallValueTests(unittest.TestCase):
    def test_firewall_literals_accept_both_families_without_expanding_http_addresses(self):
        for address in ('192.0.2.1', '192.0.2.0/24', '::1/128', '2001:db8::/64', 'ff02::fb'):
            with self.subTest(address=address):
                types.rule_address(address, ipv6=True)
        for address in ('::1/128', 'fe80::1%net0', '[ff02::fb]', '2001:db8::/129',
                        '999.0.0.1', 'PRIVATE_SENTINEL'):
            with self.subTest(address=address), self.assertRaises(ComponentError) as caught:
                types.rule_address(address)
            self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))
        with self.assertRaises(ComponentError):
            types.rule_address('fe80::1%net0', ipv6=True)

    def test_shared_group_values_keep_order_duplicates_and_existing_network_family(self):
        groups = {'local': {'members': ['fe80::/64', 'fd00:1234::/64']},
                  'selected': {'members': [{'network': 'lan'}, {'address_group': 'local'},
                                            'ff02::fb/128', {'address_group': 'local'}]}}
        before = copy.deepcopy(groups)
        with patch.object(Path, 'open', side_effect=AssertionError('No private reads')):
            selected = addresses.resolve(groups, {'lan': {'cidr': '192.0.2.0/24'}})
        self.assertEqual(selected['selected'], ['192.0.2.0/24', 'fe80::/64', 'fd00:1234::/64',
                                               'ff02::fb/128', 'fe80::/64', 'fd00:1234::/64'])
        self.assertEqual(groups, before)
        with self.assertRaises(ComponentError):
            addresses.resolve({'x': {'members': [{'network': 'lan'}]}},
                              {'lan': {'cidr': 'fd00:1234::/64'}})

    def test_ipv6_group_cannot_implicitly_expand_http_allowlist_audience(self):
        for values in (['192.0.2.0/24', 'fd00:1234::/64'], ['fd00:1234::/64']):
            resolver = exposure_fixture()
            resolver.address_groups = {'clients': values}
            resolver.policy['middlewares']['clients'] = {
                'type': 'ip-allow-list', 'ranges': [{'address_group': 'clients'}]}
            with self.subTest(values=values), self.assertRaises(ComponentError):
                component_exposures.Exposures(resolver).validate_policies()

    def test_single_icmp_types_and_transport_ranges_have_distinct_bounds(self):
        for value in ('0', '1', '130', '131', '132', '143', '255'):
            with self.subTest(icmp=value): types.rule_port(value, icmp=True)
        for value in ('1', '65535', '53,5353', '32768:60999', '1:1,65535'):
            with self.subTest(port=value): types.rule_port(value)
        for icmp, values in ((True, (None, 143, '', '-1', '256', '000', '130,143', '130:143')),
                             (False, (None, 53, '', '0', '01', '65536', '1:65536',
                                      '2:1', '53,', ',53', 'PRIVATE_SENTINEL'))):
            for value in values:
                with self.subTest(icmp=icmp, value=value), self.assertRaises(ComponentError):
                    types.rule_port(value, icmp=icmp)

    def test_protocol_port_contract_refuses_igmp_ports_and_nontransport_endpoint_ports(self):
        for proto in ('icmp', 'icmpv6', 'igmp'):
            for port in ({'endpoint': 'service'}, '130:143' if proto != 'igmp' else '1'):
                value = rule(proto); value['port'] = port
                with self.subTest(proto=proto, port=port), self.assertRaises(ComponentError):
                    types.network_policy({'rules': [value]})
        for value in (dict(rule('igmp'), port=None, destination='224.0.0.22/32'),
                      dict(rule('icmpv6'), port='143', destination='ff02::16/128')):
            before = copy.deepcopy(value)
            types.network_policy({'rules': [value]}); types.rule_family(value)
            self.assertEqual(value, before)

    def test_resolved_families_refuse_mixing_wrong_protocols_and_unrestricted_ingress(self):
        cases = [dict(rule(), source='192.0.2.1'),
                 dict(rule('icmp'), port='3'), dict(rule('igmp'), port=None),
                 dict(rule('icmpv6'), destination='192.0.2.1', port='130'),
                 dict(rule(), direction='in', source='::/0'),
                 dict(rule(), direction='in', source='0.0.0.0/0', destination='192.0.2.1')]
        cases += [dict(rule(), direction='in', source=value, destination=None) for value in (
            '::/00', '2001:db8::/00', '::/000', '0.0.0.0/00', '192.0.2.1/00')]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ComponentError): types.rule_family(value)
        for value in (dict(rule(), source='fd00:1234::1'), dict(rule('icmpv6'), port='0'),
                      dict(rule('icmp'), port='3', destination='192.0.2.1'),
                      dict(rule('igmp'), port=None, destination='224.0.0.22')):
            with self.subTest(value=value): types.rule_family(value)


class FirewallMatcherTests(unittest.TestCase):
    def test_flow_families_and_protocols_refuse_impossible_packets_without_a_source_selector(self):
        cases = [
            (rule(), traffic.Flow('192.0.2.10', 'ff02::fb', 'udp', 5353)),
            (dict(rule('igmp'), destination='224.0.0.22', port=None),
             traffic.Flow('fd00:1234::10', '224.0.0.22', 'igmp', None)),
            (dict(rule('icmpv6'), destination='192.0.2.11', port='130'),
             traffic.Flow('192.0.2.10', '192.0.2.11', 'icmpv6', 130)),
            (dict(rule('icmp'), port='3'), traffic.Flow('fe80::10', 'ff02::fb', 'icmp', 3)),
            (dict(rule('igmp'), port=None), traffic.Flow('fe80::10', 'ff02::fb', 'igmp', None)),
        ]
        for selected, flow in cases:
            with self.subTest(protocol=flow.protocol):
                self.assertFalse(traffic.permits([selected], 'out', flow, 'net1'))

    def test_invalid_flow_sources_are_sanitized_and_hostname_family_never_requires_dns(self):
        for address in ('PRIVATE_SENTINEL', '', None, True, 42, [], b'192.0.2.10'):
            with self.subTest(kind=type(address).__name__), self.assertRaises(ComponentError) as caught:
                traffic.permits([rule()], 'out', traffic.Flow(address, 'ff02::fb', 'udp', 5353), 'net1')
            self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))
            rendered = ''.join(traceback.format_exception(caught.exception))
            self.assertNotIn('PRIVATE_SENTINEL', rendered)
        for address in (None, '', 42):
            with self.subTest(target=address), self.assertRaises(ComponentError):
                traffic.permits([rule()], 'out', traffic.Flow('192.0.2.10', address, 'udp', 5353), 'net1')
        with patch('socket.getaddrinfo', side_effect=AssertionError('No DNS')):
            flow = traffic.Flow('fd00:1234::10', 'service.example.invalid', 'udp', 5353)
            self.assertTrue(traffic.permits([dict(rule(), destination='::/0')], 'out', flow, 'net1'))
            self.assertFalse(traffic.permits([dict(rule(), destination='0.0.0.0/0')], 'out', flow, 'net1'))

    def test_ipv6_discovery_and_mld_match_only_selected_family_interface_type_and_peer(self):
        selected = dict(rule(), source='fe80::/64', interface='net1')
        flow = traffic.Flow('fe80::10', 'ff02::fb', 'udp', 5353)
        self.assertTrue(traffic.permits([selected], 'out', flow, 'net1'))
        for values in (dict(source='192.0.2.10', target='224.0.0.251'),
                       dict(source='fd00:1234::10'), dict(target='ff02::c'),
                       dict(proto='tcp'), dict(port=1900), dict(interface='net0')):
            other = traffic.Flow(values.get('source', flow.source_address),
                                 values.get('target', flow.target_address),
                                 values.get('proto', flow.protocol), values.get('port', flow.port))
            with self.subTest(values=values):
                self.assertFalse(traffic.permits([selected], 'out', other, values.get('interface', 'net1')))
        for number in (0, 130, 131, 132, 143, 255):
            value = dict(rule('icmpv6'), port=str(number), interface='net1')
            self.assertTrue(traffic.permits([value], 'out', traffic.Flow('fe80::10', 'ff02::fb', 'icmpv6', number), 'net1'))
            self.assertFalse(traffic.permits([value], 'out', traffic.Flow('fe80::10', 'ff02::fb', 'icmpv6', None), 'net1'))
        with self.assertRaises(ComponentError):
            traffic.permits([dict(rule('igmp'), port='1', destination='224.0.0.22')],
                            'out', traffic.Flow('192.0.2.10', '224.0.0.22', 'igmp', 1), 'net1')

    def test_ipv6_rule_never_authorizes_ipv4_hostname_or_changes_literal_ipv4_matching(self):
        value = dict(rule('tcp'), destination='::/0', port='443')
        flow = traffic.Flow('192.0.2.10', 'download.example.invalid', 'tcp', 443)
        with patch('socket.getaddrinfo', side_effect=AssertionError('No DNS')):
            self.assertFalse(traffic.permits([value], 'out', flow, 'net0'))
            value['destination'] = '0.0.0.0/0'
            self.assertTrue(traffic.permits([value], 'out', flow, 'net0'))
            value['destination'] = '192.0.2.0/24'
            self.assertTrue(traffic.permits([value], 'out', traffic.Flow('192.0.2.10', '192.0.2.11', 'tcp', 443), 'net0'))
            value = dict(rule('igmp'), destination='224.0.0.22', port=None)
            self.assertTrue(traffic.permits([value], 'out', traffic.Flow('192.0.2.10', '224.0.0.22', 'igmp', None), 'net0'))


class FirewallCompilerTests(unittest.TestCase):
    def setUp(self):
        self.case = fixtures.PacketIntegrationTests(); self.case.setUp()
        self.addCleanup(self.case.doCleanups)

    def select(self, rows):
        self.case.site['policies'] = {'network': {'discovery': {'rules': rows}}}
        self.case.site['guests']['resolver']['network_policy'] = [
            {'policy': 'discovery', 'interfaces': {'wire': 'backend'}}]

    def test_real_group_binding_lowering_and_closed_receiver_preserve_rules_and_other_configuration(self):
        import component_guest
        before = self.case.resolve()
        provider = component_lower.provider_config(before, 'resolver')
        self.case.site['address_groups'] = {'peers': {'members': ['fe80::/64', 'fd00:1234::/64']}}
        self.select([dict(rule(), direction='in', source={'address_group': 'peers'}, interface='wire'),
                     dict(rule('icmpv6'), destination='ff02::16/128', port='143', interface='wire'),
                     dict(rule('igmp'), destination='224.0.0.22/32', port=None, interface='wire')])
        self.case.site['guests']['resolver']['network_policy'][0]['address_groups'] = {'peers': 'peers'}
        plan = self.case.resolve(); compiled = component_lower.provider_config(plan, 'resolver')
        rows = compiled['guest'].pop('rules')
        expected = copy.deepcopy(provider); expected['guest'].pop('rules')
        self.assertEqual(compiled, expected)
        self.assertEqual([r.get('source') for r in rows[:2]], ['fe80::/64', 'fd00:1234::/64'])
        self.assertEqual([r['interface'] for r in rows], ['net1'] * 4)
        packet = component_packet.lower_plan(plan)['resolver']
        cfg, _ = component_guest.packet(packet, component_packet.INPUTS)
        self.assertEqual(cfg['guest']['rules'], rows)
        self.assertEqual(plan.resolved['guest_dependencies'], before.resolved['guest_dependencies'])
        self.assertEqual(cfg['deployment']['phases'], ['preparation', 'recursive_a'])

    def test_real_compiler_refuses_wrong_bound_family_group_interface_and_protocol(self):
        original = dict(rule(), interface='wire')
        for change in ({'source': '192.0.2.1'}, {'proto': 'icmp'}, {'proto': 'igmp', 'port': None},
                       {'direction': 'in', 'source': '::/0'}, {'interface': 'missing'},
                       {'source': {'endpoint': 'dns'}}):
            self.select([dict(original, **change)])
            if isinstance(change.get('source'), dict):
                self.case.site['guests']['resolver']['network_policy'][0]['endpoints'] = {'dns': {'external': 'dns'}}
            with self.subTest(change=change), self.assertRaises(ComponentError): self.case.resolve()
        self.case.site['address_groups'] = {'peers': {'members': ['fe80::/64', '192.0.2.0/24']}}
        self.select([dict(original, source={'address_group': 'peers'})])
        self.case.site['guests']['resolver']['network_policy'][0]['address_groups'] = {'peers': 'peers'}
        with self.assertRaisesRegex(ComponentError, 'policy-family'): self.case.resolve()

    def test_same_rule_contract_supports_fresh_creation_policy_and_retained_updates(self):
        for lifecycle in ('fresh', 'retained'):
            if lifecycle == 'retained':
                guest = self.case.site['guests']['resolver']
                guest.update(lifecycle='retained', compose_projects={'owned': {'name': 'owned-resolver'}},
                             root_paths={'config': {'path': '/srv/example/unbound/config'}})
                self.case.spec['app_profiles']['recursive']['storage'] = {'config': {
                    'target': '/opt/unbound/etc/unbound', 'read_only': False,
                    'required': True, 'kind': 'directory'}}
                self.case.site['apps']['recursive_a'].update(lifecycle='retained', identity={
                    'phase': 'recursive_a', 'runtime_id': 'recursive_a', 'project': 'owned',
                    'services': {'unbound': 'owned-unbound'}, 'networks': {'default': 'default'}},
                    storage={'config': {'root_path': 'config', 'subpath': ''}})
            self.select([dict(rule('icmpv6'), destination='ff02::16', port='143', interface='wire')])
            with self.subTest(lifecycle=lifecycle):
                plan = self.case.resolve()
                packet = component_packet.lower_plan(plan)['resolver']
                cfg = json.loads(packet['files']['site.json'])
                self.assertEqual(cfg['guest']['rules'], [dict(rule('icmpv6'),
                    destination='ff02::16', port='143', interface='net1')])
                self.assertEqual(cfg['deployment']['lifecycle'], lifecycle)


if __name__ == '__main__': unittest.main()
