import contextlib
import copy
import ipaddress
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import fdb


CONFIG = {'overlay': {'network': 'underground', 'local_ip': '192.0.2.5',
                     'peer_subnet': '192.0.2.0/24', 'route_interface': 'ens1.100',
                     'peer_probe_port': 22}}
IP = '198.18.200.243'
MAC = '02:00:00:00:01:f3'
PEER = '192.0.2.6'
NAMESPACE = {'path': '/var/run/docker/netns/1-fixture012', 'device': 4, 'inode': 123}


def fixture():
    network = {'Name': 'underground', 'Id': 'fixture0123456789abcdefghi', 'Created': '2000-01-01',
               'Scope': 'swarm', 'Driver': 'overlay', 'Ingress': False,
               'IPAM': {'Config': [{'Subnet': '198.18.200.0/24'}]},
               'Options': {'com.docker.network.driver.overlay.vxlanid_list': '4098'},
               'Peers': [{'IP': x} for x in ('192.0.2.5', PEER)],
               'Services': {'': {'Tasks': [{'Name': 'remote', 'EndpointIP': IP,
                                            'EndpointID': 'a'*64, 'Info': {'Host IP': PEER}}]}}}
    links = [{'ifname': 'br0', 'ifindex': 2, 'flags': ['UP'], 'linkinfo': {'info_kind': 'bridge'}},
             {'ifname': 'vxlan0', 'ifindex': 51, 'master': 'br0', 'flags': ['UP'],
              'linkinfo': {'info_kind': 'vxlan', 'info_data': {'id': 4098, 'port': 4789}}}]
    neighbours = [{'dst': IP, 'dev': 'vxlan0', 'lladdr': MAC, 'state': ['PERMANENT']}]
    entries = [{'mac': MAC, 'ifname': 'vxlan0', 'master': 'br0', 'flags': [], 'state': ''}]
    routes = {PEER: [{'dev': 'ens1.100', 'prefsrc': '192.0.2.5'}]}
    return network, links, neighbours, entries, routes


def plan(values):
    network, links, neighbours, entries, routes = values
    return fdb._plan(CONFIG['overlay'], network, 4098, ipaddress.IPv4Network('198.18.200.0/24'),
                     NAMESPACE, links, neighbours, entries, routes)


def self_entry(state='permanent', **kw):
    value = {'mac': MAC, 'ifname': 'vxlan0', 'flags': ['self'], 'dst': PEER, 'state': state}
    value.update(kw)
    return value


class ReconciliationTests(unittest.TestCase):
    def assert_blocked(self, values, reason):
        result = plan(values)
        self.assertFalse(result['candidates'])
        self.assertIn(reason, [x['reason'] for x in result['issues']])

    def test_missing_tunnel_mapping_is_only_candidate(self):
        result = plan(fixture())
        self.assertFalse(result['healthy'])
        self.assertFalse(result['issues'])
        self.assertEqual(len(result['candidates']), 1)
        candidate = result['candidates'][0]
        self.assertEqual(candidate['identity']['mac'], MAC)
        self.assertEqual(candidate['identity']['peer'], PEER)

    def test_dynamic_and_permanent_matching_entries_are_both_noop(self):
        for state in ('permanent', ''):
            with self.subTest(state=state):
                values = fixture(); values[3].append(self_entry(state))
                result = plan(values)
                self.assertTrue(result['healthy'])
                self.assertEqual(result['entries'][0]['state'], 'present')

    def test_present_tunnel_with_aged_master_is_noop(self):
        values = fixture(); values[3].clear(); values[3].append(self_entry())
        self.assertTrue(plan(values)['healthy'])

    def test_missing_or_nonpermanent_neighbour_never_infers_mac(self):
        for neighbours in ([], [{'dst': IP, 'dev': 'vxlan0', 'lladdr': MAC, 'state': ['STALE']}]):
            values = list(fixture()); values[2] = neighbours
            self.assert_blocked(values, 'permanent_neighbour_missing_or_conflicting')

    def test_neighbour_on_wrong_device_and_duplicate_are_blocked(self):
        values = fixture(); values[2][0]['dev'] = 'br0'
        self.assert_blocked(values, 'permanent_neighbour_missing_or_conflicting')
        values = fixture(); values[2].append(copy.deepcopy(values[2][0]))
        self.assert_blocked(values, 'permanent_neighbour_missing_or_conflicting')

    def test_broadcast_mac_and_reused_mac_are_blocked(self):
        values = fixture(); values[2][0]['lladdr'] = 'ff:ff:ff:ff:ff:ff'
        self.assert_blocked(values, 'permanent_neighbour_missing_or_conflicting')
        values = fixture(); values[2].append(dict(values[2][0], dst='198.18.200.244'))
        self.assert_blocked(values, 'neighbour_mac_conflict')

    def test_missing_and_wrong_master_mapping_are_blocked(self):
        values = fixture(); values[3].clear()
        self.assert_blocked(values, 'bridge_fdb_missing_or_conflicting')
        values = fixture(); values[3][0]['ifname'] = 'veth7'
        self.assert_blocked(values, 'bridge_fdb_missing_or_conflicting')

    def test_conflicting_tunnel_never_replaced(self):
        for rows in ([self_entry(dst='192.0.2.7')], [self_entry(), self_entry()],
                     [self_entry(ifname='vxlan1')]):
            values = fixture(); values[3].extend(rows)
            self.assert_blocked(values, 'tunnel_fdb_conflict')

    def test_multicast_and_zero_fallback_are_preserved(self):
        values = fixture(); values[3].extend([self_entry(mac='00:00:00:00:00:00'),
                                            self_entry(mac='01:00:5e:00:00:01')])
        self.assertEqual(len(plan(values)['candidates']), 1)

    def test_local_endpoint_never_repaired(self):
        values = fixture(); values[0]['Services']['']['Tasks'][0]['Info']['Host IP'] = '192.0.2.5'
        self.assertTrue(plan(values)['healthy'])
        self.assertFalse(plan(values)['entries'])

    def test_conflicting_endpoint_ip_and_id_blocked(self):
        values = fixture(); values[0]['Services']['']['Tasks'].append(
            dict(values[0]['Services']['']['Tasks'][0], EndpointID='b'*64))
        self.assert_blocked(values, 'endpoint_ip_conflict')
        values = fixture(); values[0]['Services']['']['Tasks'].append(
            dict(values[0]['Services']['']['Tasks'][0], EndpointIP='198.18.200.244'))
        self.assert_blocked(values, 'endpoint_id_conflict')

    def test_unknown_remote_peer_is_blocked(self):
        values = fixture(); values[0]['Services']['']['Tasks'][0]['Info']['Host IP'] = '192.0.2.9'
        self.assert_blocked(values, 'endpoint_peer_unknown')

    def test_route_must_match_current_local_data_path(self):
        for route in ([{'dev': 'ens1.100', 'prefsrc': '192.0.2.5', 'gateway': '192.0.2.1'}],
                      [{'dev': 'old0', 'prefsrc': '192.0.2.5'}], [],
                      [{'dev': 'ens1.100', 'prefsrc': '192.0.2.9'}]):
            values = fixture(); values[4][PEER] = route
            self.assert_blocked(values, 'underlay_route_not_ready')

    def test_vni_and_link_down_are_global_guards(self):
        values = fixture(); values[1][1]['linkinfo']['info_data']['id'] = 4099
        with self.assertRaisesRegex(fdb.GuardError, 'vxlan_vni_not_unique'): plan(values)
        values = fixture(); values[1][1]['flags'] = []
        with self.assertRaisesRegex(fdb.GuardError, 'vxlan_interface_not_ready'): plan(values)

    def test_multi_vni_network_rejected_without_guessing(self):
        network = fixture()[0]
        network['Options']['com.docker.network.driver.overlay.vxlanid_list'] = '4098,4099'
        with patch.object(fdb, '_json', return_value=[network]):
            with self.assertRaisesRegex(fdb.GuardError, 'single_vni_required'):
                fdb._network(CONFIG['overlay'])

    def test_wrong_driver_and_encrypted_overlay_fail_closed(self):
        for field, value, error in [('Driver', 'bridge', 'unsupported_network_kind'),
                                    ('Options', {'encrypted': ''}, 'encrypted_overlay_requires_separate_review')]:
            network = fixture()[0]; network[field] = value
            with patch.object(fdb, '_json', return_value=[network]):
                with self.assertRaisesRegex(fdb.GuardError, error):
                    fdb._network(CONFIG['overlay'])

    def test_duplicate_logical_name_cannot_share_ageing_key(self):
        values = fixture()
        values[0]['Services']['']['Tasks'].append({'Name': 'remote', 'EndpointIP': '198.18.200.244',
                                                  'EndpointID': 'b'*64, 'Info': {'Host IP': PEER}})
        values[2].append({'dst': '198.18.200.244', 'dev': 'vxlan0',
                          'lladdr': '02:00:00:00:01:f4', 'state': ['PERMANENT']})
        values[3].append({'mac': '02:00:00:00:01:f4', 'ifname': 'vxlan0', 'master': 'br0', 'flags': []})
        self.assert_blocked(values, 'logical_key_conflict')

    def test_namespace_matches_exact_network_prefix_not_substring(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'1-fixture012x').touch()
            with patch.object(fdb, 'NETNS_ROOT', root):
                with self.assertRaisesRegex(fdb.GuardError, 'network_namespace_not_unique'):
                    with fdb._namespace(fixture()[0]): pass
                (root/'1-fixture012').touch()
                with fdb._namespace(fixture()[0]) as (fd, identity):
                    self.assertGreaterEqual(fd, 0)
                    self.assertEqual(identity['path'], str(root/'1-fixture012'))
                (root/'2-fixture012').touch()
                with self.assertRaisesRegex(fdb.GuardError, 'network_namespace_not_unique'):
                    with fdb._namespace(fixture()[0]): pass

    def test_synthetic_mixed_states_select_only_missing_zwave(self):
        # Synthetic missing, present and aged forwarding states. No host report
        # or private runtime identifiers are needed to reproduce the behavior.
        network, links, _, _, _ = fixture()
        records = [('agent-fixture-a', '183', 'b7', '6', '', True),
                   ('pihole2', '3', '03', '4', 'permanent', False),
                   ('zigbee2', '152', '98', '6', 'permanent', False),
                   ('zwave-js-ui', '243', 'f3', '6', None, True),
                   ('agent-fixture-b', '182', 'b6', '4', '', True),
                   ('agent-fixture-c', '184', 'b8', '7', '', True)]
        network['Peers'] = [{'IP': '192.0.2.' + s} for s in ('4', '5', '6', '7')]
        tasks, neighbours, entries, routes = [], [], [], {}
        for index, (name, suffix, mac_suffix, peer_suffix, state, master_present) in enumerate(records):
            ip, mac, peer = '198.18.200.' + suffix, '02:00:00:00:01:' + mac_suffix, '192.0.2.' + peer_suffix
            tasks.append({'Name': name, 'EndpointIP': ip, 'EndpointID': format(index, '064x'),
                          'Info': {'Host IP': peer}})
            neighbours.append({'dst': ip, 'dev': 'vxlan0', 'lladdr': mac, 'state': ['PERMANENT']})
            if master_present:
                entries.append({'mac': mac, 'ifname': 'vxlan0', 'master': 'br0', 'flags': []})
            if state is not None:
                entries.append(self_entry(state, mac=mac, dst=peer))
            routes[peer] = [{'dev': 'ens1.100', 'prefsrc': '192.0.2.5'}]
        network['Services']['']['Tasks'] = tasks
        result = fdb._plan(CONFIG['overlay'], network, 4098, ipaddress.IPv4Network('198.18.200.0/24'),
                           NAMESPACE, links, neighbours, entries, routes)
        self.assertFalse(result['issues'])
        self.assertEqual([x['key'] for x in result['candidates']], ['underground:zwave-js-ui'])


class RepairTests(unittest.TestCase):
    def setUp(self):
        self.values = fixture()
        self.snapshot = plan(self.values)
        self.candidate = self.snapshot['candidates'][0]
        present_values = fixture(); present_values[3].append(self_entry())
        self.present = plan(present_values)
        self.records = []

    def execute(self, snapshots=None, after=None, command=None, record=None, namespaces=None, peer_error=None):
        contexts = list(namespaces or [NAMESPACE, NAMESPACE])
        @contextlib.contextmanager
        def namespace(_network):
            yield 99, contexts.pop(0)
        with patch.object(fdb, '_network', return_value=(self.values[0], 4098, ipaddress.IPv4Network('198.18.200.0/24'))), \
             patch.object(fdb, '_namespace', side_effect=namespace), \
             patch.object(fdb, '_snapshot', side_effect=snapshots or [self.snapshot, self.snapshot]), \
             patch.object(fdb, '_probe_peer', side_effect=peer_error), \
             patch.object(fdb, '_run', return_value=command or subprocess.CompletedProcess([], 0, '', '')) as runner, \
             patch.object(fdb, 'observe', return_value=after or self.present):
            try:
                result = fdb.repair(self.candidate, CONFIG, record or (lambda p, d: self.records.append((p, d))))
                return result, runner.call_args_list
            finally:
                self.calls = runner.call_args_list

    def test_add_one_and_verify(self):
        result, calls = self.execute()
        self.assertEqual(result['status'], 'repaired')
        self.assertTrue(result['success'])
        self.assertTrue(result['changed'])
        self.assertFalse(result['connectivity_verified'])
        self.assertEqual(len(calls), 1)
        command = calls[0].args[0]
        self.assertEqual(command[3:], ['bridge', 'fdb', 'add', MAC, 'dev', 'vxlan0', 'dst', PEER, 'self', 'permanent'])
        self.assertEqual([p for p, _ in self.records], ['before', 'attempted', 'after'])

    def test_already_fixed_has_no_mutation(self):
        result, calls = self.execute(snapshots=[self.present])
        self.assertEqual(result['status'], 'already_resolved')
        self.assertFalse(calls)
        self.assertTrue(result['success'])

    def test_peer_unreachable_prevents_intent_and_mutation(self):
        result, calls = self.execute(peer_error=fdb.PeerUnavailable('underlay_peer_probe_failed'))
        self.assertFalse(calls)
        self.assertTrue(result['deferred'])
        self.assertFalse(result['success'])
        self.assertFalse(result['changed'])
        self.assertFalse(result['mutation_attempted'])
        self.assertEqual(result['reason'], 'peer_unreachable')
        self.assertEqual([p for p, _ in self.records], ['deferred'])

    def test_unexpected_local_probe_error_does_not_defer(self):
        with self.assertRaises(PermissionError):
            self.execute(peer_error=PermissionError('permission denied'))
        self.assertFalse(self.calls)
        self.assertFalse(self.records)

    def test_probe_is_bound_to_local_ip_and_sends_no_payload(self):
        with patch.object(fdb.socket, 'create_connection') as connect:
            fdb._probe_peer(PEER, CONFIG['overlay'])
            connect.assert_called_once_with((PEER, 22), timeout=3, source_address=('192.0.2.5', 0))
            self.assertFalse(connect.return_value.__enter__.return_value.send.called)
        with patch.object(fdb.socket, 'create_connection', side_effect=TimeoutError):
            with self.assertRaisesRegex(fdb.PeerUnavailable, 'underlay_peer_probe_failed'):
                fdb._probe_peer(PEER, CONFIG['overlay'])
        with patch.object(fdb.socket, 'create_connection', side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                fdb._probe_peer(PEER, CONFIG['overlay'])

    def test_invalid_probe_port_rejected(self):
        for port in (True, 0, 65536, '22'):
            config = copy.deepcopy(CONFIG); config['overlay']['peer_probe_port'] = port
            with self.assertRaisesRegex(fdb.GuardError, 'invalid_peer_probe_port'):
                fdb._config(config)

    def test_resolved_during_journal_has_no_mutation(self):
        result, calls = self.execute(snapshots=[self.snapshot, self.present])
        self.assertEqual(result['status'], 'already_resolved')
        self.assertFalse(calls)

    def test_durable_journal_failure_prevents_mutation(self):
        def broken(*_): raise OSError('disk full')
        with self.assertRaises(OSError): self.execute(record=broken)
        self.assertFalse(self.calls)

    def test_eexist_race_requires_exact_post_mapping(self):
        command = subprocess.CompletedProcess([], 2, '', 'RTNETLINK answers: File exists\n')
        result, calls = self.execute(command=command)
        self.assertEqual(result['status'], 'concurrently_resolved')
        self.assertFalse(result['changed'])
        with self.assertRaisesRegex(fdb.GuardError, 'fdb_add_not_confirmed'):
            self.execute(command=command, after=self.snapshot)

    def test_unrelated_command_failure_not_masked_by_later_success(self):
        command = subprocess.CompletedProcess([], 2, '', 'Operation not permitted\n')
        with self.assertRaisesRegex(fdb.GuardError, 'fdb_add_failed'):
            self.execute(command=command)
        self.assertEqual(self.records[-1][0], 'attempted')

    def test_endpoint_lifecycle_change_before_add_stops(self):
        changed = copy.deepcopy(self.snapshot); changed['entries'][0]['identity']['endpoint_id'] = 'b'*64
        with self.assertRaisesRegex(fdb.GuardError, 'candidate_identity_changed'):
            self.execute(snapshots=[self.snapshot, changed])
        self.assertFalse(self.calls)

    def test_namespace_replacement_stops_before_add(self):
        with self.assertRaisesRegex(fdb.GuardError, 'namespace_changed_before_add'):
            self.execute(namespaces=[NAMESPACE, dict(NAMESPACE, inode=456)])
        self.assertFalse(self.calls)

    def test_changed_interface_or_peer_before_add_stops(self):
        for field, value in [('ifindex', 99), ('peer', '192.0.2.7'), ('network_created', 'new')]:
            changed = copy.deepcopy(self.snapshot); changed['entries'][0]['identity'][field] = value
            with self.assertRaisesRegex(fdb.GuardError, 'candidate_identity_changed'):
                self.execute(snapshots=[self.snapshot, changed])
            self.assertFalse(self.calls)

    def test_return_zero_without_mapping_is_failure(self):
        with self.assertRaisesRegex(fdb.GuardError, 'fdb_add_not_confirmed'):
            self.execute(after=self.snapshot)
        self.assertEqual(self.records[-1][0], 'attempted')

    def test_post_add_lifecycle_change_is_error_without_delete(self):
        changed = copy.deepcopy(self.present); changed['entries'][0]['identity']['endpoint_id'] = 'b'*64
        with self.assertRaisesRegex(fdb.GuardError, 'candidate_identity_changed'):
            self.execute(after=changed)
        self.assertEqual(len(self.calls), 1)
        self.assertIn('add', self.calls[0].args[0])


if __name__ == '__main__':
    unittest.main()
