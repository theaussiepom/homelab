"""Future guests use explicit finite ACL additions, never credential recreation."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_provider_access as fixture


class ApplicationScopeTests(unittest.TestCase):
    def test_untagged_application_bridge_gets_only_a_bridge_grant_without_network_reload(self):
        host, original = self.setup()
        host.api.network.append({'iface':'vmbr9','type':'bridge','active':1,'autostart':1})
        host.c['application_networks'] = [{'vmid':200,'bridge':'vmbr9','vlan':None}]
        network=copy.deepcopy(host.api.network)
        start=len(host.api.writes)
        host.run_cd()
        writes=host.api.writes[start:]
        self.assertEqual(len(writes),3)  # Guest admin, bridge use, provider guest read.
        self.assertTrue(all(path == '/access/acl' and method == 'PUT' for path,method,_ in writes))
        self.assertEqual(host.api.network,network)
        paths={row[2].get('path') for row in writes}
        self.assertIn('/sdn/zones/localnetwork/vmbr9',paths)
        self.assertFalse(any(path and path.endswith('/None') for path in paths))

    def setup(self):
        host = fixture.DiscoveryTests()
        host.setUp(); self.addCleanup(host.doCleanups)
        host.run_cd()
        original = copy.deepcopy(host.c)
        host.c['applications'].append({'vmid': 200, 'hostname': 'automation'})
        host.c['service_discovery']['guests'] = [200, 202, 211, 212]
        host.c['service_discovery_extension'] = {'previous_guests': [202, 211, 212]}
        return host, original

    def test_new_guest_and_existing_vlan_can_be_added_without_mint_or_network_reload(self):
        host, original = self.setup()
        host.api.network.append({'iface': 'vmbr1', 'type': 'bridge', 'active': 1, 'bridge_vlan_aware': 1,
                                 'bridge_ports': 'existing0', 'autostart': 1})
        host.c['application_networks'] = [{'vmid': 200, 'bridge': 'vmbr1', 'vlan': 100}]
        network, firewall = copy.deepcopy(host.api.network), copy.deepcopy(host.api.rules)
        token = (host.root / 'service-discovery/token.json').read_bytes()
        previous = (host.root / 'service-discovery/owner.json').read_bytes()
        start = len(host.api.writes)
        result = host.run_cd()
        writes = host.api.writes[start:]
        self.assertEqual(len(writes), 4)  # Guest admin, bridge/tag use, provider guest read.
        self.assertTrue(all(path == '/access/acl' and method == 'PUT' for path, method, _ in writes))
        self.assertTrue(result['service_discovery']['extended'])
        self.assertEqual(host.api.network, network); self.assertEqual(host.api.rules, firewall)
        self.assertEqual((host.root / 'service-discovery/token.json').read_bytes(), token)
        self.assertEqual(len(host.api.tokens), 1)
        archives = list((host.root / 'service-discovery').glob('owner-*.previous.json'))
        self.assertEqual(len(archives), 1)
        self.assertEqual(json.loads(archives[0].read_text()), json.loads(previous))
        written = copy.deepcopy(host.api.writes)
        host.run_cd()
        self.assertEqual(host.api.writes, written)

    def test_changed_scope_without_an_exact_previous_scope_is_refused(self):
        for problem in ('missing', 'wrong', 'removal'):
            with self.subTest(problem=problem):
                host, original = self.setup(); writes = copy.deepcopy(host.api.writes)
                if problem == 'missing': host.c.pop('service_discovery_extension')
                if problem == 'wrong': host.c['service_discovery_extension']['previous_guests'] = [211, 212]
                if problem == 'removal': host.c['service_discovery']['guests'] = [200, 212]
                with self.assertRaises(ValueError): host.run_cd()
                self.assertEqual(host.api.writes, writes)

    def test_partial_scope_failure_keeps_previous_owner_and_native_hold(self):
        host, original = self.setup()
        owner = (host.root / 'service-discovery/owner.json').read_bytes()
        host.api.fail_provider_acl = True
        with self.assertRaises(ValueError): host.run_cd()
        self.assertEqual((host.root / 'service-discovery/owner.json').read_bytes(), owner)
        self.assertTrue((host.root / 'BOOTSTRAP-CD-HOLD.json').exists())
        writes = copy.deepcopy(host.api.writes)
        with self.assertRaises(ValueError): host.run_cd()
        self.assertEqual(host.api.writes, writes)

    def test_network_access_requires_a_declared_guest_and_an_existing_vlan_bridge(self):
        for problem in ('undeclared', 'not-vlan-aware', 'missing'):
            with self.subTest(problem=problem):
                host, original = self.setup(); writes = copy.deepcopy(host.api.writes)
                host.c['application_networks'] = [{'vmid': 200, 'bridge': 'vmbr1', 'vlan': 100}]
                if problem == 'undeclared': host.c['application_networks'][0]['vmid'] = 4914
                if problem == 'not-vlan-aware': host.api.network.append({'iface':'vmbr1','type':'bridge','active':1})
                with self.assertRaises(ValueError): host.run_cd()
                self.assertEqual(host.api.writes, writes)


if __name__ == '__main__': unittest.main()
