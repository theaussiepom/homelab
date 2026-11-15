"""Future application admission never changes the all-guest discovery credential."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_provider_access as fixture
import provider_access


class ApplicationScopeTests(unittest.TestCase):
    def test_untagged_application_bridge_gets_only_a_bridge_grant_without_network_reload(self):
        host, original = self.setup()
        host.api.network.append({'iface':'vmbr9','type':'bridge','active':1,'autostart':1})
        host.c['application_networks'] = [{'vmid':200,'bridge':'vmbr9','vlan':None}]
        network=copy.deepcopy(host.api.network)
        start=len(host.api.writes)
        host.run_cd()
        writes=host.api.writes[start:]
        self.assertEqual(len(writes),2)  # Guest admin and bridge use.
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
        self.assertEqual(len(writes), 3)  # Guest admin and bridge/tag use.
        self.assertTrue(all(path == '/access/acl' and method == 'PUT' for path, method, _ in writes))
        self.assertEqual(result['service_discovery']['new_acl_rows'],0)
        self.assertEqual(host.api.network, network); self.assertEqual(host.api.rules, firewall)
        self.assertEqual((host.root / 'service-discovery/token.json').read_bytes(), token)
        self.assertEqual(len(host.api.tokens), 1)
        self.assertEqual((host.root/'service-discovery/owner.json').read_bytes(),previous)
        self.assertFalse((host.root/'service-discovery/scope-extensions').exists())
        written = copy.deepcopy(host.api.writes)
        host.run_cd()
        self.assertEqual(host.api.writes, written)

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
