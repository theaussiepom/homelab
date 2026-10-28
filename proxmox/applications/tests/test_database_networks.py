"""Database network contracts must produce finite, isolated guest connections."""
import copy
import ipaddress
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import database_networks as networks
import site_config


def contract():
    return json.loads((networks.ROOT / 'examples/database-networks.example.json').read_text())


class DatabaseNetworksTests(unittest.TestCase):
    def test_connections_use_one_contract_and_never_add_gateway_or_vlan(self):
        value = contract()
        networks.validate(value)
        for engine, net in value['networks'].items():
            for guest in [net['server'], *net['clients']]:
                nic = networks.interface(value, engine, guest['vmid'])
                self.assertEqual(nic, {'bridge': net['bridge'], 'vlan': None,
                    'ipv4': guest['address'] + '/24', 'mac': guest['mac'], 'ipv6': 'manual'})
                self.assertNotIn('gateway', nic)
            self.assertEqual(networks.endpoint(value, engine),
                             {'address': net['server']['address'], 'port': networks.PORTS[engine]})

    def test_unlisted_guest_and_unknown_engine_do_not_get_access(self):
        for engine, vmid in [('mariadb', 900), ('mariadb', 212), ('redis', 200)]:
            with self.subTest(engine=engine, vmid=vmid), self.assertRaises(ValueError):
                networks.interface(contract(), engine, vmid)

    def test_rules_authorise_exact_members_and_server_not_a_whole_subnet(self):
        value = contract(); net = value['networks']['mariadb']
        incoming = networks.rules(value, 'mariadb', net['server']['vmid'])
        self.assertEqual({row['source'] for row in incoming}, {g['address'] + '/32' for g in net['clients']})
        for client in net['clients']:
            outgoing = networks.rules(value, 'mariadb', client['vmid'])
            self.assertEqual(len(outgoing), 1)
            self.assertEqual(outgoing[0]['destination'], net['server']['address'] + '/32')
            self.assertEqual(outgoing[0]['source'], client['address'] + '/32')

    def test_bridge_purpose_is_part_of_the_closed_contract(self):
        value = contract()
        selected = networks.bridges(value)
        self.assertEqual({b['name'] for b in selected}, {'vmbr31', 'vmbr32', 'vmbr33'})
        self.assertTrue(all('no physical uplink' in b['description'] for b in selected))

    def test_unsafe_or_ambiguous_contracts_are_refused(self):
        mutations = [
            lambda c: c.update(enabled=True),
            lambda c: c['networks']['mariadb'].update(gateway='10.88.32.1'),
            lambda c: c['networks']['mariadb'].update(bridge='vmbr0'),
            lambda c: c['networks']['mariadb'].update(cidr='0.0.0.0/24'),
            lambda c: c['networks']['mariadb'].update(cidr='10.88.31.0/24'),
            lambda c: c['networks']['mariadb']['clients'][0].update(address='10.88.32.0'),
            lambda c: c['networks']['mariadb']['clients'][0].update(address='10.88.32.255'),
            lambda c: c['networks']['mariadb']['clients'][0].update(vmid=900),
            lambda c: c['networks']['mariadb']['clients'][0].update(mac=c['networks']['mariadb']['server']['mac']),
            lambda c: c['networks']['mariadb']['clients'].append(copy.deepcopy(c['networks']['mariadb']['clients'][0])),
            lambda c: c['networks']['mariadb'].update(description='bad\ncomment'),
        ]
        for mutate in mutations:
            value = contract(); mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): networks.validate(value)

    def test_guest_overlay_appends_nics_and_preserves_management_and_application_network(self):
        value = contract(); old = [{'bridge': 'vmbr0', 'vlan': 25, 'mac': '02:25:00:00:02:00',
                'ipv4': '10.88.25.21/24', 'ipv6': 'manual', 'gateway': '10.88.25.1'},
            {'bridge': 'vmbr30', 'vlan': None, 'mac': '02:30:00:00:02:00',
             'ipv4': '10.88.30.21/24', 'ipv6': 'manual'}]
        guest = {'vmid': 200, 'hostname': 'automation', 'interfaces': old, 'rules': []}
        updated = networks.attach(guest, value, ['mariadb', 'influxdb'])
        self.assertEqual(updated['interfaces'][:2], old)
        self.assertEqual(len(updated['interfaces']), 4)
        self.assertEqual(guest['interfaces'], old)
        self.assertEqual(networks.attach(updated, value, ['mariadb', 'influxdb']), updated)
        updated['interfaces'][-1]['mac'] = '02:01:02:03:04:05'
        with self.assertRaises(ValueError): networks.attach(updated, value, ['influxdb'])

    def test_database_catalogue_cannot_overlap_existing_site_networks(self):
        value = contract()
        with self.assertRaises(ValueError): networks.validate(value, ['10.88.31.0/24'])

    def test_network_and_member_addresses_require_strings_before_ip_parsing(self):
        address = ipaddress.IPv4Address('10.88.31.23')
        for item in (int(address), address.packed, None, True):
            value = contract(); value['networks']['postgresql']['server']['address'] = item
            with self.subTest(field='address', value=item), self.assertRaises(ValueError): networks.validate(value)
        for item in (int(ipaddress.IPv4Address('10.88.31.0')), ('10.88.31.0', 24), None):
            value = contract(); value['networks']['postgresql']['cidr'] = item
            with self.subTest(field='cidr', value=item), self.assertRaises(ValueError): networks.validate(value)

    def test_database_bridge_cannot_reuse_a_site_bridge_with_a_different_subnet(self):
        site = site_config.read(networks.ROOT / 'examples/foundation.site.example.json')
        value = contract()
        for engine, net in value['networks'].items():
            net['server']['vmid'] = site['databases'][engine]['vmid']
        for name in site['networks']:
            selected = copy.deepcopy(site)
            selected['networks'][name]['bridge'] = value['networks']['postgresql']['bridge']
            with self.subTest(network=name), self.assertRaises(ValueError): site_config.render(selected, value)

    def test_foundation_extension_changes_only_bootstrap_not_commissioned_app_profiles(self):
        site = site_config.read(networks.ROOT / 'examples/foundation.site.example.json')
        value = contract()
        # Example guest identities are site data, not reusable behavior.
        for engine, net in value['networks'].items():
            net['server']['vmid'] = site['databases'][engine]['vmid']
        original = site_config.render(site)
        rendered = site_config.render(site, value)
        for name in original:
            if name != 'bootstrap.json': self.assertEqual(rendered[name], original[name])
        extension = rendered['bootstrap.json'].pop('private_bridges')
        self.assertEqual(rendered, original)
        self.assertEqual(extension, networks.bridges(value))
        value['networks']['postgresql']['server']['vmid'] = 999
        with self.assertRaises(ValueError): site_config.render(site, value)


if __name__ == '__main__':
    unittest.main()
