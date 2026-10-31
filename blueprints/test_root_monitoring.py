"""A root marker expands inventory; it never contacts a target or reads a key."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import zabbix
import connections


def composition():
    result = {}
    addresses = {'ingress': 33, 'postgresql': 23, 'mariadb': 24,
                 'influxdb': 26, 'monitoring': 36, 'automation': 21}
    for i, (name, suffix) in enumerate(addresses.items(), 200):
        interfaces = [{'ipv4': f'198.18.25.{suffix}/24', 'gateway': '198.18.25.1'}]
        if name in {'postgresql', 'monitoring'}:
            interfaces.append({'ipv4': f'198.18.31.{suffix}/24'})
        if name in {'influxdb', 'monitoring'}:
            interfaces.append({'ipv4': f'198.18.33.{suffix}/24'})
        cfg = {'site': {'node': 'fixture-pve', 'api_endpoint': 'https://198.18.25.10:8006/'},
               'paths': {'ca_file': '/private/pve-ca'},
               'guest': {'vmid': i, 'hostname': name, 'interfaces': interfaces, 'rules': []},
               'app': {'address': f'198.18.25.{suffix}', 'kind': name},
               'deployment': {'capabilities': ['linux'] if name in {'postgresql', 'mariadb', 'influxdb'} else ['linux', 'docker']}}
        result[name] = (cfg, {'monitoring': {'bind_address': '198.18.25.36'}} if name == 'monitoring' else None,
                        {'pg_hba.conf': 'local all postgres peer\n'} if name == 'postgresql' else {})
    return result


VALUES = {'addresses.postgresql_backend': '198.18.31.23',
          'addresses.mariadb_backend': '198.18.32.24',
          'addresses.influxdb_backend': '198.18.33.26'}


class ZabbixTests(unittest.TestCase):
    def test_presence_selects_defaults_without_a_boolean_or_guest_property(self):
        self.assertFalse(zabbix.enabled({}))
        self.assertTrue(zabbix.enabled({'zabbix': None}))
        for bad in [True, False, {}, [], '', 0]:
            with self.subTest(value=bad), self.assertRaises(ValueError):
                zabbix.enabled({'zabbix': bad})
        spec = {'guests': {'dns': {}, 'monitoring': {}}}
        self.assertEqual(zabbix.selected(spec, {})['guests'], {'dns': {}})
        self.assertEqual(zabbix.selected(spec, {'zabbix': None}), spec)
        self.assertIn('monitoring', spec['guests'])
        with self.assertRaises(ValueError):
            zabbix.selected({'guests': {}}, {'zabbix': None})

    def test_profiles_and_exact_network_edges_are_inventory_derived(self):
        resolved = composition()
        zabbix.bind(resolved, list(resolved), VALUES)
        server = resolved['monitoring'][0]
        members = {m['guest']: m for m in server['app']['monitoring']['members']}
        self.assertEqual(members['postgresql']['profiles'], ['linux', 'postgresql'])
        self.assertEqual(members['mariadb']['profiles'], ['linux', 'mysql'])
        self.assertEqual(members['automation']['profiles'], ['linux', 'docker'])
        self.assertEqual(members['influxdb']['url'], 'http://198.18.33.26:8086')
        self.assertEqual(len({m['psk_identity'] for m in members.values()}), len(members))
        hba = resolved['postgresql'][2]['pg_hba.conf']
        self.assertEqual(hba, 'local all postgres peer\nhost zabbix zabbix 198.18.31.36/32 scram-sha-256\n')
        cfgs = {k: v[0] for k, v in resolved.items()}
        for edge in zabbix.connections_for(cfgs):
            self.assertTrue(connections.permits(cfgs[edge.source]['guest']['rules'], 'out', edge))
            self.assertTrue(connections.permits(cfgs[edge.target]['guest']['rules'], 'in', edge))
        self.assertNotIn('secret', json.dumps(members).lower())
        self.assertEqual(list(zabbix.connections_for({})), [])

    def test_disabled_execution_does_not_remove_profiles_from_configured_guests(self):
        resolved = composition()
        zabbix.bind(resolved, ['monitoring', 'postgresql'], VALUES)
        members = resolved['monitoring'][0]['app']['monitoring']['members']
        self.assertEqual({m['guest'] for m in members}, {'monitoring', 'postgresql'})
        self.assertEqual(resolved['automation'][0]['app']['monitoring']['profiles'], ['linux', 'docker'])

    def test_forged_agent_settings_listener_and_duplicate_identities_refuse(self):
        for fault in ['settings', 'listener', 'identity']:
            resolved = composition()
            if fault == 'settings':
                resolved['automation'][0]['app']['monitoring'] = {}
            elif fault == 'listener':
                resolved['monitoring'][1]['monitoring']['bind_address'] = '198.18.25.99'
            else:
                resolved['automation'][0]['guest']['vmid'] = resolved['monitoring'][0]['guest']['vmid']
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                zabbix.bind(resolved, list(resolved), VALUES)

    def test_optional_workload_is_not_synthesized_into_a_reduced_inventory(self):
        resolved=composition();resolved.pop('mariadb')
        zabbix.bind(resolved,list(resolved),VALUES)
        members=resolved['monitoring'][0]['app']['monitoring']['members']
        self.assertNotIn('mysql',[p for m in members for p in m['profiles']])
