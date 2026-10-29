"""Routing previews cannot admit a guest or conceal the unfinished cutover inputs."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import automation_routes as automation
import site_config


class AutomationRoutes(unittest.TestCase):
    def setUp(self):
        self.base = site_config.read(site_config.ROOT / 'examples/foundation.site.example.json')
        self.cfg = site_config.read(site_config.ROOT / 'examples/automation.routes.example.json')

    def test_one_address_drives_both_routes_and_proxy_destinations(self):
        self.cfg['backend_address'] = '10.88.30.41'
        value = automation.preview(self.base, self.cfg)
        self.assertFalse(value['deployable'])
        self.assertEqual([row['url'] for row in value['automation_discovery_routes']],
                         ['http://10.88.30.41:8123', 'http://10.88.30.41:1880'])
        self.assertEqual({row['destination'] for row in value['ingress_additional_rules']}, {'10.88.30.41/32'})
        self.assertEqual(value['discovery_guest_ids'], [200, 202, 211, 212])
        self.assertTrue(value['remaining_inputs'])
        self.assertNotIn('secret', json.dumps(value))

    def test_existing_identity_and_proxy_settings_drive_the_optional_wiring(self):
        self.base['guests']['identity']['interfaces']['backend']['address'] = '10.88.30.40'
        self.base['guests']['ingress']['interfaces']['frontend']['address'] = '10.88.40.41'
        self.base['domains']['identity'] = 'login.lab.example.org'
        before = copy.deepcopy(self.base)
        value = automation.preview(self.base, self.cfg)
        self.assertEqual(self.base, before)
        self.assertEqual(value['ingress_foundation_settings'], {'authentik_url':'http://10.88.30.40:9000'})
        self.assertEqual(value['identity_additional_discovery_route']['url'], 'http://10.88.30.40:9000')
        self.assertEqual(set(value['dns_records'].values()), {'10.88.40.41'})
        self.assertEqual(value['existing_authentik_settings_to_reconcile']['embedded_outpost_authentik_host'],
                         'https://login.lab.example.org/')

    def test_preserved_dns_names_cannot_become_automation_records(self):
        for key in ('homeassistant_host', 'node_red_host'):
            base = copy.deepcopy(self.base)
            base['domains']['preserve'][0]['name'] = self.cfg[key]
            # A retained name inside a redirect zone is a valid foundation input.
            site_config.validate(base)
            with self.subTest(host=key), self.assertRaises(ValueError):
                automation.preview(base, self.cfg)

    def test_collisions_unknown_fields_and_wrong_networks_are_refused(self):
        for key, value in [('vmid', 900), ('vmid', 208), ('vmid', True), ('backend_address', '10.88.25.21'),
                           ('backend_address', '10.88.30.20'), ('backend_address','10.88.30.0'),
                           ('node_red_host',self.cfg['homeassistant_host']), ('node_red_host','flows.other.org'),
                           ('node_red_host', 'sso.lab.example.org'), ('arbitrary_path','/etc/passwd')]:
            cfg = copy.deepcopy(self.cfg); cfg[key] = value
            with self.subTest(key=key,value=value), self.assertRaises(ValueError): automation.preview(self.base, cfg)
