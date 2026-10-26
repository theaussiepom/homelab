"""One reviewed site definition must drive every related deployment input."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import site_config as site
import foundation_dns as dns
import render


class SiteConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.cfg = site.read(site.ROOT / 'examples/foundation.site.example.json')

    def test_generated_profiles_use_existing_compose_renderer_and_private_secret_files(self):
        files = site.render(self.cfg)
        for kind in site.KINDS:
            with self.subTest(kind=kind):
                stack = files[kind + '/stack.json']
                self.assertEqual(stack['kind'], kind)
                compose = render.compose(stack)
                self.assertTrue(compose['services'])
                self.assertNotIn('${', json.dumps(files[kind + '/site.json']))
                self.assertNotIn('$ref', json.dumps(files[kind + '/site.json']))
                self.assertTrue(all(path.startswith('/var/lib/homelab-inputs/foundation-')
                                    for path in stack['foundation']['secret_files'].values()))

    def test_new_host_address_reaches_bootstrap_api_profile_and_firewall(self):
        self.cfg['host']['address'] = '10.88.25.12'
        files = site.render(self.cfg)
        self.assertEqual(files['bootstrap.json']['endpoint'], 'https://10.88.25.12:8006/')
        self.assertEqual(files['ingress/stack.json']['foundation']['proxmox_url'], 'https://10.88.25.12:8006')
        for kind in site.KINDS:
            self.assertEqual(files[kind + '/site.json']['site']['api_endpoint'], files['bootstrap.json']['endpoint'])
        rule = next(row for row in files['ingress/site.json']['guest']['rules'] if row['port'] == '8006')
        self.assertEqual(rule['destination'], '10.88.25.12/32')
        self.assertEqual(files['dns-settings.json']['site']['api_endpoint'], files['bootstrap.json']['endpoint'])

    def test_guest_id_and_route_changes_propagate_without_new_literal_code(self):
        self.cfg['guests']['ingress']['vmid'] = 312
        self.cfg['domains']['identity'] = 'login.lab.example.org'
        files = site.render(self.cfg)
        self.assertEqual(files['bootstrap.json']['service_discovery']['vmid'], 312)
        self.assertIn(312, files['bootstrap.json']['service_discovery']['guests'])
        self.assertEqual(files['rollout.json']['targets']['ingress']['vmid'], 312)
        self.assertEqual(files['ingress/stack.json']['foundation']['proxmox_token_id'], 'root@pam!homelab-traefik-312')
        self.assertEqual(files['identity/site.json']['app']['discovery_routes'][0]['host'], 'login.lab.example.org')
        self.assertEqual(files['db-tools/stack.json']['foundation']['identity_url'], 'https://login.lab.example.org')
        self.assertIn('_acme-challenge.login.lab.example.org', files['dns-settings.json']['acme_exceptions'])

    def test_object_key_order_cannot_move_the_management_interface_or_bootstrap_targets(self):
        before = site.render(self.cfg)
        for guest in self.cfg['guests'].values():
            guest['interfaces'] = dict(reversed(list(guest['interfaces'].items())))
        self.cfg['databases'] = dict(reversed(list(self.cfg['databases'].items())))
        self.cfg['guests'] = dict(reversed(list(self.cfg['guests'].items())))
        self.assertEqual(site.render(self.cfg), before)

    def test_unknown_fields_wrong_types_collisions_and_out_of_network_addresses_stop_render(self):
        mutations = [lambda c: c.update(unknown=True),
                     lambda c: c['host'].update(address='8.8.8.8'),
                     lambda c: c['networks']['backend'].update(cidr=c['networks']['management']['cidr']),
                     lambda c: c['networks']['management'].update(vlan=True),
                     lambda c: c['guests']['identity'].update(vmid=4914),
                     lambda c: c['guests']['identity'].update(vmid=c['guests']['ingress']['vmid']),
                     lambda c: c['guests']['identity']['interfaces']['management'].update(address=c['runner']['address']),
                     lambda c: c['guests']['identity']['interfaces']['backend'].update(address='10.88.25.99'),
                     lambda c: c['domains'].update(identity='bad;command'),
                     lambda c: c['domains'].update(identity='login.other.example.org')]
        for mutation in mutations:
            cfg = copy.deepcopy(self.cfg); mutation(cfg)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): site.render(cfg)

    def test_config_cannot_select_arbitrary_template_code_or_file_reads(self):
        cfg = copy.deepcopy(self.cfg); cfg['guests']['ingress']['template_path'] = '/etc/passwd'
        with self.assertRaises(ValueError): site.render(cfg)
        cfg = copy.deepcopy(self.cfg); cfg['ssh_public_keys'] = [{'$ref':'host.address'}]
        with self.assertRaises(ValueError): site.render(cfg)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'site.json'; path.write_text('{"schema":"first","schema":"second"}')
            with self.assertRaisesRegex(ValueError, 'Duplicate'): site.read(path)

    def test_output_is_new_private_data_and_never_overwrites_an_existing_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'bundle'; site.write_bundle(self.cfg, output)
            before = {path: path.read_bytes() for path in output.rglob('*.json')}
            # Sorted JSON object keys must not reorder or invalidate ACME admission.
            dns.configure(json.loads((output / 'dns-settings.json').read_text()))
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in before))
            with self.assertRaises(FileExistsError): site.write_bundle(self.cfg, output)
            self.assertEqual({path: path.read_bytes() for path in before}, before)

    def test_dns_settings_are_closed_and_data_is_copied_before_remote_execution(self):
        settings = site.render(self.cfg)['dns-settings.json']
        dns.configure(settings)
        expected = copy.deepcopy(dns.SETTINGS)
        settings['records'].clear()
        self.assertEqual(dns.SETTINGS, expected)
        for field, value in [('unknown', True), ('target', {'vmid': 4914}), ('acme_exceptions', ['_acme-challenge.other.example.org'])]:
            bad = copy.deepcopy(expected); bad[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): dns.configure(bad)
        dns.configure(expected)
