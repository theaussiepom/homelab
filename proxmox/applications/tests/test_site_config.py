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

    def test_dns_and_generated_acme_names_respect_the_full_wire_name_limit(self):
        def long_name(length):
            suffix = 'lab.example.org'
            remaining = length - len(suffix) - 1
            labels = []
            while remaining > 63:
                labels.append('a' * 63); remaining -= 64
            labels.append('b' * remaining)
            return '.'.join([*labels, suffix])
        for length in (238, 239, 253, 254):
            cfg = copy.deepcopy(self.cfg)
            cfg['domains']['identity'] = long_name(length)
            with self.subTest(route_length=length), self.assertRaises(ValueError): site.render(cfg)
        cfg = copy.deepcopy(self.cfg); cfg['domains']['identity'] = long_name(237)
        files = site.render(cfg)
        dns.configure(files['dns-settings.json'])
        self.assertEqual(len(files['dns-settings.json']['acme_exceptions'][0]), 253)
        # Preserved zones do not have generated children, so the ordinary253 limit applies.
        cfg = copy.deepcopy(self.cfg); cfg['domains']['preserve'][0]['name'] = long_name(253)
        dns.configure(site.render(cfg)['dns-settings.json'])
        cfg['domains']['preserve'][0]['name'] = long_name(254)
        with self.assertRaises(ValueError): site.render(cfg)
        settings = site.render(self.cfg)['dns-settings.json']
        previous = next(iter(settings['records']))
        settings['records'][long_name(239)] = settings['records'].pop(previous)
        settings['acme_exceptions'] = ['_acme-challenge.' + name for name in settings['records']]
        with self.assertRaises(ValueError): dns.configure(settings)

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

    def test_frontend_policy_does_not_add_a_second_proxmox_default_gateway(self):
        files = site.render(self.cfg)
        cfg = files['ingress/site.json']
        self.assertEqual(cfg['app']['frontend_routing'], {'address':'10.88.40.33/24', 'gateway':'10.88.40.1',
                         'mac':self.cfg['guests']['ingress']['interfaces']['frontend']['mac']})
        self.assertEqual([nic['gateway'] for nic in cfg['guest']['interfaces'] if 'gateway' in nic], ['10.88.25.1'])
        self.cfg['guests']['ingress']['interfaces']['frontend']['address'] = '10.88.40.34'
        self.assertEqual(site.render(self.cfg)['ingress/site.json']['app']['frontend_routing']['address'], '10.88.40.34/24')
        import deploy
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'stack.json'; path.write_text(json.dumps(files['ingress/stack.json']))
            cfg['app']['stack_config'] = str(path)
            self.assertEqual(deploy.validate(cfg), cfg['guest']['vmid'])
            original = cfg['app'].pop('frontend_routing')
            with self.assertRaisesRegex(ValueError, 'Multihomed ingress'): deploy.validate(cfg)
            cfg['app']['frontend_routing'] = dict(original, mac='02:00:00:00:00:99')
            with self.assertRaisesRegex(ValueError, 'exact selected guest interface'): deploy.validate(cfg)

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
