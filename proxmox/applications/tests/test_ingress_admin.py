"""Offline administration routes must preserve the commissioned document."""
import copy
import json
import stat
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ingress_admin


def settings():
    return {'schema': 'homelab-ingress-admin-routes-v1',
            'client_networks': ['10.15.0.0/24'],
            'routes': [
                {'name': 'pve', 'host': 'host.example.invalid',
                 'url': 'https://10.25.0.10:8006', 'server_name': 'pve.example.invalid',
                 'root_cas': ['/etc/ssl/certs/homelab-pve.pem']},
                {'name': 'nas', 'host': 'nas.example.invalid',
                 'url': 'https://10.25.0.2:31764', 'server_name': 'nas.example.invalid',
                 'root_cas': []}]}


class AdminRoutes(unittest.TestCase):
    def test_merge_preserves_every_existing_value_and_input(self):
        base = {'tls': {'options': {'default': {'minVersion': 'VersionTLS12'}}},
                'http': {'middlewares': {'security-headers': {'headers': {'contentTypeNosniff': True}}},
                         'routers': {'other': {'rule': 'Host(`other.example.invalid`)'}}}}
        before = copy.deepcopy(base)
        result = ingress_admin.merge(base, settings())
        self.assertEqual(base, before)
        self.assertEqual(result['tls'], base['tls'])
        self.assertEqual(result['http']['routers']['other'], base['http']['routers']['other'])
        self.assertEqual(result['http']['middlewares']['security-headers'],
                         base['http']['middlewares']['security-headers'])
        http = result['http']
        self.assertEqual(http['routers']['admin-pve'], {
            'rule': 'Host(`host.example.invalid`)', 'entryPoints': ['websecure'],
            'tls': {'certResolver': 'letsencrypt'}, 'service': 'admin-pve',
            'middlewares': ['admin-clients']})
        self.assertEqual(http['middlewares']['admin-clients'], {
            'ipAllowList': {'sourceRange': ['10.15.0.0/24']}})
        self.assertEqual(http['services']['admin-pve']['loadBalancer'], {
            'servers': [{'url': 'https://10.25.0.10:8006'}],
            'passHostHeader': True, 'serversTransport': 'admin-pve'})
        self.assertEqual(http['serversTransports']['admin-pve'], {
            'serverName': 'pve.example.invalid', 'insecureSkipVerify': False,
            'rootCAs': ['/etc/ssl/certs/homelab-pve.pem']})
        self.assertNotIn('forwardAuth', json.dumps(result))

    def test_unknown_options_and_unsafe_targets_fail_closed(self):
        for value in ('http://10.25.0.2:80', 'https://user@10.25.0.2:443',
                      'https://8.8.8.8:443', 'https://10.25.0.2',
                      'https://10.25.0.2:443/path', 'https://10.25.0.2:443?x=1'):
            cfg = settings(); cfg['routes'][0]['url'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                ingress_admin.merge({}, cfg)
        cfg = settings(); cfg['routes'][0]['insecureSkipVerify'] = True
        with self.assertRaises(ValueError): ingress_admin.merge({}, cfg)
        for key, value in [('server_name', None), ('host', '*.example.invalid'),
                           ('root_cas', ['/tmp/../secret']), ('root_cas', ['/run/secrets/key'])]:
            cfg = settings(); cfg['routes'][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): ingress_admin.merge({}, cfg)

    def test_client_ranges_are_explicit_canonical_and_private(self):
        for ranges in (None, [], ['0.0.0.0/0'], ['10.0.0.1/24'], ['::/0'],
                       ['10.0.0.0/8', '10.0.0.0/8'], ['8.8.8.8/32']):
            cfg = settings(); cfg['client_networks'] = ranges
            with self.subTest(ranges=ranges), self.assertRaises(ValueError): ingress_admin.merge({}, cfg)

    def test_collisions_refuse_instead_of_adopting_or_overwriting(self):
        for section, name in [('routers', 'admin-pve'), ('services', 'admin-pve'),
                              ('serversTransports', 'admin-pve'), ('middlewares', 'admin-clients')]:
            with self.subTest(section=section), self.assertRaises(ValueError):
                ingress_admin.merge({'http': {section: {name: {}}}}, settings())
        base = {'http': {'routers': {'existing': {'rule': 'Host(`host.example.invalid`)'}}}}
        with self.assertRaises(ValueError): ingress_admin.merge(base, settings())
        cfg = settings(); cfg['routes'][1]['host'] = cfg['routes'][0]['host']
        with self.assertRaises(ValueError): ingress_admin.merge({}, cfg)

    def test_static_or_malformed_documents_are_not_exported_as_proposals(self):
        for base in ({'providers': {'plugin': {'token': 'synthetic-only'}}},
                     {'http': {'routers': {'broken': []}}}):
            with self.subTest(base=base), self.assertRaises(ValueError):
                ingress_admin.merge(base, settings())

    def test_cli_writes_new_offline_artifacts_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'settings.json').write_text(json.dumps(settings()))
            (root/'shared.json').write_text('{}\n')
            cmd = [sys.executable, str(Path(ingress_admin.__file__)), '--settings', str(root/'settings.json'),
                   '--shared', str(root/'shared.json'), '--output', str(root/'proposal.json')]
            subprocess.run(cmd, check=True, capture_output=True)
            result = json.loads((root/'proposal.json').read_text())
            self.assertFalse(result['deployable'])
            self.assertEqual(stat.S_IMODE((root/'proposal.json').stat().st_mode), 0o600)
            self.assertEqual(len(result['before_sha256']), 64)
            self.assertEqual(len(result['after_sha256']), 64)
            self.assertNotEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
            self.assertEqual((root/'shared.json').read_text(), '{}\n')
