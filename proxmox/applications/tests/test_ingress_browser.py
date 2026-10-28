"""The browser proxy is an explicit Influx/SSO route, never raw dynamic YAML."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ingress_browser as browser


def settings():
    return {'schema': 'homelab-influx-browser-v1', 'host': 'influx.example.invalid',
            'backend': 'http://10.88.33.26:8086', 'authentik': 'http://10.88.30.20:9000',
            'issuer': 'https://sso.example.invalid', 'proxy_address': '10.88.33.33',
            'frontend_address': '10.88.40.33',
            'source_cidrs': ['10.88.15.0/24'], 'header_domain': 'example.invalid'}


class BrowserTests(unittest.TestCase):
    def test_route_keeps_outer_gates_and_native_authorization(self):
        http = browser.objects(settings())['http']
        main, callback = http['routers']['influx-browser'], http['routers']['influx-outpost']
        self.assertEqual(main['rule'], 'Host(`influx.example.invalid`)')
        self.assertEqual(main['middlewares'], ['influx-local', 'influx-authentik', 'influx-security'])
        self.assertEqual(callback['middlewares'], ['influx-local', 'influx-security'])
        self.assertGreater(callback['priority'], main['priority'])
        for route in (main, callback):
            self.assertEqual(route['entryPoints'], ['websecure'])
            self.assertEqual(route['tls'], {'certResolver': 'letsencrypt'})
        self.assertEqual(http['services']['influx-private']['loadBalancer'],
                         {'servers': [{'url': 'http://10.88.33.26:8086'}], 'passHostHeader': True})
        auth = http['middlewares']['influx-authentik']['forwardAuth']
        self.assertEqual(auth['address'], 'http://10.88.30.20:9000/outpost.goauthentik.io/auth/traefik')
        self.assertNotIn('Authorization', auth['authResponseHeaders'])
        self.assertEqual(http['middlewares']['influx-local'],
                         {'ipAllowList': {'sourceRange': ['10.88.15.0/24']}})
        headers = http['middlewares']['influx-security']['headers']
        self.assertTrue(headers['contentTypeNosniff'])
        self.assertEqual(headers['stsSeconds'], 63072000)
        self.assertIn("'unsafe-eval'", headers['contentSecurityPolicy'])

    def test_merge_preserves_every_unrelated_definition_without_mutating_input(self):
        original = {'tls': {'options': {'default': {'minVersion': 'VersionTLS12'}}},
                    'http': {'routers': {'other': {'rule': 'Host(`other.example.invalid`)'}},
                             'middlewares': {'security-headers': {'headers': {'contentTypeNosniff': True}}}},
                    'tcp': {'services': {'unrelated': {'loadBalancer': {'servers': []}}}}}
        before = copy.deepcopy(original)
        updated = browser.merge(original, settings())
        self.assertEqual(original, before)
        for section, values in before.items():
            if section != 'http': self.assertEqual(updated[section], values)
        self.assertEqual(updated['http']['routers']['other'], before['http']['routers']['other'])
        self.assertEqual(updated['http']['middlewares']['security-headers'],
                         before['http']['middlewares']['security-headers'])
        with self.assertRaises(ValueError): browser.merge(updated, settings())

    def test_colliding_hostname_or_reserved_object_is_a_hold(self):
        for original in ({'http': {'routers': {'existing': {'rule': 'Host(`influx.example.invalid`)'}}}},
                         {'http': {'routers': {'wildcard': {'rule': 'HostRegexp(`.*`)'}}}},
                         {'tcp': {'routers': {'wildcard': {'rule': 'HostSNI(`*`)', 'entryPoints': ['websecure']}}}},
                         {'http': {'services': {'influx-private': {}}}},
                         {'http': {'middlewares': {'influx-local': {}}}}):
            with self.subTest(original=original), self.assertRaises(ValueError):
                browser.merge(original, settings())

    def test_rejects_widening_injection_credentials_and_nonprivate_endpoints(self):
        for key, bad in [('host', '*.example.invalid'), ('host', 'influx`) || Host(`evil'),
                         ('backend', 'http://10.88.33.26:9000'), ('backend', 'http://user:pass@10.88.33.26:8086'),
                         ('backend', 'http://10.88.33.26:8086/prefix'), ('backend', 'http://8.8.8.8:8086'),
                         ('authentik', 'https://10.88.30.20:9000'), ('issuer', 'http://sso.example.invalid'),
                         ('source_cidrs', ['0.0.0.0/0']), ('source_cidrs', ['10.88.15.1/24']),
                         ('source_cidrs', []), ('source_cidrs', ['10.88.15.0/24'] * 2),
                         ('proxy_address', '10.88.30.33')]:
            value = settings(); value[key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(ValueError): browser.validate(value)
        value = settings(); value['middlewares'] = ['bypass']
        with self.assertRaises(ValueError): browser.validate(value)

    def test_optional_fresh_render_retains_the_same_route_objects(self):
        from test_foundation import fixture
        import foundation
        with tempfile.TemporaryDirectory() as temp:
            cfg = fixture(temp, 'ingress')
            cfg['foundation']['browser_route'] = settings()
            artifacts = {a['path']: a['content'] for a in foundation.files(cfg)}
            expected = browser.objects(settings())['http']
            shared = json.loads(artifacts['shared.yml'])
            for section, objects in expected.items():
                for name, value in objects.items(): self.assertEqual(shared['http'][section][name], value)


if __name__ == '__main__': unittest.main()
