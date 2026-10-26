"""Synthetic ingress contracts: login ownership, aliases and TLS selection."""
import copy
import unittest

from test_render import fixture, render


def ingress_fixture():
    cfg = fixture('ingress')
    for name, prefix in [('homeassistant', 'ha'), ('node_red', 'flows'), ('identity', 'auth')]:
        del cfg[f'{name}_host']
        cfg[f'{name}_hosts'] = [f'{prefix}.example.invalid', f'{prefix}.alias.invalid']
    cfg.update(pgadmin_hosts=['pgadmin.example.invalid', 'pgadmin.alias.invalid'],
               pgadmin_url='http://198.18.30.32:80',
               pgadmin_middlewares=['chain-lan-unsafe@file'],
               ingress_entrypoint='https', ingress_cert_resolver='cloudflare')
    return cfg


class IngressTests(unittest.TestCase):
    def test_existing_single_host_inputs_keep_their_defaults(self):
        http = render.ingress(fixture('ingress'))['http']
        self.assertNotIn('pgadmin', http['routers'])
        for router in http['routers'].values():
            self.assertEqual(router['entryPoints'], ['websecure'])
            self.assertEqual(router['tls'], {})

    def test_aliases_keep_host_headers_and_certificate_resolver(self):
        cfg = ingress_fixture()
        http = render.ingress(cfg)['http']
        for name in ('homeassistant', 'node_red', 'identity', 'pgadmin'):
            router = http['routers'][name]
            hosts = cfg[f'{name}_hosts']
            self.assertEqual(router['rule'], '(' + ' || '.join(f'Host(`{h}`)' for h in hosts) + ')')
            self.assertEqual(router['entryPoints'], ['https'])
            self.assertEqual(router['tls'], {'certResolver': 'cloudflare'})
            self.assertEqual(http['services'][name]['loadBalancer'], {
                'servers': [{'url': cfg[f'{name}_url']}], 'passHostHeader': True})

    def test_native_logins_and_issuer_do_not_get_forward_auth(self):
        http = render.ingress(ingress_fixture())['http']
        for name in ('homeassistant', 'identity', 'outpost'):
            self.assertNotIn('middlewares', http['routers'][name])
        self.assertEqual(http['routers']['pgadmin']['middlewares'], ['chain-lan-unsafe@file'])
        self.assertEqual(http['routers']['node_red']['middlewares'], ['authentik'])
        self.assertEqual(http['middlewares']['authentik']['forwardAuth']['address'],
                         'http://198.18.30.20:9000/outpost.goauthentik.io/auth/traefik')

    def test_outpost_matches_both_hosts_and_always_outranks_node_red(self):
        cfg = ingress_fixture()
        # Default Traefik rule-length priority would outrank the old fixed 100.
        cfg['node_red_hosts'] = ['flows.' + 'x' * 50 + '.example.invalid',
                                 'flows.' + 'y' * 50 + '.alias.invalid']
        routers = render.ingress(cfg)['http']['routers']
        self.assertEqual(routers['outpost']['rule'], routers['node_red']['rule'] +
                         ' && PathPrefix(`/outpost.goauthentik.io/`)')
        self.assertGreater(routers['outpost']['priority'], routers['node_red']['priority'])
        self.assertEqual(routers['outpost']['service'], 'identity')
        self.assertEqual(routers['outpost']['tls'], routers['node_red']['tls'])

    def test_pgadmin_is_optional_but_partial_inputs_are_refused(self):
        cfg = fixture('ingress')
        cfg.update(pgadmin_host='pgadmin.example.invalid', pgadmin_url='http://198.18.30.32')
        self.assertNotIn('middlewares', render.ingress(cfg)['http']['routers']['pgadmin'])
        for key in ('pgadmin_host', 'pgadmin_url'):
            bad = copy.deepcopy(cfg); del bad[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                render.ingress(bad)
        bad = fixture('ingress'); bad['pgadmin_middlewares'] = ['chain-lan-unsafe@file']
        with self.assertRaises(ValueError):
            render.ingress(bad)

    def test_host_rules_reject_ambiguity_collisions_and_injection(self):
        for hosts in ([], 'ha.example.invalid', [123], ['bad`host'], ['*.example.invalid'],
                      ['ha..example.invalid'], ['-ha.example.invalid'],
                      ['ha.example.invalid', 'ha.example.invalid'], ['a' * 64 + '.invalid']):
            cfg = ingress_fixture(); cfg['homeassistant_hosts'] = hosts
            with self.subTest(hosts=hosts), self.assertRaises(ValueError):
                render.ingress(cfg)
        cfg = ingress_fixture(); cfg['homeassistant_host'] = 'other.example.invalid'
        with self.assertRaises(ValueError): render.ingress(cfg)
        cfg = ingress_fixture(); cfg['identity_hosts'] = cfg['node_red_hosts']
        with self.assertRaises(ValueError): render.ingress(cfg)

    def test_backends_are_origin_urls_without_credentials_or_paths(self):
        for url in ('http://user:password@backend.invalid', 'http://backend.invalid/path',
                    'http://backend.invalid?secret=value', 'http://backend.invalid#fragment',
                    'http://backend.invalid:bad', 'http://backend.invalid:70000',
                    'http://backend.invalid\\@elsewhere.invalid', 'http://backend.invalid\t',
                    'ftp://backend.invalid'):
            cfg = ingress_fixture(); cfg['pgadmin_url'] = url
            with self.subTest(url=url), self.assertRaises(ValueError):
                render.ingress(cfg)

    def test_route_settings_are_literal_and_pgadmin_does_not_gain_forward_auth(self):
        for key, value in [('ingress_entrypoint', ''), ('ingress_entrypoint', ['https']),
                           ('ingress_cert_resolver', 'bad@file'),
                           ('pgadmin_middlewares', 'chain-lan-unsafe@file'),
                           ('pgadmin_middlewares', [123]), ('pgadmin_middlewares', ['bad\nname']),
                           ('pgadmin_middlewares', ['authentik']),
                           ('pgadmin_middlewares', ['authentik@file'])]:
            cfg = ingress_fixture(); cfg[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                render.ingress(cfg)


if __name__ == '__main__':
    unittest.main()
