"""Only an Authentik outpost callback may share a protected app hostname."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import discovery as d


def settings():
    return {
        'routes': {'app': {'host': 'app.example.invalid', 'aliases': ['alias.example.invalid'],
                          'url': 'https://198.18.30.21:9443', 'transport': 'app-ca',
                          'middlewares': ['security-headers', 'login', 'management'],
                          'authentik_forward_auth': 'login'}},
        'middlewares': {
            'login': {'forwardAuth': {'address': 'http://198.18.30.20:9000/outpost.goauthentik.io/auth/traefik',
                                      'trustForwardHeader': True, 'authResponseHeaders': ['X-authentik-username']}},
            'management': {'ipAllowList': {'sourceRange': ['198.18.15.0/24', '198.18.25.0/24']}},
        },
        'transports': {'app-ca': {'server_name': 'backend.example.invalid', 'ca_file': '/trust/app.pem'}},
    }


class AuthentikCallbackTests(unittest.TestCase):
    def test_external_callback_is_fixed_higher_priority_https_and_bypasses_only_selected_auth(self):
        value = settings(); before = copy.deepcopy(value); out = d.shared(value)
        self.assertEqual(value, before)
        app = out['http']['routers']['app']; callback = out['http']['routers']['app-authentik-callback']
        self.assertEqual(app['rule'], '(Host(`app.example.invalid`) || Host(`alias.example.invalid`))')
        self.assertEqual(app['priority'], 10)
        self.assertEqual(app['middlewares'], ['security-headers@file', 'login@file', 'management@file'])
        self.assertEqual(callback['rule'], app['rule'] + ' && PathPrefix(`/outpost.goauthentik.io/`)')
        self.assertEqual(callback['priority'], 15)
        self.assertEqual(callback['entryPoints'], ['websecure'])
        self.assertEqual(callback['tls'], {'certResolver': 'letsencrypt'})
        self.assertEqual(callback['middlewares'], ['security-headers@file', 'management@file'])
        self.assertEqual(callback['service'], 'app-authentik-callback')
        self.assertEqual(out['http']['services']['app-authentik-callback'],
                         {'loadBalancer': {'servers': [{'url': 'http://198.18.30.20:9000'}]}})
        self.assertEqual(out['http']['services']['app']['loadBalancer']['serversTransport'], 'app-ca@file')
        self.assertEqual(out['tls']['options']['default']['minVersion'], 'VersionTLS12')
        self.assertNotIn('insecureSkipVerify', json.dumps(out))
        self.assertEqual(out['http']['middlewares']['login'], value['middlewares']['login'])

    def test_single_host_and_verified_https_outpost_origin(self):
        value = settings(); value['routes']['app'].pop('aliases')
        value['middlewares']['login']['forwardAuth']['address'] = 'https://198.18.30.20:9443/outpost.goauthentik.io/auth/traefik'
        value['routes']['app']['middlewares'] = ['login']
        out = d.shared(value)
        self.assertEqual(out['http']['routers']['app-authentik-callback']['rule'],
                         'Host(`app.example.invalid`) && PathPrefix(`/outpost.goauthentik.io/`)')
        self.assertEqual(out['http']['routers']['app-authentik-callback']['middlewares'], [])
        self.assertEqual(out['http']['services']['app-authentik-callback'],
                         {'loadBalancer': {'servers': [{'url': 'https://198.18.30.20:9443'}]}})

    def test_ordinary_routes_have_no_callback_and_notes_keep_managed_backend_ownership(self):
        value = settings(); value['routes']['app'].pop('authentik_forward_auth')
        out = d.shared(value)
        self.assertEqual(set(out['http']['routers']), {'app'})
        self.assertEqual(set(out['http']['services']), {'app'})
        cfg = {'guest': {'interfaces': [{'ipv4': '198.18.30.21/24'}]}, 'routes': settings()['routes']}
        labels = d.labels(cfg)
        self.assertEqual(labels['traefik.http.routers.app.priority'], '10')
        self.assertEqual(labels['traefik.http.services.app.loadbalancer.server.url'], 'https://198.18.30.21:9443')
        self.assertFalse(any('callback' in key for key in labels))

    def test_callback_refuses_unbound_provider_auth_loops_raw_rules_and_unsafe_origins(self):
        mutations = [
            lambda v: v['routes']['app'].update(authentik_forward_auth='absent'),
            lambda v: v['routes']['app'].update(authentik_forward_auth='login@file'),
            lambda v: v['routes']['app'].update(authentik_forward_auth=[]),
            lambda v: v['routes']['app'].update(middlewares=['security-headers']),
            lambda v: v['middlewares'].update(login={'headers': {}}),
            lambda v: v['middlewares']['login']['forwardAuth'].update(tls={'insecureSkipVerify': True}),
            lambda v: v['middlewares'].update(other={'forwardAuth': {'address': 'http://198.18.30.20:9000/auth'}}) or v['routes']['app']['middlewares'].append('other'),
            lambda v: v['middlewares'].update(other={'chain': {'middlewares': ['login']}}) or v['routes']['app']['middlewares'].append('other'),
            lambda v: v['routes']['app'].update(rule='Host(`anything.invalid`)'),
            lambda v: v['routes']['app'].update(path_prefix='/'),
            lambda v: v['routes']['app'].update(priority=100),
            lambda v: v['routes'].update({'app-authentik-callback': {'host': 'other.example.invalid', 'url': 'http://198.18.30.22'}}),
            lambda v: v['routes'].update({'copy': copy.deepcopy(v['routes']['app'])}),
            lambda v: v['routes'].update({'a' * 63: v['routes'].pop('app')}),
            lambda v: v.update(authentik_callbacks=[]),
            lambda v: v.update(authentik_callbacks={'managed': {k: copy.deepcopy(x) for k, x in v['routes']['app'].items() if k in {'host', 'aliases', 'middlewares', 'authentik_forward_auth'}}}),
            lambda v: v['middlewares'].update(other={'plugin': {'opaque': {}}}) or v['routes']['app']['middlewares'].append('other'),
            lambda v: v.update(authentik_callbacks={'managed': {'host': 'managed.example.invalid', 'authentik_forward_auth': 'login', 'middlewares': ['login', []]}}),
            lambda v: v.update(authentik_callbacks={'managed': {'host': 'managed.example.invalid'}}),
            lambda v: v.update(authentik_callbacks={'managed': dict(v['routes']['app'], rule='anything')}),
        ]
        for i, mutate in enumerate(mutations):
            value = settings(); mutate(value)
            with self.subTest(mutation=i), self.assertRaises(ValueError): d.shared(value)
        for address in (None, [], 'http://198.18.30.20:9000/auth',
                        'http://198.18.30.20:9000/outpost.goauthentik.io/auth/traefik/',
                        'http://198.18.30.20:9000/outpost.goauthentik.io/auth/traefik?x=1',
                        'http://198.18.30.20:9000/outpost.goauthentik.io/auth/traefik#fragment',
                        'http://user:password@198.18.30.20:9000/outpost.goauthentik.io/auth/traefik',
                        'http://8.8.8.8:9000/outpost.goauthentik.io/auth/traefik',
                        'http://outpost.example.invalid:9000/outpost.goauthentik.io/auth/traefik',
                        'http://[invalid/outpost.goauthentik.io/auth/traefik',
                        'http://198.18.30.20:0/outpost.goauthentik.io/auth/traefik',
                        'http://198.18.30.20:bad/outpost.goauthentik.io/auth/traefik',
                        'http://198.18.30.20\\bad/outpost.goauthentik.io/auth/traefik',
                        'http://198.18.30.20:9000/outpost.goauthentik.io/auth/traefik\n'):
            value = settings(); value['middlewares']['login']['forwardAuth']['address'] = address
            with self.subTest(address=address), self.assertRaises(ValueError): d.shared(value)
