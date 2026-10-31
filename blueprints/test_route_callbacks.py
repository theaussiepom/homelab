"""Global route binding owns callback derivation for both discovery and file apps."""
import copy
import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "proxmox/applications"))
import routes
import discovery
from test_routes import fixture


def configured():
    value = fixture()
    value['ingress'][1]['routing']['middlewares']['login'] = {
        'forwardAuth': {'address': 'http://198.18.30.20:9000/outpost.goauthentik.io/auth/traefik'}}
    return value


def selected():
    return {'app': {'host': 'app.invalid', 'target': {'endpoint': 'native.web.ui'},
                    'aliases': ['alias.invalid'], 'middlewares': ['login', 'limits'],
                    'authentik_forward_auth': 'login'}}


class CallbackBindingTests(unittest.TestCase):
    def test_managed_callback_is_file_owned_without_duplicating_app_route_or_changing_dns(self):
        value = configured(); chosen = selected(); before = copy.deepcopy(chosen)
        self.assertEqual(routes.bind(value, chosen), {'app.invalid': '198.18.40.33', 'alias.invalid': '198.18.40.33'})
        self.assertEqual(chosen, before)
        self.assertEqual(value['ingress'][1]['routing']['routes'], {})
        self.assertIn('app', value['ingress'][1]['routing']['authentik_callbacks'])
        shared = discovery.shared(value['ingress'][1]['routing'])
        self.assertEqual(set(shared['http']['routers']), {'app-authentik-callback'})
        self.assertEqual(shared['http']['routers']['app-authentik-callback']['middlewares'], ['limits@file'])
        self.assertEqual(shared['http']['services']['app-authentik-callback']['loadBalancer']['servers'],
                         [{'url': 'http://198.18.30.20:9000'}])
        labels = discovery.labels(value['native'][0])
        self.assertEqual(labels['traefik.http.routers.app.rule'], '(Host(`app.invalid`) || Host(`alias.invalid`))')
        self.assertEqual(labels['traefik.http.routers.app.middlewares'], 'login@file,limits@file')
        self.assertFalse(any('callback' in key for key in labels))

    def test_external_callback_uses_same_closed_model(self):
        value = configured(); chosen = selected(); chosen['app']['target'] = {'url': 'http://192.168.1.2:80'}
        routes.bind(value, chosen)
        self.assertNotIn('authentik_callbacks', value['ingress'][1]['routing'])
        self.assertEqual(set(discovery.shared(value['ingress'][1]['routing'])['http']['routers']),
                         {'app', 'app-authentik-callback'})

    def test_raw_callback_input_unbound_provider_and_global_name_collisions_refuse(self):
        value = configured(); value['ingress'][1]['routing']['authentik_callbacks'] = {}
        with self.assertRaises(ValueError): routes.bind(value, selected())
        value = configured(); chosen = selected(); chosen['app']['authentik_forward_auth'] = 'missing'
        with self.assertRaises(ValueError): routes.bind(value, chosen)
        value = configured(); chosen = selected(); chosen['app-authentik-callback'] = {
            'host': 'other.invalid', 'target': {'url': 'http://192.168.1.2:80'}}
        with self.assertRaises(ValueError): routes.bind(value, chosen)
