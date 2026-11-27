"""Compile a retained editor registration and check its native sign-in contract."""
from copy import deepcopy
import unittest

import component_auth as auth
import component_authentik_blueprints as blueprints
import component_routed_checks as routes
from component_errors import ComponentError
from test_component_authentik_blueprints import composition


def editor():
    resolver, exposures, graph = composition()
    client = resolver.apps['manager']
    client.update(id='manager', adapter='node_red', authentication='editor', lifecycle='retained')
    provider = resolver.site['identity_providers']['identity']
    provider.update(issuer_path='/application/o/editor/', endpoints={
        'authorization': '/application/o/authorize/', 'token': '/application/o/token/',
        'userinfo': '/application/o/userinfo/', 'jwks': '/application/o/editor/jwks/'})
    policy = {
        'type': 'node-red-retained-oidc', 'provider': 'identity', 'client_id': 'editor-client',
        'registration': {
            'slug': 'editor', 'provider_name': 'Editor', 'admission_group': 'Operators',
            'authentication_flow': None, 'authorization_flow': 'authorize', 'invalidation_flow': 'logout',
            'signing_key': 'Example key', 'callback_aliases': ['second'], 'client_secret': 'old_oauth',
            'secret_slot': 2, 'launch_url': '', 'policy_engine_mode': 'any',
        },
    }
    resolver.policy['authentication']['editor'] = policy
    exposures.domains['second'] = 'alias.example.invalid'
    exposures.resolved['web']['aliases'] = ['second']
    client['authentication_resolved'] = auth._node_red(auth.oidc_provider(provider, exposures), policy, client)
    return resolver, exposures, graph


class RetainedEditorTests(unittest.TestCase):
    def test_editor_shares_final_probe_and_preserves_native_client_and_existing_group(self):
        resolver, exposures, graph = editor()
        client = resolver.apps['manager']
        native = deepcopy(client['authentication_resolved'])
        source = resolver.policy['authentication']['editor']['registration']
        for flow in (None, 'explicit-login'):
            source['authentication_flow'] = flow
            resolver.apps['login']['settings'].clear()
            blueprints.bind(resolver, exposures)
            spec = resolver.apps['login']['settings']['oidc_blueprints']['editor']
            self.assertEqual(spec['secret_role'], 'oidc_client_2')
            self.assertEqual(spec['additional_callbacks'], ['https://alias.example.invalid/auth/strategy/callback/'])
            self.assertIn('!Find [authentik_core.group, [name, Operators]]', spec['blueprint'])
            self.assertNotIn('model: authentik_core.group', spec['blueprint'])
            self.assertEqual(spec['authentication_flow'], flow)
        result = routes.bind(resolver, exposures, graph)
        check, = [row for row in result['routed_checks']['room']['rows'] if row['mode'] == 'oidc']
        self.assertEqual((check['path'], check['oidc']['callback']), ('/auth/strategy', spec['callback']))
        self.assertEqual(native, client['authentication_resolved'])
        self.assertEqual(graph['guest_dependencies']['room'], [])

    def test_closed_registration_refuses_invalid_grants_inputs_and_callbacks(self):
        for key, value in [('callback_aliases', ['foreign']), ('callback_aliases', ['second', 'second']),
                           ('authentication_flow', ''), ('launch_url', 'https://elsewhere.invalid/'),
                           ('policy_engine_mode', 'unbound'), ('secret_slot', True), ('secret_slot', 9),
                           ('client_secret', 'unbound'), ('slug', 'other')]:
            with self.subTest(key=key, value=value):
                resolver, exposures, _ = editor()
                resolver.policy['authentication']['editor']['registration'][key] = value
                with self.assertRaises(ComponentError):
                    blueprints.bind(resolver, exposures)

    def test_only_the_managed_provider_can_be_adopted_and_checked(self):
        resolver, exposures, graph = editor()
        resolver.site['identity_providers']['identity']['type'] = 'retained-node-red-oidc'
        with self.assertRaises(ComponentError):
            blueprints.bind(resolver, exposures)
        with self.assertRaises(ComponentError):
            routes.bind(resolver, exposures, graph)

    def test_editor_requires_its_native_issuer_and_signing_key_endpoint(self):
        for field in ('issuer_path', 'jwks'):
            with self.subTest(field=field):
                resolver, exposures, _ = editor()
                source = resolver.site['identity_providers']['identity']
                (source if field == 'issuer_path' else source['endpoints'])[field] = '/other/'
                provider = auth.oidc_provider(source, exposures)
                with self.assertRaises(ComponentError):
                    auth._node_red(provider, resolver.policy['authentication']['editor'], resolver.apps['manager'])

    def test_only_existing_editors_and_their_explicit_aliases_can_be_adopted(self):
        resolver, exposures, _ = editor()
        resolver.apps['manager']['lifecycle'] = 'fresh'
        with self.assertRaises(ComponentError):
            blueprints.bind(resolver, exposures)
        resolver, exposures, _ = editor()
        exposures.domains['second'] = 'web.example.invalid'
        with self.assertRaises(ComponentError):
            blueprints.bind(resolver, exposures)

    def test_existing_clients_keep_their_own_secret_slots(self):
        resolver, exposures, _ = editor()
        old_resolver, _, _ = composition()
        resolver.apps['console'] = old_resolver.apps['manager']
        console = resolver.policy['authentication']['login']['registration']
        console['secret_slot'] = 2
        with self.assertRaises(ComponentError):
            blueprints.bind(resolver, exposures)
        resolver.apps['login']['settings'].clear()
        console['secret_slot'] = 1
        blueprints.bind(resolver, exposures)
        specs = resolver.apps['login']['settings']['oidc_blueprints']
        self.assertEqual({slug: row['secret_role'] for slug, row in specs.items()},
                         {'console': 'oidc_client_1', 'editor': 'oidc_client_2'})
