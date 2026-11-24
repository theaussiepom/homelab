"""Resolve one native client through both the Identity worker and final routing contracts."""
import copy
import json
import unittest

import component_auth
import component_authentik_blueprints as blueprints
import component_routed_checks as routes
import component_secrets
from component_errors import ComponentError
from identity_callbacks import canonical
from test_component_pegaprox_auth import selected
from test_component_routed_checks import fixture as routed_fixture


def composition():
    auth, _ = selected()
    resolver, exposures, graph = routed_fixture()
    resolver.apps = auth.apps
    resolver.policy = auth.policy
    resolver.site = auth.site
    resolver.site['identity_providers']['identity'].update(origin={'exposure':'idp'},
        issuer_path='/application/o/console/')
    resolver.library = auth.library
    policy = resolver.policy['authentication']['login']
    policy['registration'] = {'slug':'console','provider_name':'Example Console','admission_group':'Console users',
        'authentication_flow':'default-authentication-flow','authorization_flow':'consent',
        'invalidation_flow':'logout','signing_key':'Example key'}
    client = resolver.apps['manager']
    client.update(guest='room',display_name='Console', origin={'exposure':'web'},
                  origin_url='https://web.example.invalid')
    client['authentication_resolved'] = component_auth.authentication(resolver,
        component_auth.providers(resolver, exposures))['manager']
    image = {'image': 'ghcr.io/goauthentik/server:2026.8.6@sha256:' + '1' * 64}
    resolver.apps['login'] = {'adapter':'authentik','settings':{},'guest':'login',
                              'software_selection':{'images':{'server':image.copy(),'worker':image.copy()}}}
    exposures.resolved['web']['target']['app'] = 'manager'
    exposures.resolved['web']['check']['oidc'] = True
    exposures.resolved['idp'].update(resolver='filter', middlewares=['acl','headers'])
    exposures.middlewares.update(acl={'type':'ip-allow-list','ranges':['198.18.0.0/15']},
                                 headers={'type':'default-headers'})
    resolver.guests['room']['route_checks'] = {'mode':'deferred','name':'Web','source':{'address_group':'runner'}}
    return resolver, exposures, graph


class IntegrationTests(unittest.TestCase):
    def test_declarative_idp_yaml_and_exact_public_projection(self):
        resolver, exposures, graph = composition()
        blueprints.bind(resolver, exposures)
        records = resolver.apps['login']['settings']['oidc_blueprints']
        self.assertEqual(set(records), {'console'})
        spec = records['console']
        self.assertEqual(spec['blueprint'], blueprints.render(spec))
        self.assertIn("!File '/run/secrets/oidc-console'", spec['blueprint'])
        self.assertIn('!Find', spec['blueprint'])
        self.assertNotIn('management', spec['secret_source'])
        self.assertEqual(component_secrets.action_inputs(resolver,'login'), {
            'authentik_oidc_client_1':{'environment':'EXISTING_OAUTH_SECRET','workflow_secret':'EXISTING_OAUTH_SECRET'}})
        before = copy.deepcopy(graph)
        compiled = routes.bind(resolver, exposures, graph)
        self.assertEqual(graph, before)
        rows = compiled['routed_checks']['room']['rows']
        self.assertEqual([row['mode'] for row in rows], ['page','page','oidc'])
        self.assertEqual(rows[-1]['oidc']['client_id'], resolver.policy['authentication']['login']['client_id'])
        self.assertEqual(rows[-1]['oidc']['callback'], 'https://web.example.invalid/oidc/callback')
        self.assertEqual(rows[-1]['auth_origins'], ['https://idp.example.invalid'])
        self.assertNotIn('secret', json.dumps(rows))
        self.assertEqual(compiled['deferred_routed_checks']['room']['row_needs'],
                         [['edge','names','room'],['edge','names','room'],['edge','login','names','room']])
        self.assertEqual(resolver.apps['manager']['authentication_resolved']['discovery_check'], 'deferred')
        resolver.apps['manager']['authentication_resolved']['settings']['oidc_enabled'] = False
        rows = routes.bind(resolver, exposures, graph)['routed_checks']['room']['rows']
        self.assertEqual(len(rows),2)

    def test_reject_competing_ownership_or_unresolvable_route(self):
        for change in ('callback','duplicate','missing-owner','old-worker','mismatched-server','wrong-slug','extra-field','wrong-mode','denied-network'):
            resolver, exposures, graph = composition()
            spec = resolver.policy['authentication']['login']['registration']
            if change == 'callback':
                resolver.apps['login']['settings']['allowed_callback_additions'] = [
                    {'client_id_sha256':canonical(resolver.policy['authentication']['login']['client_id'])}]
            if change == 'duplicate':
                resolver.apps['other'] = copy.deepcopy(resolver.apps['manager'])
            if change == 'old-worker':
                for role in resolver.apps['login']['software_selection']['images'].values():
                    role['image'] = role['image'].replace('2026.8.6', '2025.2.1')
            if change == 'mismatched-server':
                resolver.apps['login']['software_selection']['images']['server']['image'] = 'different'
            if change == 'missing-owner':
                exposures.resolved['idp']['target']['app'] = 'unselected'
            if change == 'wrong-slug':
                spec['slug'] = 'different'
            if change == 'extra-field':
                spec['bind_any_user'] = True
            if change == 'wrong-mode':
                resolver.guests['room']['route_checks'] = {'mode':'inline','source':{'interface':'wire'}}
            if change == 'denied-network':
                exposures.middlewares['acl']['ranges'] = ['192.0.2.0/24']
            with self.subTest(change=change), self.assertRaises(ComponentError):
                blueprints.bind(resolver, exposures)
                routes.bind(resolver, exposures, graph)
        resolver, exposures, graph = composition()
        del resolver.policy['authentication']['login']['registration']
        blueprints.bind(resolver, exposures)
        self.assertNotIn('oidc_blueprints', resolver.apps['login']['settings'])
