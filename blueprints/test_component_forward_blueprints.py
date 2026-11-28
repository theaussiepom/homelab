"""An admission group is referenced by a dedicated single-host Authentik provider."""
import copy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'proxmox/applications'))
import component_authentik_blueprints as blueprints
import component_auth
import component_exposures
from component_errors import ComponentError


def example():
    spec = dict(middleware='auth', slug='console', provider_name='Console proxy', admission_group='Operators',
                outpost='embedded', authorization_flow='allow', invalidation_flow='logout')
    app = dict(id='console', guest='tools', display_name='Database console', forward_auth=spec,
               identity=dict(project='tools', networks={'private':'console_net'}),
               origin={'exposure':'console'}, origin_url='https://console.example.invalid',
               settings={'auth_headers':{'user':'X-authentik-username','team':'X-Team'}},
               authentication_resolved={'type':'forward-auth'})
    image = {'image':'example.invalid/authentik:2026.8.6@sha256:' + '1' * 64}
    owner = dict(id='identity', guest='identity', adapter='authentik', settings={},
                 software_selection={'images':{'worker': image, 'server': image}})
    route = dict(type='http', target={'app':'console','address':'192.0.2.5','port':8978},
                 hosts=['console.example.invalid'], middlewares=['auth','headers'])
    exposures = SimpleNamespace(resolved={'console':route}, middlewares={'auth':{'type':'forward-auth',
        'target':{'app':'identity'}}, 'headers':{'type':'cloudbeaver-headers'}})
    return SimpleNamespace(apps={'console':app, 'identity':owner}), exposures


class ForwardBlueprintTests(unittest.TestCase):
    def test_multiple_existing_registrations_do_not_publish_ingress(self):
        resolver, exposures = example()
        app = resolver.apps['console']
        del app['forward_auth']
        app.update(lifecycle='retained', adapter='console')
        exposures.domains = {'first': 'one.example.invalid', 'second': 'two.example.invalid'}
        registration = dict(name='First portal', provider_name='First provider', origin={'domain': 'first'},
                            admission_group='Operators', policy_engine_mode='any', launch_path='/admin')
        second = dict(registration, name='Second portal', provider_name='Second provider',
                      origin={'domain': 'second'}, launch_path='')
        source = app['retained_proxy_registrations'] = dict(
            identity='identity', outpost='embedded', authorization_flow='allow', invalidation_flow='logout',
            registrations={'first': registration, 'second': second})
        routes = copy.deepcopy(exposures.resolved)
        blueprints.bind(resolver, exposures)
        registered = resolver.apps['identity']['settings']['forward_blueprints']
        self.assertEqual(set(registered), {'first', 'second'})
        self.assertEqual(registered['first']['retained_application']['launch_url'], 'https://one.example.invalid/admin')
        self.assertEqual(registered['second']['retained_application']['launch_url'], '')
        self.assertIn('group, [name, Operators]', registered['second']['blueprint'])
        self.assertEqual(routes, exposures.resolved)
        registered.clear()
        for changes in ({'identity':'missing'}, {'identity':'console'}, {'outpost':'external'},
                        {'registrations':{}}, {'registrations':{'bad_slug':registration}}):
            with self.subTest(changes=changes), mock.patch.dict(source, changes), self.assertRaises(ComponentError):
                blueprints.bind(resolver, exposures)
        for changes in ({'launch_path':'//other.invalid'}, {'policy_engine_mode':'none'},
                        {'admission_group':''}, {'origin':{'domain':'unknown'}}, {'secret':'value'}):
            with self.subTest(changes=changes), mock.patch.dict(registration, changes), self.assertRaises(ComponentError):
                blueprints.bind(resolver, exposures)
        with mock.patch.dict(app, lifecycle='fresh'):
            blueprints.bind(resolver, exposures)
            self.assertEqual(set(registered), {'first', 'second'})

    def test_retained_application_preserves_existing_portal_settings(self):
        resolver, exposures = example()
        app = resolver.apps['console']
        app['lifecycle'] = 'retained'
        retained = app['forward_auth']['retained_application'] = {
            'name': 'Existing radio', 'policy_engine_mode': 'any', 'launch_url': ''}
        for changes in ({'name': ' '}, {'policy_engine_mode': 'other'}, {'launch_url': 'https://other.invalid/'},
                        {'extra': True}):
            with self.subTest(changes=changes), mock.patch.dict(retained, changes), self.assertRaises(ComponentError):
                blueprints.bind(resolver, exposures)
        with mock.patch.dict(app, lifecycle='fresh'), self.assertRaises(ComponentError):
            blueprints.bind(resolver, exposures)
        blueprints.bind(resolver, exposures)
        spec = resolver.apps['identity']['settings']['forward_blueprints']['console']
        self.assertEqual(spec['app_name'], retained['name'])
        self.assertIn('policy_engine_mode: any', spec['blueprint'])
        self.assertIn("meta_launch_url: ''", spec['blueprint'])

    def test_direct_authentication_requires_an_owned_origin_and_header_policy_has_no_overrides(self):
        resolver, exposures = example()
        app = resolver.apps['console']
        app.update(adapter='cloudbeaver', profile='console', authentication='signin', secrets={'recovery_password':'private'})
        resolver.apps = {'console':app}
        resolver.library = {'app_profiles':{'console':{'authentication':'console'}},'authentication_profiles':{
            'console':{'type':'cloudbeaver-forward-auth','required':True}}}
        resolver.policy = {'authentication':{'signin':{'type':'cloudbeaver-forward-auth'}},'tls':{},
                           'middlewares':{'headers':{'type':'cloudbeaver-headers'}}}
        resolver.site = {'domains':{}}
        self.assertEqual(component_auth.authentication(resolver, {}), {'console':{'type':'forward-auth'}})
        with self.assertRaises(ComponentError):
            component_auth.authentication(SimpleNamespace(**dict(vars(resolver), apps={'console':dict(app,secrets={})})), {})
        del app['forward_auth']
        with self.assertRaises(ComponentError): component_auth.authentication(resolver,{})
        policy = component_exposures.Exposures(resolver)
        policy.validate_policies()
        self.assertEqual(policy.middlewares, resolver.policy['middlewares'])
        resolver.policy['middlewares']['headers']['team'] = 'admin'
        with self.assertRaises(ComponentError): policy.validate_policies()

    def test_existing_forward_auth_app_can_manage_its_provider(self):
        resolver, exposures = example()
        del resolver.apps['console']['authentication_resolved']
        exposures.resolved['console']['middlewares'] = ['auth']
        blueprints.bind(resolver, exposures)
        self.assertIn('console', resolver.apps['identity']['settings']['forward_blueprints'])

    def test_reference_existing_group_without_owning_members_or_replacing_outpost(self):
        resolver, exposures = example()
        blueprints.bind(resolver, exposures)
        row = resolver.apps['identity']['settings']['forward_blueprints']['console']
        self.assertEqual(row['origin'], 'https://console.example.invalid')
        self.assertEqual(row['scope_mappings'], list(blueprints.FORWARD_SCOPE_MAPPINGS))
        document = row['blueprint']
        self.assertIn('!Find [authentik_core.group, [name, Operators]]', document)
        self.assertIn('mode: forward_single', document)
        self.assertNotIn('model: authentik_core.group', document)
        self.assertNotIn('authentik_outposts.outpost', document)
        self.assertNotIn('!File', document)
        with self.assertRaises(ComponentError):
            blueprints.bind(resolver, exposures)

    def test_refuse_ambiguous_admission_route_or_identity_owner(self):
        for case in ('field','slug','group','outpost','missing-identity','alias','server',
                     'missing-auth','untrusted-team','other-route','external-route','oidc','bridge'):
            with self.subTest(case=case):
                resolver, exposures = example()
                app = resolver.apps['console']
                spec = app['forward_auth']
                route = exposures.resolved['console']
                if case == 'field': spec['provider_id'] = 1
                if case == 'slug': spec['slug'] = '../bad'
                if case == 'group': spec['admission_group'] = 'Ops\n'
                if case == 'outpost': spec['outpost'] = 'arbitrary'
                if case == 'missing-identity': exposures.middlewares['auth']['target']['app'] = 'missing'
                if case == 'alias': route['hosts'].append('other.example.invalid')
                if case == 'server': resolver.apps['identity']['software_selection']['images']['server'] = {'image':'old'}
                if case == 'missing-auth': route['middlewares'] = ['headers']
                if case == 'untrusted-team': app['settings']['auth_headers']['team'] = 'X-Role'
                if case in ('other-route','external-route'):
                    other = exposures.resolved['alternate'] = copy.deepcopy(route)
                    if case == 'external-route': del other['target']['app']
                if case == 'oidc':
                    resolver.apps['identity']['settings']['oidc_blueprints'] = {'prior':{
                        'slug':'prior', 'provider_name':spec['provider_name']}}
                if case == 'bridge':
                    resolver.apps['other'] = dict(id='other', guest=app['guest'], identity=copy.deepcopy(app['identity']))
                with self.assertRaises(ComponentError):
                    blueprints.bind(resolver, exposures)
