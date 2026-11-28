"""A retained registration must resolve its existing ownership and must never acquire a new grant."""
import unittest
from unittest.mock import patch
from component_errors import ComponentError
import component_authentik_blueprints as blueprints
from test_component_forward_blueprints import example


class RetainedRegistrations(unittest.TestCase):
    def test_unbound_provider_requires_explicit_null_and_a_pinned_scope(self):
        resolver, routes = example()
        app = resolver.apps['console']
        del app['forward_auth']
        scopes = {'extra': {'name': 'Existing claims', 'scope_name': 'profile', 'expression_sha256': 'f' * 64}}
        row = dict(origin={'domain': 'console'}, name='Console', provider_name='Existing proxy',
                   admission_group=None, policy_engine_mode='any', launch_path='', additional_scope_mapping='extra')
        app['retained_proxy_registrations'] = dict(identity='identity', outpost='embedded', authorization_flow='allow',
            invalidation_flow='logout', additional_scope_mappings=scopes, registrations={'console': row})
        routes.domains = {'console': 'console.example.invalid'}
        blueprints.bind(resolver, routes)
        rendered = resolver.apps['identity']['settings'].pop('forward_blueprints')['console']['blueprint']
        self.assertIn('Existing claims', rendered)
        self.assertNotIn('authentik_policies.policybinding', rendered)
        for value in (None, 'wrong'):
            with patch.dict(scopes['extra'], expression_sha256=value), self.assertRaises(ComponentError):
                blueprints.bind(resolver, routes)
        with patch.dict(row, additional_scope_mapping='unknown'), self.assertRaises(ComponentError):
            blueprints.bind(resolver, routes)
        del row['admission_group']
        with self.assertRaises(ComponentError):
            blueprints.bind(resolver, routes)

    def test_completed_callback_guard_has_one_owner(self):
        resolver, routes = example()
        app = resolver.apps['console']
        del app['forward_auth']
        source = app['retained_oidc_registration'] = dict(identity='identity', slug='database', provider_id=5,
            provider_name='Database provider', application_name='Database', admission_group='Operators',
            policy_engine_mode='any', launch_url='')
        record = dict(provider_id=5, application_id='00000000-0000-0000-0000-000000000005',
                      existing_redirects=[{'matching_mode':'strict','url':'https://db.example.invalid/authorize'}],
                      additions=['https://old.example.invalid/oauth2/callback'], client_id_sha256='a'*64)
        settings = resolver.apps['identity']['settings']
        for rows in ([], [record, record]):
            settings['allowed_callback_additions'] = rows
            with self.assertRaises(ComponentError): blueprints.bind(resolver, routes)
        for changes in ({'identity':'console'}, {'slug':'bad_slug'}, {'launch_url':'/'}, {'provider_id':True}):
            with patch.dict(source, changes), self.assertRaises(ComponentError): blueprints.bind(resolver, routes)
        other = dict(record, provider_id=6)
        for guards in ([record], [record, other]):
            settings.clear()
            settings['allowed_callback_additions'] = guards
            blueprints.bind(resolver, routes)
            self.assertEqual(settings.get('allowed_callback_additions', []), [item for item in guards if item is other])
            spec = settings['retained_oidc_blueprints']['database']
            self.assertIs(spec['guard'], record)
            self.assertNotIn('client_secret', spec['blueprint'])
            self.assertIn('old.example.invalid/oauth2/callback', spec['blueprint'])
        for kind, foreign in (('forward', dict(slug='other', provider_name='Database provider')),
                              ('saml', dict(slug='database', provider_name='Other')),
                              ('oidc', dict(slug='other', provider_name='Other', client_id='existing'))):
            settings.clear()
            settings['allowed_callback_additions'] = [dict(record, client_id_sha256=blueprints.canonical('existing'))]
            settings[kind+'_blueprints'] = {'other': foreign}
            with self.assertRaises(ComponentError): blueprints.bind(resolver, routes)
        settings.clear()
        settings['allowed_callback_additions'] = [record]
        settings['retained_oidc_blueprints'] = {'another': dict(provider_name=source['provider_name'])}
        with self.assertRaises(ComponentError): blueprints.bind(resolver, routes)
