"""Only an explicitly identified retained registration or strict callback can be retired."""
from unittest import TestCase
from unittest.mock import patch
from component_errors import ComponentError
import component_authentik_blueprints as bp
from test_component_forward_blueprints import example


class RetirementTests(TestCase):
    def test_proxy_retirement(self):
        resolver, routes = example()
        app = resolver.apps['console']
        del app['forward_auth']
        ids = {'application_id': '00000000-0000-0000-0000-000000000001', 'provider_id': 3}
        row = dict(origin={'domain': 'console'}, name='Console', provider_name='Existing', admission_group='Operators',
                   policy_engine_mode='any', launch_path='', retire=ids)
        app['retained_proxy_registrations'] = dict(identity='identity', outpost='embedded', authorization_flow='allow',
            invalidation_flow='logout', registrations={'console': row})
        routes.domains = {'console': 'console.example.invalid'}
        bp.bind(resolver, routes)
        spec = resolver.apps['identity']['settings'].pop('forward_blueprints')['console']
        self.assertEqual(spec['retire'], ids)
        self.assertEqual(spec['blueprint'].count('state: absent'), 2)
        self.assertIn('confirmed_retirement', spec['blueprint'])
        self.assertNotIn('policybinding', spec['blueprint'])
        for bad in ({'provider_id': True}, {'provider_id': 0}, {'application_id': None}, {'application_id': 'wrong'}):
            with patch.dict(ids, bad), self.assertRaises(ComponentError):
                bp.bind(resolver, routes)

    def test_callback_subset_must_be_known_and_leave_a_canonical_callback(self):
        resolver, routes = example()
        app = resolver.apps['console']
        del app['forward_auth']
        alias, canonical = ['https://' + name + '.example.invalid/authorize' for name in ('old', 'current')]
        record = dict(provider_id=5, application_id='00000000-0000-0000-0000-000000000005',
                      existing_redirects=[{'matching_mode':'strict','url':v} for v in (alias, canonical)],
                      additions=['https://client.example.invalid/oauth2/callback'], client_id_sha256='a'*64)
        source = app['retained_oidc_registration'] = dict(identity='identity', slug='database', provider_id=5,
            provider_name='Database provider', application_name='Database', admission_group='Operators',
            policy_engine_mode='any', launch_url='', retire_callbacks=[alias])
        settings = resolver.apps['identity']['settings']
        for bad in (None, [], [1], [alias, alias], [alias, canonical], ['https://unknown.example.invalid']):
            settings['allowed_callback_additions'] = [record]
            with patch.dict(source, retire_callbacks=bad), self.assertRaises(ComponentError):
                bp.bind(resolver, routes)
        bp.bind(resolver, routes)
        spec = settings['retained_oidc_blueprints']['database']
        self.assertIs(spec['previous_guard'], record)
        self.assertEqual(spec['guard']['existing_redirects'], record['existing_redirects'][1:])
        self.assertIn('confirmed_retirement', spec['blueprint'])
        self.assertIn(canonical, spec['blueprint'])
        self.assertNotIn(alias, spec['blueprint'])
