"""Native login contract: explicit trust, narrow roles, separate secrets and no I/O."""
import copy
import unittest
from unittest.mock import patch
from test_component_auth import fixture
from component_errors import ComponentError
import component_auth as auth
import component_secrets


def selected():
    r, e = fixture()
    r.site['secret_sources']['management'] = {'type': 'file', 'path': '/private/management-token'}
    r.library['authentication_profiles']['pega'] = {'type': 'pegaprox-oidc', 'required': False}
    r.library['app_profiles']['pega'] = {'authentication': 'pega'}
    r.apps = {'manager': {'adapter': 'pegaprox', 'profile': 'pega', 'authentication': 'login',
                         'origin_url': 'https://manager.example.invalid'}}
    r.policy['authentication']['login'] = {'type': 'pegaprox-oidc', 'provider': 'identity',
        'client_id': 'management-ui', 'client_secret': 'old_oauth', 'management_token': 'management',
        'display_name': 'Sign in with Identity', 'user_claim': 'preferred_username',
        'group_mappings': [{'group_id': 'Management administrators', 'role': 'admin'}],
        'enabled': True, 'allow_private_ip': True}
    return r, auth.providers(r, e)


class PegaAuthentication(unittest.TestCase):
    def test_lowering_selects_both_private_roles_without_opening_sources(self):
        from test_component_lower import fixture as lower_fixture, app as lower_app
        import component_lower
        plan=lower_fixture(); selected_app=lower_app('pegaprox')
        selected_app['authentication_resolved']={'client_secret':'oauth','management_token':'broker-password'}
        plan.resolved['apps']['selected']=selected_app
        result=component_lower.runtime_config(plan,'one')['applications']['selected']
        self.assertEqual(result['input_sources'],{
            'client_secret':plan.site['secret_sources']['oauth'],
            'management_token':plan.site['secret_sources']['broker-password']})

    def test_complete_policy_resolves_without_reading_or_provisioning_secrets(self):
        r, providers = selected()
        with patch('builtins.open', side_effect=AssertionError('No private I/O')):
            result = auth.authentication(r, providers)['manager']
        self.assertEqual(result['settings']['oidc_redirect_uri'], 'https://manager.example.invalid/oidc/callback')
        self.assertEqual(result['settings']['oidc_default_role'], 'viewer')
        self.assertFalse(result['settings']['oidc_skip_ssl_verify'])
        self.assertFalse(result['settings']['oidc_skip_jwt_verification'])
        r.apps['manager']['authentication_resolved'] = result
        self.assertEqual(component_secrets.action_inputs(r, 'manager'), {
            'pegaprox_client_secret': {'environment': 'EXISTING_OAUTH_SECRET', 'workflow_secret': 'EXISTING_OAUTH_SECRET'}})
        result['settings']['oidc_group_mappings'][0]['role'] = 'viewer'
        self.assertEqual(r.policy['authentication']['login']['group_mappings'][0]['role'], 'admin')

    def test_explicit_disable_retains_policy_and_secret_custody(self):
        r, providers = selected()
        r.policy['authentication']['login']['enabled'] = False
        result = auth.authentication(r, providers)['manager']
        self.assertFalse(result['settings']['oidc_enabled'])
        self.assertEqual(result['management_token'], 'management')
        del r.apps['manager']['authentication']
        self.assertEqual(auth.authentication(r, providers), {})

    def test_closed_policy_refuses_unknown_missing_weak_and_ambiguous_values(self):
        mutations = [lambda p: p.update(skip_jwt_verification=True),
            lambda p: p.pop('management_token'), lambda p: p.update(management_token='missing'),
            lambda p: p.update(management_token='old_oauth'), lambda p: p.update(client_secret='missing'),
            lambda p: p.update(client_id=''), lambda p: p.update(client_id=' leading'),
            lambda p: p.update(client_id='a'*257), lambda p: p.update(client_id='a\x7f'),
            lambda p: p.update(display_name='newline\n'), lambda p: p.update(display_name=None),
            lambda p: p.update(user_claim='sub'), lambda p: p.update(enabled=1),
            lambda p: p.update(allow_private_ip='true'), lambda p: p.update(group_mappings=[]),
            lambda p: p.update(group_mappings={}), lambda p: p.update(group_mappings=[{}]),
            lambda p: p.update(group_mappings=[{'group_id':'g','role':'root'}]),
            lambda p: p.update(group_mappings=[{'group_id':'','role':'admin'}]),
            lambda p: p.update(group_mappings=[{'group_id':' g','role':'admin'}]),
            lambda p: p.update(group_mappings=[{'group_id':'g\n','role':'admin'}]),
            lambda p: p.update(group_mappings=[{'group_id':'g'*257,'role':'admin'}]),
            lambda p: p.update(group_mappings=[{'group_id':'g','role':'admin'},{'group_id':'G','role':'viewer'}]),
            lambda p: p.update(group_mappings=[{'group_id':str(i),'role':'viewer'} for i in range(33)])]
        for mutation in mutations:
            r, providers = selected(); mutation(r.policy['authentication']['login'])
            with self.subTest(mutation=mutation), self.assertRaises(ComponentError):
                auth.authentication(r, providers)
        r, providers = selected(); providers['identity']['type'] = 'saml'
        with self.assertRaises(ComponentError): auth.authentication(r, providers)
        r, providers = selected(); r.site['secret_sources']['management']['type'] = 'generated'
        with self.assertRaises(ComponentError): auth.authentication(r, providers)

    def test_all_supported_claims_and_roles_and_environment_inputs(self):
        for claim in ('preferred_username', 'email', 'upn'):
            r, providers = selected()
            r.policy['authentication']['login'].update(user_claim=claim,
                group_mappings=[{'group_id':role,'role':role} for role in ('admin','user','viewer')])
            r.site['secret_sources']['management'] = {'type':'environment','name':'MANAGEMENT_TOKEN'}
            r.apps['manager']['authentication_resolved'] = auth.authentication(r, providers)['manager']
            self.assertEqual(set(component_secrets.action_inputs(r, 'manager')),
                             {'pegaprox_client_secret','pegaprox_management_token'})
