"""Secret component units use metadata only; no secret source is opened."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import component_secrets as secrets
from component_errors import ComponentError


class SecretTests(unittest.TestCase):
    def test_action_slots_are_closed_roles_with_direct_existing_secret_aliases(self):
        resolver = self.resolver()
        resolver.site['secret_sources']['key'] = {'type': 'environment', 'name': 'AUTHENTIK_SECRET_KEY',
                                                 'workflow_secret': 'FOUNDATION_AUTHENTIK_SECRET_KEY'}
        secrets.bind(resolver)
        self.assertEqual(secrets.action_inputs(resolver, 'sso'), {'authentik_secret_key': {
            'environment': 'AUTHENTIK_SECRET_KEY', 'workflow_secret': 'FOUNDATION_AUTHENTIK_SECRET_KEY'}})
        resolver.apps['second'] = copy.deepcopy(resolver.apps['sso'])
        resolver.apps['second']['secret_bindings']['secret_key']['workflow_secret'] = 'SECOND_KEY'
        self.assertNotEqual(secrets.action_inputs(resolver, 'sso'), secrets.action_inputs(resolver, 'second'))
        resolver.apps['second']['secret_bindings']['secret_key'] = {'type': 'file', 'path': '/existing/record'}
        self.assertEqual(secrets.action_inputs(resolver, 'second'), {})
        resolver.apps['cloud'] = {'adapter': 'cloudbeaver', 'authentication_resolved': {'client_secret': 'key'}}
        self.assertEqual(set(secrets.action_inputs(resolver, 'cloud')), {'cloudbeaver_client_secret'})
        with self.assertRaises(ComponentError):
            secrets.action_inputs(resolver, 'missing')
        resolver.apps['second']['secret_bindings']['arbitrary'] = {'type': 'environment', 'name': 'ANY_KEY'}
        with self.assertRaisesRegex(ComponentError, 'secret-role'):
            secrets.action_inputs(resolver, 'second')

    def test_sources_are_closed_and_values_never_echo(self):
        secrets.source({'type': 'environment', 'name': 'RUNTIME_KEY', 'workflow_secret': 'EXISTING_KEY'})
        for selected in ({'type': 'file', 'path': '/private/example'},
                         {'type': 'environment', 'name': 'EXAMPLE_TOKEN'},
                         {'type': 'generated', 'credential_id': 'example-account'}):
            with self.subTest(selected=selected['type']):
                secrets.source(selected)
                for change in ({'value': 'PRIVATE_SENTINEL'}, {'type': 'inline'}):
                    bad = dict(selected, **change)
                    with self.assertRaises(ComponentError) as caught:
                        secrets.source(bad)
                    self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))
        for name in ('lowercase', 'A;echo PRIVATE_SENTINEL', 'A\nSECRET', '', 'A' * 129):
            with self.subTest(name=name):
                with self.assertRaises(ComponentError):
                    secrets.source({'type': 'environment', 'name': name})
                with self.assertRaises(ComponentError):
                    secrets.source({'type': 'environment', 'name': 'RUNTIME_KEY', 'workflow_secret': name})
        with self.assertRaises(ComponentError):
            secrets.source({'type': 'file', 'path': '/example/input', 'workflow_secret': 'EXISTING_KEY'})

    def resolver(self):
        return SimpleNamespace(
            library={'app_profiles': {'identity': {'secrets': {
                'secret_key': {'required': True}, 'smtp_password': {'required': False}}}}},
            site={'secret_sources': {'key': {'type': 'file', 'path': '/never-read/key'}}},
            apps={'sso': {'adapter': 'authentik', 'profile': 'identity', 'secrets': {'secret_key': 'key'}}})

    def test_named_requirement_and_binding_with_no_filesystem_boundary(self):
        resolver = self.resolver()
        with patch('builtins.open', side_effect=AssertionError('No source read')):
            secrets.bind(resolver)
        self.assertEqual(resolver.apps['sso']['secret_bindings'], {
            'secret_key': {'type': 'file', 'path': '/never-read/key', 'source_id': 'key'}})
        resolver.site['secret_sources']['key']['path'] = '/changed'
        self.assertEqual(resolver.apps['sso']['secret_bindings']['secret_key']['path'], '/never-read/key')

    def test_unknown_missing_foreign_generated_and_malformed_requirements(self):
        changes = [
            lambda r: r.apps['sso']['secrets'].clear(),
            lambda r: r.apps['sso']['secrets'].update(extra='key'),
            lambda r: r.apps['sso']['secrets'].update(secret_key='absent'),
            lambda r: r.site['secret_sources']['key'].update(type='generated'),
            lambda r: r.library['app_profiles']['identity']['secrets'].update(extra={'required': False}),
            lambda r: r.library['app_profiles']['identity']['secrets']['secret_key'].update(required=1),
            lambda r: r.library['app_profiles']['identity']['secrets']['secret_key'].update(filename='escape'),
        ]
        for change in changes:
            with self.subTest(case=changes.index(change)):
                resolver = self.resolver()
                change(resolver)
                with self.assertRaises(ComponentError):
                    secrets.bind(resolver)

    def test_absent_capability_and_optional_role_do_not_add_runtime_inputs(self):
        resolver = self.resolver()
        resolver.apps['sso'].pop('secrets')
        resolver.library['app_profiles']['identity']['secrets']['secret_key']['required'] = False
        secrets.bind(resolver)
        self.assertEqual(resolver.apps['sso']['secret_bindings'], {})
        for adapter in ('unbound', 'pihole', 'mqtt'):
            secrets.requirements(adapter, {})
            with self.assertRaises(ComponentError):
                secrets.requirements(adapter, {'secret_key': {'required': True}})


if __name__ == '__main__':
    unittest.main()
