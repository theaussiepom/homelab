"""Source and materialization contracts for retained SAML sign-in."""
import hashlib
from pathlib import Path
import ssl
import unittest

import component_auth as auth
import component_authentik_blueprints as blueprints
from component_errors import ComponentError
from test_component_authentik_blueprints import composition


def fixture():
    resolver, exposures, _ = composition()
    cert = (Path(__file__).resolve().parents[1] / 'proxmox/applications/tests/monitoring-synthetic-saml-certificate.txt').read_text()
    resolver.site['identity_providers']['identity'] = {'type': 'saml', 'signing_certificate': cert, 'origin': {'exposure': 'idp'}}
    registration = dict(slug='monitor', application_name='Monitoring', provider_name='Monitor SAML',
                        issuer='monitor', signing_key='Monitoring key', admission_group='Operators',
                        authentication_flow=None, authorization_flow='consent', invalidation_flow='logout',
                        policy_engine_mode='any', session_minutes=120, attribute_mappings=['username', 'groups'])
    app = resolver.apps['manager']
    app.update(id='manager', adapter='zabbix', lifecycle='retained',
               authentication_resolved={'idp_signing_certificate': cert})
    resolver.policy['authentication']['login'] = dict(type='zabbix-saml', provider='identity',
                                                      default_login='saml', registration=registration)
    return resolver, exposures, registration


class SamlRegistrationTests(unittest.TestCase):
    def test_resolves_native_trust_and_preserves_existing_references(self):
        for flow in (None, 'interactive-login'):
            resolver, exposures, registration = fixture()
            registration['authentication_flow'] = flow
            selected = auth.providers(resolver, exposures)['identity']
            blueprints.bind(resolver, exposures)
            spec = resolver.apps['login']['settings']['saml_blueprints']['monitor']
            self.assertEqual(spec['certificate_sha256'], hashlib.sha256(ssl.PEM_cert_to_DER_cert(selected['signing_certificate'])).hexdigest())
            self.assertEqual(spec['attributes']['acs_url'], 'https://web.example.invalid/index_sso.php?acs')
            self.assertEqual(spec['flows']['authentication_flow'], flow)
            self.assertIn('model: authentik_providers_saml.samlprovider', spec['blueprint'])
            self.assertIn('!Find [authentik_core.group, [name, Operators]]', spec['blueprint'])
            self.assertNotIn('model: authentik_crypto.certificatekeypair', spec['blueprint'])
            self.assertNotIn('!File', spec['blueprint'])
            with self.assertRaises(ComponentError):
                blueprints.bind(resolver, exposures)

    def test_reject_incomplete_wrong_owner_or_conflicting_registration(self):
        for case in ('slug', 'grant', 'duplicate', 'no_groups', 'unknown_mapping', 'time', 'fresh', 'owner',
                     'wrong_type', 'auth_flow', 'cross_protocol', 'duplicate_endpoint', 'unknown_field'):
            resolver, exposures, source = fixture()
            if case == 'slug':
                source['slug'] = 'bad/slug'
            elif case == 'grant':
                source['policy_engine_mode'] = 'open'
            elif case == 'duplicate':
                source['attribute_mappings'] += ['username']
            elif case == 'no_groups':
                source['attribute_mappings'] = ['username']
            elif case == 'unknown_mapping':
                source['attribute_mappings'] += ['other']
            elif case == 'time':
                source['session_minutes'] = True
            elif case == 'fresh':
                resolver.apps['manager']['lifecycle'] = 'fresh'
            elif case == 'owner':
                del resolver.site['identity_providers']['identity']['origin']
            elif case == 'wrong_type':
                resolver.site['identity_providers']['identity']['type'] = 'oidc'
            elif case == 'auth_flow':
                source['authentication_flow'] = ''
            elif case == 'cross_protocol':
                resolver.apps['login']['settings']['forward_blueprints'] = {'other': {
                    'slug': 'different', 'provider_name': source['provider_name']}}
            elif case == 'duplicate_endpoint':
                resolver.apps['login']['settings']['saml_blueprints'] = {'other': {'provider_name': 'Other',
                    'attributes': {'acs_url': 'https://web.example.invalid/index_sso.php?acs'}}}
            else:
                source['extra'] = 'field'
            with self.subTest(case=case), self.assertRaises(ComponentError):
                blueprints.bind(resolver, exposures)
