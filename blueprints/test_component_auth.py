"""Focused unit controls for the inert proposal, with component-boundary fakes."""
import copy
import importlib.util
import os
from pathlib import Path
import ssl
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

FRAMEWORK = Path(Path(__file__).resolve().parents[1])
sys.path.insert(0, str(FRAMEWORK / 'blueprints'))
import component_auth as auth
from component_errors import ComponentError


def fixture():
    selected = {'type': 'http', 'domain': 'cloud', 'hosts': ['db.example.invalid'],
                'target': {'app': 'cloud', 'address': '198.18.30.32', 'port': 80, 'protocol': 'http'},
                'ingress_target': {'app': 'edge', 'address': '198.18.40.33', 'port': 443,
                                   'protocol': 'https'}, 'middlewares': ['headers', 'clients']}
    legacy = copy.deepcopy(selected)
    legacy.update(domain='legacy', hosts=['old.example.invalid'],
                  middlewares=['headers', 'clients', 'canonical'])
    exposure = SimpleNamespace(domains={'identity': 'sso.example.invalid', 'cloud': 'db.example.invalid',
                                        'legacy': 'old.example.invalid', 'host': 'host.example.invalid'},
        resolved={'cloud': selected, 'legacy': legacy})
    provider = {'type': 'oidc', 'origin': {'domain': 'identity'},
        'issuer_path': '/application/o/retained-client/',
        'endpoints': {'authorization': '/application/o/authorize/', 'token': '/application/o/token/',
                      'userinfo': '/application/o/userinfo/', 'jwks': '/application/o/retained-client/jwks/'},
        'signing_algorithms': ['RS256']}
    resolver = SimpleNamespace(site={'identity_providers': {'identity': provider},
        'secret_sources': {'old_oauth': {'type': 'environment', 'name': 'EXISTING_OAUTH_SECRET'}},
        'contexts': {'primary': {'trust': {'ca_file': '/declared/public-ca.crt'}}}},
        library={'authentication_profiles': {
            'cloud': {'type': 'cloudbeaver-oidc', 'required': True},
            'node': {'type': 'node-red-retained-oidc', 'required': True},
            'monitoring': {'type': 'zabbix-saml', 'required': False}},
            'app_profiles': {'cloud': {'authentication': 'cloud'}, 'node': {'authentication': 'node'},
                             'monitoring': {'authentication': 'monitoring'}}},
        policy={'transport': {'pve': {'type': 'tls', 'context': 'primary'},
                              'host': {'type': 'tls', 'server_name': {'domain': 'host'}}},
                'authentication': {'login': {'type': 'cloudbeaver-oidc', 'provider': 'identity',
                    'client_id': 'retained-client', 'client_secret': 'old_oauth',
                    'display_name': 'Existing sign-in', 'user_claim': 'preferred_username'}},
                'middlewares': {'canonical': {'type': 'canonical-home-redirect', 'app': 'cloud'}}},
        apps={'cloud': {'adapter': 'cloudbeaver', 'profile': 'cloud', 'authentication': 'login',
                       'origin': {'exposure': 'cloud'}, 'origin_url': 'https://db.example.invalid'}})
    return resolver, exposure


class ProviderUnitTests(unittest.TestCase):
    def test_retained_node_provider_needs_no_new_jwks_or_algorithm_metadata(self):
        r, e = fixture();r.site['identity_providers'] = {'node': {
            'type': 'retained-node-red-oidc', 'origin': {'domain': 'identity'}, 'provider_slug': 'old-client'}}
        self.assertEqual(auth.providers(r, e)['node'], {'type': 'retained-node-red-oidc',
            'origin': 'https://sso.example.invalid', 'provider_slug': 'old-client'})
        r.site['identity_providers']['node']['jwks_url'] = 'https://foreign.invalid/keys'
        with self.assertRaises(ComponentError):auth.providers(r, e)

    def test_complete_metadata_is_derived_once_and_exact_trailing_slashes_survive(self):
        r, e = fixture()
        value = auth.providers(r, e)['identity']
        self.assertEqual(value['issuer'], 'https://sso.example.invalid/application/o/retained-client/')
        self.assertEqual(value['endpoints']['authorization_url'],
                         'https://sso.example.invalid/application/o/authorize/')
        self.assertEqual(value['endpoints']['signing_algorithms'], ['RS256'])

    def test_named_exposure_and_member_alias_preserve_selected_https_port(self):
        r, e = fixture()
        e.resolved['cloud'].update(aliases=['legacy'])
        e.resolved['cloud']['ingress_target']['port'] = 8443
        r.site['identity_providers']['identity']['origin'] = {'exposure': 'cloud', 'domain': 'legacy'}
        self.assertEqual(auth.providers(r, e)['identity']['origin'], 'https://old.example.invalid:8443')

    def test_unknown_foreign_alias_and_dns_origin_refuse(self):
        for update in ({'domain': 'missing'}, {'exposure': 'cloud', 'domain': 'identity'}):
            with self.subTest(update=update):
                r, e = fixture();r.site['identity_providers']['identity']['origin'] = update
                with self.assertRaises(ComponentError):auth.providers(r, e)
        r, e = fixture();r.site['identity_providers']['identity']['origin'] = {'exposure': 'cloud'}
        e.resolved['cloud']['type'] = 'dns'
        with self.assertRaises(ComponentError):auth.providers(r, e)

    def test_relative_endpoint_paths_refuse_cross_origin_query_fragment_and_encoding(self):
        for path in ('https://foreign.invalid/path', '//foreign.invalid/', '/authorize?', '/authorize#',
                     '/a/../token', '/a/./token', '/a/%2e%2e/token', '/a\\token', '/a\ntoken'):
            with self.subTest(path=path):
                r, e = fixture();r.site['identity_providers']['identity']['endpoints']['token'] = path
                with self.assertRaises(ComponentError):auth.providers(r, e)

    def test_complete_endpoint_and_algorithm_contract_refuses_weak_or_duplicate(self):
        for algorithms in ([], ['none'], ['HS256'], ['RS256', 'RS256'], [None], 'RS256'):
            with self.subTest(algorithms=algorithms):
                r, e = fixture();r.site['identity_providers']['identity']['signing_algorithms'] = algorithms
                with self.assertRaises(ComponentError):auth.providers(r, e)
        r, e = fixture();del r.site['identity_providers']['identity']['endpoints']['jwks']
        with self.assertRaises(ComponentError):auth.providers(r, e)

    def test_existing_asymmetric_eddsa_option_remains_supported(self):
        r, e = fixture();r.site['identity_providers']['identity']['signing_algorithms'] = ['EdDSA']
        self.assertEqual(auth.providers(r, e)['identity']['endpoints']['signing_algorithms'], ['EdDSA'])

    def test_saml_certificate_bytes_delegate_to_tls_parser_without_reformatting(self):
        r, e = fixture();pem = '-----BEGIN CERTIFICATE-----\nSYNTHETIC\n-----END CERTIFICATE-----\n'
        r.site['identity_providers'] = {'saml': {'type': 'saml', 'signing_certificate': pem}}
        with patch.object(auth.ssl, 'SSLContext') as context:
            self.assertEqual(auth.providers(r, e)['saml']['signing_certificate'], pem)
            context.return_value.load_verify_locations.assert_called_once_with(cadata=pem)

    def test_private_key_extra_certificate_and_invalid_x509_refuse(self):
        for cert in ('-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY-----',
                     '-----BEGIN CERTIFICATE-----x-----END CERTIFICATE-----' * 2, 'not-a-certificate'):
            with self.subTest(cert=cert):
                with self.assertRaises(ComponentError):auth.certificate(cert)
        with patch.object(auth.ssl, 'SSLContext') as context:
            context.return_value.load_verify_locations.side_effect = ssl.SSLError('synthetic parse failure')
            with self.assertRaises(ComponentError):
                auth.certificate('-----BEGIN CERTIFICATE-----x-----END CERTIFICATE-----')


class AuthenticationUnitTests(unittest.TestCase):
    def setUp(self):
        self.r, self.e = fixture()
        self.providers = auth.providers(self.r, self.e)

    def test_cloud_maps_only_existing_secret_reference_and_verified_claim(self):
        with patch('builtins.open', side_effect=AssertionError('No configured secret must be read')):
            selected = auth.authentication(self.r, self.providers)['cloud']
        self.assertEqual(selected['client_secret'], 'old_oauth')
        self.assertEqual(selected['user_claim'], 'preferred_username')
        self.assertEqual(selected['oidc_endpoints'], self.providers['identity']['endpoints'])
        self.assertNotIn('skip_nonce', selected)
        self.assertNotIn('skip_signature', selected)
        self.assertNotIn('skip_email_verification', selected)

    def test_unknown_auth_adapter_provider_claim_or_secret_refuses(self):
        for key, value in (('type', 'arbitrary-oauth'), ('provider', 'missing'),
                           ('user_claim', 'unverified_header'), ('client_secret', 'missing')):
            with self.subTest(key=key):
                r, _ = fixture();r.policy['authentication']['login'][key] = value
                with self.assertRaises(ComponentError):auth.authentication(r, self.providers)

    def test_generated_new_account_cannot_be_reused_as_oauth_secret(self):
        self.r.site['secret_sources']['old_oauth'] = {'type': 'generated', 'credential_id': 'db-admin'}
        with self.assertRaises(ComponentError):auth.authentication(self.r, self.providers)

    def test_cloud_extra_bypass_field_wrong_adapter_and_missing_origin_refuse(self):
        mutations = (lambda r: r.policy['authentication']['login'].update(skip_nonce=True),
                     lambda r: r.apps['cloud'].update(adapter='pihole'),
                     lambda r: r.apps['cloud'].pop('origin_url'))
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                r, _ = fixture();mutation(r)
                with self.assertRaises(ComponentError):auth.authentication(r, self.providers)

    def test_node_red_maps_metadata_but_keeps_retained_settings_secret_owner(self):
        self.r.apps['cloud'].update(adapter='node_red', profile='node')
        self.r.policy['authentication']['login'] = {'type': 'node-red-retained-oidc',
                                                   'provider': 'identity', 'client_id': 'retained-client'}
        providers = {'identity': {'type': 'retained-node-red-oidc',
            'origin': 'https://sso.example.invalid', 'provider_slug': 'retained-client'}}
        value = auth.authentication(self.r, providers)['cloud']
        self.assertEqual(set(value), {'identity_url', 'node_red_url', 'client_id', 'provider_slug'})
        self.assertEqual(value['provider_slug'], 'retained-client')
        self.assertEqual(value['node_red_url'], 'https://db.example.invalid')

    def test_node_red_foreign_provider_kind_or_explicit_origin_port_refuses(self):
        self.r.apps['cloud'].update(adapter='node_red', profile='node')
        self.r.policy['authentication']['login'] = {'type': 'node-red-retained-oidc',
                                                   'provider': 'identity', 'client_id': 'retained-client'}
        base = {'identity': {'type': 'retained-node-red-oidc',
            'origin': 'https://sso.example.invalid', 'provider_slug': 'retained-client'}}
        for mutate in (lambda p: p.update(type='oidc'),
                       lambda p: p.update(origin='https://sso.example.invalid:8443')):
            with self.subTest(mutate=mutate):
                selected = copy.deepcopy(base);mutate(selected['identity'])
                with self.assertRaises(ComponentError):auth.authentication(self.r, selected)

    def test_node_red_never_accepts_an_extra_secret_or_unselected_policy(self):
        self.r.apps['cloud'].update(adapter='node_red', profile='node')
        self.r.policy['authentication']['login'] = {'type': 'node-red-retained-oidc', 'provider': 'identity',
            'client_id': 'retained-client', 'client_secret': 'old_oauth'}
        with self.assertRaises(ComponentError):auth.authentication(self.r, self.providers)
        self.r.apps['cloud']['authentication'] = 'missing'
        with self.assertRaises(ComponentError):auth.authentication(self.r, self.providers)

    def test_saml_binds_only_public_trust_origin_and_existing_login_selection(self):
        self.r.apps['cloud'].update(adapter='zabbix', profile='monitoring')
        self.r.policy['authentication']['login'] = {'type': 'zabbix-saml', 'provider': 'saml', 'default_login': 'saml'}
        selected = auth.authentication(self.r, {'saml': {'type': 'saml', 'signing_certificate': 'public-pem'}})['cloud']
        self.assertEqual(selected, {'public_url': 'https://db.example.invalid',
                                  'idp_signing_certificate': 'public-pem', 'default_login': 'saml'})

    def test_library_auth_profile_declares_only_type_and_required_requirement(self):
        self.r.library['authentication_profiles']['cloud']['client_id'] = 'site-specific-client'
        with self.assertRaises(ComponentError):auth.authentication(self.r, self.providers)

    def test_missing_required_auth_refuses_but_unselected_optional_auth_does_not(self):
        del self.r.apps['cloud']['authentication']
        with self.assertRaises(ComponentError):auth.authentication(self.r, self.providers)
        self.r.library['authentication_profiles']['cloud']['required'] = False
        self.assertEqual(auth.authentication(self.r, self.providers), {})

    def test_missing_requirement_bad_required_type_or_binding_type_refuses(self):
        for mutate in (lambda r: r.library['app_profiles']['cloud'].update(authentication='missing'),
                       lambda r: r.library['authentication_profiles']['cloud'].update(required='yes'),
                       lambda r: r.library['authentication_profiles']['cloud'].update(type='zabbix-saml')):
            with self.subTest(mutate=mutate):
                r, _ = fixture();mutate(r)
                with self.assertRaises(ComponentError):auth.authentication(r, self.providers)

    def test_cross_protocol_provider_refuses(self):
        with self.assertRaises(ComponentError):
            auth.authentication(self.r, {'identity': {'type': 'saml', 'signing_certificate': 'public-pem'}})

    def test_error_paths_do_not_echo_client_or_metadata_values(self):
        self.r.policy['authentication']['login']['client_id'] = 'SYNTHETIC_PRIVATE_VALUE\n'
        with self.assertRaises(ComponentError) as raised:auth.authentication(self.r, self.providers)
        self.assertNotIn('SYNTHETIC_PRIVATE_VALUE', str(raised.exception))


class TransportUnitTests(unittest.TestCase):
    def test_public_trust_delegates_validation_and_preserves_exact_bytes_without_file_reads(self):
        r, e = fixture()
        r.policy['transport'] = {'selected': {'type': 'tls', 'certificate': 'public-pem',
                                             'server_name': {'domain': 'host'}}}
        with patch.object(auth, 'certificate', return_value='validated-public-pem') as parser, \
             patch('builtins.open', side_effect=AssertionError('No configured trust file read')):
            self.assertEqual(auth.transports(r, e), {'selected': {
                'certificate': 'validated-public-pem', 'server_name': 'host.example.invalid'}})
        parser.assert_called_once_with('public-pem', 'component.transport')

    def test_real_public_certificate_integration_and_closed_trust_source_conflicts(self):
        pem = (FRAMEWORK / 'proxmox/applications/tests/transport-synthetic-public-certificate.txt').read_text()
        r, e = fixture()
        r.policy['transport'] = {'selected': {'type': 'tls', 'certificate': pem}}
        self.assertEqual(auth.transports(r, e), {'selected': {'certificate': pem}})
        for value in ({'type': 'tls', 'context': 'primary', 'certificate': pem},
                      {'type': 'tls', 'certificate': None}, {'type': 'tls', 'certificate': ''},
                      {'type': 'tls', 'certificate': 'not-a-certificate'},
                      {'type': 'tls', 'certificate': pem, 'insecure_skip_verify': True}):
            with self.subTest(keys=list(value)):
                r.policy['transport'] = {'selected': value}
                with self.assertRaises(ComponentError) as raised:
                    auth.transports(r, e)
                self.assertNotIn('BEGIN CERTIFICATE', str(raised.exception))

    def test_context_ca_and_named_server_name_are_reused_with_no_file_read(self):
        r, e = fixture()
        with patch('builtins.open', side_effect=AssertionError('No trust file is read by source binding')):
            self.assertEqual(auth.transports(r, e), {'pve': {'ca_file': '/declared/public-ca.crt'},
                                                   'host': {'server_name': 'host.example.invalid'}})

    def test_empty_unverified_tls_arbitrary_ca_and_missing_references_refuse(self):
        for value in ({'type': 'tls'}, {'type': 'tls', 'insecure_skip_verify': True},
                      {'type': 'tls', 'ca_file': '/foreign.pem'}, {'type': 'tls', 'context': 'missing'},
                      {'type': 'tls', 'server_name': {'domain': 'missing'}}):
            with self.subTest(value=value):
                r, e = fixture();r.policy['transport'] = {'bad': value}
                with self.assertRaises(ComponentError):auth.transports(r, e)


class CanonicalUnitTests(unittest.TestCase):
    def test_only_fixed_302_canonical_home_is_emitted(self):
        r, e = fixture()
        self.assertEqual(auth.canonical_home_middlewares(r, e)['canonical'], {'redirectRegex': {
            'regex': '^https://[^/]+/(.*)', 'replacement': 'https://db.example.invalid/', 'permanent': False}})

    def test_redirect_cannot_supply_status_regex_foreign_destination_or_path(self):
        for key, value in (('status', 301), ('regex', '(.*)'), ('url', 'https://foreign.invalid/'),
                           ('path', '/browser'), ('permanent', True)):
            with self.subTest(key=key):
                r, e = fixture();r.policy['middlewares']['canonical'][key] = value
                with self.assertRaises(ComponentError):auth.canonical_home_middlewares(r, e)

    def test_canonical_loop_foreign_app_and_changed_ingress_refuse(self):
        for mutate in (lambda e: e.resolved['cloud']['middlewares'].append('canonical'),
                       lambda e: e.resolved['legacy']['target'].update(app='foreign'),
                       lambda e: e.resolved['legacy']['ingress_target'].update(app='foreign')):
            with self.subTest(mutate=mutate):
                r, e = fixture();mutate(e)
                with self.assertRaises(ComponentError):auth.canonical_home_middlewares(r, e)

    def test_same_host_unused_redirect_and_canonical_origin_with_path_refuse(self):
        for mutate in (lambda r, e: e.resolved['legacy'].update(hosts=['db.example.invalid']),
                       lambda r, e: e.resolved.pop('legacy'),
                       lambda r, e: r.apps['cloud'].update(origin_url='https://db.example.invalid/browser')):
            with self.subTest(mutate=mutate):
                r, e = fixture();mutate(r, e)
                with self.assertRaises(ComponentError):auth.canonical_home_middlewares(r, e)

    def test_redirect_must_follow_the_exact_canonical_security_middleware(self):
        for rows in (['headers', 'canonical'], ['canonical', 'headers', 'clients'],
                     ['headers', 'clients', 'extra', 'canonical']):
            with self.subTest(rows=rows):
                r, e = fixture();e.resolved['legacy']['middlewares'] = rows
                with self.assertRaises(ComponentError):auth.canonical_home_middlewares(r, e)


class BindOrchestrationUnitTests(unittest.TestCase):
    def test_bind_uses_component_boundaries_once_without_revalidating_implementations(self):
        r, e = fixture()
        with patch.object(auth, 'providers', return_value={'selected': 'provider'}) as providers, \
             patch.object(auth, 'authentication', return_value={'selected': 'auth'}) as authentication, \
             patch.object(auth, 'transports', return_value={'selected': 'trust'}) as transports, \
             patch.object(auth, 'canonical_home_middlewares', return_value={'selected': 'redirect'}) as redirect:
            self.assertEqual(auth.bind(r, e), {'identity_providers': {'selected': 'provider'},
                'authentication': {'selected': 'auth'}, 'transports': {'selected': 'trust'},
                'canonical_middlewares': {'selected': 'redirect'}})
        providers.assert_called_once_with(r, e)
        authentication.assert_called_once_with(r, {'selected': 'provider'})
        transports.assert_called_once_with(r, e)
        redirect.assert_called_once_with(r, e)


if __name__ == '__main__':
    unittest.main()
