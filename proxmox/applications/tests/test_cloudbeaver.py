"""Pure Community protocol/JDBC contracts; no fixed guest-kind wrapper."""
import base64
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import cloudbeaver as c
from protocol_component_fixtures import cloudbeaver_app


def app():
    return cloudbeaver_app({'oidc_issuer':'https://sso.example.invalid/application/o/database/',
        'oauth_client_id':'fixture-client','oauth_name':'Sign in','user_claim':'preferred_username'},
        {'public_url':'https://db.example.invalid'},image='example.invalid/cloudbeaver@sha256:'+'b'*64,
        gateway_image='example.invalid/gateway@sha256:'+'b'*64)


def endpoints():
    return {**{name:'https://sso.example.invalid/oidc/'+path for name,path in (
        ('authorization_url','authorize'),('token_url','token'),('userinfo_url','userinfo'),('jwks_url','jwks'))},
        'signing_algorithms':['RS256']}


class CommunityProtocolTests(unittest.TestCase):
    def test_domain_separated_keys_preserve_private_secret_validation(self):
        secret=b'fixture-secret-entropy-not-production'*2
        self.assertNotEqual(c.derive(secret,'session-cookie'),c.derive(secret,'local-recovery'))
        self.assertEqual(len(c.derive(secret,'session-cookie')),32)
        for bad in (b'x',b'a'*32+b'\n',b'a'*32+b'\x00',b'',b' '*64,b'x'*65537):
            with self.subTest(length=len(bad)),self.assertRaises(ValueError):c.derive(bad,'cookie')

    def test_gateway_strips_every_auth_header_and_namespaces_verified_user(self):
        value=app();value['settings']['auth_headers']={'user':'X-Custom-User','team':'X-Custom-Team'}
        alpha,toml=c.gateway(value['settings'],value['authentication_resolved'],b'a'*64)
        rows={row['name']:row for row in alpha['injectRequestHeaders']}
        self.assertEqual(set(rows),set(c.HEADERS)|{'X-Custom-User','X-Custom-Team'})
        self.assertTrue(all(row['preserveRequestValue']is False for row in rows.values()))
        self.assertEqual(rows['X-Custom-User']['values'],[{'claimSource':{'claim':'preferred_username','prefix':'oidc.'}}])
        self.assertEqual(rows['X-Custom-Team']['values'],[{'secretSource':{'value':'user'}}])
        self.assertEqual(rows['X-Role-TE']['values'],[])
        self.assertIn('cookie_secure = true',toml);self.assertIn('cookie_samesite = "lax"',toml)
        self.assertNotIn('cookie_domains',toml);self.assertNotIn('insecure',toml)

    def test_explicit_endpoints_preserve_nonce_pkce_claim_and_discovery_output(self):
        value=app();secret=b'a'*64
        original=c.gateway(value['settings'],value['authentication_resolved'],secret)
        alpha,options=original
        self.assertEqual(alpha['providers'][0]['oidcConfig'],{
            'issuerURL':value['authentication_resolved']['oidc_issuer'],'insecureSkipNonce':False})
        value['authentication_resolved']['oidc_endpoints']=endpoints()
        explicit,explicit_options=c.gateway(value['settings'],value['authentication_resolved'],secret)
        provider=explicit['providers'][0]
        self.assertEqual(provider['oidcConfig'],{**alpha['providers'][0]['oidcConfig'],
            'skipDiscovery':True,'jwksURL':endpoints()['jwks_url'],'enabledSigningAlgs':['RS256']})
        self.assertEqual({key:provider[key]for key in('loginURL','redeemURL','profileURL')},
            dict(loginURL=endpoints()['authorization_url'],redeemURL=endpoints()['token_url'],profileURL=endpoints()['userinfo_url']))
        self.assertEqual(explicit_options,options)
        self.assertEqual(explicit['injectRequestHeaders'],alpha['injectRequestHeaders'])
        self.assertEqual(provider['code_challenge_method'],'S256')
        value['authentication_resolved'].pop('oidc_endpoints')
        self.assertEqual(c.gateway(value['settings'],value['authentication_resolved'],secret),original)

    def test_metadata_connections_are_password_free_and_require_resolved_engine_listener(self):
        value=app()['settings'];doc=c.connection_document(value)
        self.assertEqual(doc['connections']['postgresql']['configuration']['properties'],{'sslmode':'prefer'})
        self.assertEqual(doc['connections']['mariadb']['configuration']['database'],'')
        self.assertNotIn('password',doc['connections']['postgresql'])
        self.assertFalse(doc['connections']['postgresql']['save-password'])
        for change in ('host','port'):
            bad=copy.deepcopy(value)
            if change=='host':bad['connections']['postgresql'].pop('host')
            else:bad['connections']['postgresql']['port']=3306
            with self.assertRaises(ValueError):c.connection_document(bad)

    def test_configuration_keeps_closed_trust_and_enables_saved_credentials_only_when_selected(self):
        value=app()['settings'];original=c.configuration(value)
        self.assertFalse(original['app']['anonymousAccessEnabled'])
        self.assertFalse(original['app']['adminCredentialsSaveEnabled'])
        self.assertEqual(original['app']['enabledAuthProviders'],['local','reverseProxy'])
        self.assertTrue(original['server']['forceHttps'])
        value['managed_connections']={'one':{'driver':'postgresql'}}
        current=c.configuration(value)
        self.assertTrue(current['app'].pop('adminCredentialsSaveEnabled'))
        self.assertTrue(current['app'].pop('secretManagerEnabled'))
        original['app'].pop('adminCredentialsSaveEnabled')
        self.assertEqual(current,original)

    def test_jdbc_vendor_artifact_is_closed_and_only_selected_for_managed_maria(self):
        value=app()['settings'];self.assertIsNone(c.jdbc(value))
        value['managed_connections']={'maria':{'driver':'mariadb'}}
        artifact={'version':'3.5.11','sha256':'42604178b9e57ec08ee0035079961516f086e455d0141f0b22c6eff29fb2fff4',
                  'image_filename':'mariadb-java-client-3.5.10.jar'}
        value['mariadb_jdbc']=artifact
        actual=c.jdbc(value)
        self.assertTrue(actual['url'].startswith('https://repo.maven.apache.org/maven2/org/mariadb/jdbc/mariadb-java-client/3.5.11/'))
        self.assertEqual(actual['target'],'/opt/cloudbeaver/drivers/mariadb/mariadb-java-client-3.5.10.jar')
        for changes in ({'version':'3.5.10'},{'version':'3.6.0'},{'sha256':'bad'},
                        {'image_filename':'../other.jar'},{'foreign':True}):
            bad=copy.deepcopy(value);bad['mariadb_jdbc'].update(changes)
            with self.subTest(changes=changes),self.assertRaises(ValueError):c.jdbc(bad)
        value.pop('managed_connections')
        with self.assertRaises(ValueError):c.jdbc(value)


if __name__=='__main__':unittest.main()
