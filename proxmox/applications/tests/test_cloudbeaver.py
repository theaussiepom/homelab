"""Closed Community rendering and authentication configuration, without private inputs."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cloudbeaver as c
import render
import foundation


def fixture():
    return {'kind': 'db-tools', 'variant': 'cloudbeaver', 'guest_memory_mib': 2048,
        'cloudbeaver': {'bind_address': '198.18.30.32', 'public_url': 'https://db.example.invalid',
          'server_name': 'Database Tools', 'recovery_admin': 'recovery_admin', 'heap_mib': 1024,
          'auth_headers': {'user': 'X-User', 'team': 'X-Team'},
          'connections': {'postgresql': {'name': 'PostgreSQL', 'driver': 'postgresql', 'database': 'postgres',
              'sslmode': 'prefer', 'host': '198.18.31.23', 'port': 5432},
            'mariadb': {'name': 'MariaDB', 'driver': 'mariadb', 'database': '', 'host': '198.18.32.24', 'port': 3306}},
          'retained_pgadmin_image': 'dpage/pgadmin4@sha256:' + 'a'*64},
        'foundation': {'version': 1, 'oidc_issuer': 'https://sso.example.invalid/application/o/database/',
          'oauth_client_id': 'fixture-client', 'oauth_name': 'Sign in', 'user_claim': 'preferred_username',
          'secret_files': {'oauth_client_secret': '/private/oauth-secret'}},
        'services': {k: {'image': 'example.invalid/' + k + '@sha256:' + 'b'*64, 'memory_mib': m,
                    'cpus': 1, 'pids_limit': 128, 'environment': {}}
                    for k, m in [('cloudbeaver',1536),('auth_gateway',128)]}}


class CloudBeaverTests(unittest.TestCase):
    def test_legacy_variant_and_other_kinds_remain_explicit(self):
        self.assertFalse(c.selected({'kind':'db-tools'}))
        self.assertFalse(c.selected({'kind':'music'}))
        self.assertIsNone(c.validate({'kind':'db-tools'}))
        for value in ({'kind':'music','variant':'cloudbeaver'}, {'kind':'db-tools','variant':[]},
                      {'kind':'db-tools','cloudbeaver':{}}):
            with self.assertRaises(ValueError):c.validate(value)

    def test_closed_input_refusals(self):
        mutations = [lambda v:v.update(cloudbeaver=None), lambda v:v['cloudbeaver'].update(extra=True),
          lambda v:v['cloudbeaver'].update(bind_address=None),lambda v:v['cloudbeaver'].update(bind_address='127.0.0.1'),
          lambda v:v['cloudbeaver'].update(server_name='bad\nname'),lambda v:v['cloudbeaver'].update(recovery_admin='oidc.admin'),
          lambda v:v['cloudbeaver'].update(heap_mib=True),lambda v:v['cloudbeaver'].update(auth_headers={'user':'X-User','team':'x-user'}),
          lambda v:v['cloudbeaver'].update(auth_headers={'user':'X-Forwarded-For','team':'X-Team'}),
          lambda v:v['cloudbeaver'].update(retained_pgadmin_image='latest'),lambda v:v['cloudbeaver'].update(connections=[]),
          lambda v:v['cloudbeaver']['connections'].update(bad={'driver':[]}),
          lambda v:v['cloudbeaver']['connections']['postgresql'].update(password='never'),
          lambda v:v['cloudbeaver']['connections']['postgresql'].update(sslmode='verify-ca'),
          lambda v:v['cloudbeaver']['connections']['postgresql'].update(port=3306),lambda v:v.update(services={}),
          lambda v:v['services']['cloudbeaver'].update(environment={'ADMIN_PASSWORD':'never'}),
          lambda v:v['services']['cloudbeaver'].update(memory_mib=1024)]
        for mutate in mutations:
            value=fixture();mutate(value)
            with self.subTest(value=value),self.assertRaises(ValueError):c.validate(value)
        for url in (None,'http://db.example.invalid','https://user@db.example.invalid','https://[bad',
                    'https://db.example.invalid:bad','https://db.example.invalid:0','https://db.example.invalid/a',
                    'https://db.example.invalid/?bad','https://db.example.invalid/\\bad'):
            with self.subTest(url=url),self.assertRaises(ValueError):c.https(url)
        self.assertEqual(c.https('https://db.example.invalid/'),'https://db.example.invalid')
        self.assertEqual(c.https('https://sso.example.invalid/app/',issuer=True),'https://sso.example.invalid/app/')

    def test_oidc_contract_and_domain_separated_private_files(self):
        cfg=fixture();self.assertIs(foundation.validate(cfg),cfg['foundation'])
        self.assertEqual(foundation.source_files(cfg),['/private/oauth-secret'])
        for change in ({'user_claim':[]},{'version':2},{'oauth_name':'bad\nname'}):
            value=fixture();value['foundation'].update(change)
            with self.assertRaises(ValueError):foundation.validate(value)
        for secret in (b'x',b'a'*32+b'\n',b'a'*32+b'\x00'):
            with self.assertRaises(ValueError):c.derive(secret,'cookie')
        secret=b'fixture-secret-entropy-not-production'*2
        self.assertNotEqual(c.derive(secret,'session-cookie'),c.derive(secret,'local-recovery'))
        files=c.files(cfg,secret);rows={r['path']:r for r in files}
        self.assertEqual(len(rows),8)
        self.assertTrue(all(r['mode']=='0400' for r in files))
        self.assertNotIn(secret.decode(),rows['cloudbeaver-public.json']['content'])
        self.assertIn(secret.decode(),rows['oauth2-alpha.json']['content'])
        self.assertNotIn(secret.decode(),rows['oauth2.cfg']['content'])
        doc=json.loads(rows['cloudbeaver-connections.json']['content'])
        self.assertEqual(doc['connections']['postgresql']['configuration']['properties'],{'sslmode':'prefer'})
        self.assertEqual(doc['connections']['mariadb']['configuration']['database'],'')
        self.assertNotIn('password',doc['connections']['postgresql'])
        unresolved=copy.deepcopy(cfg['cloudbeaver']);unresolved['connections']['mariadb'].pop('host');unresolved['connections']['mariadb'].pop('port')
        with self.assertRaises(ValueError):c.connection_document(unresolved)
        cfg['cloudbeaver']['connections'] = unresolved['connections']
        self.assertIsNotNone(c.validate(cfg))

    def test_gateway_strips_every_auth_header_and_namespaces_verified_user(self):
        cfg=fixture();cfg['cloudbeaver']['auth_headers']={'user':'X-Custom-User','team':'X-Custom-Team'}
        alpha,toml=c.gateway(cfg['cloudbeaver'],cfg['foundation'],b'a'*64)
        rows={r['name']:r for r in alpha['injectRequestHeaders']}
        self.assertEqual(set(rows),set(c.HEADERS)|{'X-Custom-User','X-Custom-Team'})
        self.assertTrue(all(r['preserveRequestValue'] is False for r in rows.values()))
        self.assertEqual(rows['X-Custom-User']['values'],[{'claimSource':{'claim':'preferred_username','prefix':'oidc.'}}])
        self.assertEqual(rows['X-Custom-Team']['values'],[{'secretSource':{'value':'user'}}])
        self.assertEqual(rows['X-Role-TE']['values'],[])
        self.assertIn('cookie_secure = true',toml);self.assertIn('cookie_samesite = "lax"',toml)
        self.assertNotIn('cookie_domains',toml);self.assertNotIn('insecure',toml)

    def test_compose_only_gateway_publishes_and_database_bridge_can_egress(self):
        cfg=fixture();before=copy.deepcopy(cfg);doc=render.compose(cfg)
        self.assertEqual(cfg,before)
        self.assertNotIn('ports',doc['services']['cloudbeaver'])
        self.assertEqual(doc['services']['auth_gateway']['ports'],['198.18.30.32:80:4180'])
        self.assertEqual(doc['networks'],{'database_tools':{}})
        self.assertEqual(doc['services']['cloudbeaver']['user'],'8978:8978')
        self.assertIn('/opt/cloudbeaver/conf/CloudBeaverHealth.java',doc['services']['cloudbeaver']['healthcheck']['test'])
        self.assertEqual(doc['services']['auth_gateway']['depends_on'],{'cloudbeaver':{'condition':'service_healthy'}})
        self.assertNotIn('secret',json.dumps(doc))


if __name__=='__main__':unittest.main()
