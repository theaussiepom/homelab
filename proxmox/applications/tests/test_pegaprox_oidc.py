"""Settings ownership, private transport, idempotence and failed-apply recovery."""
import copy
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pegaprox_oidc as host
import pegaprox_oidc_client as client
import component_private_inputs
import application_contract
import component_prepare
from component_pegaprox_fixture import descriptor, guest
import component_runtime
from private_io import encoded, write_new


def configuration():
    return {'settings': {**client.FIXED, 'oidc_enabled': True, 'oidc_client_id': 'fixture',
        'oidc_authority': 'https://sso.example.invalid/application/o/manager/',
        'oidc_redirect_uri': 'https://manager.example.invalid/oidc/callback',
        'oidc_username_claim': 'preferred_username', 'oidc_button_text': 'Sign in with Identity',
        'oidc_group_mappings': [{'group_id': 'Managers', 'role': 'admin'}], 'oidc_allow_private_ip': True},
        'oidc_endpoints': {**{key:'https://sso.example.invalid/'+key for key in client.ENDPOINTS},
                           'signing_algorithms':['RS256']},
        'client_secret':'synthetic-client-value','management_token':'pgx_synthetic-management-value'}


class SettingsAPI:
    def __init__(self):
        self.value = configuration()
        self.current = {'smtp_host':'preserve.example.invalid','ldap_enabled':False}
        self.writes = []
        self.discovery = {'issuer':self.value['settings']['oidc_authority'],
            **{field:self.value['oidc_endpoints'][key] for key,field in client.ENDPOINTS.items()},
            'id_token_signing_alg_values_supported':['RS256']}

    def request(self, url, *, token=None, data=None, public=False):
        if 'well-known' in url:
            assert token is None
            return self.discovery
        if public:
            return {'initialized':True,'authenticated':False,'oidc_enabled':self.current['oidc_enabled']}
        assert token == self.value['management_token']
        if data is not None:
            self.writes.append(copy.deepcopy(data))
            self.current.update(data)
            self.current['oidc_client_secret'] = '********'
            return {'success':True}
        return copy.deepcopy(self.current)


class Reconciliation(unittest.TestCase):
    def test_first_repeat_drift_and_missing_secret_preserve_unowned_settings(self):
        api = SettingsAPI()
        with patch.object(client,'request',side_effect=api.request):
            self.assertEqual(client.reconcile(api.value), {'changed':True})
            self.assertEqual(client.reconcile(api.value,applied=True), {'changed':False})
            api.current['oidc_skip_ssl_verify'] = True
            self.assertEqual(client.reconcile(api.value,applied=True), {'changed':True})
            self.assertEqual(api.writes[-1], {'oidc_skip_ssl_verify':False})
            api.current['oidc_client_secret'] = ''
            client.reconcile(api.value,applied=True)
        self.assertEqual(api.writes[-1], {'oidc_client_secret':'synthetic-client-value'})
        self.assertEqual(api.current['smtp_host'],'preserve.example.invalid')
        self.assertFalse(api.current['ldap_enabled'])
        self.assertTrue(all(set(row) <= set(api.value['settings']) | {'oidc_client_secret'} for row in api.writes))

    def test_disable_does_not_require_available_identity_provider(self):
        api = SettingsAPI();api.value['settings']['oidc_enabled'] = False
        with patch.object(client,'request',side_effect=api.request) as call:
            self.assertTrue(client.reconcile(api.value)['changed'])
        self.assertFalse(any('well-known' in c.args[0] for c in call.call_args_list))

    def test_untrusted_discovery_refuses_before_settings_write(self):
        for key,value in [('issuer','https://foreign.invalid/'), ('token_endpoint','https://foreign.invalid/'),
                          ('id_token_signing_alg_values_supported',['HS256'])]:
            api = SettingsAPI();api.discovery[key] = value
            with patch.object(client,'request',side_effect=api.request), self.assertRaises(ValueError):
                client.reconcile(api.value)
            self.assertEqual(api.writes,[])

    def test_failed_write_or_readback_is_not_success(self):
        for responses in ([{}, {'success':False}], [{}, {'success':True}, {}],
                          [dict(configuration()['settings'],oidc_client_secret='********'),
                           {'initialized':False,'authenticated':False,'oidc_enabled':False}]):
            value = configuration();value['settings']['oidc_enabled'] = False
            with patch.object(client,'request',side_effect=responses), self.assertRaises(ValueError):
                client.reconcile(value,applied=len(responses)==2)

    def test_closed_runtime_configuration_refuses_unsafe_inputs(self):
        changes = [lambda v:v.update(extra=True),lambda v:v['settings'].update(domain='other'),
            lambda v:v['settings'].update(oidc_skip_jwt_verification=True),
            lambda v:v['settings'].update(oidc_enabled=1),
            lambda v:v['settings'].update(oidc_client_id='a'*257),
            lambda v:v['settings'].update(oidc_username_claim='sub'),
            lambda v:v['settings'].update(oidc_authority='http://sso.invalid/'),
            lambda v:v['settings'].update(oidc_redirect_uri='https://manager.invalid/wrong'),
            lambda v:v['settings'].update(oidc_group_mappings=[]),
            lambda v:v['settings'].update(oidc_group_mappings=[{}]),
            lambda v:v['settings'].update(oidc_group_mappings=[{'group_id':'a','role':'root'}]),
            lambda v:v['settings'].update(oidc_group_mappings=[{'group_id':'a','role':'admin'},{'group_id':'A','role':'user'}]),
            lambda v:v['oidc_endpoints'].update(extra='unknown'),
            lambda v:v['oidc_endpoints'].update(token_url='https://foreign.invalid/token'),
            lambda v:v['oidc_endpoints'].update(signing_algorithms=['none']),
            lambda v:v['oidc_endpoints'].update(signing_algorithms=[]),
            lambda v:v.update(client_secret='********'),lambda v:v.update(management_token='wrong'),
            lambda v:v.update(management_token='pgx_same',client_secret='pgx_same')]
        for change in changes:
            value=configuration();change(value)
            with self.subTest(change=change),self.assertRaises(ValueError):client.validate(value)
        for value in ('',None,' trailing ','line\n','nul\x00'):
            with self.assertRaises(ValueError):client.scalar(value)
        for url in ('https://user@host/', 'https://host/?query', 'https://host/#fragment', 'https://host/\\path'):
            with self.assertRaises(ValueError):client.https(url)

    def test_http_transport_refuses_redirects_errors_and_large_or_nonobject_responses(self):
        with self.assertRaises(ValueError):client.NoRedirect().redirect_request(None)
        for code,body,accepted in [(200,b'{}',True),(401,b'{}',True),(500,b'{}',False),
                                   (200,b'[]',False),(200,b'x'*1048577,False)]:
            response=io.BytesIO(body);response.code=code
            with patch.object(client,'build_opener') as build:
                build.return_value.open.return_value=response
                if accepted:
                    self.assertEqual(client.request('http://127.0.0.1/',token='pgx_synthetic',data={},public=True),{})
                    self.assertEqual(build.return_value.open.call_args.args[0].headers['Authorization'],'Bearer pgx_synthetic')
                else:
                    with self.assertRaises(ValueError):client.request('http://127.0.0.1/')
        from urllib.error import HTTPError
        with patch.object(client,'build_opener') as build:
            build.return_value.open.side_effect=HTTPError('http://localhost/',401,'unauthorized',{},io.BytesIO(b'{}'))
            self.assertEqual(client.request('http://localhost/',public=True),{})

    def test_client_cli_redacts_errors_and_returns_only_change_status(self):
        for value,code in [({'configuration':configuration(),'applied':False},0),({'private':'do-not-log'},1)]:
            out,err=io.StringIO(),io.StringIO()
            with patch('sys.stdin',io.StringIO(json.dumps(value))),patch('sys.stdout',out),patch('sys.stderr',err),\
                 patch.object(client,'reconcile',return_value={'changed':False}):
                self.assertEqual(client.main(),code)
            self.assertNotIn('do-not-log',out.getvalue()+err.getvalue())
        with patch('sys.stdin',io.StringIO('{}')),patch('sys.stderr',io.StringIO()),self.assertRaises(SystemExit) as stopped:
            runpy.run_path(client.__file__,run_name='__main__')
        self.assertEqual(stopped.exception.code,1)


class ProtectedHost(unittest.TestCase):
    def test_runtime_materialization_preserves_opaque_database_key_and_declares_generated_receipt(self):
        app=descriptor();config=configuration()
        app['authentication_resolved']={**config,'client_secret':'reference','management_token':'other-reference'}
        values={'database_key':b'\x00\xffopaque','client_secret':config['client_secret'].encode(),
                'management_token':config['management_token'].encode()}
        rows=component_private_inputs.bind(app,values)['files']
        self.assertEqual(rows[0]['content'],values['database_key'])
        self.assertEqual(json.loads(rows[1]['content']),config)
        app['runtime_files']={'app':app['id'],'directory':app['identity']['runtime_directory'],
                              'files':sorted(application_contract.runtime_files(app))}
        payload={};installed=component_prepare.install_rows(app,rows,payload)
        self.assertEqual(len(installed),2)
        self.assertNotIn('pegaprox-oidc-applied.json',payload)
        app['resolved_connections']={'identity':{'hostname':'sso.example.invalid','target':{'address':'198.18.25.33'}}}
        self.assertEqual(component_runtime._pegaprox(app,guest())['pegaprox']['extra_hosts'],{'sso.example.invalid':'198.18.25.33'})

    def test_success_record_repeat_configuration_change_and_failure_retry(self):
        with tempfile.TemporaryDirectory() as root:
            config=Path(root)/'pegaprox-oidc.json';compose=Path(root)/'compose.yml'
            write_new(config,encoded(configuration()))
            calls=[]
            def execute(argv,**kwargs):
                self.assertNotIn(configuration()['client_secret'],str(argv))
                calls.append(json.loads(kwargs['input']))
                return SimpleNamespace(returncode=0,stdout=b'{"changed":false}')
            with patch.object(host.subprocess,'run',side_effect=execute):
                host.reconcile(config,compose,'manager')
                host.reconcile(config,compose,'manager')
            self.assertFalse(calls[0]['applied']);self.assertTrue(calls[1]['applied'])
            receipt=config.with_name('pegaprox-oidc-applied.json');before=receipt.read_bytes()
            self.assertEqual(receipt.stat().st_mode & 0o777,0o600)
            value=configuration();value['settings']['oidc_button_text']='Changed button';config.write_bytes(encoded(value))
            with patch.object(host.subprocess,'run',return_value=SimpleNamespace(returncode=1)),self.assertRaises(ValueError):
                host.reconcile(config,compose,'manager')
            self.assertEqual(receipt.read_bytes(),before)
            with patch.object(host.subprocess,'run',side_effect=execute):host.reconcile(config,compose,'manager')
            self.assertFalse(calls[-1]['applied'])
            with self.assertRaises(ValueError):host.reconcile(config,compose,'different-owner')

    def test_paths_malformed_response_and_cli_fail_closed(self):
        with self.assertRaises(ValueError):host.reconcile(Path('relative'),Path('/compose.yml'),'service')
        with tempfile.TemporaryDirectory() as root:
            config=Path(root)/'pegaprox-oidc.json';write_new(config,encoded(configuration()))
            with patch.object(host.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=b'{}')),self.assertRaises(ValueError):
                host.reconcile(config,Path('/compose.yml'),'service')
            self.assertFalse(config.with_name('pegaprox-oidc-applied.json').exists())
        for failure in (False,True):
            with patch.object(host,'reconcile',side_effect=ValueError('secret-value') if failure else None,
                              return_value={'changed':True}),patch('sys.stdout',io.StringIO()) as out,patch('sys.stderr',io.StringIO()) as err:
                self.assertEqual(host.main(['--config','/owned/pegaprox-oidc.json','--compose','/compose.yml','--service','service']),int(failure))
                self.assertNotIn('secret-value',out.getvalue()+err.getvalue())
        with patch('sys.argv',['pegaprox_oidc.py','--config','/absent/pegaprox-oidc.json',
                '--compose','/compose.yml','--service','service']),patch('sys.stderr',io.StringIO()),\
                self.assertRaises(SystemExit) as stopped:
            runpy.run_path(host.__file__,run_name='__main__')
        self.assertEqual(stopped.exception.code,1)
