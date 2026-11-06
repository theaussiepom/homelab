"""Real protocol shapes and idempotent, non-destructive owned host updates."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import monitoring_configure as setup


class FakeAPI:
    def __init__(self):
        self.hosts = {};self.calls = [];self.password = 'zabbix';self.groups = []

    def __call__(self, method, params):
        self.calls.append((method, copy.deepcopy(params)))
        if method == 'user.login':
            if params['password'] != self.password:raise ValueError('Authentication refused')
            return 'synthetic-session'
        if method == 'user.logout':return True
        if method == 'configuration.import':
            assert not any('deleteMissing' in r for r in params['rules'].values())
            return True
        if method == 'template.get':return [{'host': n, 'templateid': str(i)} for i, n in enumerate(params['filter']['host'], 10)]
        if method == 'hostgroup.get':return copy.deepcopy(self.groups)
        if method == 'hostgroup.create':self.groups = [{'groupid':'1'}];return {'groupids':['1']}
        if method == 'host.get':return [copy.deepcopy(self.hosts[n]) for n in params['filter']['host'] if n in self.hosts]
        if method == 'host.create':
            name = params['host'];identifier = str(len(self.hosts) + 1)
            self.hosts[name] = {'hostid': identifier, 'description': params['description'], 'parentTemplates': params['templates'],
                                'macros': [{'hostmacroid': identifier+'-'+str(i), 'macro': m['macro'], 'type': str(m.get('type', 0))}
                                           for i,m in enumerate(params.get('macros', []))]}
            return {'hostids':[identifier]}
        if method == 'host.update':
            row = next(r for r in self.hosts.values() if r['hostid'] == params['hostid'])
            row.update(description=params['description'], parentTemplates=params['templates'])
            return {'hostids':[row['hostid']]}
        if method == 'user.get':return [{'userid':'1'}]
        if method == 'user.update':self.password=params['passwd'];return {'userids':['1']}
        if method in {'usermacro.update','usermacro.create'}:return {'hostmacroids':['synthetic']}
        raise AssertionError(method)


def value():
    return {'owner': {'node':'fixture-pve','vmid':216,'hostname':'zabbix'},
            'admin_password':'a'*64,'templates':[{'zabbix_export':{'version':'7.0'}}],
            'members':[{'hostname':'fixture-208','psk_identity':'fixture-208','psk':'1'*64,
                        'profiles':['linux','postgresql']},
                       {'hostname':'fixture-206','psk_identity':'fixture-206','psk':'2'*64,
                        'profiles':['linux','mysql']},
                       {'hostname':'fixture-204','psk_identity':'fixture-204','psk':'3'*64,
                        'profiles':['linux','influxdb'],'url':'http://198.18.33.26:8086'},
                       {'hostname':'fixture-216','psk_identity':'fixture-216','psk':'4'*64,
                        'profiles':['linux','docker']}],
            'proxmox':{'hostname':'fixture-pve','endpoint':'https://198.18.25.10:8006/',
                       'token_id':'fixture@pve!monitoring','token_secret':'synthetic-token'}}


class ConfigureTests(unittest.TestCase):
    def test_first_and_repeat_preserve_keys_and_history_and_reject_unknown_ownership(self):
        with tempfile.TemporaryDirectory() as td:
            receipt=Path(td)/'owner.json';api=FakeAPI();v=value()
            self.assertTrue(setup.configure(api,v,receipt)['first_install'])
            self.assertEqual(api.password,v['admin_password'])
            api.calls.clear()
            self.assertFalse(setup.configure(api,v,receipt)['first_install'])
            self.assertFalse(any(m in {'host.create','user.update'} for m,_ in api.calls))
            self.assertTrue(all('tls_psk' not in p for m,p in api.calls if m=='host.update'))
            self.assertTrue(all('macros' not in p for m,p in api.calls if m=='host.update'))
            self.assertFalse(any(m=='usermacro.update' and p.get('type')==1 for m,p in api.calls))
            self.assertEqual(len(api.hosts),5)
            before=copy.deepcopy(api.hosts)
            for bad in ['owner','key','template','server-owner']:
                changed=copy.deepcopy(v)
                if bad=='owner':api.hosts['fixture-208']['description']='foreign'
                elif bad=='key':changed['members'][0]['psk']='f'*64
                elif bad=='template':api.hosts['fixture-208']['parentTemplates']=[{'templateid':'foreign'}]
                else:changed['owner']['vmid']=217
                with self.subTest(fault=bad),self.assertRaises(ValueError):setup.configure(api,changed,receipt)
                api.hosts=copy.deepcopy(before)

    def test_missing_template_and_duplicate_host_group_refuse_without_a_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            for fault in ['template','group']:
                api=FakeAPI();v=value();receipt=Path(td)/(fault+'.json')
                def call(method,params):
                    if method=='template.get' and fault=='template':return []
                    if method=='hostgroup.get' and fault=='group':return [{'groupid':'1'},{'groupid':'2'}]
                    return api(method,params)
                with self.assertRaises(ValueError):setup.configure(call,v,receipt)
                self.assertFalse(receipt.exists())
                self.assertEqual(api.hosts,{})

    def test_logout_failure_does_not_hide_success_or_actual_failure(self):
        with tempfile.TemporaryDirectory() as td:
            api=FakeAPI()
            def call(method,params):
                if method=='user.logout':raise OSError('fixture logout')
                return api(method,params)
            self.assertTrue(setup.configure(call,value(),Path(td)/'owner.json')['configured'])

    def test_guest_local_api_cannot_select_a_remote_destination(self):
        self.assertEqual(setup.API().endpoint,'http://127.0.0.1:8081/api_jsonrpc.php')
        for invalid in [True,0,80,65536,'remote']:
            with self.assertRaises(ValueError):setup.API(invalid)
        with self.assertRaises(ValueError):setup.RefuseRedirects().redirect_request(None,None,302,'',{},'http://remote/')

class TransportAndRefusalTests(unittest.TestCase):
    def setUp(self):
        import os
        before=os.umask(0o077);os.umask(before)
        self.addCleanup(os.umask,before)

    def test_transport_bounds_errors_and_credentials_for_public_methods(self):
        from contextlib import nullcontext
        from unittest.mock import Mock
        api=setup.API();api.token='private-session'
        for method,body,length,accepted in [('apiinfo.version',{'result':'7.0.32'},None,True),
                ('user.login',{'result':'session'},100,True),('host.get',{'result':[]},100,True),
                ('host.get',{'error':{'code':-1,'data':'private-error'}},100,False),
                ('host.get',{'result':[]},4_000_001,False)]:
            response=Mock();response.length=length;response.read.return_value=json.dumps(body).encode()
            api.opener=Mock();api.opener.open.return_value=nullcontext(response)
            if accepted:api(method,{})
            else:
                with self.assertRaises(ValueError):api(method,{})
            request=api.opener.open.call_args.args[0]
            self.assertEqual(request.get_header('Authorization') is not None,method not in {'apiinfo.version','user.login'})
            self.assertNotIn('private-error',json.dumps(api.last_error))
        response.length=None;response.read.return_value=b'x'*4_000_001
        with self.assertRaises(ValueError):api('host.get',{})

    def test_receipts_refuse_symlinks_public_modes_and_hardlinks(self):
        import os
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);receipt=root/'owner.json';api=FakeAPI();v=value()
            setup.configure(api,v,receipt)
            self.assertEqual(receipt.stat().st_mode & 0o777,0o600)
            link=root/'linked';link.symlink_to(receipt)
            with self.assertRaises(ValueError):setup.configure(api,v,link)
            receipt.chmod(0o644)
            with self.assertRaises(ValueError):setup.configure(api,v,receipt)
            receipt.chmod(0o600);os.link(receipt,root/'second-name')
            with self.assertRaises(ValueError):setup.configure(api,v,receipt)

    def test_factory_host_and_macro_drift_are_closed_and_retained_secrets_are_not_replayed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);api=FakeAPI();v=value()
            def call(method,params):
                if method=='host.get' and params['filter']['host']==['Zabbix server']:return [{'hostid':'10084'}]
                if method=='host.update' and params['hostid']=='10084':return {'hostids':['10084']}
                return api(method,params)
            setup.configure(call,v,root/'owner.json')
            api.hosts['fixture-pve']['macros']=[]
            setup.configure(api,v,root/'owner.json')
            self.assertTrue(any(m=='usermacro.create' and p.get('type')==1 for m,p in api.calls))
            api.hosts['fixture-pve']['macros']=[{'hostmacroid':'1','macro':'{$PVE.TOKEN.SECRET}','type':'0'}]
            with self.assertRaises(ValueError):setup.configure(api,v,root/'owner.json')
            def foreign(method,params):
                if method=='host.get' and params['filter']['host']==['Zabbix server']:return [{'hostid':'foreign'}]
                return api(method,params)
            with self.assertRaises(ValueError):setup.configure(foreign,v,root/'foreign.json')

    def test_cli_readiness_uses_bounded_reads_and_safe_failure_output(self):
        from unittest.mock import Mock,patch
        v=value()
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'input.json';path.write_text(json.dumps(v))
            api=Mock(side_effect=[OSError('startup'), '7.0.32'])
            with patch.object(sys,'argv',['configure','--input',str(path)]),patch.object(setup,'API',return_value=api),patch.object(setup.time,'sleep'),patch.object(setup,'configure',return_value={'configured':True}) as configure,patch('builtins.print'):
                setup.main();configure.assert_called_once()
            api=Mock(side_effect=OSError('private transport error'))
            with patch.object(sys,'argv',['configure','--input',str(path)]),patch.object(setup,'API',return_value=api),patch.object(setup.time,'monotonic',side_effect=[0,121]),self.assertRaises(SystemExit) as error:
                setup.main()
            self.assertNotIn('private transport error',str(error.exception))

    def test_script_entrypoint_refuses_incomplete_inputs_without_external_error_details(self):
        import runpy
        from unittest.mock import patch,Mock
        from contextlib import nullcontext
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'input.json';path.write_text('{}')
            response=Mock();response.length=None;response.read.return_value=b'{"result":"7.0.32"}'
            opener=Mock();opener.open.return_value=nullcontext(response)
            with patch.object(sys,'argv',['configure','--input',str(path)]),patch('urllib.request.build_opener',return_value=opener),self.assertRaises(SystemExit) as error:
                runpy.run_path(setup.__file__,run_name='__main__')
            self.assertIn('preserve the current guest attempt',str(error.exception))

    def test_actual_transport_carries_the_authenticated_session_through_configuration(self):
        from unittest.mock import Mock
        from contextlib import nullcontext
        backend=FakeAPI();api=setup.API()
        def open_request(request,timeout):
            payload=json.loads(request.data)
            response=Mock();response.length=None
            response.read.return_value=json.dumps({'result':backend(payload['method'],payload['params'])}).encode()
            if payload['method'] not in {'user.login','apiinfo.version'}:
                self.assertEqual(request.get_header('Authorization'),'Bearer synthetic-session')
            return nullcontext(response)
        api.opener=Mock();api.opener.open.side_effect=open_request
        with tempfile.TemporaryDirectory() as td:
            self.assertTrue(setup.configure(api,value(),Path(td)/'owner.json')['configured'])
