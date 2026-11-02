"""Read-only ingress adoption: exact mirrored ownership, scope and GET-only API."""
import copy
import io
import json
from http.client import HTTPException
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
from urllib.error import HTTPError,URLError

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import discovery_scope as d
from test_foundation import fixture
import foundation


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.local=self.root/'local/service-discovery';self.mirror=self.root/'mirror/service-discovery'
        self.local.mkdir(parents=True);self.mirror.mkdir(parents=True)
        self.value={'local_directory':str(self.local),'mirror_directory':str(self.mirror),
            'owner_sha256':'a'*64,'guests':[808,809]}
        self.stack={'kind':'ingress','foundation':{'discovery_scope':self.value,'proxmox_url':'https://198.18.25.10:8006',
           'proxmox_token_id':'root@pam!discovery','pve_ca_file':'/public/ca.pem',
           'secret_files':{'proxmox_token':str(self.root/'secret')}}}
        (self.root/'secret').write_text('synthetic-token\n');(self.root/'secret').chmod(0o600)
        self.cfg={'guest':{'vmid':818,'interfaces':[{'ipv4':'198.18.25.33/24'}]},'site':{'node':'fixture-pve'}}
        self.owner={'endpoint':'https://198.18.25.10:8006/','node':'fixture-pve',
            'configuration':{'vmid':818,'address':'198.18.25.33','guests':[808,809]}}

    def test_selected_inputs_and_safe_refusals(self):
        self.assertIsNone(d.selected({'kind':'music'}));self.assertEqual(d.source_files({}),[])
        for change in [lambda s:s.update(kind='music'),lambda s:s['foundation'].update(discovery_scope=[]),
             lambda s:s['foundation']['discovery_scope'].update(local_directory='../service-discovery'),
             lambda s:s['foundation']['discovery_scope'].update(owner_sha256=[]),
             lambda s:s['foundation']['discovery_scope'].update(guests=[808,808]),
             lambda s:s['foundation']['discovery_scope'].update(guests=[True]),
             lambda s:s['foundation']['discovery_scope'].update(guests=[900])]:
            stack=copy.deepcopy(self.stack);change(stack)
            with self.assertRaises(ValueError):d.selected(stack)
        self.assertEqual(d.verify({},{}),{'status':'not_selected','writes':False})
        for url in (None,'http://198.18.25.10','https://user@198.18.25.10','https://198.18.25.10/a',
                    'https://198.18.25.10:bad','https://198.18.25.10:0'):
            with self.assertRaises(ValueError):d.origin(url)
        self.assertEqual(d.origin(self.owner['endpoint']),self.stack['foundation']['proxmox_url'])

    def test_source_files_include_both_complete_chains_without_mutation(self):
        self.assertEqual(len(d.source_files(self.stack)),6)
        for root in (self.local,self.mirror):
            (root/'scope-extensions').mkdir()
            for i in range(1,6):(root/'scope-extensions'/f'{i:04}.json').write_text('{}')
        self.assertEqual(len(d.source_files(self.stack)),16)
        bad=self.local/'scope-extensions/unbounded.json';bad.write_text('{}')
        with self.assertRaises(ValueError):d.source_files(self.stack)
        bad.unlink()
        target=self.local/'scope-extensions';saved=self.local/'retained';target.rename(saved);target.symlink_to(saved,target_is_directory=True)
        with self.assertRaises(ValueError):d.source_files(self.stack)

    def test_exact_owner_scope_node_endpoint_and_visible_configs(self):
        access=Mock();access.scope_owner.return_value=self.owner;access.owner_sha256.return_value='a'*64
        access.retained.return_value='root@pam!discovery=synthetic-token';access.identity.return_value=('user','root@pam!discovery')
        api=Mock();api.discovery.return_value.call.return_value={'data':{'hostname':'fixture'}}
        with patch.object(d,'provider',return_value=access):
            result=d.verify(self.cfg,self.stack,api)
            self.assertEqual(result['visible_guests'],2);self.assertFalse(result['writes'])
            access.verify_secret.assert_called_once()
            access.verify_secret.side_effect=ValueError('effective permission drift')
            with self.assertRaisesRegex(ValueError,'privileged bootstrap CD'):d.verify(self.cfg,self.stack,api)
            for error in (HTTPError('https://pve.example.invalid',403,'private response',{},None),URLError('transport'),TimeoutError('timeout'),HTTPException('private protocol error')):
                access.verify_secret.side_effect=error
                with self.assertRaisesRegex(ValueError,'privileged bootstrap CD'):d.verify(self.cfg,self.stack,api)
            access.verify_secret.side_effect=None
            (self.root/'secret').write_text('foreign-token')
            with self.assertRaisesRegex(ValueError,'Configured discovery'):d.verify(self.cfg,self.stack,api)
            (self.root/'secret').write_text('synthetic-token')
            self.assertEqual(api.discovery.return_value.call.call_count,2)
            for key,value in [('node','foreign'),('endpoint','https://198.18.25.11:8006/')]:
                old=self.owner[key];self.owner[key]=value
                with self.assertRaises(ValueError):d.verify(self.cfg,self.stack,api)
                self.owner[key]=old
            access.retained.return_value=None
            with self.assertRaises(ValueError):d.verify(self.cfg,self.stack,api)
            access.retained.return_value='root@pam!discovery=synthetic-token';api.discovery.return_value.call.return_value={'data':{}}
            with self.assertRaises(ValueError):d.verify(self.cfg,self.stack,api)
            api.discovery.return_value.call.return_value={'data':{'hostname':'fixture'}}
            for error in (HTTPError('https://pve.example.invalid',403,'private response',{},None),URLError('transport'),TimeoutError('timeout'),HTTPException('private protocol error'),ValueError('bad native envelope')):
                api.discovery.return_value.call.side_effect=error
                with self.assertRaisesRegex(ValueError,'declared guest is not visible'):d.verify(self.cfg,self.stack,api)
            api.discovery.return_value.call.side_effect=None
            with patch.object(d,'Reader',return_value=api):d.verify(self.cfg,self.stack)
        with patch.object(d.importlib,'import_module',return_value=SimpleNamespace(__file__='/foreign/provider_access.py')):
            with self.assertRaises(ValueError):d.provider()
        self.assertEqual(Path(d.provider().__file__).resolve(),d.BOOTSTRAP/'provider_access.py')

    def test_real_permission_verifier_malformed_data_has_safe_recovery_error(self):
        actual=d.provider();access=Mock();access.scope_owner.return_value=self.owner
        access.owner_sha256.return_value='a'*64
        access.retained.return_value='root@pam!discovery=synthetic-token'
        access.identity.return_value=('user','root@pam!discovery')
        access.verify_secret.side_effect=actual.verify_secret
        api=Mock()
        permissions={path:{'VM.Audit':0,'Sys.Audit':0}
                     for path in ('/nodes/fixture-pve','/vms/808','/vms/809')}
        malformed=[None,[]]
        for value in (1,['VM.Audit','Sys.Audit'],'private malformed value',
                      {'VM.Audit':0,'Sys.Audit':[]}):
            data=copy.deepcopy(permissions);data['/vms/808']=value;malformed.append(data)
        with patch.object(d,'provider',return_value=access):
            for data in malformed:
                with self.subTest(data_type=type(data).__name__):
                    api.discovery.return_value.call.return_value={'data':data}
                    with self.assertRaises(ValueError) as caught:d.verify(self.cfg,self.stack,api)
                    self.assertEqual(str(caught.exception),'Discovery read access is not verified; complete reviewed privileged bootstrap CD')

    def test_reader_is_get_only_verified_tls_no_redirects_and_bounded(self):
        reader=d.Reader('https://pve.example.invalid:8006/','/public/ca.pem').discovery('synthetic')
        response=Mock();response.__enter__=Mock(return_value=response);response.__exit__=Mock(return_value=False)
        response.read.return_value=b'{"data":{"hostname":"fixture"}}'
        opener=Mock();opener.open.return_value=response
        with patch.object(d.ssl,'create_default_context',return_value=object()) as tls,patch.object(d.urllib.request,'build_opener',return_value=opener):
            self.assertEqual(reader.call('/nodes/fixture-pve/lxc/808/config')['data']['hostname'],'fixture')
            tls.assert_called_once_with(cafile='/public/ca.pem')
            request=opener.open.call_args.args[0];self.assertEqual(request.get_method(),'GET')
            self.assertEqual(request.get_header('Authorization'),'PVEAPIToken=synthetic')
            for raw in (b'x'*(2*1024**2+1),b'[]'):
                response.read.return_value=raw
                with self.assertRaises(ValueError):reader.call('/access/permissions')
        with self.assertRaises(ValueError):reader.call('/nodes/fixture-pve/lxc/808/status/start')
        with self.assertRaises(ValueError):d.Reader('https://pve.invalid','/ca').call('/access/permissions')
        with self.assertRaises(ValueError):d.NoRedirect().redirect_request(None,None,302,'redirect',{},'https://other.invalid')

    def test_foundation_source_extension_is_optional_and_identity_callback_is_typed(self):
        cfg=fixture(self.root,'ingress');cfg['foundation']['discovery_scope']=self.value
        self.assertTrue(set(d.source_files(cfg)) <= set(foundation.source_files(cfg)))
        identity=fixture(self.root,'identity');identity['foundation']['allowed_callback_additions']=[]
        with self.assertRaises(ValueError):foundation.validate(identity)


if __name__=='__main__':unittest.main()
