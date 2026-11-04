"""Mocked caller boundaries and real synthetic mirrored receipt relationships."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

F=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(F/'proxmox/applications'),str(F/'proxmox/applications/tests')]
import discovery_scope as old_discovery
import deployment_state


class DiscoveryCallerTests(unittest.TestCase):
    def setUp(self):
        import component_discovery, runtime_secrets
        self.scope=old_discovery;self.runtime=runtime_secrets;self.caller=component_discovery
        self.cfg={'deployment':{'protected_guests':[9900]},'site':{'api_endpoint':'https://198.18.25.10:8006/','node':'fixture-pve'},
                  'paths':{'ca_file':'/public/context.pem'},'guest':{'vmid':818,'interfaces':[{'ipv4':'198.18.25.33/24'}]}}
        self.value={'local_directory':'/var/lib/example/service-discovery','mirror_directory':'/backup/example/service-discovery','owner_sha256':'a'*64,'guests':[818,808]}
        self.app={'adapter':'traefik','settings':{'provider':{'url':'https://198.18.25.10:8006','ca_file':'/public/context.pem','token_id':'root@pam!homelab-traefik-818','discovery':self.value}}}
        self.raw=json.dumps({'schema':'homelab-service-discovery-v1','identity':'root@pam!homelab-traefik-818','token':'root@pam!homelab-traefik-818=synthetic-token'}).encode()
    def test_component_unit_delegates_same_context_and_full_owned_token_once(self):
        api=Mock();expected={'status':'verified','writes':False}
        with patch.object(deployment_state,'bootstrap_closed')as markers,patch.object(self.scope,'verify_selection',return_value=expected)as verify:
            result=self.caller.verify(self.cfg,self.app,self.raw,api)
        markers.assert_called_once_with(Path('/var/lib/example'))
        self.assertEqual(verify.call_args.args,(self.cfg,self.value));kw=verify.call_args.kwargs
        self.assertEqual(kw['read_configured'](),'root@pam!homelab-traefik-818=synthetic-token');self.assertEqual(kw['endpoint'],'https://198.18.25.10:8006');self.assertEqual(kw['ca_file'],'/public/context.pem');self.assertIs(kw['api'],api)
        self.assertEqual(result,expected)
    def test_context_mismatch_refuses_before_any_reader(self):
        for field in ('url','ca_file'):
            app=copy.deepcopy(self.app);app['settings']['provider'][field]='https://198.18.25.11:8006'if field=='url'else'/foreign.pem'
            with self.subTest(field=field),patch.object(self.scope,'verify_selection')as reader,self.assertRaises(ValueError):self.caller.verify(self.cfg,app,self.raw)
            reader.assert_not_called()
    def test_bootstrap_hold_refuses_before_token_parse_or_provider_api(self):
        with patch.object(deployment_state,'bootstrap_closed',side_effect=ValueError('held')),patch.object(self.scope,'verify_selection')as reader,patch.object(self.runtime,'retained_provider_token')as parser,self.assertRaises(ValueError):self.caller.verify(self.cfg,self.app,self.raw)
        reader.assert_not_called();parser.assert_not_called()
    def test_unknown_adapter_scope_duplicate_and_foreign_token_refuse(self):
        cases=[]
        app=copy.deepcopy(self.app);app['adapter']='mqtt';cases.append((app,self.raw))
        app=copy.deepcopy(self.app);app['settings']['provider']['discovery']['guests']=[818,818];cases.append((app,self.raw))
        value=json.loads(self.raw);value['identity']='foreign@pam!token';cases.append((self.app,json.dumps(value).encode()))
        cases.extend((self.app,raw)for raw in (b'',b'x'*65537,b'raw-token'))
        for app,raw in cases:
            with self.subTest(length=len(raw)),patch.object(deployment_state,'bootstrap_closed'),patch.object(self.scope,'verify_selection',side_effect=lambda *a,**kw:kw['read_configured']())as reader,self.assertRaises(ValueError):self.caller.verify(self.cfg,app,raw)
            if app['adapter']!='traefik' or app['settings']['provider']['discovery']['guests']==[818,818] or not raw or len(raw)>65536:reader.assert_not_called()
    def test_omitted_scope_preserves_not_selected_without_claiming_privilege(self):
        app=copy.deepcopy(self.app);app['settings']['provider'].pop('discovery')
        with patch.object(deployment_state,'bootstrap_closed')as markers,patch.object(self.scope,'verify_selection')as reader:
            self.assertEqual(self.caller.verify(self.cfg,app,self.raw),{'status':'not_selected','writes':False})
        reader.assert_not_called();markers.assert_not_called()
    def test_real_synthetic_owner_chain_ready_token_and_effective_permission_relationship(self):
        access=self.scope.provider()
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);local=root/'local/service-discovery';remote=root/'remote/service-discovery'
            for folder in (local,remote):folder.mkdir(parents=True,mode=0o700)
            c={'node':'fixture-pve','endpoint':'https://198.18.25.10:8006/',
               'applications':[{'vmid':818},{'vmid':808},{'vmid':809}],
               'service_discovery':{'vmid':818,'address':'198.18.25.33','guests':[818,808]}}
            previous=access.owner(c);following=copy.deepcopy(previous);following['configuration']['guests'].append(809)
            record=json.loads(self.raw)
            def save(path,value):path.write_text(json.dumps(value,sort_keys=True)+'\n');path.chmod(0o600)
            for folder in (local,remote):
                save(folder/'owner.json',previous);save(folder/'token.json',record);save(folder/'READY.json',{'schema':access.SCHEMA,'status':'ready'})
                (folder/'scope-extensions').mkdir(mode=0o700)
                save(folder/'scope-extensions/0001.json',{'schema':access.EXTENSION_SCHEMA,'previous_owner_sha256':access.owner_sha256(previous),'owner':following})
            app=copy.deepcopy(self.app);app['settings']['provider']['discovery']={'local_directory':str(local),'mirror_directory':str(remote),'owner_sha256':access.owner_sha256(following),'guests':[818,808,809]}
            class API:
                def __init__(self):self.paths=[]
                def discovery(self,token):
                    if token!=record['token']:raise AssertionError('foreign token')
                    return self
                def call(self,path):
                    self.paths.append(path)
                    if path=='/access/permissions':return{'data':{p:{'VM.Audit':0,'Sys.Audit':0}for p in ('/nodes/fixture-pve','/vms/818','/vms/808','/vms/809')}}
                    if path in ('/nodes/fixture-pve/lxc/818/config','/nodes/fixture-pve/lxc/808/config','/nodes/fixture-pve/lxc/809/config'):return{'data':{'hostname':'fixture'}}
                    raise AssertionError('foreign API route')
            before={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()for p in root.rglob('*')if p.is_file()};api=API()
            result=self.caller.verify(self.cfg,app,self.raw,api)
            self.assertEqual(result,{'status':'verified','owned_scope':True,'effective_permissions':True,'visible_guests':3,'writes':False})
            self.assertEqual(api.paths,['/access/permissions','/nodes/fixture-pve/lxc/818/config','/nodes/fixture-pve/lxc/808/config','/nodes/fixture-pve/lxc/809/config'])
            after={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()for p in root.rglob('*')if p.is_file()};self.assertEqual(before,after)
            save(remote/'READY.json',{'schema':access.SCHEMA,'status':'incomplete'})
            api=API()
            with self.assertRaises(ValueError):self.caller.verify(self.cfg,app,self.raw,api)
            self.assertEqual(api.paths,[])
    def test_real_bootstrap_markers_are_not_readiness_exceptions(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);local=root/'local/service-discovery';local.mkdir(parents=True)
            app=copy.deepcopy(self.app);app['settings']['provider']['discovery']['local_directory']=str(local)
            for name in ('BOOTSTRAP-CD-HOLD.json','CONFIGURING','.CONFIGURING.pending'):
                marker=local.parent/name;marker.write_text('retained')
                with self.subTest(name=name),patch.object(self.scope,'verify_selection')as reader,self.assertRaises(ValueError):self.caller.verify(self.cfg,app,self.raw)
                reader.assert_not_called();marker.unlink()
    def test_no_fabricated_legacy_stack_is_passed_to_the_shared_primitive(self):
        with patch.object(deployment_state,'bootstrap_closed'),patch.object(self.scope,'verify_selection',return_value={'writes':False})as primitive:
            self.caller.verify(self.cfg,self.app,self.raw,Mock())
        args=primitive.call_args;self.assertIs(args.args[0],self.cfg);self.assertNotIn('kind',self.app);self.assertNotIn('foundation',self.app)


if __name__=='__main__':unittest.main()
