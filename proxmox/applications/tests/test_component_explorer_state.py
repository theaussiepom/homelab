"""Real scratch state; Docker, UID, platform xattrs and shared path bindings are mocked."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(os.environ.get('HOMELAB_FRAMEWORK',Path(__file__).resolve().parents[3]))
SOURCE=ROOT/'proxmox/applications'

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

s=load('mqtt_explorer_state',SOURCE/'mqtt_explorer_state.py');sys.modules['mqtt_explorer_state']=s
runtime=load('component_explorer_runtime',SOURCE/'mqtt-explorer-runtime.py')
a=load('component_explorer_account',SOURCE/'mqtt-explorer-account.py')


class StateContractTests(unittest.TestCase):
    def test_defaults_and_finite_dynamic_metadata(self):
        value=s.context();self.assertEqual(value['data_path'],s.DATA);self.assertEqual(value['custody'],s.CUSTODY)
        self.assertEqual(value['services'],s.SERVICES);self.assertEqual(s.broker_context(),s.BROKER)
        value=s.context({'project':'gui-project','runtime_id':'browser-two','data_path':'/srv/example/gui',
                         'runtime_directory':s.RUNTIME+'/browser-two','custody_directory':s.CUSTODY+'/browser-two','services':{'mqtt_explorer':'app2','explorer_gateway':'gateway2'}})
        self.assertEqual(value['custody'],s.CUSTODY+'/browser-two')
        self.assertEqual(s.broker_context({'project':'broker-project','service':'broker2','config_path':'/srv/example/broker'}),
                         {'project':'broker-project','service':'broker2','config_path':'/srv/example/broker'})

    def test_metadata_and_existing_native_fields_refuse_unsupported_input(self):
        cases=[{'foreign':True},{'project':'../bad'},{'runtime_id':'x/y'},{'services':{'mqtt_explorer':'same','explorer_gateway':'same'}},
               {'services':{'mqtt_explorer':[],'explorer_gateway':'safe'}},{'data_path':'/etc'},
               {'data_path':'/srv/example/../escape'},{'data_path':'/var/lib/homelab-inputs/private'},
               {'runtime_directory':'/tmp/runtime'},{'data_path':'/srv/a\\bad'},{'project':'${{ bad }}'}]
        for value in cases:
            with self.subTest(value=value),self.assertRaises(ValueError):s.context(value)
        for connection in ({'name':'x','hostname':'broker.example.invalid','port':8883,'username':'fixture'},
                           {'name':'x','hostname':'broker.example.invalid','port':1883,'username':'bad\nname'},
                           {'name':'x','hostname':'broker.example.invalid','port':1883,'username':'fixture','extra':True}):
            with self.subTest(connection=connection),self.assertRaises(ValueError):s.native_profile(connection,'fixture-value','existing-app')
        for value in ('', 'bad\nvalue','bad\x00value'):
            with self.assertRaises(ValueError):s.native_profile({'name':'x','hostname':'broker.example.invalid','port':1883,'username':'fixture'},value,'existing-app')


class ScratchStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.parent=self.root/'app-parent';self.parent.mkdir(mode=0o700)
        self.data=self.parent/'data';self.data.mkdir(mode=0o700)
        self.custody=self.root/'custody';self.custody.mkdir(mode=0o700)
        self.programs=self.root/'runtime';self.programs.mkdir(mode=0o700)
        self.selected={'project':'gui-project','services':{'mqtt_explorer':'app2','explorer_gateway':'gateway2'},
            'data_path':str(self.data),'runtime_directory':str(self.programs),'runtime_id':'mqtt_explorer','custody':str(self.custody)}
        self.owner={'node':'example-node','vmid':817,'hostname':'example-gui'}
        self.owners={self.data.stat().st_ino:(1001,1001)}
        def chown(fd,uid,gid):self.owners[os.fstat(fd).st_ino]=(uid,gid)
        for target,kwargs in [(s,'CUSTODY')]:
            p=patch.object(target,kwargs,str(self.custody));p.start();self.addCleanup(p.stop)
        for p in [patch.object(s,'owner',side_effect=lambda info:self.owners.get(info.st_ino,(0,0))),
                  patch.object(s.os,'fchown',side_effect=chown),patch.object(s.os,'geteuid',return_value=0),
                  patch.object(s,'context',return_value=copy.deepcopy(self.selected))]:
            p.start();self.addCleanup(p.stop)
        (self.custody/'workspace.json').write_text(json.dumps(s.workspace_document(self.owner,self.selected)));(self.custody/'workspace.json').chmod(0o600)
        self.settings={'theme':'retained','ConnectionManager_connections':{'unrelated':{'configVersion':1,'name':'Existing'}}}
        self.write_settings(self.settings)
        self.document={'schema':'homelab-mqtt-explorer-existing-profile-v1','profile_id':'mqtt_explorer',
            'connection':{'name':'Existing broker','hostname':'broker.example.invalid','port':1883,'username':'fixture-existing'},
            'password':'fixture existing scalar $ `value`'}
        self.running=True;self.commands=[];self.cid='a'*64
        self.row={'Id':self.cid,'Config':{'User':'1001:1001','Labels':{'com.docker.compose.project':'gui-project','com.docker.compose.service':'app2'}},
            'Mounts':[{'Type':'bind','Source':str(self.data),'Destination':'/app/data','RW':True}],'State':{'Running':True}}

    def write_settings(self,value):
        p=self.data/'settings.json';p.write_text(json.dumps(value));p.chmod(0o600);self.owners[p.stat().st_ino]=(1001,1001)

    def docker(self,args,*unused):
        self.commands.append(args)
        if args[0]=='ps':
            self.assertIn('label=com.docker.compose.project=gui-project',args)
            self.assertIn('label=com.docker.compose.service=app2',args)
            return self.cid+'\n'
        if args[0]=='inspect':
            row=copy.deepcopy(self.row);row['State']['Running']=self.running;return json.dumps([row])
        if args[0]=='stop':
            self.running=False;value=json.loads((self.data/'settings.json').read_text());value['flushed']=True;self.write_settings(value);return ''
        raise AssertionError('unexpected Docker mutation '+repr(args))

    def test_existing_profile_first_seed_repeat_and_readiness_preserve_unrelated_state(self):
        with patch.object(a,'account',side_effect=AssertionError('broker account forbidden')), \
             patch.object(a,'authenticate',side_effect=AssertionError('broker auth forbidden')),patch.object(a,'docker',side_effect=self.docker):
            self.assertEqual(a.profile_existing(self.document),{'saved_connection':'verified'})
            path=self.data/'settings.json';receipt=self.custody/'existing-mqtt_explorer-profile.json'
            before=(path.stat().st_ino,path.read_bytes(),receipt.stat().st_ino,receipt.read_bytes())
            self.commands.clear();self.assertEqual(a.profile_existing(self.document),{'saved_connection':'verified'});self.assertEqual(self.commands,[])
            self.assertEqual(before,(path.stat().st_ino,path.read_bytes(),receipt.stat().st_ino,receipt.read_bytes()))
        value=json.loads(path.read_text());self.assertEqual(value['theme'],'retained');self.assertTrue(value['flushed'])
        self.assertEqual(value['ConnectionManager_connections']['unrelated'],self.settings['ConnectionManager_connections']['unrelated'])
        selected=value['ConnectionManager_connections']['existing-mqtt_explorer'];self.assertEqual(selected['password'],self.document['password'])
        public={'data_path':str(self.data),'broker_connection':dict(self.document['connection'],profile_id='mqtt_explorer')}
        self.assertEqual(s.verify_existing(public),{'saved_connection':'verified'})
        self.assertFalse(any(p.name.endswith('account.json') for p in self.custody.iterdir()))
        self.assertFalse(any(p.name.endswith('HOLD.json') for p in self.custody.iterdir()))

    def test_existing_profile_password_target_and_unowned_collision_refuse(self):
        with patch.object(a,'docker',side_effect=self.docker):a.profile_existing(self.document)
        before=(self.data/'settings.json').read_bytes()
        for mutate in (lambda v:v.update(password='changed'),lambda v:v['connection'].update(username='changed'),
                       lambda v:v['connection'].update(hostname='other.example.invalid'),lambda v:v.update(image='forbidden')):
            value=copy.deepcopy(self.document);mutate(value)
            with self.subTest(mutation=repr(mutate)),patch.object(a,'docker',side_effect=AssertionError('repeat cannot mutate')),self.assertRaises(ValueError):a.profile_existing(value)
        self.assertEqual((self.data/'settings.json').read_bytes(),before)
        (self.custody/'existing-mqtt_explorer-profile.json').unlink()
        with patch.object(a,'docker',side_effect=AssertionError('collision cannot mutate')),self.assertRaises(ValueError):a.profile_existing(self.document)

    def test_interruption_holds_before_stop_and_nested_mount_refuses_before_mutation(self):
        original=self.docker
        def interrupted(args,*unused):
            if args[0]=='stop':raise RuntimeError('synthetic interruption')
            return original(args)
        with patch.object(a,'docker',side_effect=interrupted),self.assertRaises(RuntimeError):a.profile_existing(self.document)
        hold=self.custody/'existing-mqtt_explorer-PROFILE-HOLD.json';self.assertTrue(hold.is_file())
        with patch.object(a,'docker',side_effect=AssertionError('hold cannot mutate')),self.assertRaises(ValueError):a.profile_existing(self.document)
        hold.unlink();self.row['Mounts'].append({'Type':'bind','Source':'/other','Destination':'/app/data/profiles','RW':True})
        self.commands=[]
        with patch.object(a,'docker',side_effect=self.docker),self.assertRaises(ValueError):a.profile_existing(self.document)
        self.assertFalse(any(args[0]=='stop' for args in self.commands));self.assertFalse(hold.exists())

    def test_profile_seed_cannot_cross_a_workspace_owner_boundary(self):
        expected=s.native_profile(self.document['connection'],self.document['password'],'existing-mqtt_explorer')
        owned=dict(self.owner,node='foreign-node',purpose='mqtt-explorer-existing-profile')
        with self.assertRaises(ValueError):
            s.seed_profile(self.selected,expected,owned,'existing-mqtt_explorer',lambda args:(_ for _ in ()).throw(AssertionError('foreign owner cannot act')))
        self.assertFalse((self.custody/'existing-mqtt_explorer-profile.json').exists())

    def test_managed_profile_keeps_exact_native_document_receipt_and_no_broker_mutation(self):
        connection={'name':'Broker','hostname':'broker.example.invalid','port':1883,'username':'fixture_gui','credential_id':'fixture-gui',
                    'password_file':'/mosquitto/config/selected_passwords','access':'read-write-all'}
        owner=dict(self.owner,purpose='mqtt-explorer',username='fixture_gui')
        value={'connection':connection,'credential':{'schema':'homelab-application-account-v1','owner':owner,'password':'b'*64},
               'image':'example/mqtt@sha256:'+'c'*64,'runtime':{}}
        with patch.object(a,'docker',side_effect=self.docker):self.assertEqual(a.profile(value),{'saved_connection':'verified'})
        native=json.loads((self.data/'settings.json').read_text())['ConnectionManager_connections']['managed-fixture-gui']
        expected={'configVersion':1,'type':'mqtt','id':'managed-fixture-gui','name':'Broker','host':'broker.example.invalid','protocol':'mqtt',
            'port':1883,'encryption':False,'certValidation':True,'username':'fixture_gui','password':'b'*64,
            'subscriptions':[{'topic':'#','qos':0},{'topic':'$SYS/#','qos':0}]}
        self.assertEqual(native,expected)
        proof=json.loads((self.custody/'fixture-gui-profile.json').read_text())
        self.assertEqual(proof,{'owner':owner,'profile_fingerprint':a.fingerprint(json.dumps(expected,sort_keys=True),owner,'profile')})
        self.assertFalse(any(args[0] in ('kill','run') for args in self.commands))

    def test_before_and_after_ancestor_open_swaps_never_read_outside_settings(self):
        outside=self.root/'outside';outside.mkdir();(outside/'data').mkdir();foreign=outside/'data/settings.json';foreign.write_text('{"outside":"synthetic"}')
        outside_inode=foreign.stat().st_ino
        real_open=os.open;real_fdopen=os.fdopen
        for boundary in ('app-parent','data'):
            triggered=False;outside_read=False;retired=self.root/('retired-'+boundary)
            def opened(path,*args,**kwargs):
                nonlocal triggered
                if not triggered and path==boundary and 'dir_fd' in kwargs:
                    triggered=True;self.parent.rename(retired);self.parent.symlink_to(outside,target_is_directory=True)
                return real_open(path,*args,**kwargs)
            class Observed:
                def __init__(self,value):self.value=value
                def __enter__(self):self.value.__enter__();return self
                def __exit__(self,*args):return self.value.__exit__(*args)
                def fileno(self):return self.value.fileno()
                def read(self,*args):
                    nonlocal outside_read
                    if os.fstat(self.value.fileno()).st_ino==outside_inode:outside_read=True
                    return self.value.read(*args)
                def __getattr__(self,key):return getattr(self.value,key)
            with self.subTest(boundary=boundary):
                try:
                    with patch.object(s.os,'open',side_effect=opened),patch.object(s.os,'fdopen',side_effect=lambda *a,**kw:Observed(real_fdopen(*a,**kw))),patch.object(a,'docker',side_effect=self.docker):
                        with self.assertRaises((ValueError,OSError)):a.profile_existing(self.document)
                    self.assertTrue(triggered);self.assertFalse(outside_read)
                    self.assertEqual(foreign.read_text(),'{"outside":"synthetic"}')
                    self.assertFalse(any(args[0]=='stop' for args in self.commands))
                finally:
                    if self.parent.is_symlink():self.parent.unlink();retired.rename(self.parent)
                    self.commands=[]

    def test_workspace_create_repeat_and_foreign_first_use_preserve_ownership(self):
        self.assertEqual(runtime.workspace(self.owner,{}),{'workspace':'owned'})
        with self.assertRaises(ValueError):runtime.workspace(dict(self.owner,vmid=999),{})
        (self.custody/'workspace.json').unlink()
        with self.assertRaises(ValueError):runtime.workspace(self.owner,{})
        (self.data/'settings.json').unlink();self.data.rmdir()
        self.assertEqual(runtime.workspace(self.owner,{}),{'workspace':'owned'})
        self.assertEqual(s.owner(self.data.stat()),(1001,1001))
        self.assertEqual(json.loads((self.custody/'workspace.json').read_text()),s.workspace_document(self.owner,self.selected))
        self.assertEqual(runtime.workspace(self.owner,{}),{'workspace':'owned'})

    def test_managed_account_preserves_old_lines_mode_receipt_and_container(self):
        config=self.root/'broker-config';config.mkdir(mode=0o700)
        target=config/'passwd_file';before=b'old_client:$7$101$YQ==$Yg==\n';target.write_bytes(before);target.chmod(0o755)
        (config/'mosquitto.conf').write_text('allow_anonymous false\npassword_file /mosquitto/config/passwd_file\n')
        selected={'project':'broker-project','service':'broker2','config_path':str(config)}
        owner=dict(self.owner,purpose='mqtt-explorer',username='fixture_gui')
        value={'connection':{'name':'Broker','hostname':'broker.example.invalid','port':1883,'username':'fixture_gui',
            'credential_id':'fixture-gui','password_file':'/mosquitto/config/passwd_file','access':'read-write-all'},
            'credential':{'schema':'homelab-application-account-v1','owner':owner,'password':'b'*64},
            'image':'example/mqtt@sha256:'+'c'*64,'runtime':{},'broker_runtime':selected}
        cid='f'*64;commands=[];auth=[]
        row={'Id':cid,'State':{'Running':True},'Config':{'Image':value['image'],
            'Labels':{'com.docker.compose.project':'broker-project','com.docker.compose.service':'broker2'},
            'Cmd':['/usr/sbin/mosquitto','-c','/mosquitto/config/mosquitto.conf']},
            'Mounts':[{'Type':'bind','Source':str(config),'Destination':'/mosquitto/config','RW':True}]}
        def docker(args,input=None):
            commands.append(args)
            if args[0]=='ps':
                self.assertIn('label=com.docker.compose.project=broker-project',args)
                self.assertIn('label=com.docker.compose.service=broker2',args)
                return cid+'\n'
            if args[0]=='inspect':return json.dumps([row])
            if args[0]=='run':
                self.assertNotIn('b'*64,repr(args));self.assertEqual(input,'b'*64+'\n'+'b'*64+'\n')
                return 'fixture_gui:$7$101$YQ==$Yg==\n'
            if args[0]=='kill':self.assertEqual(args,['kill','--signal','HUP',cid]);return ''
            raise AssertionError('unexpected mutation '+repr(args))
        with patch.object(s,'broker_context',return_value=selected),patch.object(a,'docker',side_effect=docker), \
             patch.object(a.os,'listxattr',return_value=[],create=True),patch.object(a,'authenticate',side_effect=lambda username,password:auth.append((username,password))):
            self.assertEqual(a.account(value),{'account':'verified','broker_container_preserved':True})
            receipt=self.custody/'fixture-gui-account.json';proof=receipt.read_bytes()
            self.assertTrue(target.read_bytes().startswith(before));self.assertEqual(target.stat().st_mode&0o777,0o755)
            snapshot=(target.stat().st_ino,target.read_bytes(),receipt.stat().st_ino,proof)
            commands.clear();self.assertEqual(a.account(value),{'account':'verified','broker_container_preserved':True})
            self.assertEqual(snapshot,(target.stat().st_ino,target.read_bytes(),receipt.stat().st_ino,receipt.read_bytes()))
            self.assertFalse(any(args[0] in ('run','kill','stop') for args in commands))
            changed=copy.deepcopy(value);changed['credential']['password']='d'*64
            with self.assertRaises(ValueError):a.account(changed)
            self.assertEqual(snapshot,(target.stat().st_ino,target.read_bytes(),receipt.stat().st_ino,receipt.read_bytes()))
        self.assertTrue(auth);self.assertTrue(all(username=='fixture_gui' and password=='b'*64 for username,password in auth))

    def test_attribute_boundary_receives_anchored_descriptor_not_a_path(self):
        with patch.object(a.os,'listxattr',return_value=['user.fixture'],create=True) as listed, \
             patch.object(a.os,'getxattr',return_value=b'fixture',create=True) as fetched:
            self.assertEqual(a.attributes(self.data/'settings.json'),{'user.fixture':b'fixture'})
        self.assertIsInstance(listed.call_args.args[0],int)
        self.assertIsInstance(fetched.call_args.args[0],int)

    def test_existing_profile_cli_dispatch_does_not_call_account_or_authentication(self):
        import contextlib,io
        config=self.root/'profile.json';config.write_text(json.dumps(self.document));config.chmod(0o600)
        output=io.StringIO()
        with patch.object(sys,'argv',['helper','--config',str(config)]),patch.object(a,'docker',side_effect=self.docker), \
             patch.object(a,'account',side_effect=AssertionError('broker account forbidden')), \
             patch.object(a,'authenticate',side_effect=AssertionError('broker authentication forbidden')),contextlib.redirect_stdout(output):
            a.main()
        self.assertEqual(json.loads(output.getvalue()),{'saved_connection':'verified'})
        self.assertNotIn(self.document['password'],output.getvalue())

    def test_legacy_leaf_only_negative_control_reads_outside_after_ancestor_swap(self):
        # Exact unsafe primitive is a regression discriminator, not a supported
        # legacy account branch or a dependency on a historical checkout.
        def legacy_read(path):
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
            with os.fdopen(fd,'rb') as stream:return stream.read(1024)
        outside=self.root/'outside-control';outside.mkdir();(outside/'data').mkdir()
        foreign=outside/'data/settings.json';foreign.write_text('{"outside":"synthetic"}')
        before=self.data.lstat();self.assertTrue(before.st_mode&0o40000)
        retired=self.root/'control-retired';self.parent.rename(retired);self.parent.symlink_to(outside,target_is_directory=True)
        try:
            self.assertEqual(legacy_read(self.data/'settings.json'),foreign.read_bytes())
            with self.assertRaises(OSError):a.read(self.data/'settings.json')
        finally:
            self.parent.unlink();retired.rename(self.parent)

    def health_config(self):
        cfg={'data_path':str(self.data),'bind_address':'198.18.30.37','broker_address':'198.18.31.19',
             'broker_connection':dict(self.document['connection'],profile_id='mqtt_explorer'),
             'images':{'mqtt_explorer':'example/app@sha256:'+'a'*64,'explorer_gateway':'example/gateway@sha256:'+'b'*64},'runtime_sha256':{}}
        for name in ('explorer-traefik.json','explorer-routes.yml'):
            raw=(name+'\n').encode();p=self.programs/name;p.write_bytes(raw);p.chmod(0o400);self.owners[p.stat().st_ino]=(65532,65532)
            cfg['runtime_sha256'][name]=hashlib.sha256(raw).hexdigest()
        command=['node','-e',"process.umask(0o077);for(const level of ['log','info','debug','dir','table','trace'])console[level]=()=>{};console.warn=()=>process.stderr.write('MQTT Explorer warning\\n');console.error=()=>process.stderr.write('MQTT Explorer error\\n');require('./dist/src/server.js')"]
        rows={}
        for name,service in self.selected['services'].items():
            cid=('c' if name=='mqtt_explorer' else 'd')*64
            rows[cid]={'Id':cid,'Config':{'Labels':{'com.docker.compose.project':'gui-project','com.docker.compose.service':service},
                'Image':cfg['images'][name],'User':'1001:1001' if name=='mqtt_explorer' else '65532:65532','Cmd':command if name=='mqtt_explorer' else [],
                'Env':['MQTT_EXPLORER_SKIP_AUTH=true'] if name=='mqtt_explorer' else []},
                'State':{'Running':True,'Health':{'Status':'healthy'}},'HostConfig':{'ReadonlyRootfs':True,'NetworkMode':'gui-private',
                'ExtraHosts':['broker.example.invalid:198.18.31.19'] if name=='mqtt_explorer' else [],
                'PortBindings':{} if name=='mqtt_explorer' else {'4180/tcp':[{'HostIp':'198.18.30.37','HostPort':'80'}]}},
                'NetworkSettings':{'Networks':{'gui-private':{}}},
                'Mounts':[{'Type':'bind','Source':str(self.data),'Destination':'/app/data','RW':True}] if name=='mqtt_explorer' else []}
        def docker(args):
            if args[0]=='ps':
                wanted=args[-1].split('=',2)[-1]
                return next(cid for cid,row in rows.items() if row['Config']['Labels']['com.docker.compose.service']==wanted)+'\n'
            if args[0]=='inspect':return json.dumps([rows[args[1]]])
            raise AssertionError('health mutation forbidden')
        return cfg,rows,docker

    def test_dynamic_readiness_checks_exact_runtime_alias_and_existing_profile(self):
        with patch.object(a,'docker',side_effect=self.docker):a.profile_existing(self.document)
        cfg,rows,docker=self.health_config()
        with patch.object(runtime,'docker',side_effect=docker):
            self.assertEqual(runtime.health(cfg),{'mqtt_explorer':'passed','gateway_only_listener':True,'sign_in':'identity_provider_required'})
            rows['c'*64]['HostConfig']['ExtraHosts']=['broker.example.invalid:198.18.41.9']
            with self.assertRaises(ValueError):runtime.health(cfg)
            rows['c'*64]['HostConfig']['ExtraHosts']=['broker.example.invalid:198.18.31.19']
            saved=json.loads((self.data/'settings.json').read_text());saved['ConnectionManager_connections']['existing-mqtt_explorer']['password']='changed';self.write_settings(saved)
            with self.assertRaises(ValueError):runtime.health(cfg)



class ExplorerFileContractTests(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0,str(ROOT/'proxmox/applications'))
        self.files=load('component_explorer_file_candidate',SOURCE/'component_proxy_files.py')
        self.broker={'type':'mqtt','target':{'address':'198.18.31.19','port':1883},'hostname':'broker.example.invalid',
            'credential':{'principal':'fixture-existing','secret':'existing-password'}}
        self.app={'id':'browser','adapter':'mqtt_explorer','identity':{'services':{'mqtt_explorer':'browser2','explorer_gateway':'gateway2'},
            'runtime_directory':'/opt/homelab-app/runtime/browser2','runtime_id':'browser2'},'project_name':'gui-project',
            'origin_url':'https://gui.example.invalid','role_addresses':{'web':'198.18.30.37'},
            'settings':{'connection_name':'Broker','authentik_outpost_url':'http://198.18.30.20:9000','broker':self.broker},
            'storage_paths':{'data':{'source':'/srv/example/gui'}},'software_selection':{'images':{
                key:{'image':'example/'+key+'@sha256:'+'a'*64} for key in ('mqtt_explorer','explorer_gateway')}}}

    def test_existing_credential_file_is_separate_closed_profile_only_payload(self):
        value=b'fixture unchanged $value `literal` '
        with patch.object(Path,'open',side_effect=AssertionError('private input reads forbidden')):
            rows=self.files.files(self.app,secrets={'broker_password':value},records={},public_ca=None)
        values={row['path']:row for row in rows}
        self.assertNotIn('mqtt-explorer-account.json',values)
        document=json.loads(values['mqtt-explorer-profile.json']['content'])
        self.assertEqual(set(document),{'schema','profile_id','connection','password','runtime'})
        self.assertEqual(document['schema'],'homelab-mqtt-explorer-existing-profile-v1')
        self.assertEqual(document['password'].encode(),value)
        self.assertEqual(document['runtime'],{'project':'gui-project','services':self.app['identity']['services'],
            'runtime_directory':self.app['identity']['runtime_directory'],'runtime_id':'browser2','data_path':'/srv/example/gui'})
        self.assertEqual(values['mqtt-explorer-profile.json']['mode'],'0600')
        public=json.loads(values['mqtt-explorer-public.json']['content'])
        self.assertEqual(public['runtime_id'],'browser2');self.assertEqual(public['broker_address'],'198.18.31.19')
        self.assertNotIn(value.decode(),values['mqtt-explorer-public.json']['content'])
        routes=json.loads(values['explorer-routes.yml']['content'])
        self.assertEqual(routes['http']['services']['explorer']['loadBalancer']['servers'],[{'url':'http://browser2:3000'}])
        for extra in ({'broker_password':value,'foreign':b'x'}, {}, {'broker_password':b'bad\nvalue'}):
            with self.subTest(roles=list(extra)),self.assertRaises(ValueError):self.files.files(self.app,secrets=extra,records={},public_ca=None)

    def test_default_managed_file_bytes_match_frozen_pre_removal_wrapper(self):
        import mqtt_explorer as legacy
        self.app['identity']={'services':{'mqtt_explorer':'mqtt_explorer','explorer_gateway':'explorer_gateway'},'runtime_directory':'/opt/homelab-app/runtime'}
        self.app['project_name']='homelab-mqtt';self.app['storage_paths']['data']['source']=legacy.DATA
        self.broker.pop('credential')
        owner={'node':'example-node','vmid':817,'hostname':'example-broker','purpose':'mqtt-explorer','username':'fixture_gui'}
        selected={'credential_id':'fixture-gui','owner':owner,'credential_file':'${inputs}/managed-fixture-gui.json'}
        self.broker.update(account={'principal':'fixture_gui','access':'read-write-all'},managed_credential=selected,
            password_file='/mosquitto/config/selected_passwords',image='example/mqtt@sha256:'+'b'*64)
        record={'schema':'homelab-application-account-v1','owner':owner,'password':'c'*64}
        baseline=json.loads(Path(__file__).with_name('proxy-file-wrapper-baseline.json').read_text())['explorer_state_rows']
        rows=self.files.files(self.app,secrets={},records={'fixture-gui':record},public_ca=None)
        actual={row['path']:{'sha256':hashlib.sha256(row['content'].encode()if isinstance(row['content'],str)else row['content']).hexdigest(),
            'content_type':type(row['content']).__name__,'uid':row['uid'],'gid':row['gid'],'mode':row['mode']}for row in rows}
        self.assertEqual(actual,baseline)


if __name__=='__main__':unittest.main()
