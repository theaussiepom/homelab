"""Synthetic two-stage radio lifecycle; no PVE, SSH or USB is contacted."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_zigbee2mqtt import DEVICE


class UsbLifecycleTests(unittest.TestCase):
    def cfg(self):
        return {'site':{'node':'practice-pve'},
                'guest':{'vmid':6101,'hostname':'radio','serial_device':{'path':DEVICE},
                         'started':True,'start_on_boot':True},
                'app':{'kind':'zigbee2mqtt','usb_stage':'prepare'}}

    def test_initial_variables_never_attach_usb_or_boot_the_guest(self):
        import zigbee_usb as usb
        cfg=self.cfg(); original=copy.deepcopy(cfg)
        self.assertEqual(usb.guest_variables(cfg),dict(cfg['guest'],serial_device=None,started=False,start_on_boot=False))
        self.assertEqual(cfg,original)
        cfg['app']['usb_stage']='attached'
        self.assertEqual(usb.guest_variables(cfg),cfg['guest'])

    def plan(self, actions, before, after):
        return {'resource_changes':[{'address':'module.guest.proxmox_virtual_environment_container.guest',
                  'change':{'actions':actions,'before':before,'after':after,'after_unknown':{}}}]}

    def test_preparation_requires_fresh_stopped_creation_and_attached_phase_never_writes_devices(self):
        import zigbee_usb as usb
        cfg=self.cfg(); stopped={'started':False,'start_on_boot':False,'device_passthrough':[]}
        usb.check_plan(self.plan(['create'],None,stopped),cfg)
        for bad in (dict(stopped,started=True),dict(stopped,start_on_boot=True),
                    dict(stopped,device_passthrough=[usb.desired(cfg)])):
            with self.assertRaises(ValueError):usb.check_plan(self.plan(['create'],None,bad),cfg)
        with self.assertRaises(ValueError):usb.check_plan(self.plan(['update'],stopped,stopped),cfg)
        cfg['app']['usb_stage']='attached'
        before=dict(stopped,device_passthrough=[usb.desired(cfg)])
        usb.check_plan(self.plan(['update'],before,dict(before,started=True)),cfg)
        known=self.plan(['no-op'],before,before)
        known['resource_changes'][0]['change']['after_unknown']={'device_passthrough':[{}]}
        usb.check_plan(known,cfg)
        known['resource_changes'][0]['change']['after_unknown']={'device_passthrough':[{'path':True}]}
        with self.assertRaises(ValueError):usb.check_plan(known,cfg)
        for old,new in ((stopped,before),(before,stopped),(None,before),
                        (before,dict(before,device_passthrough=[dict(usb.desired(cfg),gid=0)]))):
            with self.assertRaises(ValueError):usb.check_plan(self.plan(['update'],old,new),cfg)

    def live(self):
        return {'hostname':'radio','unprivileged':1,'protection':1,'digest':'a'*40,
                'dev0':'path='+DEVICE+',uid=0,gid=20,mode=0660,deny-write=0'}

    def test_live_readback_refuses_extra_devices_ownership_or_protection_drift(self):
        import zigbee_usb as usb
        cfg=self.cfg();cfg['app']['usb_stage']='attached'
        with patch.object(usb,'read_live',return_value=(self.live(),{'status':'running'})):
            usb.verify_live(cfg,lambda *_:None)
        for change in ({'dev1':'/dev/other'},{'unprivileged':0},{'protection':0},
                       {'hostname':'other'},{'dev0':'path='+DEVICE+',uid=0,gid=0,mode=0660'}):
            live=dict(self.live(),**change)
            with patch.object(usb,'read_live',return_value=(live,{'status':'stopped'})),self.assertRaises(ValueError):
                usb.verify_live(cfg,lambda *_:None)

    def test_runner_state_lineage_cannot_be_replaced_between_stages(self):
        import zigbee_usb as usb
        cfg=self.cfg()
        with tempfile.TemporaryDirectory() as tmp:
            work=Path(tmp);state=work/'terraform.tfstate'
            state.write_text(json.dumps({'lineage':'runner-owned','serial':1}))
            receipt=usb.prepared_receipt(cfg,state)
            (work/'usb-prepared.json').write_text(json.dumps(receipt))
            usb.require_prepared(cfg,work)
            for lineage,serial in [('different-owner',2),('runner-owned',0)]:
                state.write_text(json.dumps({'lineage':lineage,'serial':serial}))
                with self.assertRaises(ValueError):usb.require_prepared(cfg,work)

    def test_host_attachment_is_one_digest_guarded_edit_with_exact_readback(self):
        import zigbee_usb as usb
        cfg=self.cfg();request={'node':'practice-pve','vmid':6101,'hostname':'radio','path':DEVICE,
                               'exclusive_writer_confirmed':True,'native_action_approved':True}
        live=self.live();live.pop('dev0');calls=[]
        def command(args):
            calls.append(args)
            if args[1]=='set':
                live['dev0']=args[args.index('--dev0')+1];live['digest']='b'*40
                return ''
            return json.dumps({'status':'stopped'} if args[2].endswith('/status/current') else live)
        device=lambda _: {'resolved':'/dev/ttyACM0','major':166,'minor':0,'uid':0,'gid':20,'mode':'0660'}
        plan=usb.host_plan(request,command,device)
        usb.host_apply(request,plan['plan_sha256'],command,device)
        writes=[x for x in calls if x[1]=='set']
        self.assertEqual(len(writes),1)
        self.assertIn('--digest',writes[0]);self.assertNotIn('--protection',writes[0])
        self.assertEqual(live['protection'],1)
        with self.assertRaises(ValueError):usb.host_apply(request,'0'*64,command,device)

    def test_host_plan_refuses_wrong_target_extra_device_and_missing_human_inputs(self):
        import zigbee_usb as usb
        request={'node':'practice-pve','vmid':6101,'hostname':'radio','path':DEVICE,
                 'exclusive_writer_confirmed':True,'native_action_approved':True}
        for change in ({'vmid':900},{'path':'/dev/*'},{'native_action_approved':False},
                       {'node':True},{'node':1234}):
            with self.assertRaises(ValueError):usb.validate_request(dict(request,**change))
        def run(args):return json.dumps({'status':'running'} if args[2].endswith('/status/current') else self.live())
        with self.assertRaises(ValueError):usb.host_plan(request,run,lambda _: {})


class UsbOperatorTests(unittest.TestCase):
    def test_timeout_holds_the_operator_attempt_and_never_copies_state_or_replays(self):
        import subprocess
        import zigbee_usb_operator as operator
        request={'node':'practice-pve','vmid':6101,'hostname':'radio','path':DEVICE,
                 'exclusive_writer_confirmed':True,'native_action_approved':True}
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'tofu').mkdir()
            (root/'tofu/site.auto.tfvars.json').write_text(json.dumps({'site':{
                'node':'practice-pve','api_endpoint':'https://pve.example.invalid:8006/'}}))
            key=root/'operator-key';key.write_text('synthetic only')
            hosts=root/'known_hosts';hosts.write_text('synthetic host key only')
            state=root/'tofu/terraform.tfstate';state.write_text('synthetic state must remain on its owner')
            reply=type('Result',(),{'returncode':0,'stderr':'','stdout':json.dumps({'request':request,'plan_sha256':'1'*64})})
            with patch.object(operator,'authenticated_revision',return_value='1'*40),patch.object(operator.subprocess,'run',return_value=reply) as run:
                operator.execute(root,request,key,hosts,revision='1'*40)
                args=run.call_args.args[0]
                self.assertIn('root@pve.example.invalid',args)
                self.assertIn('StrictHostKeyChecking=yes',args)
                self.assertNotIn(state.read_text(),' '.join(args))
                self.assertEqual(state.read_text(),'synthetic state must remain on its owner')
            with patch.object(operator,'authenticated_revision',return_value='1'*40),patch.object(operator.subprocess,'run',side_effect=subprocess.TimeoutExpired('ssh',120)),self.assertRaises(subprocess.TimeoutExpired):
                operator.execute(root,request,key,hosts,'1'*64,revision='1'*40)
            self.assertTrue((root/'zigbee-usb-HOLD-6101.json').exists())
            with patch.object(operator,'authenticated_revision',return_value='1'*40),patch.object(operator.subprocess,'run') as run,self.assertRaises(ValueError):
                operator.execute(root,request,key,hosts,'1'*64,revision='1'*40)
            run.assert_not_called()

    def test_operator_authenticates_the_reviewed_commit_and_exact_executed_files(self):
        import subprocess
        import zigbee_usb_operator as operator
        revision='1'*40;repo=operator.HERE.parents[1]
        for mode in ('trusted','wrong-head','unsigned','untrusted','dirty'):
            def git(args,**kwargs):
                if args[1:]==['rev-parse','--show-toplevel']:return str(repo)+'\n'
                if args[1:]==['rev-parse','HEAD']:return ('2'*40 if mode=='wrong-head' else revision)+'\n'
                if args[1]=='verify-commit':
                    if mode=='unsigned':raise subprocess.CalledProcessError(1,args)
                    return b''
                if args[1]=='log':return 'U\n' if mode=='untrusted' else 'G\n'
                if args[1]=='show':
                    relative=args[2].split(':',1)[1]
                    return b'modified code' if mode=='dirty' else (repo/relative).read_bytes()
                raise AssertionError(args)
            with self.subTest(mode=mode),patch.object(operator.subprocess,'check_output',side_effect=git):
                if mode=='trusted':self.assertEqual(operator.authenticated_revision(revision),revision)
                else:
                    with self.assertRaises((ValueError,subprocess.CalledProcessError)):operator.authenticated_revision(revision)
        with self.assertRaises(ValueError):operator.authenticated_revision('main')


class UsbRunnerTests(unittest.TestCase):
    def test_same_runner_state_moves_from_stopped_prepare_to_refreshed_attached_apply(self):
        import hashlib,io,tarfile
        import deploy,zigbee_usb
        from test_deploy import fixture as site_fixture
        from test_plan import fixture as plan_fixture
        from test_zigbee2mqtt import fixture,state
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cfg=site_fixture(root);stack=fixture();files=state()
            stack['zigbee']['bind_address']=cfg['app']['address']
            stack['zigbee']['state_sha256']={n:hashlib.sha256(v).hexdigest() for n,v in files.items()}
            path=root/'stack.json';path.write_text(json.dumps(stack))
            capture=root/'capture.tar'
            with tarfile.open(capture,'w') as archive:
                for name,data in files.items():
                    member=tarfile.TarInfo('zigbee2mqtt/'+name);member.size=len(data);archive.addfile(member,io.BytesIO(data))
            cfg['guest'].update(serial_device={'path':DEVICE},started=True,start_on_boot=True)
            cfg['guest']['interfaces'][0]['role']='backend'
            cfg['app'].update(kind='zigbee2mqtt',usb_stage='prepare',stack_config=str(path),
                capture={'path':str(capture),'coherent':True,'sha256':deploy.sha(capture)})
            cfg['ssh_public_keys']=[];(root/'api').write_text('synthetic');(root/'ca').write_text('synthetic')
            site=root/'site.json';site.write_text(json.dumps(cfg));work=root/'state/6101'
            value=plan_fixture()
            for row in value['resource_changes']:
                key='vm_id' if row['type']=='proxmox_virtual_environment_container' else 'container_id'
                row['change']['after'].update({key:6101,'node_name':'practice-pve'})
                if row['address']==zigbee_usb.RESOURCE:
                    row['change']['after'].update(started=False,start_on_boot=False,device_passthrough=[])
            def quiet(args,*_):
                for arg in args:
                    if arg.startswith('-out='):Path(arg[5:]).write_bytes(b'synthetic plan')
                if 'apply' in args:(work/'terraform.tfstate').write_text(json.dumps({'lineage':'same-runner','serial':1}))
            with patch.object(deploy,'backup'),patch.object(deploy,'quiet',side_effect=quiet), \
                    patch.object(deploy.subprocess,'check_output',side_effect=lambda *_,**__:json.dumps(value).encode()), \
                    patch.object(deploy,'api_get') as api:
                first=deploy.execute('plan',site)
                variables=json.loads((work/'tofu/site.auto.tfvars.json').read_text())
                self.assertIsNone(variables['guest']['serial_device']);self.assertFalse(variables['guest']['started'])
                deploy.execute('apply',site,first['plan_sha256']);api.assert_not_called()
                with self.assertRaises(ValueError):deploy.execute('stage',site)
                with self.assertRaises(deploy.InputNeeded):deploy.execute('deploy',site,first['plan_sha256'])
                cfg['app']['usb_stage']='attached';site.write_text(json.dumps(cfg))
                live={'hostname':cfg['guest']['hostname'],'unprivileged':1,'protection':1,
                      'dev0':'path='+DEVICE+',uid=0,gid=20,mode=0660,deny-write=0'}
                api.side_effect=lambda _cfg,url: {'status':'stopped'} if url.endswith('/status/current') else live
                for row in value['resource_changes']:
                    row['change']['actions']=['update'];row['change']['before']=copy.deepcopy(row['change']['after'])
                    if row['address']==zigbee_usb.RESOURCE:
                        row['change']['before']['device_passthrough']=[zigbee_usb.desired(cfg)]
                        row['change']['after'].update(device_passthrough=[zigbee_usb.desired(cfg)],started=True,start_on_boot=True)
                final=deploy.execute('plan',site)
                deploy.execute('apply',site,final['plan_sha256'])
                self.assertEqual(json.loads((work/'terraform.tfstate').read_text())['lineage'],'same-runner')
                self.assertEqual(final['usb_stage'],'attached')
                self.assertEqual(json.loads((work/'tofu/site.auto.tfvars.json').read_text())['guest']['serial_device'],{'path':DEVICE})

