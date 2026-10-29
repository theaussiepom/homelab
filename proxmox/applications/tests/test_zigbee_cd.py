"""Exercise the actual radio CD phases without PVE, SSH, USB or services."""
import copy,json
from datetime import datetime,timedelta,timezone
from pathlib import Path
import tempfile,unittest
from unittest.mock import Mock,patch
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import zigbee_cd as cd
from test_zigbee2mqtt import fixture,DEVICE
from test_deploy import fixture as site_fixture

class InitialRadioCD(unittest.TestCase):
    def config(self,root,mode='prepare'):
        cfg=site_fixture(root);stack=fixture();cfg['guest'].update(serial_device={'path':DEVICE},started=True,start_on_boot=True)
        cfg['guest']['interfaces'][0]['role']='backend';stack['zigbee']['bind_address']=cfg['app']['address']
        cfg['app'].update(kind='zigbee2mqtt',radio_cd_mode=mode,usb_stage='prepare' if mode=='prepare' else 'attached',
            radio_creation_approved=mode=='prepare',exclusive_writer_confirmed=mode!='prepare',
            capture={'path':str(root/'capture.tar'),'coherent':True,'sha256':'1'*64})
        path=root/'stack.json';path.write_text(json.dumps(stack));cfg['app']['stack_config']=str(path)
        return cfg,stack

    def test_prepare_is_available_without_USB_or_first_admission_and_cannot_start_apps(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg,stack=self.config(Path(tmp));cd.validate(cfg,stack)
            for change in [{'usb_stage':'attached'},{'radio_creation_approved':False},
                           {'zigbee_admission':{}},{'zigbee_first_start_approval':{}}]:
                with self.subTest(change=change),self.assertRaises(ValueError):cd.validate(dict(cfg,app=dict(cfg['app'],**change)),stack)

    def test_first_start_requires_the_actual_external_restore_and_selected_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg,stack=self.config(Path(tmp),'first-start')
            with self.assertRaises(ValueError):cd.validate(cfg,stack)
            current=datetime.now(timezone.utc)
            stamp=lambda value:value.strftime('%Y-%m-%dT%H:%M:%SZ')
            cfg['app']['zigbee_first_start_approval']={'schema':1,'approved':True,'capture_sha256':'1'*64,
                'selection_sha256':cd.zigbee2mqtt.fingerprint(stack['zigbee']),'restore_receipt_sha256':'2'*64,
                'exclusive_writer_window':{'id':'reviewed','confirmed':True,'not_before':stamp(current-timedelta(minutes=1)),'expires_at':stamp(current+timedelta(hours=1))}}
            cd.validate(cfg,stack)
            expired=copy.deepcopy(cfg);expired['app']['zigbee_first_start_approval']['exclusive_writer_window']['expires_at']=stamp(current-timedelta(seconds=1))
            with self.assertRaises(ValueError):cd.validate(expired,stack)
            bad=copy.deepcopy(cfg);bad['app']['zigbee_first_start_approval']['restore_receipt_sha256']=None
            with self.assertRaises(ValueError):cd.validate(bad,stack)

    def test_workflow_calls_the_shared_creation_engine_and_only_first_start_has_application_phase(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for mode,action in [('prepare','radio-prepare'),('attached','radio-attach'),('first-start','radio-attach')]:
                cfg,_=self.config(root,mode)
                with patch.object(cd.ordinary_cd,'prepare',return_value=(cfg,root/'site.json')),patch.object(cd.deploy,'execute',return_value={'passed':True}) as call:
                    cd.run('infrastructure',root/'packet');call.assert_called_once_with(action,root/'site.json')
                    if mode!='first-start':
                        with self.assertRaises(ValueError):cd.run('application',root/'packet')

    def test_low_level_CD_dispatch_runs_under_existing_workflow_hold_checks(self):
        import deploy
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cfg,_=self.config(root);site=root/'site.json';site.write_text(json.dumps(cfg))
            with patch.object(cd,'initial',return_value={'status':'prepared'}) as initial:
                self.assertEqual(deploy.execute('radio-prepare',site),{'status':'prepared'});initial.assert_called_once()
                work=root/'state/6101';(work/'ROLLOUT-HOLD.json').write_text('{}')
                with self.assertRaises(ValueError):deploy.execute('radio-prepare',site)
                self.assertEqual(initial.call_count,1)

class InitialTransactions(unittest.TestCase):
    config=InitialRadioCD.config
    def setUp(self):
        self.environment=patch.dict(cd.os.environ,{'GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'1'});self.environment.start();self.addCleanup(self.environment.stop)
    def test_successful_stopped_creation_retains_creation_metadata_and_repeat_is_no_target(self):
        import types,deploy,zigbee_usb
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cfg,_=self.config(root);site=root/'site.json';site.write_text(json.dumps(cfg));work=root/'work';work.mkdir(mode=0o700);calls=[]
            def step(action,site,plan):
                calls.append(action)
                if action=='plan':
                    deploy.write(work/'plan.json',{'plan_sha256':'1'*64});return {'plan_sha256':'1'*64}
                deploy.write(work/'apply-window.json',{'plan_sha256':'1'*64,'started_at_ns':1,'finished_at_ns':2})
                deploy.write(work/'terraform.tfstate',{'lineage':'original-runner','serial':1})
                deploy.write(work/'usb-prepared.json',zigbee_usb.prepared_receipt(cfg,work/'terraform.tfstate'))
                return {'status':'passed'}
            engine=types.SimpleNamespace(sha=deploy.sha,source_hash=lambda:'reviewed-source',input_hashes=lambda _: {},check_radio_capture=Mock(),write=deploy.write,sync_directory=deploy.sync_directory,_execute_step=step)
            result=cd.initial('radio-prepare',site,cfg,work,engine=engine);self.assertTrue(result['guest_stays_stopped']);self.assertEqual(calls,['plan','apply']);self.assertEqual((work/'usb-creation/apply-window.json').read_bytes(),(work/'apply-window.json').read_bytes());self.assertFalse((work/'ROLLOUT-HOLD.json').exists())
            result=cd.initial('radio-prepare',site,cfg,work,engine=engine);self.assertFalse(result['changed']);self.assertFalse(result['target_contacted']);self.assertEqual(calls,['plan','apply'])
            deploy.write(work/'terraform.tfstate',{'lineage':'foreign','serial':2})
            with self.assertRaises(ValueError):cd.initial('radio-prepare',site,cfg,work,engine=engine)
            self.assertEqual(calls,['plan','apply'])

    def test_failed_apply_preserves_the_existing_rollout_hold_and_no_completion(self):
        import types,deploy
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cfg,_=self.config(root);site=root/'site.json';site.write_text(json.dumps(cfg));work=root/'work';work.mkdir(mode=0o700)
            def step(action,*_):
                if action=='plan':return {'plan_sha256':'1'*64}
                raise ValueError('Unconfirmed native result')
            engine=types.SimpleNamespace(sha=deploy.sha,source_hash=lambda:'reviewed-source',input_hashes=lambda _: {},check_radio_capture=Mock(),write=deploy.write,sync_directory=deploy.sync_directory,_execute_step=step)
            with self.assertRaises(ValueError):cd.initial('radio-prepare',site,cfg,work,engine=engine)
            self.assertTrue((work/'ROLLOUT-HOLD.json').exists());self.assertFalse((work/'radio-prepare-radio-prepare-complete.json').exists())

    def test_attached_apply_pins_from_preserved_creation_window_not_the_updated_plan(self):
        import types,deploy,zigbee_usb
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cfg,_=self.config(root);site=root/'site.json';site.write_text(json.dumps(cfg));work=root/'work';work.mkdir(mode=0o700);serial=[0]
            def step(action,site,plan):
                if action=='plan':deploy.write(work/'plan.json',{'plan_sha256':str(serial[0]+1)*64});return {'plan_sha256':str(serial[0]+1)*64}
                serial[0]+=1;deploy.write(work/'apply-window.json',{'started_at_ns':serial[0],'finished_at_ns':serial[0]+1});deploy.write(work/'terraform.tfstate',{'lineage':'same-runner','serial':serial[0]})
                if serial[0]==1:deploy.write(work/'usb-prepared.json',zigbee_usb.prepared_receipt(cfg,work/'terraform.tfstate'))
                return {'status':'passed'}
            def pin(cfg,evidence,*_):
                self.assertEqual(json.loads((evidence/'apply-window.json').read_text())['started_at_ns'],1)
                self.assertEqual(json.loads((work/'apply-window.json').read_text())['started_at_ns'],2)
            identity=types.SimpleNamespace(pin=Mock(side_effect=pin))
            engine=types.SimpleNamespace(sha=deploy.sha,source_hash=lambda:'source',input_hashes=lambda _: {},check_radio_capture=Mock(),write=deploy.write,sync_directory=deploy.sync_directory,_execute_step=step,guest_identity=identity,api_get=Mock())
            cd.initial('radio-prepare',site,cfg,work,engine=engine)
            cfg,_=self.config(root,'attached');site.write_text(json.dumps(cfg))
            result=cd.initial('radio-attach',site,cfg,work,engine=engine);self.assertFalse(result['application_started']);identity.pin.assert_called_once();self.assertEqual(json.loads((work/'terraform.tfstate').read_text())['lineage'],'same-runner')

class ActualInitialPreparation(unittest.TestCase):
    config=InitialRadioCD.config
    def test_actual_packet_preparer_accepts_only_explicit_initial_radio_capture(self):
        import hashlib,io,tarfile,types
        import ordinary_cd,zigbee_ordinary,deploy
        from test_zigbee2mqtt import state
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cfg,stack=self.config(root);data=state();capture=root/'capture.tar'
            with tarfile.open(capture,'w') as archive:
                for name,raw in data.items():
                    member=tarfile.TarInfo('zigbee2mqtt/'+name);member.size=len(raw);archive.addfile(member,io.BytesIO(raw))
            cfg['app']['capture']['sha256']=deploy.sha(capture);stack['zigbee']['state_sha256']={name:hashlib.sha256(raw).hexdigest() for name,raw in data.items()}
            inputs=root/'inputs';identity='1'*64;destination=inputs/'zigbee2mqtt'/identity;cfg['app']['stack_config']=str(destination/'stack.json')
            packet=root/'packet.json';packet.write_text(json.dumps({'schema':'homelab-ordinary-deployment-v1','enabled':True,'kind':'zigbee2mqtt','identity':identity,'files':{'site.json':json.dumps(cfg),'stack.json':json.dumps(stack)}}))
            with patch.object(cd.deploy,'execute',return_value={'status':'prepared'}) as engine:
                self.assertEqual(cd.run('infrastructure',packet,inputs=inputs),{'status':'prepared'})
                engine.assert_called_once_with('radio-prepare',destination/'site.json')
            prepared=json.loads((destination/'site.json').read_text());self.assertEqual(prepared['app']['capture'],cfg['app']['capture']);deploy.check_radio_capture(prepared)
            self.assertNotIn('zigbee_admission',prepared['app']);self.assertNotIn('zigbee_first_start_approval',prepared['app'])
            fake=types.SimpleNamespace(KIND='zigbee2mqtt',ADAPTER_API=1,INITIAL_CAPTURE=True,validate=Mock())
            for adapter in [zigbee_ordinary,fake]:
                with self.subTest(adapter=adapter.__class__.__name__),self.assertRaises(ValueError):ordinary_cd.prepare(packet,inputs=root/'refused',adapter=adapter)
            fake.validate.assert_not_called()
            # Run the real script entry point, while redirecting only its private
            # input root and mocking the final native engine call.
            import contextlib,runpy
            actual_prepare=ordinary_cd.prepare
            def bounded_prepare(*args,**kwargs):
                kwargs['inputs']=inputs
                return actual_prepare(*args,**kwargs)
            output=io.StringIO()
            with patch.object(ordinary_cd,'prepare',side_effect=bounded_prepare), \
                 patch.object(deploy,'execute',return_value={'status':'prepared'}) as native, \
                 patch.object(sys,'argv',[str(Path(cd.__file__)),'--phase','infrastructure','--packet',str(packet)]), \
                 contextlib.redirect_stdout(output):
                runpy.run_path(cd.__file__,run_name='__main__')
            native.assert_called_once_with('radio-prepare',destination/'site.json')
            self.assertEqual(json.loads(output.getvalue()),{'status':'prepared'})

            ordinary_packet=json.loads(packet.read_text());ordinary_packet['kind']='automation';ordinary_site=json.loads(ordinary_packet['files']['site.json']);ordinary_site['app']['kind']='automation';ordinary_packet['files']['site.json']=json.dumps(ordinary_site);packet.write_text(json.dumps(ordinary_packet))
            with self.assertRaisesRegex(ValueError,'cannot migrate or restore'):
                ordinary_cd.prepare(packet,inputs=root/'automation-refused')
