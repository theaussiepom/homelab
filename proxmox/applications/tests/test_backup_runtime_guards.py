"""Actual local filesystem/process guards; no real guest or PBS connection."""
import copy
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backup_agent
import backup_controller as controller
import backup_group
import backup_policy
import backup_staging
import backup_worker as worker
import component_generation
from private_io import encoded, sha, write_new
from test_backup_agent import fixture
from test_backup_group import scope
import test_backup_worker as worker_fixture


class RuntimeGuardTests(unittest.TestCase):
    def setUp(self):
        self.mask=os.umask(0o077);self.addCleanup(os.umask,self.mask)
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.tmp=Path(temp.name).resolve()
        self.fixture=worker_fixture.WorkerTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)

    def test_engine_real_success_nonzero_duration_and_process_group_timeout(self):
        limits={'max_bytes':1048576,'max_files':100,'timeout_seconds':60}
        engine=worker.Engine(self.tmp/'engine.log',limits)
        output=self.tmp/'stdout'
        engine.run([sys.executable,'-c','print("safe metadata")'],output=output)
        self.assertEqual(output.read_text(),'safe metadata\n')
        with self.assertRaises(ValueError):engine.run([sys.executable,'-c','raise SystemExit(2)'])
        with self.assertRaises(ValueError):engine.run(['arbitrary','start'],restore=True)
        engine.deadline=time.monotonic()-1
        with self.assertRaises(ValueError):engine.run([sys.executable,'-c','pass'])
        engine.deadline=time.monotonic()+.03
        with self.assertRaises(subprocess.TimeoutExpired):engine.run([sys.executable,'-c','import time;time.sleep(10)'])
        self.assertEqual(stat.S_IMODE((self.tmp/'engine.log').stat().st_mode),0o600)

    def test_filesystem_limits_types_links_and_verified_cleanup(self):
        root=self.tmp/'tree';root.mkdir();(root/'value').write_bytes(b'hello');(root/'link').symlink_to('/outside')
        selected=[{'path':str(root),'kind':'directory'}];limits={'max_bytes':1000,'max_files':100}
        self.assertEqual(worker.inventory(selected,[],limits),{'files':3,'bytes':5})
        for bound in ({'max_bytes':1,'max_files':100},{'max_bytes':100,'max_files':1}):
            with self.assertRaises(ValueError):worker.inventory(selected,[],bound)
        self.assertEqual(worker.inventory(selected,[str(root)],limits),{'files':0,'bytes':0})
        with self.assertRaises(ValueError):worker.inventory([{'path':str(root/'link'),'kind':'file'}],[],limits)
        with self.assertRaises(ValueError):worker.manifest(root,limits)
        (root/'link').unlink();os.mkfifo(root/'fifo')
        with self.assertRaises(ValueError):worker.inventory(selected,[],limits)
        (root/'fifo').unlink()
        with self.assertRaises(ValueError):worker.manifest(root,{'max_bytes':1,'max_files':100})
        expected=worker.manifest(root,limits)
        with self.assertRaises(ValueError):worker.release_copy(root,{},limits)
        worker.release_copy(root,expected,limits);self.assertFalse(root.exists())
        root.mkdir()
        with self.assertRaises(ValueError):worker.manifest(root,limits)

    def test_private_inputs_closed_policy_and_staging_bindings(self):
        cfg=fixture();value=copy.deepcopy(self.fixture.value)
        cfg['app']['backup']=value
        cfg['guest']['interfaces']=[{'ipv4':'manual'},{'ipv4':'192.0.2.10/24'}]
        cfg['guest']['volumes']['stage']={'path':'/srv/backup-stage','backup':False,'size_gib':1}
        value['managed_volumes']['stage']={'path':'/srv/backup-stage','include':False}
        value['configuration']={};value['applications']['app']['configuration']={}
        self.assertEqual(json.loads(backup_agent.configuration(cfg)['inventory']),value)
        with patch('private_io.regular',return_value=b'private'):
            self.assertEqual(set(backup_agent.inputs(value)),{'pbs-password','pbs-key'})
            value['job']['secrets']['key_password']={'type':'file','path':'/key-pass'}
            value['job']['capture']['influx_tokens']={'db':{'type':'file','path':'/token'}}
            self.assertEqual(set(backup_agent.inputs(value)),{'pbs-password','pbs-key','pbs-key-password','influx-db'})
        with patch('private_io.regular',return_value=b''):
            with self.assertRaises(ValueError):backup_agent.inputs(value)
        self.assertEqual(backup_agent.inputs({}),{})
        cfg['guest']['volumes']['stage']['backup']=True
        with self.assertRaises(ValueError):backup_agent.configuration(cfg)
        mutations=[lambda v:v.update(unknown=True),lambda v:v['transport'].update(device='eth;cmd'),
            lambda v:v['staging'].update(size_bytes=True),lambda v:v['destination'].update(backup_id='foreign'),
            lambda v:v['destination'].update(server='-bad'),lambda v:v['destination'].update(datastore='a/b'),
            lambda v:v['destination'].update(namespace='a/b/c/d/e/f/g'),lambda v:v['destination'].update(auth_id='root@pam'),
            lambda v:v['destination'].update(fingerprint='invalid'),lambda v:v['schedule'].update(calendar='24:00'),
            lambda v:v['limits'].update(max_bytes=True),lambda v:v['capture'].update(pause=['x','x']),
            lambda v:v['capture'].update(influx_tokens=[]),lambda v:v['secrets']['password'].update(path='/a/../b')]
        for mutate in mutations:
            job=copy.deepcopy(self.fixture.value['job']);mutate(job)
            with self.subTest(case=mutations.index(mutate)),self.assertRaises(ValueError):backup_policy.validate(job)
        for owner in ({}, {'node':'bad','vmid':True,'hostname':'bad'}):
            with self.assertRaises(ValueError):backup_policy.owner(owner)
        for previous,current in [({},{}),({}, {'backup':{'job':{}}}),
                                 ({'backup':{'job':{'group':{'name':'x'}}}}, {'backup':{'job':{'group':{'name':'x'}}}})]:
            component_generation.backup_continuity(previous,current)
        for current in ({},{'backup':{'job':{'group':{'name':'foreign'}}}}):
            with self.assertRaises(ValueError):component_generation.backup_continuity({'backup':{'job':{'group':{'name':'x'}}}},current)

    def test_admission_uses_actual_completed_generation_trust_and_backend(self):
        row=scope()['members']['example-node-610'];row['state_root']=str(self.tmp)
        work=self.tmp/'610';work.mkdir(mode=0o700)
        source=self.tmp/'inputs';source.mkdir(mode=0o700)
        cfg={'paths':{'state_root':str(self.tmp)},'site':{'node':'example-node','api_endpoint':'https://192.0.2.10:8006/'},
            'guest':{'vmid':610,'hostname':'example'},'app':{'backup':self.fixture.value}}
        write_new(source/'site.json',encoded(cfg))
        receipt={'binding':{'app_inputs_directory':str(source/'applications'),'input_hashes':{str(source/'site.json'):sha(source/'site.json')}},
            'state_sha256':'a'*64,'state_identity':{'serial':'actual'}}
        write_new(work/'ordinary-complete.json',encoded(receipt))
        with patch.object(component_generation,'previous',return_value=(receipt,cfg,{})) as previous, \
             patch.object(component_generation,'backend',return_value=('a'*64,{'serial':'actual'})), \
             patch('proxmox_guest.guest_trust') as trust:
            result=controller.admit('example-node-610',row)
            self.assertEqual(result[0],cfg);previous.assert_called_once();trust.assert_called_once()
            with self.assertRaises(ValueError):controller.admit('foreign',row)
            changed=dict(row,hostname='foreign')
            with self.assertRaises(ValueError):controller.admit('example-node-610',changed)
            with patch.object(component_generation,'previous',return_value=None):
                with self.assertRaises(ValueError):controller.admit('example-node-610',row)
            with patch.object(component_generation,'backend',return_value=('b'*64,{})):
                with self.assertRaises(ValueError):controller.admit('example-node-610',row)
        write_new(work/'ORDINARY-HOLD.json',b'{}')
        with self.assertRaises(ValueError):controller.admit('example-node-610',row)

    def test_controls_staging_and_readonly_preimage_contract(self):
        path=self.tmp/'compose.yml';path.write_text('synthetic controls')
        recipes={'pause':[{'file':str(path)}]}
        worker.controls(recipes,{str(path):sha(path)})
        for selected in ({},{str(path):'wrong'}):
            with self.assertRaises(ValueError):worker.controls(recipes,selected)
        path.chmod(0o666)
        with self.assertRaises(ValueError):worker.controls(recipes,{str(path):sha(path)})
        value={'job':{'staging':{'path':str(self.tmp),'size_bytes':2**60}}}
        with self.assertRaises(ValueError):worker.staging(value)
        with patch('os.path.ismount',return_value=True):
            with self.assertRaises(ValueError):worker.staging(value)
        plan={'resource_changes':[{'type':'proxmox_virtual_environment_container','change':{'before':{'mount_point':[{'path':'/srv/existing'}]}}}]}
        self.assertTrue(backup_staging.newly_allocated(plan,'/srv/new'))
        self.assertFalse(backup_staging.newly_allocated(plan,'/srv/existing'))
        with patch.object(backup_staging,'quiet') as command:
            backup_staging.inspect({'paths':{'known_hosts':'/known','private_key':'/key'},'app':{'address':'192.0.2.1'}},'/srv/stage',None)
            self.assertEqual(command.call_args.kwargs['input_bytes'],backup_staging.SCRIPT)
            argv=command.call_args.args[0]
            for option in ('StrictHostKeyChecking=yes','BatchMode=yes','IdentitiesOnly=yes','ControlMaster=no',
                           'GlobalKnownHostsFile=/dev/null','VerifyHostKeyDNS=no','UpdateHostKeys=no','UserKnownHostsFile=/known'):
                self.assertIn(option,argv)
            self.assertEqual(argv[argv.index('-i')+1],'/key')
            self.assertEqual(argv[-2],'root@192.0.2.1')
            self.assertEqual(argv[-1],'python3 - /srv/stage')
            with self.assertRaises(ValueError):backup_staging.inspect({},'/srv/../outside',None)

    def test_native_command_abort_cleanup_and_restore_allowance_are_bounded(self):
        from types import SimpleNamespace
        limits={'max_bytes':1048576,'max_files':100,'timeout_seconds':60}
        engine=worker.Engine(self.tmp/'native.log',limits)
        with patch.object(worker.subprocess,'Popen') as launch, patch.object(worker.resource,'setrlimit') as resource:
            launch.return_value.wait.return_value=0
            engine.run(['docker','compose','start'],restore=True)
            launch.call_args.kwargs['preexec_fn']()
            resource.assert_called_once()
        timeout=subprocess.TimeoutExpired('fixture',.1)
        with patch.object(worker.subprocess,'Popen') as launch,patch.object(worker.os,'killpg') as kill:
            launch.return_value.pid=12345;launch.return_value.wait.side_effect=[timeout,timeout,-9]
            with self.assertRaises(subprocess.TimeoutExpired):engine.run(['fixture'])
            self.assertEqual(kill.call_count,2)
        read,write=os.pipe();os.close(write)
        with os.fdopen(read,'rb',buffering=0) as abort:
            engine=worker.Engine(self.tmp/'abort.log',limits,abort)
            with self.assertRaises(ValueError):engine.run([sys.executable,'-c','import time;time.sleep(10)'])

    def test_controller_control_hashes_cli_and_worker_staging_entry(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        import runpy
        work=self.tmp/'610';work.mkdir(mode=0o700)
        directory=self.tmp/'inputs';directory.mkdir(mode=0o700)
        write_new(directory/'compose.yml',b'owned source')
        payload=self.tmp/'payload';payload.mkdir(mode=0o700);write_new(payload/'environment.yml',b'private overlay')
        value=copy.deepcopy(self.fixture.value)
        value['applications']['app']['producer']['overlay']='/opt/homelab-app/component-app-environment.yml'
        cfg={'paths':{'state_root':str(self.tmp)},'guest':{'vmid':610},
             'deployment':{'input_directory':str(directory)},'app':{'backup':value}}
        receipt={'binding':{'app_inputs_directory':str(directory/'applications')},
                 'phase_inputs':{'app':{'app':'app'},'preparation':None}}
        write_new(work/'ordinary-complete.json',encoded(receipt))
        with patch('component_payload.AppPayload.load',return_value=SimpleNamespace(directory=payload)):
            controls=controller.controls(cfg)
            self.assertEqual(controls[value['applications']['app']['producer']['overlay']],sha(payload/'environment.yml'))
            value['applications']['app']['producer'].pop('overlay')
            self.assertEqual(controller.controls(cfg),{'/opt/homelab-app/compose.yml':sha(directory/'compose.yml')})
            value['job']['capture']['pause']=[];value['applications']['app']['storage']={}
            self.assertEqual(controller.controls(cfg),{})
        with patch.object(controller,'run',return_value={'status':'passed'}),patch.object(sys,'argv',['controller','--group',str(self.tmp/'group')]), \
             patch.object(controller.signal,'signal') as signals,patch('builtins.print'):
            controller.main()
            with self.assertRaises(InterruptedError):signals.call_args.args[1](None,None)
        empty=self.tmp/'stage';empty.mkdir()
        selected={'job':{'staging':{'path':str(empty),'size_bytes':2**60}}}
        with patch('os.path.ismount',return_value=True):worker.staging(selected)
        with patch.object(worker,'read_json',return_value=self.fixture.value),patch.object(worker,'staging'), \
             patch.object(worker,'serve') as serve,patch.object(sys,'argv',['worker','--serve']), \
             patch.object(worker.signal,'signal') as signals:
            worker.main();serve.assert_called_once()
            with self.assertRaises(InterruptedError):signals.call_args.args[1](None,None)
        for script,args in [('backup_worker.py',[]),('backup_controller.py',['--group',str(self.tmp/'absent')])]:
            with patch.object(sys,'argv',[script,*args]),self.assertRaises(SystemExit):
                runpy.run_path(str(Path(worker.__file__).parent/script),run_name='__main__')

    def test_reap_escalates_only_unresponsive_peer_and_reports_failed_success(self):
        from unittest.mock import Mock
        for sequence in ([subprocess.TimeoutExpired('peer',1),0],
                         [subprocess.TimeoutExpired('peer',1),subprocess.TimeoutExpired('peer',5),-9], [1]):
            peer=Mock(pid=12345,stdin=io.BytesIO(),stdout=io.BytesIO());peer.wait.side_effect=sequence
            with patch.object(controller.os,'killpg') as kill,self.assertRaises(ValueError):
                controller.reap({'peer':peer},success=True,deadline=time.monotonic()+.01)
            self.assertTrue(peer.stdin.closed and peer.stdout.closed)

    def test_prepared_job_forwards_sealed_inputs_and_immutable_schedule_to_ansible(self):
        import component_ansible as ansible
        import component_inputs
        import component_prepare
        import deployment_inputs
        from types import SimpleNamespace
        value=copy.deepcopy(self.fixture.value)
        value['job']['secrets']['key_password']={'type':'file','path':'/unset'}
        value['job']['capture']['influx_tokens']={'app':{'type':'file','path':'/unset'}}
        for index, row in enumerate([*value['job']['secrets'].values(),*value['job']['capture']['influx_tokens'].values()]):
            path=self.tmp/('input-'+str(index));write_new(path,b'private synthetic fixture');row['path']=str(path)
        inputs=self.tmp/'inputs';inputs.mkdir(mode=0o700);apps=inputs/'applications';apps.mkdir(mode=0o700)
        write_new(inputs/'component-runtime.json',encoded({'applications':{}}))
        group={'schema':'homelab-pbs-schedule-v1','group':scope(),'schedule':value['job']['schedule'],'limits':value['job']['limits']}
        write_new(inputs/'backup-group.json',encoded(group))
        cfg={'guest':{'vmid':610,'interfaces':[{'ipv4':'192.0.2.10/24'}]},'app':{'backup':value},
            'paths':{'ca_file':str(self.tmp/'ca')},'deployment':{'input_identity':'a'*64,
            'capabilities':['linux'],'input_directory':str(inputs),'runtime_file':str(inputs/'component-runtime.json')}}
        write_new(self.tmp/'ca',b'public synthetic certificate')
        with patch.object(backup_agent,'configuration',return_value={'inventory':json.dumps(value)}), \
             patch.object(component_inputs,'app_directory',return_value=apps):
            payload=component_prepare.prepare_backup(cfg,{})
        source=self.tmp/'source'/'applications';source.mkdir(parents=True);common=source.parent/'common';common.mkdir()
        (source/'public.py').write_text('PUBLIC = True');(common/'asset').write_text('public data')
        with patch.object(ansible.component_guest,'phases',return_value=['pbs-agent']), \
             patch.object(backup_agent,'configuration',return_value={'inventory':json.dumps(value)}), \
             patch.object(ansible,'SOURCE',source),patch.object(deployment_inputs,'source_hash',return_value='b'*64):
            result=ansible.variables(cfg,'pbs-agent',payload=payload)
        self.assertEqual(len(result['backup_controller_files']),2)
        self.assertEqual(result['backup_controller']['configuration'],group)
        self.assertEqual({row['name'] for row in result['backup_agent']['credentials']},
            {'pbs-password','pbs-key','pbs-key-password','influx-app'})
        self.assertFalse(result['app']['start_services'])
        # Binding itself owns external digest collection; source shape validation
        # is mocked here and exercised by real packet integrations elsewhere.
        write_new(inputs/'site.json',encoded(cfg))
        with patch.object(component_inputs,'inspect',return_value={}), \
             patch.object(deployment_inputs,'source_hash',return_value='b'*64):
            binding=component_inputs.binding(cfg,inputs/'site.json')
        self.assertTrue(all(row['path'] in binding['input_hashes'] for row in value['job']['secrets'].values()))

    def test_post_group_health_reads_never_restart_or_retry_a_failed_service(self):
        from types import SimpleNamespace
        records=[{'Service':'owned','State':'running','Health':'healthy'}]
        row={'app':'app','services':['owned'],'project':'fixture','file':'/opt/homelab-app/compose.yml'}
        for case,values in [('array',[records]),('ndjson',[records]),('starting',[ [{**records[0],'Health':'starting'}],records]),
                            ('unhealthy',[[{**records[0],'Health':'unhealthy'}]]),
                            ('exited',[[{**records[0],'State':'exited'}]]),('foreign',[[{**records[0],'Service':'foreign'}]]),
                            ('shape',[[42]]),('timeout',[[{**records[0],'Health':'starting'}]]),
                            ('count',[[{**records[0],'Health':'starting'}]])]:
            target=self.tmp/case;target.mkdir(mode=0o700);calls=[]
            def run(argv,*,output):
                self.assertIn('ps',argv);self.assertNotIn('start',argv);calls.append(argv)
                data=values[min(len(calls)-1,len(values)-1)]
                output.write_text('\n'.join(json.dumps(item) for item in data) if case=='ndjson' else json.dumps(data))
            clock=iter([0,61]) if case=='timeout' else None
            with patch.object(worker.time,'sleep'),patch.object(worker.time,'monotonic',side_effect=(lambda:next(clock)) if clock else lambda:0):
                if case in ('array','ndjson','starting'):worker.ready([row],target,SimpleNamespace(run=run))
                else:
                    with self.assertRaises(ValueError):worker.ready([row],target,SimpleNamespace(run=run))
            if case=='count':self.assertEqual(len(calls),60)
