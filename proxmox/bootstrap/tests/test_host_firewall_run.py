"""Actual caller/private files, with finite API and OpenTofu boundaries."""
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import host_firewall as h
import host_firewall_run as r
from test_host_firewall_contract import before, config, native, plan

TOKEN='root@pam!homelab-bootstrap-cd-900=00000000-0000-4000-8000-000000000000'
SENTINEL='private-sentinel-never-in-public-error'


def backend(c,b):
    attrs={h.HOST:{'id':'rule-1','node_name':c['node'],'container_id':None,'vm_id':None,'rule':b['rules']},
           h.CLUSTER:dict(b['cluster'],id='cluster-firewall')}
    attrs[h.CLUSTER]['log_ratelimit']=[attrs[h.CLUSTER]['log_ratelimit']]
    return {'version':4,'lineage':'synthetic-lineage','serial':1,'resources':[
        {'type':address.split('.')[0],'name':address.split('.')[1],'mode':'managed',
         'provider':'provider["registry.opentofu.org/bpg/proxmox"]','instances':[{'attributes':attrs[address]}]}
        for address in (h.HOST,h.CLUSTER)]}


class FakeAPI:
    def __init__(self,c,b):
        self.c=c;self.b=deepcopy(b);self.reads=[];self.native_reads=0;self.case=''
    def call(self,path,method='GET',values=None):
        assert method=='GET' and values is None
        self.reads.append(path)
        if path=='/nodes/'+self.c['node']+'/firewall/rules':
            self.native_reads+=1
            rows=native(self.b['rules'])
            if self.case=='api-digest-drift' and self.native_reads==2:rows[0]['digest']='changed-only-digest'
            return {'data':rows}
        assert path=='/cluster/firewall/options'
        v=self.b['cluster']
        return {'data':{'enable':int(v['enabled']),'ebtables':int(v['ebtables']),
                        'policy_in':v['input_policy'],'policy_out':v['output_policy'],
                        'policy_forward':v['forward_policy'],
                        'log_ratelimit':f"enable={int(v['log_ratelimit']['enabled'])},rate={v['log_ratelimit']['rate']},burst={v['log_ratelimit']['burst']}"}}


class Fixture:
    def __init__(self,folder,case='',c=None):
        self.c=config() if c is None else c;self.b=before(self.c);self.case=case
        self.root=Path(folder).resolve()/'bootstrap';self.root.mkdir(mode=0o700)
        self.work=self.root/'host-firewall';self.work.mkdir(mode=0o700)
        self.source=Path(folder).resolve()/'firewall.yaml';self.source.write_text(json.dumps(self.c))
        self.backend=self.work/'terraform.tfstate';self.state=backend(self.c,self.b)
        self.write(self.backend,self.state)
        self.write(self.work/'policy.auto.tfvars.json',{'policy':self.c})
        self.api=FakeAPI(self.c,self.b);self.api.case=case
        self.calls=[];self.applies=0;self.final=False
    def write(self,path,value):
        path.write_text(json.dumps(value));path.chmod(0o600)
    def execute(self):
        with patch.object(r.platform,'system',return_value='Linux'), \
             patch.object(r,'API',return_value=self.api), \
             patch.object(r.subprocess,'run',side_effect=self.command), \
             patch.object(r,'apply_process',side_effect=self.apply), \
             patch.dict(os.environ,{'PROXMOX_BOOTSTRAP_TOKEN':TOKEN,'TF_LOG':'TRACE','TF_VAR_private':SENTINEL},clear=True):
            return r.run(self.c,self.work,self.source,root=self.root)
    def command(self,argv,**kwargs):
        assert argv[0]=='/usr/local/bin/tofu'
        env=kwargs['env'];assert env['PROXMOX_VE_API_TOKEN']==TOKEN
        assert set(env)=={'PATH','PROXMOX_VE_API_TOKEN','SSL_CERT_FILE','TF_CLI_CONFIG_FILE','TF_IN_AUTOMATION','CHECKPOINT_DISABLE'}
        command=argv[2];self.calls.append(command)
        status=0;value=b''
        if self.case==command+'-failure':status=1;kwargs['stderr'].write(SENTINEL.encode())
        if command=='version':value=json.dumps({'terraform_version':'bad' if self.case=='version-wrong' else '1.13.1','provider_selections':{'registry.opentofu.org/bpg/proxmox':'0.117.0'}}).encode()
        elif command=='plan':
            for arg in argv:
                if arg.startswith('-out='):Path(arg[5:]).write_bytes(b'private-plan')
            if self.final and self.case=='verify-changed':status=2
        elif command=='show':
            p=plan(self.c,self.api.b)
            if self.final:
                for resource in p['resource_changes']:resource['change']['actions']=['no-op']
            if self.case=='bad-plan':p['resource_changes'][0]['change']['actions']=['create']
            value=b'invalid JSON' if self.case=='bad-show-json' else json.dumps(p).encode()
            if not self.final:
                if self.case=='state-drift':self.state['serial']+=1;self.write(self.backend,self.state)
                if self.case=='source-drift':self.source.write_text(json.dumps(self.c)+'\n')
                if self.case=='marker-drift':self.write(self.root/'CONFIGURING',{'foreign':True})
        kwargs['stdout'].write(value)
        return subprocess.CompletedProcess(argv,status)
    def apply(self,args,cwd,out,err,env):
        assert set(env)=={'PATH','PROXMOX_VE_API_TOKEN','SSL_CERT_FILE','TF_CLI_CONFIG_FILE','TF_IN_AUTOMATION','CHECKPOINT_DISABLE'}
        self.applies+=1
        if self.case=='apply-timeout':raise subprocess.TimeoutExpired(args,900)
        if self.case=='apply-failure':return subprocess.CompletedProcess(args,1)
        self.final=True;self.api.b={'rules':h.rules(self.c),'cluster':deepcopy(self.c['cluster'])}
        self.state=backend(self.c,self.api.b);self.state['serial']=2
        if self.case=='lineage-drift':self.state['lineage']='foreign-lineage'
        self.write(self.backend,self.state)
        if self.case=='post-api-drift':self.api.b['rules'][0]['comment']='foreign'
        if self.case=='post-marker-drift':self.write(self.root/'CONFIGURING',{'foreign':True})
        return subprocess.CompletedProcess(args,0)


class CallerControls(unittest.TestCase):
    def fixture(self,case='',c=None):
        t=tempfile.TemporaryDirectory(prefix='host-fw-caller-');self.addCleanup(t.cleanup)
        return Fixture(t.name,case,c)
    def test_actual_caller_saved_apply_private_evidence_and_normal_repeat(self):
        f=self.fixture();self.assertEqual(f.execute(),{'status':'passed','api_verified':True,'provider_noop':True,'kernel_verified':False})
        self.assertEqual(f.applies,1)
        self.assertEqual(f.calls,['init','version','plan','show','plan','show'])
        self.assertFalse((f.root/'CONFIGURING').exists());self.assertFalse((f.root/'BOOTSTRAP-CD-HOLD.json').exists())
        for path in f.work.rglob('*'):
            if path.is_file():self.assertEqual(path.stat().st_mode & 0o777,0o600,path.name)
        self.assertEqual(f.execute()['status'],'passed')
        self.assertEqual(len(list((f.work/'operations').glob('host-firewall-*'))),2)
    def test_future_reviewed_policy_change_is_normal_without_migration_switch(self):
        f=self.fixture();f.execute();f.c=deepcopy(f.c)
        f.c['allowances'][1]['source']='203.0.113.0/24';f.c['cluster']['enabled']=False
        f.source.write_text(json.dumps(f.c));f.final=False
        self.assertEqual(f.execute()['status'],'passed')
        self.assertFalse(f.api.b['cluster']['enabled'])

    def test_added_host_address_allowance_keeps_existing_state_target_and_management_policy(self):
        f=self.fixture();self.assertEqual(f.execute()['status'],'passed')
        previous=deepcopy(f.api.b['rules']);target={key:f.c[key]for key in r.TARGET}
        f.c=deepcopy(f.c)
        f.c['allowances'].append({'source':'198.18.40.33/32','destination':'198.18.40.10',
            'port':8006,'comment':'Application ingress to host UI'})
        f.source.write_text(json.dumps(f.c));f.final=False
        self.assertEqual(f.execute(),{'status':'passed','api_verified':True,
                                      'provider_noop':True,'kernel_verified':False})
        self.assertEqual({key:f.c[key]for key in r.TARGET},target)
        self.assertEqual(f.api.b['rules'][:-1],previous)
        self.assertEqual(f.api.b['rules'][-1]['dest'],'198.18.40.10/32')
        self.assertEqual(f.applies,2)
        self.assertEqual({item['type']+'.'+item['name']for item in f.state['resources']},
                         {h.HOST,h.CLUSTER})
    def test_missing_state_wrong_target_existing_hold_and_environment_refuse_before_api(self):
        for case in ('missing-state','target','hold','work-path','platform'):
            f=self.fixture()
            if case=='missing-state':f.backend.unlink()
            elif case=='target':v=deepcopy(f.c);v['endpoint']='https://other.example.invalid:8006/';f.write(f.work/'policy.auto.tfvars.json',{'policy':v})
            elif case=='hold':f.write(f.root/'BOOTSTRAP-CD-HOLD.json',{'foreign':True})
            elif case=='work-path':f.work=f.root/'other'
            with self.subTest(case=case):
                with self.assertRaises((ValueError,OSError)):
                    if case=='platform':r.run(f.c,f.work,f.source,root=f.root)
                    else:f.execute()
            self.assertEqual(f.api.reads,[]);self.assertEqual(f.applies,0)
    def test_invalid_owned_state_shapes_refuse_before_any_tofu(self):
        for case in ('version','lineage','serial','extra','provider','target','deposed','different-rule','different-cluster'):
            f=self.fixture();s=f.state
            if case=='version':s['version']=3
            elif case=='lineage':s['lineage']=''
            elif case=='serial':s['serial']=False
            elif case=='extra':s['resources'].append(deepcopy(s['resources'][0]))
            elif case=='provider':s['resources'][0]['provider']='foreign'
            elif case=='target':s['resources'][0]['instances'][0]['attributes']['node_name']='foreign'
            elif case=='deposed':s['resources'][0]['instances'][0]['deposed']='x'
            elif case=='different-rule':s['resources'][0]['instances'][0]['attributes']['rule'][0]['dport']='22'
            else:s['resources'][1]['instances'][0]['attributes']['ebtables']=False
            f.write(f.backend,s)
            with self.subTest(case=case):
                with self.assertRaisesRegex(ValueError,h.ERROR):f.execute()
            self.assertEqual(f.calls,[]);self.assertEqual(f.applies,0)
            self.assertTrue((f.root/'BOOTSTRAP-CD-HOLD.json').exists())
    def test_preapply_state_source_marker_digest_plan_and_command_errors_hold(self):
        for case in ('state-drift','source-drift','marker-drift','api-digest-drift','init-failure','version-wrong','plan-failure','bad-plan','bad-show-json'):
            f=self.fixture(case);original=f.backend.read_bytes()
            with self.subTest(case=case):
                with self.assertRaisesRegex(ValueError,h.ERROR):f.execute()
            self.assertEqual(f.applies,0);self.assertTrue((f.root/'BOOTSTRAP-CD-HOLD.json').exists())
            if case!='state-drift':self.assertEqual(f.backend.read_bytes(),original)
    def test_postapply_uncertainty_keeps_hold_and_does_not_retry(self):
        for case in ('apply-timeout','apply-failure','post-api-drift','lineage-drift','verify-changed','post-marker-drift'):
            f=self.fixture(case)
            with self.subTest(case=case):
                with self.assertRaisesRegex(ValueError,h.ERROR):f.execute()
            self.assertEqual(f.applies,1)
            self.assertTrue((f.root/'BOOTSTRAP-CD-HOLD.json').exists())
            self.assertTrue(list((f.work/'operations').glob('*/failure.json')))
            self.assertFalse(list((f.work/'operations').glob('*/result.json')))
    def test_environment_uses_no_debug_or_user_provider_overrides(self):
        env=r.environment(TOKEN,Path('/private/test/tofu.rc'))
        self.assertNotIn('TF_LOG',env);self.assertNotIn('HOME',env)
        self.assertNotIn('PROXMOX_BOOTSTRAP_TOKEN',env)
        self.assertEqual(env['TF_CLI_CONFIG_FILE'],'/private/test/tofu.rc')
        self.assertIn('/usr/local/bin',env['PATH'])


    def test_late_release_faults_retain_blockers_and_never_admit_second_apply(self):
        cases = ('hold-unlink-before', 'hold-unlink-after', 'marker-unlink-before',
                 'marker-unlink-after', 'root-sync', 'terminal-write-before',
                 'terminal-write-after', 'terminal-sync', 'foreign-hold', 'foreign-marker')
        for case in cases:
            with self.subTest(case=case):
                f=self.fixture();used=[False]
                unlink, sync, write = Path.unlink, r.io.sync, r.io.write_new
                foreign = f.root/('CONFIGURING' if case=='foreign-marker' else 'BOOTSTRAP-CD-HOLD.json')
                def bad_unlink(path,*args,**kwargs):
                    kind='hold' if path==f.root/'BOOTSTRAP-CD-HOLD.json' else 'marker' if path==f.root/'CONFIGURING' else ''
                    if kind and case.startswith(kind+'-unlink') and not used[0]:
                        used[0]=True
                        if case.endswith('after'):unlink(path,*args,**kwargs)
                        raise OSError(SENTINEL)
                    return unlink(path,*args,**kwargs)
                def bad_sync(path):
                    final_root=f.final and path==f.root
                    terminal=f.final and (path/'result.json').is_file()
                    if not used[0] and ((case in ('root-sync','foreign-hold','foreign-marker') and final_root) or (case=='terminal-sync' and terminal)):
                        used[0]=True
                        if case.startswith('foreign'):f.write(foreign,{'foreign':True})
                        raise OSError(SENTINEL)
                    return sync(path)
                def bad_write(path,value,**kwargs):
                    if path.name=='result.json' and case.startswith('terminal-write') and not used[0]:
                        used[0]=True
                        if case.endswith('after'):write(path,value,**kwargs)
                        raise OSError(SENTINEL)
                    return write(path,value,**kwargs)
                with patch.object(Path,'unlink',bad_unlink), \
                     patch.object(r.io,'sync',bad_sync),patch.object(r.io,'write_new',bad_write):
                    with self.assertRaisesRegex(ValueError,h.ERROR):f.execute()
                self.assertTrue(used[0])
                self.assertTrue((f.root/'BOOTSTRAP-CD-HOLD.json').exists() or (f.root/'CONFIGURING').exists())
                self.assertEqual(f.applies,1)
                self.assertEqual(json.loads(next((f.work/'operations').glob('*/api-result.json')).read_bytes())['status'],'api-verified')
                if case.startswith('foreign'):self.assertEqual(json.loads(foreign.read_bytes()),{'foreign':True})
                api_calls=len(f.api.reads)
                with self.assertRaises(ValueError):f.execute()
                self.assertEqual(f.applies,1)
                self.assertEqual(len(f.api.reads),api_calls)


class ApplyProcessControls(unittest.TestCase):
    def test_success_timeout_interrupt_kill_and_cleanup_failures_are_bounded(self):
        for case in ('success','interrupt','kill','signal-failure','wait-failure'):
            class Process:
                returncode=0
                def __init__(self):self.waits=[];self.signals=[];self.kills=0
                def wait(self,timeout):
                    self.waits.append(timeout)
                    if case!='success' and timeout==900 or case in ('kill','wait-failure') and timeout==300 or case=='wait-failure' and timeout==5:
                        raise subprocess.TimeoutExpired('fake',timeout)
                def send_signal(self,value):
                    self.signals.append(value)
                    if case=='signal-failure':raise OSError('private-sentinel')
                def kill(self):self.kills+=1
            p=Process()
            with self.subTest(case=case),patch.object(r.subprocess,'Popen',return_value=p) as popen:
                if case=='success':self.assertIs(r.apply_process(['tofu'],Path('/owned'),io.BytesIO(),io.BytesIO(),{'safe':'env'}),p)
                else:
                    with self.assertRaises(subprocess.TimeoutExpired):r.apply_process(['tofu'],Path('/owned'),io.BytesIO(),io.BytesIO(),{'safe':'env'})
                self.assertEqual(popen.call_args.kwargs['env'],{'safe':'env'})
                self.assertEqual(p.signals,[] if case=='success' else [signal.SIGINT])
                self.assertEqual(p.kills,1 if case in ('kill','wait-failure') else 0)
