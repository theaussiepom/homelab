"""Current source/manifest and real Ansible command tasks, with an inert Docker CLI."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
import yaml

F=Path(os.environ.get('HOMELAB_FRAMEWORK',Path(__file__).resolve().parents[3])).resolve()
sys.path[:0]=[str(F/'blueprints'),str(F/'proxmox/applications'),str(F/'proxmox/applications/tests')]
import component_ansible
import component_inputs
import component_packet
import component_plan
import component_prepare
from private_io import encoded,read_json,write_bytes
import test_component_deployment as source_fixture

TASKS=F/'proxmox/applications/ansible/tasks/component-compose.yml'
HELPER=F/'proxmox/applications/component-preflight.py'
DOCKER='''import json,os,sys
from pathlib import Path
args=sys.argv[1:];trace=Path(os.environ['TRACE'])
with trace.open('a') as f:f.write(json.dumps(args)+'\\n')
path=Path(os.environ['STATE']);state=json.loads(path.read_text());project=os.environ['PROJECT']
if args[0]=='ps':
    assert 'label=com.docker.compose.project='+project in args
    if '--format' in args:
        assert args[args.index('--format')+1]=='{{.ID}} {{.Label "com.docker.compose.service"}}'
        print('\\n'.join(row['id']+' '+name for name,row in state.items()))
    else:
        name=next(v.split('=',2)[-1] for v in args if v.startswith('label=com.docker.compose.service='))
        print(state[name]['id'] if name in state else '')
elif args[0]=='inspect':
    name=next(name for name,row in state.items() if row['id']==args[-1]);row=state[name]
    print(json.dumps({'com.docker.compose.project':project,'com.docker.compose.service':name}))
    print(json.dumps(row['started']));print(row['restarts'])
elif args[0]=='compose':
    assert 'up' in args and '--no-deps' in args and '--remove-orphans=false' in args
    selected=json.loads(os.environ['SELECTED']);tail=args[args.index('--no-deps')+1:]
    assert [v for v in tail if not v.startswith('--')]==selected
    for name in selected:
        state.setdefault(name,{'id':'b'*64,'started':'new-start','restarts':0})
    path.write_text(json.dumps(state))
else:raise AssertionError('Native Docker mutations forbidden')
'''


class CurrentOrphanGuardTests(unittest.TestCase):
    def setUp(self):
        fixture=source_fixture.DeploymentIntegrationTests()
        fixture.setUp();self.addCleanup(fixture.doCleanups);self.fixture=fixture
        self.root=fixture.root
        path=self.root/'consumer/site.json';source=json.loads(path.read_text())
        source['guests']['resolver']['resources']={'memory_mib':1024}
        source['guests']['resolver']['compose_projects']={'shared':{'name':'synthetic-owned-project'}}
        first=source['apps']['recursive_a'];first['identity']={'project':'shared','services':{'unbound':'selected'}}
        peer=copy.deepcopy(first);peer['identity']['services']['unbound']='peer';peer['properties']={'publish_port':5336}
        source['apps']['recursive_b']=peer;path.write_bytes(encoded(source))
        plan=component_plan.resolve(self.root/'library',path)
        packet=component_packet.lower_plan(plan,inputs=fixture.inputs)['resolver']
        write_bytes(fixture.packet,encoded(packet))
        cfg,_=component_inputs.prepare(fixture.packet,fixture.inputs,create=True)
        payload=component_prepare.prepare(cfg,'recursive_a',{},attempt=SimpleNamespace(receipt=self.root/'absent'))
        self.values=component_ansible.variables(cfg,'recursive_a',payload=payload)
        self.selection=self.values['component_preflight']
        self.assertEqual(self.selection['services'],['selected']);self.assertEqual(self.selection['peers'],['peer'])
        self.assertEqual(self.selection['project'],'synthetic-owned-project')
        self.tasks=yaml.safe_load(TASKS.read_text())
        self.guard=copy.deepcopy(next(t for t in self.tasks if t['name']=='Check the owned namespace before reconciliation'))
        self.after=copy.deepcopy(next(t for t in self.tasks if t['name']=='Verify peer continuity'))
        self.start=copy.deepcopy(next(t for t in self.tasks if t['name']=="Start only this application's owned services"))
        for task in (self.guard,self.after):
            self.assertEqual(task['ansible.builtin.command']['argv'],['python3','/usr/local/bin/homelab-component-preflight.py','before' if task is self.guard else 'after'])
            # Translate only the already asserted installed helper path for this local fixture.
            task['ansible.builtin.command']['argv'][1]=str(HELPER)
        install=next(t['ansible.builtin.copy'] for t in self.tasks if t['name']=='Install component admission')
        self.assertEqual(install['dest'],'/usr/local/bin/homelab-component-preflight.py')
        self.assertEqual(install['mode'],'0700');self.assertTrue(install['src'].endswith('/../component-preflight.py'))

    def execute(self,folder,state,*,check=False):
        folder.mkdir(mode=0o700)
        state_path=folder/'state.json';state_path.write_text(json.dumps(state))
        data=folder/'retained-data';data.write_bytes(b'retained broker/inverter state')
        before=(data.stat().st_ino,data.read_bytes())
        binary=folder/'docker';binary.write_text('#!'+sys.executable+'\n'+DOCKER);binary.chmod(0o700)
        trace=folder/'trace.jsonl';play=folder/'play.yml'
        variables={'component_preflight':self.selection,'component_services':self.selection['services'],
            'component_compose_argv':['docker','compose','-f','/fixture/compose.yml'],
            'component_runtime_install':{'changed':False},'component_environment_install':{'changed':False},
            'component_driver_install':{'changed':False},'ansible_python_interpreter':sys.executable}
        play.write_text(yaml.safe_dump([{'hosts':'all','connection':'local','gather_facts':False,
                                        'vars':variables,'tasks':[self.guard,self.start,self.after]}]))
        environment=dict(os.environ,PATH=str(folder)+os.pathsep+os.environ['PATH'],TRACE=str(trace),STATE=str(state_path),
            PROJECT=self.selection['project'],SELECTED=json.dumps(self.selection['services']),
            ANSIBLE_HOME=str(folder/'ansible-home'),ANSIBLE_LOCAL_TEMP=str(folder/'ansible-local'),
            ANSIBLE_REMOTE_TEMP=str(folder/'ansible-remote'))
        command=[str(Path(sys.executable).with_name('ansible-playbook')),'-i','localhost,',str(play)]
        result=subprocess.run(command+(['--check'] if check else []),env=environment,capture_output=True,text=True,timeout=45)
        self.assertEqual((data.stat().st_ino,data.read_bytes()),before)
        calls=[json.loads(row) for row in trace.read_text().splitlines()] if trace.exists() else []
        self.assertTrue(all(row[0] in ('ps','inspect','compose') for row in calls))
        return result,calls,json.loads(state_path.read_text())

    def test_unselected_retained_mqtt_or_winet_refuses_before_copy_or_start(self):
        for orphan in ('mqtt','winet'):
            with self.subTest(orphan=orphan):
                state={orphan:{'id':'a'*64,'started':'retained-start','restarts':0}}
                result,calls,after=self.execute(self.root/orphan,state)
                self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertEqual(after,state)
                self.assertTrue(calls and '--format' in calls[0])
                self.assertFalse(any(call[0]=='compose' for call in calls))
                self.assertTrue(all(call[0]=='ps' for call in calls))

    def test_declared_peer_is_preserved_and_only_selected_service_starts(self):
        peer={'id':'a'*64,'started':'retained-peer','restarts':0}
        for previously_owned in (False,True):
            with self.subTest(previously_owned=previously_owned):
                self.selection['previously_owned']=previously_owned
                state={'peer':peer}
                if previously_owned:state['selected']={'id':'b'*64,'started':'owned-selected','restarts':0}
                result,calls,after=self.execute(self.root/str(previously_owned),state)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertEqual(after['peer'],peer);self.assertIn('selected',after)
                starts=[call for call in calls if call[0]=='compose'];self.assertEqual(len(starts),1)
                self.assertEqual(starts[0][-1],'selected');self.assertIn('--no-deps',starts[0])
                self.assertIn('--remove-orphans=false',starts[0]);self.assertNotIn('--force-recreate',starts[0])

    def test_current_guard_precedes_runtime_writes_and_check_mode_contacts_no_Docker(self):
        before=next(i for i,t in enumerate(self.tasks) if t['name']=='Check the owned namespace before reconciliation')
        first_copy=next(i for i,t in enumerate(self.tasks) if t['name']=="Install this application's service probes")
        start=next(i for i,t in enumerate(self.tasks) if t['name']=="Start only this application's owned services")
        self.assertLess(before,first_copy);self.assertLess(first_copy,start)
        # Original check-mode no-touch clause exercises the actual command task only;
        # later tasks consume its output and are not part of a check-mode runtime claim.
        original=self.after;self.after={'ansible.builtin.debug':{'msg':'check-only'}}
        try:
            result,calls,after=self.execute(self.root/'check',{'mqtt':{'id':'a'*64,'started':'retained','restarts':0}},check=True)
        finally:self.after=original
        self.assertEqual(result.returncode,0,result.stdout+result.stderr);self.assertEqual(calls,[])


if __name__=='__main__':unittest.main()
