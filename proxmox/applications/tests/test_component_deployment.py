"""Config→packet→locked inputs/receipts→Ansible integration; native engines are fakes."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'blueprints'),str(ROOT/'proxmox/applications')]
import component_plan
import component_packet
import component_ansible
import deployment_state
import deploy
from private_io import encoded, read_json, sha, write_bytes, write_new
from test_component_plan import library, site


class DeploymentIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o700)
        self.inputs=self.root/'inputs';self.state=self.root/'state';self.state.mkdir(mode=0o700)
        stack=self.root/'library';stack.mkdir();consumer=self.root/'consumer';consumer.mkdir()
        spec=library();source=site()
        spec['software']={'resolver':{'images':{'unbound':'unbound'}}}
        spec['runtime_profiles']={'resolver':{'containers':{'unbound':{
            'memory_mib':256,'cpu_limit':1,'pids_limit':128}}}}
        spec['app_profiles']['recursive'].update(software=['resolver'],runtime=['resolver'],
            health={'ready':{'type':'adapter','check':'readiness'}})
        source['contexts']['lab']['paths']['state_root']=str(self.state)
        source['contexts']['lab']['trust']['ca_file']=str(self.root/'ca.pem')
        write_new(self.root/'ca.pem',b'public synthetic CA\n')
        (stack/'stack.json').write_text(json.dumps(spec))
        (stack/'images.json').write_text(json.dumps({'unbound':{'repository':'example/unbound',
            'tag':'1','digest':'sha256:'+'a'*64}}))
        (consumer/'site.json').write_text(json.dumps(source))
        self.plan=component_plan.resolve(stack,consumer/'site.json')
        packet=component_packet.lower_plan(self.plan,inputs=self.inputs)['resolver']
        self.packet=self.root/'packet.json';write_new(self.packet,encoded(packet))
        self.cfg=json.loads(packet['files']['site.json'])
        self.calls=[];self.infra=[]
        env=patch.dict(os.environ,{'GITHUB_RUN_ID':'101','GITHUB_RUN_ATTEMPT':'1',
            'GITHUB_RUN_NUMBER':'10','GITHUB_REPOSITORY':'example/private',
            'HOMELAB_DEPLOYMENT_WORKFLOW':'example/private/.github/workflows/deploy.yml@'+'b'*40,
            'GITHUB_SHA':'c'*40,'GITHUB_WORKSPACE':str(self.root)})
        env.start();self.addCleanup(env.stop)
        for target,value in [('deploy.bootstrap_closed',None),('proxmox_guest.guest_trust',None),
                              ('proxmox_guest.dhcp_admission',None),('commands.is_ancestor',True)]:
            context=patch(target,return_value=value);context.start();self.addCleanup(context.stop)
        context=patch('proxmox_guest.infrastructure',side_effect=self.infrastructure)
        context.start();self.addCleanup(context.stop)
        context=patch('component_ansible.quiet',side_effect=self.ansible)
        context.start();self.addCleanup(context.stop)

    def infrastructure(self,cfg,site,work,operation,binding,**kwargs):
        self.assertTrue((work/'ORDINARY-HOLD.json').exists())
        self.assertEqual(cfg['deployment']['protected_guests'],[9900,9914,9915,9920])
        state=work/'terraform.tfstate'
        previous=read_json(state,private=True)['serial'] if state.exists() else 0
        from plan_policy import RESOURCES
        resources=[]
        for address,field in RESOURCES.items():
            module,kind,name=address.rsplit('.',2)
            resources.append({'module':module,'type':kind,'name':name,'mode':'managed','instances':[
                {'attributes':{field:cfg['guest']['vmid'],'node_name':cfg['site']['node'],'id':'fixture-'+kind+'-'+name}}]})
        write_bytes(state,encoded({'version':4,'lineage':'synthetic-owned-lineage','serial':previous+1,
                                  'resources':resources,'native_boundary':'fake'}))
        self.infra.append(previous)
        return {'changed':True,'created':previous==0,'state_sha256':sha(state)}

    def ansible(self,argv,environment,log):
        variables=read_json(Path(argv[-1][1:]),private=True)
        phase=log.parent.name;work=self.state/'610';operation=log.parent.parent
        self.assertTrue((work/'ORDINARY-HOLD.json').exists())
        started=read_json(operation/(phase+'-started.json'),private=True)
        self.assertEqual(Path(argv[argv.index('--private-key')+1]),Path(self.cfg['paths']['private_key']))
        self.assertFalse(any(key.startswith('HOMELAB_APP_SECRET_') for key in environment))
        if phase!='preparation':
            app=variables['component_application']
            self.assertEqual(started['phase_inputs']['app'],app['id'])
            self.assertEqual(variables['component_services'],list(app['identity']['services'].values()))
            self.assertEqual(variables['component_compose_file'],'/opt/homelab-app/'+app['project_file'])
            self.calls.append(variables['component_preflight']['previously_owned'])
        write_new(log,b'example : ok=1 changed=0 failed=0\n')

    def all_phases(self):
        return [deploy.run(phase,self.packet,inputs=self.inputs,environment={})
                for phase in ['infrastructure',*self.cfg['deployment']['phases']]]

    def test_real_source_and_receiver_repeat_owned_fresh_guest_without_lifecycle_flip(self):
        self.all_phases()
        receipt=self.state/'610/ordinary-complete.json'
        first=read_json(receipt,private=True)
        self.assertEqual(first['schema'],'homelab-component-ordinary-complete-v1')
        payload=Path(first['binding']['app_inputs_directory'])/'recursive_a'
        before={p.name:(p.stat().st_ino,p.read_bytes()) for p in payload.iterdir()}
        with patch.dict(os.environ,{'GITHUB_RUN_ID':'102','GITHUB_RUN_NUMBER':'11'}):
            self.all_phases()
            self.assertFalse(deploy.run('infrastructure',self.packet,inputs=self.inputs)['target_contacted'])
        self.assertEqual(self.calls,[False,True])
        self.assertEqual(self.infra,[0,1])
        self.assertEqual(before,{p.name:(p.stat().st_ino,p.read_bytes()) for p in payload.iterdir()})
        self.assertEqual(self.cfg['deployment']['lifecycle'],'fresh')
        self.assertFalse((self.state/'610/ORDINARY-HOLD.json').exists())

    def test_changed_hold_during_final_app_preserves_previous_success_and_payload(self):
        self.assert_hold_failure(after_phase_marker=False)

    def test_changed_hold_after_final_phase_marker_refuses_attempt_success(self):
        self.assert_hold_failure(after_phase_marker=True)

    def assert_hold_failure(self, *, after_phase_marker):
        self.all_phases()
        receipt=self.state/'610/ordinary-complete.json'
        canonical=(receipt.stat().st_ino,receipt.read_bytes())
        previous=read_json(receipt,private=True)
        immutable=Path(previous['operation'])/'complete.json'
        immutable_before=(immutable.stat().st_ino,immutable.read_bytes())
        payload=Path(previous['binding']['app_inputs_directory'])/'recursive_a'
        def payload_snapshot():
            return {str(path.relative_to(payload)):(path.stat().st_ino,path.read_bytes())
                    for path in payload.rglob('*') if path.is_file()}
        payload_before=payload_snapshot()
        hold=self.state/'610/ORDINARY-HOLD.json'
        foreign=encoded({'synthetic_foreign_hold':'replaced during final app'})
        final_phase=self.cfg['deployment']['phases'][-1]
        reached=[]
        def replace_hold_after_app(argv,environment,log):
            self.ansible(argv,environment,log)
            self.assertEqual(log.parent.name,final_phase)
            reached.append(final_phase)
            write_bytes(hold,foreign)
        original_write=deployment_state.write_new
        def replace_hold_after_phase(path,raw):
            original_write(path,raw)
            if path.name==final_phase+'-complete.json':
                reached.append(final_phase)
                write_bytes(hold,foreign)
        with patch.dict(os.environ,{'GITHUB_RUN_ID':'102','GITHUB_RUN_NUMBER':'11'}):
            deploy.run('infrastructure',self.packet,inputs=self.inputs,environment={})
            deploy.run('preparation',self.packet,inputs=self.inputs,environment={})
            injection=(patch.object(deployment_state,'write_new',side_effect=replace_hold_after_phase)
                       if after_phase_marker else
                       patch.object(component_ansible,'quiet',side_effect=replace_hold_after_app))
            with injection:
                with self.assertRaisesRegex(ValueError,'Deployment hold ownership changed'):
                    deploy.run(final_phase,self.packet,inputs=self.inputs,environment={})
        operation=self.state/'610/ordinary-102-1'
        self.assertEqual(reached,[final_phase])
        checks={
            'canonical unchanged':(receipt.stat().st_ino,receipt.read_bytes())==canonical,
            'previous immutable unchanged':(immutable.stat().st_ino,immutable.read_bytes())==immutable_before,
            'payload unchanged':payload_snapshot()==payload_before,
            'foreign hold unchanged':hold.read_bytes()==foreign,
            'current STARTED preserved':(operation/(final_phase+'-started.json')).is_file(),
            'phase marker matches mutation point':(operation/(final_phase+'-complete.json')).exists()==after_phase_marker,
            'no final attempt success':not (operation/'complete.json').exists(),
        }
        for boundary,accepted in checks.items():
            with self.subTest(boundary=boundary):self.assertTrue(accepted)

    def test_fresh_cannot_adopt_an_existing_unowned_backend(self):
        work=self.state/'610';work.mkdir(mode=0o700)
        write_new(work/'terraform.tfstate',b'{"foreign":true}')
        before=(work/'terraform.tfstate').read_bytes()
        with self.assertRaisesRegex(ValueError,'cannot adopt'):
            deploy.run('infrastructure',self.packet,inputs=self.inputs,environment={})
        self.assertEqual(self.infra,[]);self.assertEqual(self.calls,[])
        self.assertEqual((work/'terraform.tfstate').read_bytes(),before)
        self.assertFalse((work/'ORDINARY-HOLD.json').exists())

    def test_wrong_phase_or_secret_payload_drift_never_executes_next_native_step(self):
        deploy.run('infrastructure',self.packet,inputs=self.inputs,environment={})
        with self.assertRaises((ValueError,OSError)):
            deploy.run('recursive_a',self.packet,inputs=self.inputs,environment={})
        self.assertEqual(self.calls,[])
        deploy.run('preparation',self.packet,inputs=self.inputs,environment={})
        deploy.run('recursive_a',self.packet,inputs=self.inputs,environment={})
        receipt=read_json(self.state/'610/ordinary-complete.json',private=True)
        application=Path(receipt['binding']['app_inputs_directory'])/'recursive_a/application.json'
        application.write_bytes(b'changed')
        with patch.dict(os.environ,{'GITHUB_RUN_ID':'102','GITHUB_RUN_NUMBER':'11'}):
            with self.assertRaises(ValueError):
                deploy.run('infrastructure',self.packet,inputs=self.inputs,environment={})
        self.assertEqual(self.infra,[0])
        self.assertFalse((self.state/'610/ordinary-102-1').exists())


if __name__=='__main__':unittest.main()
