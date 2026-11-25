"""Authorize one held app and retain its evidence until current-main verification."""
from contextlib import nullcontext
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import guest_recovery
import authentik_forward as forward
from private_io import encoded, sha


class ForwardTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.site = Path(temporary.name).resolve(); self.work = self.site/'state'; self.work.mkdir()
        self.op = self.work/'ordinary-14-1'; self.op.mkdir(); self.folder = self.work/'recovery-14-1'; self.folder.mkdir(mode=0o700)
        self.ticket = self.site/'authentik-forward.json'; self.hold = self.work/'ORDINARY-HOLD.json'
        self.phases = ['preparation','id','zabbix-agent','pbs-agent']
        self.cfg = {'guest':{'vmid':1}, 'site':{'node':'node'}, 'deployment':{'phases':self.phases,
            'input_directory':str(self.site), 'runtime_file':str(self.site/'runtime.json')}}
        self.binding = {'source_sha256':'old','app_inputs_directory':str(self.site/'apps')}
        self.marker = {'operation':str(self.op),'binding':self.binding, 'workflow':['o/r','o/r/.github/workflows/deploy.yml']}
        self.env = {'GITHUB_REPOSITORY':'o/r','GITHUB_WORKFLOW_REF':self.marker['workflow'][1]+'@refs/heads/main',
                    'RUNNER_TEMP':str(self.site)}
        self.app = {'identity':{'phase':'id'}, 'lifecycle':'retained','adapter':'authentik','image_update':'release-series'}
        self.proofs = {phase:{'app':phase} for phase in self.phases[1:]};self.proofs['preparation']=None
        self.write(self.hold,self.marker); self.request = {'guest':'identity','operation':self.op.name,'hold_sha256':sha(self.hold)}
        self.write(self.ticket,self.request); self.write(self.site/'runtime.json',{'applications':{'app':self.app}})
        self.write(self.op/'id-started.json',dict(self.marker,phase_inputs=self.proofs['id']))
        self.write(self.op/'preparation-complete.json',{}); self.write(self.op/'infrastructure-complete.json',{
            'binding':self.binding,'state_sha256':'state','state_identity':{'id':1}})
        self.write(self.op/'id-schema-rollback-limit.json',{'schema':'homelab-authentik-schema-transition-v1','images':['a','b']})
        self.write(self.folder/'result.json',{'status':'recovery_required'})
        self.ownerfile=self.work/'owner.json'; self.write(self.ownerfile,{'owner':1}); self.saved={'marker':self.marker}
        self.mock(forward.recovery,'enabled',True); self.mock(forward.recovery,'locked',nullcontext(self.work))
        self.state=self.mock(forward.current,'read',None);self.mock(forward.recovery,'baseline',self.saved)
        self.mock(forward.recovery,'owner',(self.ownerfile,{},self.cfg));self.mock(forward.current,'owner_path',self.ownerfile)
        self.settled=self.mock(forward.recovery,'forward_settled',None);self.mock(forward.generation,'sealed_inputs',(self.cfg,{'app':self.app}))
        self.mock(forward.authentik_upgrade,'plan',{'images':['a','b']});self.mock(forward.generation,'backend',('state',{'id':1}))
        self.mock(forward.AppPayload,'load',object()); self.apply=self.mock(forward.component_ansible,'run_phase',{})
        self.finish=self.mock(forward.recovery,'reconcile',{});self.subject={'binding':dict(self.binding,source_sha256='fixed'), 'phase_inputs':self.proofs}
        self.target=Mock(return_value=(self.cfg,self.subject))

    def write(self,path,value):
        path.write_bytes(encoded(value));path.chmod(0o600)

    def mock(self,module,name,result):
        return self.enterContext(patch.object(module,name,return_value=result))

    def call(self,guest='identity'):
        forward.requested(self.site,guest,{},self.cfg,self.env,self.target)

    def test_exact_held_checkpoint_resumes_only_app_and_enrolled_agents_before_verification(self):
        self.call()
        self.assertEqual([call.args[5] for call in self.apply.call_args_list], self.phases[1:])
        self.assertTrue(self.apply.call_args_list[0].kwargs['resume'])
        self.assertNotIn('upgrade',self.apply.call_args_list[1].kwargs)
        self.assertEqual([call.kwargs for call in self.target.call_args_list],[{'phase':'zabbix-agent'},{'phase':'pbs-agent'},{}])
        self.finish.assert_called_once(); self.assertTrue(self.finish.call_args.kwargs['pending_forward'])
        self.assertEqual(sha(self.hold),self.request['hold_sha256']);self.assertFalse(self.apply.call_args.args[3].exists())

    def test_missing_foreign_spent_or_already_published_approval_is_inert(self):
        self.call('other'); self.state.return_value=({'resolved':{self.op.name:{}}},{})
        self.call(); self.write(self.hold,dict(self.marker,operation=str(self.work/'ordinary-15-1')));self.call()
        self.hold.unlink();self.call();self.ticket.unlink();self.call();self.apply.assert_not_called();self.finish.assert_not_called()

    def test_changed_hold_inputs_state_or_payload_refuses_before_app_start(self):
        for field in ['fingerprint','bindings','stage','proof','different-input','agents','backend','ticket','workflow']:
            with self.subTest(field=field):
                case=ForwardTests();case.setUp();self.addCleanup(case.doCleanups)
                if field=='fingerprint':case.write(case.ticket,dict(case.request,hold_sha256='0'*64))
                if field=='bindings':case.saved['marker']={}
                if field=='stage':case.write(case.op/'id-complete.json',{})
                if field=='proof':case.write(case.op/'id-started.json',{'phase_inputs':case.proofs['id']})
                if field=='different-input':case.subject['binding']['app_inputs_directory']='/different'
                if field=='agents':case.phases.append('unknown')
                if field=='backend':case.write(case.op/'infrastructure-complete.json',{'binding':case.binding,'state_sha256':'changed','state_identity':{}})
                if field=='ticket':case.write(case.ticket,dict(case.request,operation='../other'))
                if field=='workflow':case.env['GITHUB_WORKFLOW_REF']='o/r/.github/workflows/other.yml@refs/heads/main'
                with self.assertRaises(ValueError):case.call()
                case.apply.assert_not_called(); case.finish.assert_not_called();case.doCleanups()

    def test_failed_native_step_keeps_the_hold_and_prior_owner(self):
        self.apply.side_effect=ValueError('failed checkpoint')
        with self.assertRaises(ValueError):self.call()
        self.finish.assert_not_called();self.assertEqual(sha(self.hold),self.request['hold_sha256'])
