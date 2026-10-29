"""Exercise the ordinary engine lifecycle without target access or secrets."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import ordinary_cd as ordinary

CONTAINER='module.guest.proxmox_virtual_environment_container.guest'


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.inputs=self.root/'ordinary';self.packet=self.root/'packet.json'
        self.value={'schema':'homelab-ordinary-deployment-v1','enabled':True,'kind':'mariadb','identity':'a'*64,
                    'files':{'site.json':json.dumps({'app':{'kind':'mariadb'}}),'homelab.cnf':'approved listener\n'}}
        p=patch.object(ordinary.deploy,'validate',return_value=808);p.start();self.addCleanup(p.stop)

    def save(self):self.packet.write_text(json.dumps(self.value))

    def test_disabled_selection_precedes_input_writes_or_credentials(self):
        self.value['enabled']=False;self.save()
        with self.assertRaises(ValueError):ordinary.prepare(self.packet,self.inputs)
        self.assertFalse(self.inputs.exists())

    def test_exact_private_preparation_is_repeatable_and_incomplete_or_changed_inputs_are_not_adopted(self):
        self.save();_,site=ordinary.prepare(self.packet,self.inputs)
        original={p.name:p.read_bytes() for p in site.parent.iterdir()}
        ordinary.prepare(self.packet,self.inputs)
        self.assertEqual(original,{p.name:p.read_bytes() for p in site.parent.iterdir()})
        self.assertEqual(site.stat().st_mode & 0o777,0o600)
        (site.parent/'prepared.json').unlink()
        with self.assertRaises(ValueError):ordinary.prepare(self.packet,self.inputs)
        self.assertFalse((site.parent/'prepared.json').exists())

    def test_runtime_token_stays_private_and_drift_does_not_replace_a_prepared_stack(self):
        self.value['kind']='automation'
        destination=self.inputs/'automation'/self.value['identity']
        self.value['files']={'site.json':json.dumps({'app':{'kind':'automation','stack_config':str(destination/'stack.json')}}),
                             'stack.json':json.dumps({'services':{'node_red':{'environment':{}}}})}
        self.save();env={'NODE_RED_API_TOKEN':'synthetic-private-token'}
        _,site=ordinary.prepare(self.packet,self.inputs,env)
        stack=site.parent/'stack.json';original=stack.read_bytes()
        self.assertIn(b'synthetic-private-token',original)
        self.assertNotIn('synthetic-private-token',self.packet.read_text())
        with self.assertRaises(ValueError):ordinary.prepare(self.packet,self.inputs,{'NODE_RED_API_TOKEN':'changed-token'})
        self.assertEqual(stack.read_bytes(),original)


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.cfg={'site':{'node':'fixture'},'guest':{'vmid':808}}
        self.value={'resource_changes':[]}
        for address,key in ordinary.check_plan.__globals__['RESOURCES'].items():
            body={key:808,'node_name':'fixture','disk':[{'size':8}], 'mount_point':[{'path':'/data','size':'4G'}]}
            self.value['resource_changes'].append({'address':address,'change':{
                'actions':['no-op'],'before':copy.deepcopy(body),'after':copy.deepcopy(body)}})

    def test_current_equal_or_approved_updates_keep_managed_data(self):
        ordinary.check_ordinary_plan(self.value,self.cfg,existing=True)
        self.value['resource_changes'][0]['change']['actions']=['update']
        self.value['resource_changes'][0]['change']['after']['cpu']=[{'cores':2}]
        ordinary.check_ordinary_plan(self.value,self.cfg,existing=True)

    def test_destroy_replace_adopt_volume_change_and_drift_are_refused(self):
        for change in [lambda v:v['resource_changes'][0]['change'].update(actions=['delete','create']),
                       lambda v:v['resource_changes'][0]['change'].update(before=None),
                       lambda v:v['resource_changes'][0]['change'].update(importing={'id':'808'}),
                       lambda v:v['resource_changes'][0]['change']['after'].update(disk=[{'size':16}]),
                       lambda v:v.update(resource_drift=[{'change':{}}])]:
            value=copy.deepcopy(self.value);change(value)
            with self.assertRaises(ValueError):ordinary.check_ordinary_plan(value,self.cfg,existing=True)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.site=self.root/'site.json';self.site.write_text('{}')
        self.cfg={'app':{'kind':'mariadb'},'guest':{'vmid':808},'paths':{'state_root':str(self.root)}}
        self.work=self.root/'808';self.work.mkdir(mode=0o700)
        (self.work/'terraform.tfstate').write_text('current authoritative backend')
        self.expected={'vmid':808,'site_sha256':'a'*64}
        for target,value in [('prepare',(self.cfg,self.site)),('binding',self.expected)]:
            p=patch.object(ordinary,target,return_value=value);p.start();self.addCleanup(p.stop)
        p=patch.object(ordinary.deploy,'validate',return_value=808);p.start();self.addCleanup(p.stop)
        p=patch.dict(ordinary.os.environ,{'GITHUB_RUN_ID':'777','GITHUB_RUN_ATTEMPT':'1'});p.start();self.addCleanup(p.stop)

    def test_one_run_completes_both_steps_and_unchanged_result_contacts_no_target(self):
        state=ordinary.deploy.sha(self.work/'terraform.tfstate')
        with patch.object(ordinary,'infrastructure',return_value={'changed':False,'created':False,'state_sha256':state}) as infra, \
             patch.object(ordinary,'application',return_value={'status':'passed','changed':False}) as app:
            first=ordinary.run('infrastructure',self.site)
            self.assertFalse(first['changed']);self.assertTrue((self.work/'ORDINARY-HOLD.json').exists())
            result=ordinary.run('application',self.site)
            self.assertFalse(result['changed']);self.assertFalse((self.work/'ORDINARY-HOLD.json').exists())
            for phase in ('infrastructure','application'):
                self.assertEqual(ordinary.run(phase,self.site)['target_contacted'],False)
            self.assertEqual(infra.call_count,1);self.assertEqual(app.call_count,1)
            self.assertFalse((self.work/'rollout-complete.json').exists())

    def test_automation_service_steps_follow_mqtt_then_ha_then_node_red(self):
        self.cfg['app']['kind']='automation'
        state=ordinary.deploy.sha(self.work/'terraform.tfstate')
        # Service ordering is tested after the separately completed first infrastructure preparation.
        ordinary.deploy.write(self.work/'ordinary-infrastructure-ready.json',
            {'status':'infrastructure-ready','binding':self.expected,'state_sha256':state,'application_ready':False})
        with patch.object(ordinary,'infrastructure',return_value={'changed':False,'created':False,'state_sha256':state}), \
             patch.object(ordinary,'application',return_value={'status':'passed','changed':False}) as app:
            ordinary.run('infrastructure',self.site)
            with self.assertRaises((ValueError,FileNotFoundError)):ordinary.run('homeassistant',self.site)
            app.assert_not_called()
            for phase in ('mqtt','homeassistant','node_red'):
                ordinary.run(phase,self.site)
            self.assertEqual([c.args[-1] for c in app.call_args_list],['mqtt','homeassistant','node_red'])
            self.assertFalse((self.work/'ORDINARY-HOLD.json').exists())
            self.assertEqual(ordinary.run('mqtt',self.site)['target_contacted'],False)

    def test_failure_is_durable_and_cannot_replay_or_be_completed_by_another_run(self):
        with patch.object(ordinary,'infrastructure',side_effect=ValueError('synthetic native failure')) as action:
            with self.assertRaises(ValueError):ordinary.run('infrastructure',self.site)
            with self.assertRaises(ValueError):ordinary.run('infrastructure',self.site)
            self.assertEqual(action.call_count,1)
        with patch.dict(ordinary.os.environ,{'GITHUB_RUN_ID':'778'}),patch.object(ordinary,'application') as app:
            with self.assertRaises(ValueError):ordinary.run('application',self.site)
            app.assert_not_called()
        self.assertTrue((self.work/'ORDINARY-HOLD.json').exists())

    def test_effective_catalogue_output_drift_between_steps_cannot_complete_old_plan(self):
        state=ordinary.deploy.sha(self.work/'terraform.tfstate')
        with patch.object(ordinary,'infrastructure',return_value={'changed':False,'created':False,'state_sha256':state}), \
             patch.object(ordinary,'application') as app:
            ordinary.run('infrastructure',self.site)
            held=(self.work/'ORDINARY-HOLD.json').read_bytes()
            # The materialised site includes the helper-derived NICs and rules.
            self.expected['site_sha256']='b'*64
            with self.assertRaises(ValueError):ordinary.run('application',self.site)
            app.assert_not_called()
            self.assertEqual((self.work/'ORDINARY-HOLD.json').read_bytes(),held)

    def test_original_and_group_holds_block_before_native_work(self):
        for directory,name in [(self.work,'ROLLOUT-HOLD.json'),(self.root/'database-network-cutover-old','HOLD.json')]:
            directory.mkdir(mode=0o700,exist_ok=True);hold=directory/name;hold.write_text('{}')
            with patch.object(ordinary,'infrastructure') as action:
                with self.assertRaises(ValueError):ordinary.run('infrastructure',self.site)
                action.assert_not_called()
            hold.unlink()

    def test_legacy_execute_cannot_bypass_an_ordinary_hold(self):
        site=self.root/'legacy.json';site.write_text(json.dumps(self.cfg))
        (self.work/'ORDINARY-HOLD.json').write_text('{}')
        with self.assertRaises(ordinary.deploy.InputNeeded):ordinary.deploy.execute('verify',site)

    def test_changed_state_cannot_use_completed_noop(self):
        ordinary.deploy.write(self.work/'ordinary-complete.json',{'status':'passed','binding':self.expected,'state_sha256':'0'*64})
        with patch.object(ordinary,'infrastructure',return_value={'changed':False,'created':False,'state_sha256':ordinary.deploy.sha(self.work/'terraform.tfstate')}) as action:
            ordinary.run('infrastructure',self.site);action.assert_called_once()


if __name__=='__main__':unittest.main()
