"""Activation coordinates mocked components; real records/locks prove repeat and failure behavior."""
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import backup_activation as subject
from private_io import encoded,write_new
from test_backup_group import scope
import test_backup_worker as worker_fixture

class ActivationTests(unittest.TestCase):
    def setUp(self):
        self.mask=os.umask(0o077);self.addCleanup(os.umask,self.mask)
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        fixture=worker_fixture.WorkerTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        self.value=fixture.value; self.group=scope();self.name=next(iter(self.group['members']))
        self.group['members'][self.name]['state_root']=str(self.root)
        (self.root/'610').mkdir(mode=0o700)
        for path in (self.root/'database-network.lock',self.root/'610/workflow.lock',self.root/'610/deployment.lock'):write_new(path,b'')
        self.cfg={'app':{'backup':self.value},'paths':{'state_root':str(self.root)},'guest':{'vmid':610},
                  'deployment':{'input_identity':'a'*64,'input_directory':str(self.root/'inputs')}}
        self.schedule={'schema':'homelab-pbs-schedule-v1','group':self.group,
                       'schedule':self.value['job']['schedule'],'limits':self.value['job']['limits']}
        self.descriptor={'schedule':self.schedule,'datastore_path':'/mnt/recovery','coverage':{self.name:self.value},'enabled':[self.name]}
        self.admitted={self.name:(self.cfg,'b'*64)}
        self.api=Mock();self.deploy=Mock(return_value={'status':'passed'})
        self.fetch=Mock(return_value=b'synthetic key')
        self.provision=Mock()
        for target,value in [('deployment_state.bootstrap_closed',Mock()),('backup_activation.source_hash',Mock(return_value='c'*64)),
                             ('backup_enrollment.provision',self.provision),('backup_agent.inputs',Mock(return_value={'pbs-key':b'key'})),
                             ('component_inputs.binding',Mock(return_value={'test':'binding'}))]:
            patched=patch(target,value);patched.start();self.addCleanup(patched.stop)
    def activate(self,admission=None):
        return subject.activate(self.descriptor,'synthetic-token',admission=admission or (lambda name,row:self.admitted[name]),
            api_factory=lambda destination,token:self.api,fetch=self.fetch,deploy=self.deploy)
    def test_first_activation_and_unchanged_repeat(self):
        self.assertEqual(self.activate()['status'],'activated')
        self.api.datastore.assert_called_once_with('/mnt/recovery')
        self.provision.assert_called_once();self.deploy.assert_called_once()
        self.assertTrue(self.deploy.call_args.kwargs['backup_schedule'])
        self.assertTrue(self.deploy.call_args.kwargs['activate_backup'])
        self.assertEqual(self.activate()['status'],'verified')
        self.deploy.assert_called_once()
        self.assertEqual(self.provision.call_count,2)
        self.assertFalse(self.provision.call_args.kwargs['allow_create'])
        subject.verify(self.schedule,self.admitted)
    def second_member(self):
        name='second';row=copy.deepcopy(self.group['members'][self.name]);row.update(vmid=611,hostname='second')
        self.group['members'][name]=row
        (self.root/'611').mkdir(mode=0o700)
        for leaf in ('workflow.lock','deployment.lock'):write_new(self.root/'611'/leaf,b'')
        cfg=copy.deepcopy(self.cfg);cfg['guest']['vmid']=611;cfg['deployment']['input_identity']='d'*64
        cfg['app']['backup']['owner'].update(vmid=611,hostname='second')
        cfg['app']['backup']['job']['group']['member']=name
        cfg['app']['backup']['job']['destination']['backup_id']=name
        self.admitted[name]=(cfg,'e'*64);self.descriptor['coverage'][name]=cfg['app']['backup']
        self.descriptor['enabled'].append(name)
        return name
    def test_disabled_member_uses_prior_activation_without_any_configuration_write(self):
        second=self.second_member();self.activate()
        self.deploy.reset_mock();self.provision.reset_mock()
        self.admitted[self.name]=(self.cfg,'f'*64);self.descriptor['enabled']=[self.name]
        self.activate()
        self.deploy.assert_called_once();self.assertEqual(self.deploy.call_args.args[0],self.cfg)
        self.assertTrue(self.deploy.call_args.kwargs['backup_schedule'])
        self.assertEqual([call.kwargs['allow_create'] for call in self.provision.call_args_list],[True,False])
        subject.verify(self.schedule,self.admitted)
    def test_later_disabled_owner_failure_prevents_all_installs(self):
        self.second_member();self.activate();self.deploy.reset_mock();self.provision.reset_mock()
        self.admitted[self.name]=(self.cfg,'f'*64);self.descriptor['enabled']=[self.name]
        self.provision.side_effect=[None,ValueError('disabled owner changed')]
        with self.assertRaisesRegex(ValueError,'disabled owner changed'):self.activate()
        self.deploy.assert_not_called()

    def test_new_disabled_member_refuses_before_remote_access(self):
        self.second_member();self.descriptor['enabled']=[self.name]
        with self.assertRaisesRegex(ValueError,'Enable this guest'):self.activate()
        self.api.datastore.assert_not_called();self.provision.assert_not_called();self.deploy.assert_not_called()
    def test_conflicting_destinations_refuse_before_pbs_or_native_calls(self):
        second=self.second_member();self.admitted[second][0]['app']['backup']['job']['destination']['server']='192.0.2.99'
        with self.assertRaisesRegex(ValueError,'one declared PBS'):self.activate()
        self.api.datastore.assert_not_called();self.deploy.assert_not_called()
    def test_unsuccessful_ansible_result_cannot_complete_activation(self):
        self.deploy.return_value={'status':'failed'}
        with self.assertRaisesRegex(ValueError,'successful backup activation'):self.activate()
        root,_=subject.location(self.schedule,self.admitted)
        self.assertTrue((root/'failed.json').exists())

    def test_missing_or_changed_deployed_coverage_stops_before_api(self):
        self.descriptor['coverage']={self.name:{}}
        with self.assertRaisesRegex(ValueError,'exact declared'):self.activate()
        self.api.datastore.assert_not_called();self.deploy.assert_not_called()
    def test_missing_datastore_never_creates_accounts(self):
        self.api.datastore.side_effect=ValueError('missing datastore')
        with self.assertRaisesRegex(ValueError,'missing datastore'):self.activate()
        self.provision.assert_not_called();self.deploy.assert_not_called()
    def test_failed_activation_preserves_record_and_blocks_repeat(self):
        self.deploy.side_effect=ValueError('synthetic deployment failure')
        with self.assertRaisesRegex(ValueError,'synthetic'):self.activate()
        root,_=subject.location(self.schedule,self.admitted)
        self.assertTrue((root/'failed.json').exists());self.assertFalse((root/'complete.json').exists())
        with self.assertRaisesRegex(ValueError,'no automatic retry'):self.activate()
        self.deploy.assert_called_once()
    def test_completed_record_does_not_accept_changed_credentials(self):
        self.activate()
        with patch('backup_agent.inputs',return_value={'pbs-key':b'changed'}):
            with self.assertRaisesRegex(ValueError,'private inputs changed'):subject.verify(self.schedule,self.admitted)
    def test_deployment_receipt_changes_during_activation_refuse_completion(self):
        reads=iter([(self.cfg,'b'*64),(self.cfg,'d'*64)])
        with self.assertRaisesRegex(ValueError,'changed during'):self.activate(lambda *args:next(reads))
        root,_=subject.location(self.schedule,self.admitted)
        self.assertTrue((root/'failed.json').exists());self.assertFalse((root/'complete.json').exists())

if __name__=='__main__':unittest.main()
