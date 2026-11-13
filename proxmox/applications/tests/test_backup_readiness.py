"""Readiness uses real ordinary receipts/payloads; only native boundaries are replaced."""
import copy
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import backup_controller
import backup_readiness as subject
import backup_setup
import component_ansible
import component_inputs
import component_payload
import component_prepare
import deploy
import proxmox_guest
from private_io import digest, encoded, read_json, sha, write_bytes, write_new
from test_backup_enrollment import API
import test_backup_reconciliation_lifecycle as lifecycle_fixture

ENROLL = backup_setup.enroll
RUN_PHASE = component_ansible.run_phase


class GuestReadinessTests(unittest.TestCase):
    def setUp(self):
        self.mask=os.umask(0o077);self.addCleanup(os.umask,self.mask)
        self.fixture=lifecycle_fixture.BackupReconciliationLifecycleTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.fixture.publish(backup=True,data=False)
        self.api=API();self.api.datastore=Mock();self.events=[];self.legacy=False
        def fetch(cfg,identity,*,create):
            self.assertIn('helpers',self.events);self.events.append('create-key' if create else 'read-key')
            return b'fixture-native-client-key'
        def enroll(cfg,environment):
            return ENROLL(cfg,environment,api_factory=lambda destination,token:self.api,fetch=fetch)
        def ansible(argv,environment,log):
            self.assertNotIn('PBS_API_TOKEN',environment)
            variables=read_json(Path(argv[-1][1:]),private=True)
            if log.parent.name=='preparation':
                self.assertIn('backup_agent',variables);self.events.append('helpers')
            if log.parent.name=='pbs-agent':
                self.events.append('worker')
                self.assertEqual('credentials' in variables['backup_agent'],not self.legacy)
                self.assertNotIn('backup_controller',variables)
                self.assertNotIn('management-sentinel',json.dumps(variables))
            return self.fixture.ansible(argv,environment,log)
        for target, options in [
            ('proxmox_guest.infrastructure',{'side_effect':self.fixture.seed}),
            ('component_ansible.quiet',{'side_effect':ansible}),
            ('backup_setup.enroll',{'side_effect':enroll}),
            ('backup_controller.installation',{}),
        ]:
            guard=patch(target,**options);guard.start();self.addCleanup(guard.stop)

    def ordinary(self):
        for phase in ['infrastructure',*self.fixture.cfg['deployment']['phases']]:
            deploy.run(phase,self.fixture.fixture.packet,inputs=self.fixture.fixture.inputs,
                environment={'PBS_API_TOKEN':'management-sentinel'} if phase=='pbs-agent' else {})

    def admitted(self):
        cfg=self.fixture.cfg
        value=read_json(Path(cfg['deployment']['input_directory'])/'backup-group.json',private=True)
        admitted={name:backup_controller.admit(name,row) for name,row in value['group']['members'].items()}
        return value,admitted

    def test_own_completed_deployment_is_ready_without_final_job_and_repeat_preserves_keys(self):
        with patch.dict(os.environ,{'PBS_API_TOKEN':'management-sentinel'}):self.ordinary()
        value,admitted=self.admitted();subject.verify(value,admitted)
        self.assertEqual(self.events,['helpers','create-key','worker'])
        cfg=next(iter(admitted.values()))[0]
        credential=Path(cfg['app']['backup']['job']['secrets']['password']['path']).parent
        before={p.name:(p.stat().st_ino,p.read_bytes()) for p in credential.iterdir()}
        receipt=read_json(self.fixture.work/'ordinary-complete.json',private=True)
        old_immutable=Path(receipt['operation'])/'complete.json';old_bytes=old_immutable.read_bytes()
        with patch.dict(os.environ,{'GITHUB_RUN_ID':'102','GITHUB_RUN_NUMBER':'11'}):self.ordinary()
        value,admitted=self.admitted();subject.verify(value,admitted)
        self.assertEqual(self.events[-3:],['helpers','read-key','worker'])
        self.assertEqual(before,{p.name:(p.stat().st_ino,p.read_bytes()) for p in credential.iterdir()})
        self.assertEqual(old_immutable.read_bytes(),old_bytes)
        self.assertFalse((self.fixture.fixture.state/'backup-activation').exists())
        self.assertTrue(all(b'management-sentinel' not in p.read_bytes()
            for p in self.fixture.fixture.inputs.rglob('*') if p.is_file()))

    def test_disabled_or_failed_changed_member_cannot_borrow_an_old_ready_receipt(self):
        self.ordinary();old_value,admitted=self.admitted();subject.verify(old_value,admitted)
        self.fixture.source['backup']['job']['limits']['max_files']+=1
        self.fixture.publish(backup=True,data=False)
        packet=read_json(self.fixture.fixture.packet,private=True)
        desired=json.loads(packet['files']['backup-group.json'])
        with self.assertRaisesRegex(ValueError,'including disabled'):subject.verify(desired,admitted)
        # An unchanged member may retain its older genuinely completed deployment.
        subject.verify(old_value,admitted)
        canonical=self.fixture.work/'ordinary-complete.json';before=(canonical.stat().st_ino,canonical.read_bytes())
        def failed_worker(argv,environment,log):
            if log.parent.name=='pbs-agent':raise ValueError('worker readiness failed')
            return self.fixture.ansible(argv,environment,log)
        with patch.dict(os.environ,{'GITHUB_RUN_ID':'102','GITHUB_RUN_NUMBER':'11'}), \
             patch.object(component_ansible,'quiet',side_effect=failed_worker):
            with self.assertRaisesRegex(ValueError,'readiness failed'):self.ordinary()
        self.assertEqual(before,(canonical.stat().st_ino,canonical.read_bytes()))
        self.assertTrue((self.fixture.work/'ORDINARY-HOLD.json').exists())
        with self.assertRaises(ValueError):backup_controller.admit(next(iter(desired['group']['members'])),next(iter(desired['group']['members'].values())))

    def test_private_input_drift_missing_member_and_wrong_receipt_stop_capture(self):
        self.ordinary();value,admitted=self.admitted()
        with self.assertRaisesRegex(ValueError,'complete declared group'):subject.verify(value,{})
        legacy={key:copy.deepcopy(row) for key,row in value.items() if key!='coverage'};legacy['schema']='homelab-pbs-schedule-v1'
        with self.assertRaisesRegex(ValueError,'guest-owned'):subject.verify(legacy,admitted)
        name,(cfg,proof)=next(iter(admitted.items()))
        with self.assertRaisesRegex(ValueError,'admitted completed'):subject.verify(value,{name:(cfg,'f'*64)})
        path=Path(cfg['app']['backup']['job']['secrets']['encryption_key']['path']);raw=path.read_bytes()
        path.write_bytes(b'changed-private-key')
        with self.assertRaisesRegex(ValueError,'exact current private inputs'):subject.verify(value,admitted)
        path.write_bytes(raw);subject.verify(value,admitted)
        receipt=read_json(self.fixture.work/'ordinary-complete.json',private=True)
        payload=Path(receipt['binding']['app_inputs_directory'])/'backup-agent'/'pbs-key'
        payload.write_bytes(b'changed-sealed-key')
        with self.assertRaises(ValueError):subject.verify(value,admitted)

    def test_existing_coverage_only_deployment_transitions_through_cd_without_key_rotation(self):
        def legacy_prepare(cfg,environment):
            backup_setup.enroll(cfg,environment)
            parent=component_inputs.app_directory(cfg,create=True)
            return component_payload.prepare(parent,cfg['deployment']['input_identity'],'backup-agent',
                {'application.json':encoded(cfg['app']['backup'])})
        def legacy_phase(cfg,site,work,operation,expected,phase,**options):
            if phase!='pbs-agent':return RUN_PHASE(cfg,site,work,operation,expected,phase,**options)
            self.events.append('worker')
            self.assertEqual(set(json.loads(options['payload'].manifest)['files']),{'application.json'})
            return {'status':'passed','changed':False}
        self.legacy=True
        with patch.object(component_prepare,'prepare_backup',side_effect=legacy_prepare), \
             patch.object(component_ansible,'run_phase',side_effect=legacy_phase):self.ordinary()
        value,admitted=self.admitted()
        parent=self.fixture.fixture.state/'backup-activation'/value['group']['name']
        operation=parent/('a'*64);operation.mkdir(parents=True,mode=0o700)
        record=operation/'complete.json';write_new(record,encoded({'identity':{'schema':'homelab-pbs-activation-v1'}}))
        old=(record.stat().st_ino,record.read_bytes())
        with self.assertRaisesRegex(ValueError,'Complete this guest Backup'):subject.verify(value,admitted)
        # A new compiled input tree is installed by ordinary CD, never by editing the old payload.
        self.fixture.source['backup']['job']['limits']['max_files']+=1
        self.fixture.publish(backup=True,data=False);self.legacy=False
        with patch.dict(os.environ,{'GITHUB_RUN_ID':'102','GITHUB_RUN_NUMBER':'11'}):self.ordinary()
        value,admitted=self.admitted();subject.verify(value,admitted)
        self.assertEqual(self.events.count('create-key'),1);self.assertEqual(self.events.count('read-key'),1)
        self.assertEqual(old,(record.stat().st_ino,record.read_bytes()))
        failure=operation/'failed.json';write_new(failure,b'{}')
        with self.assertRaisesRegex(ValueError,'no automatic recovery'):subject.verify(value,admitted)
        self.assertEqual(old,(record.stat().st_ino,record.read_bytes()))


if __name__=='__main__':unittest.main()
