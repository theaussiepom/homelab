"""Real protected schedule/enrollment records; native Ansible, PBS and SSH are fakes."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backup_setup as subject
import backup_controller
import backup_identity
import backup_readiness
from private_io import digest, encoded, read_json, write_new
from test_backup_group import scope
from test_backup_enrollment import API
import test_backup_worker as worker_fixture

PARAMETERS = subject.parameters


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.mask=os.umask(0o077);self.addCleanup(os.umask,self.mask)
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        fixture=worker_fixture.WorkerTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        self.inventory=copy.deepcopy(fixture.value)
        group=scope();self.member=next(iter(group['members']));group['members'][self.member]['state_root']=str(self.root)
        self.value={'schema':'homelab-pbs-schedule-v2','group':group,'schedule':self.inventory['job']['schedule'],
                    'limits':self.inventory['job']['limits'],'coverage':{self.member:digest(encoded(self.inventory))}}
        self.execute=Mock()
        self.api_factory=Mock()
        for target, mock in [('backup_setup.source_hash',Mock(return_value='a'*64)),
                             ('deployment_state.bootstrap_closed',Mock()), ('backup_user.verify',Mock()),
                             ('backup_controller.installation',Mock()), ('backup_setup.parameters',Mock(return_value={'finite':'variables'}))]:
            guard=patch(target,mock);guard.start();self.addCleanup(guard.stop)

    def install(self):
        return subject.install(self.value,destination=self.inventory['job']['destination'],
            datastore_path='/mnt/recovery',token='management-sentinel',api_factory=self.api_factory,execute=self.execute)

    def test_first_install_and_repeat_preserve_the_one_schedule_attempt(self):
        note=self.root/'database-network-cutover-notes';write_new(note,b'operator evidence')
        with patch.dict(os.environ,{'PBS_API_TOKEN':'private-management-sentinel','HOMELAB_APP_SECRET_FIXTURE':'private-app-sentinel'}):
            self.assertEqual(self.install()['status'],'configured')
        command, environment, log=self.execute.call_args.args
        self.assertEqual(command[:5],['ansible-playbook','-i','localhost,','-c','local'])
        self.assertTrue(command[5].endswith('/ansible/backup-controller.yml'))
        self.assertNotIn('PBS_API_TOKEN',environment);self.assertNotIn('HOMELAB_APP_SECRET_FIXTURE',environment)
        self.assertEqual(environment['ANSIBLE_CONFIG'],str(subject.SOURCE/'ansible/ansible.cfg'))
        self.api_factory.return_value.datastore.assert_called_once_with('/mnt/recovery')
        before={p.name:(p.stat().st_ino,p.read_bytes()) for p in log.parent.iterdir()}
        self.assertEqual(self.install()['status'],'verified');self.execute.assert_called_once()
        self.assertEqual(before,{p.name:(p.stat().st_ino,p.read_bytes()) for p in log.parent.iterdir()})
        self.assertEqual(note.read_bytes(),b'operator evidence')

    def test_failed_install_and_historical_failure_block_future_writes(self):
        self.execute.side_effect=ValueError('synthetic setup failure')
        with self.assertRaisesRegex(ValueError,'setup failure'):self.install()
        operation=self.execute.call_args.args[2].parent
        self.assertTrue((operation/'failed.json').exists());self.assertFalse((operation/'complete.json').exists())
        before={p.name:(p.stat().st_ino,p.read_bytes()) for p in operation.iterdir()}
        with self.assertRaisesRegex(ValueError,'no automatic recovery'):self.install()
        self.execute.assert_called_once()
        self.assertEqual(before,{p.name:(p.stat().st_ino,p.read_bytes()) for p in operation.iterdir()})

    def test_manager_refusal_and_old_schedule_cannot_visit_guests_or_install(self):
        with patch('backup_user.verify',side_effect=ValueError('manager refused')):
            with self.assertRaisesRegex(ValueError,'manager refused'):self.install()
        self.execute.assert_not_called();self.assertFalse((self.root/'backup-controller').exists())
        self.api_factory.assert_not_called()
        self.value['schema']='homelab-pbs-schedule-v1';self.value.pop('coverage')
        with self.assertRaisesRegex(ValueError,'guest-readiness'):self.install()

    def test_existing_install_transition_and_membership_are_read_before_mutation(self):
        directory=self.root/'backup-controller/schedules';directory.mkdir(parents=True,mode=0o700)
        old={k:copy.deepcopy(v) for k,v in self.value.items() if k!='coverage'};old['schema']='homelab-pbs-schedule-v1'
        path=directory/'homelab-backup-example.json';write_new(path,encoded(old))
        self.install();self.execute.assert_called_once()
        changed=copy.deepcopy(self.value);changed['group']['name']='renamed'
        with self.assertRaisesRegex(ValueError,'before renaming'):subject.continuity(changed)
        changed=copy.deepcopy(self.value);changed['group']['members'][self.member]['hostname']='moved'
        with self.assertRaisesRegex(ValueError,'Retire or move'):subject.continuity(changed)
        other=copy.deepcopy(old);other['group']['name']='independent';other['group']['members'][self.member]['vmid']=611
        write_new(directory/'homelab-backup-independent.json',encoded(other));subject.continuity(self.value)
        write_new(directory/'homelab-backup-example.owner.json',b'{}');subject.continuity(self.value)

    def test_source_bundle_and_schedule_owner_are_stable_across_internal_format_upgrade(self):
        account={'uid':1000,'home':'/home/runner','environment':{'XDG_RUNTIME_DIR':'/run/user/1000'}}
        with patch('backup_user.account',return_value=account):value=PARAMETERS(self.value)
        names={Path(row['source']).name for row in value['backup_controller_files']}
        self.assertIn('backup_readiness.py',names);self.assertIn('backup_setup.py',names);self.assertNotIn('backup_activation.py',names)
        self.assertEqual(value['backup_controller']['user'],1000)
        old={key:copy.deepcopy(row) for key,row in self.value.items() if key!='coverage'};old['schema']='homelab-pbs-schedule-v1'
        previous=backup_controller.units(old,value['backup_controller']['directory'],1000,'/home/runner')
        self.assertEqual(previous['owner'],value['backup_controller']['owner'])

    def test_missing_foreign_or_failed_historical_setup_never_becomes_readiness(self):
        operation=self.root/'backup-activation'/self.value['group']['name']/('f'*64)
        operation.mkdir(parents=True,mode=0o700)
        with self.assertRaises(FileNotFoundError):backup_readiness.legacy_holds(self.value)
        write_new(operation/'complete.json',b'{}')
        with self.assertRaisesRegex(ValueError,'foreign'):backup_readiness.legacy_holds(self.value)
        (operation/'complete.json').write_bytes(encoded({'identity':{'schema':'homelab-pbs-activation-v1'}}))
        backup_readiness.legacy_holds(self.value)
        (operation/'FAILED.json').symlink_to(operation/'absent')
        with self.assertRaisesRegex(ValueError,'no automatic recovery'):backup_readiness.legacy_holds(self.value)

    def test_current_schedule_requires_exact_full_coverage_and_root_holds_block_api(self):
        for coverage in (None,{}, {'foreign':'a'*64}, {self.member:'bad'}, {self.member:True}):
            changed={**self.value,'coverage':coverage}
            with self.subTest(coverage=coverage),self.assertRaises(ValueError):backup_controller.schedule(changed)
        changed={**self.value,'schema':'homelab-pbs-schedule-v1'}
        with self.assertRaises(ValueError):backup_controller.schedule(changed)
        write_new(self.root/'ORDINARY-HOLD.json',b'{}')
        with self.assertRaises(ValueError):self.install()
        self.api_factory.assert_not_called();self.execute.assert_not_called()

    def test_guest_enrollment_keeps_existing_key_token_and_admin_token_out_of_files(self):
        job=self.inventory['job'];job['secrets']=backup_identity.binding(job['destination'],self.inventory['owner'],job['group']['name'],str(self.root))['secrets']
        selected=backup_identity.binding(job['destination'],self.inventory['owner'],job['group']['name'],str(self.root))
        job['destination']['auth_id']=selected['auth_id']
        self.value['coverage'][self.member]=digest(encoded(self.inventory))
        directory=self.root/'inputs';directory.mkdir(mode=0o700)
        write_new(directory/'backup-group.json',encoded(self.value))
        write_new(directory/'backup-management.json',encoded({'schema':'homelab-pbs-management-v1',
            'credential':{'type':'environment','name':'PBS_API_TOKEN'},'datastore_path':'/mnt/recovery'}))
        cfg={'deployment':{'input_directory':str(directory)},'paths':{'state_root':str(self.root)},'app':{'backup':self.inventory}}
        api=API();api.datastore=Mock();factory=Mock(return_value=api);fetch=Mock(return_value=b'synthetic-native-key')
        environment={'PBS_API_TOKEN':'management-sentinel'}
        first=subject.enroll(cfg,environment,api_factory=factory,fetch=fetch)
        self.assertEqual(first,selected);self.assertTrue(fetch.call_args.kwargs['create'])
        files={p.name:(p.stat().st_ino,p.read_bytes()) for p in Path(selected['directory']).iterdir()}
        writes=[call for call in api.calls if call[0]!='GET']
        subject.enroll(cfg,environment,api_factory=factory,fetch=fetch)
        self.assertFalse(fetch.call_args.kwargs['create']);self.assertEqual(writes,[call for call in api.calls if call[0]!='GET'])
        self.assertEqual(files,{p.name:(p.stat().st_ino,p.read_bytes()) for p in Path(selected['directory']).iterdir()})
        self.assertTrue(all(b'management-sentinel' not in raw for _,raw in files.values()))
        factory.assert_called_with(job['destination'],'management-sentinel');api.datastore.assert_called_with('/mnt/recovery')
        invalid=copy.deepcopy(cfg);invalid['app']['backup']['job']['limits']['max_files']+=1
        with self.assertRaisesRegex(ValueError,'exact coverage'):subject.enroll(invalid,environment,api_factory=factory,fetch=fetch)


if __name__=='__main__':unittest.main()
