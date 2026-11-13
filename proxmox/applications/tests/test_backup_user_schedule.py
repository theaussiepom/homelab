"""Account-owned units preserve the existing schedule, owner and sealed source contract."""
import copy
import json
import os
from pathlib import Path
import shlex
import stat
import sys
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import backup_controller as subject
import backup_source
from test_backup_group import scope


class ScheduleTests(unittest.TestCase):
    """Test real rendering and readback, separating platform collaborators from policy."""
    def setUp(self):
        self.value = {'schema':'homelab-pbs-schedule-v1', 'group':scope(),
            'schedule': {'calendar':'daily','jitter_seconds':120},
            'limits':{'max_bytes':1024**2,'max_files':100,'timeout_seconds':1800}}
        self.actor = {'uid':1000,'home':'/home/runner','environment':{'XDG_RUNTIME_DIR':'/run/user/1000',
            'DBUS_SESSION_BUS_ADDRESS':'unix:path=/run/user/1000/bus'}}
        self.base = min(row['state_root'] for row in self.value['group']['members'].values())+'/backup-controller'
        self.directory = self.base+'/framework/'+'b'*64+'/proxmox/applications'
        self.render = subject.units(self.value,self.directory,1000,'/home/runner')

    def test_unit_command_verifies_before_import_and_preserves_unprivileged_timer_semantics(self):
        spec = self.render
        self.assertEqual(spec['group_path'],self.base+'/schedules/homelab-backup-example.json')
        self.assertEqual(spec['unit_directory'],'/home/runner/.config/systemd/user')
        service = spec['service'];timer=spec['timer']
        self.assertNotIn('\nUser=',service);self.assertIn('NoNewPrivileges=true\n',service)
        self.assertIn('Persistent=false\n',timer);self.assertIn('RandomizedDelaySec=120\n',timer)
        self.assertIn('00:00:00 UTC\n',timer)
        argv = shlex.split(next(line.split('=',1)[1] for line in service.splitlines() if line.startswith('ExecStart=')))
        self.assertEqual(argv[:4],['/usr/bin/python3','-I','-B','-c'])
        self.assertEqual(argv[5:],[self.directory,'b'*64,spec['group_path']])
        # Execute the actual entry expression: a verification refusal must prevent any runpy/import.
        with patch.object(sys,'argv',['entry',*argv[5:]]), patch('runpy.run_path') as run, \
                patch('pathlib.Path.lstat',side_effect=ValueError('source-owner-refused')):
            with self.assertRaisesRegex(ValueError,'source-owner-refused'):exec(argv[4],{})
            run.assert_not_called()
        with patch.object(subject.backup_user,'account',return_value=self.actor):
            self.assertEqual(subject.units(self.value,self.directory,1000),spec)
        for uid in (0,True,-1,'1000'):
            with self.assertRaises(ValueError):subject.units(self.value,self.directory,uid,'/home/runner')
        for path in ['relative','/bad%path','/bad$path','/bad"path','/bad\\path','/a/../b','/a//b','/bad\npath']:
            with self.assertRaises(ValueError):subject.units(self.value,path,1000,'/home/runner')
            with self.assertRaises(ValueError):subject.units(self.value,self.directory,1000,path)
        with self.assertRaisesRegex(ValueError,'versioned'):subject.units(self.value,'/source/applications',1000,'/home/runner')

    def installation(self, changes=None, status=None, source_error=None):
        spec = self.render
        files={spec['group_path']:json.dumps(self.value).encode(),spec['owner_path']:json.dumps(spec['owner']).encode(),
            spec['unit_directory']+'/'+spec['name']+'.service':spec['service'].encode(),
            spec['unit_directory']+'/'+spec['name']+'.timer':spec['timer'].encode()}
        files.update(changes or {})
        def show(unit,keys,**kwargs):
            self.assertEqual(kwargs['scope'],'user');self.assertEqual(kwargs['environment'],self.actor['environment'])
            if keys == ['ActiveState','UnitFileState']:return status or {'ActiveState':'active','UnitFileState':'enabled'}
            return status or {'LoadState':'loaded','FragmentPath':spec['unit_directory']+'/'+unit,'DropInPaths':'','NeedDaemonReload':'no'}
        with patch.object(subject.backup_user,'verify',return_value=self.actor), \
                patch('deployment_inputs.source_hash',return_value='b'*64), \
                patch.object(subject.backup_user,'read',side_effect=lambda path,*args:files[str(path)]), \
                patch.object(subject.backup_user,'ancestors'), patch.object(subject.backup_user,'show',side_effect=show), \
                patch.object(subject.backup_source,'verify',side_effect=source_error) as verify:
            subject.installation(self.value)
            verify.assert_called_once_with(self.directory,'b'*64,1000)

    def test_repeat_installation_requires_exact_owner_source_files_and_loaded_user_timer(self):
        self.installation()
        spec=self.render
        for path,raw in [(spec['group_path'],b'{}'),(spec['owner_path'],b'{}'),
                (spec['unit_directory']+'/'+spec['name']+'.service',b'foreign'),
                (spec['unit_directory']+'/'+spec['name']+'.timer',b'foreign')]:
            with self.assertRaises(ValueError):self.installation({path:raw})
        for status in [{'LoadState':'loaded','FragmentPath':'/foreign','DropInPaths':'','NeedDaemonReload':'no'},
                {'LoadState':'loaded','FragmentPath':spec['unit_directory']+'/'+spec['name']+'.service','DropInPaths':'/override','NeedDaemonReload':'no'},
                {'ActiveState':'inactive','UnitFileState':'disabled'}]:
            with self.assertRaises(ValueError):self.installation(status=status)
        with self.assertRaisesRegex(ValueError,'hash changed'):self.installation(source_error=ValueError('hash changed'))

    def test_ancestor_root_is_allowed_but_bundle_files_must_belong_to_selected_actor(self):
        path=Path('/source/file');info=type('Info',(),{'st_uid':1000,'st_mode':stat.S_IFREG|0o444,'st_nlink':1})()
        with patch.object(Path,'lstat',return_value=info):backup_source.metadata(path,False,1000)
        for uid in (0,1001):
            info=type('Info',(),{'st_uid':uid,'st_mode':stat.S_IFREG|0o444,'st_nlink':1})()
            with patch.object(Path,'lstat',return_value=info),self.assertRaises(ValueError):backup_source.metadata(path,False,1000)


class InstallerTests(unittest.TestCase):
    """Evaluate the actual controller task assertions without executing any module."""
    @classmethod
    def setUpClass(cls):
        import tempfile
        temp=tempfile.TemporaryDirectory(prefix='backup-installer-contract-');cls.addClassCleanup(temp.cleanup)
        guard=patch.dict(os.environ,{'ANSIBLE_LOCAL_TEMP':str(Path(temp.name).resolve())})
        guard.start();cls.addClassCleanup(guard.stop)

    def setUp(self):
        import yaml
        root=Path(__file__).resolve().parents[1]
        self.block=yaml.safe_load((root/'ansible/tasks/backup-controller.yml').read_text())[-1]
        self.tasks={row['name']:row for row in self.block['block']}
        self.spec={'name':'homelab-backup-example','unit_directory':'/home/runner/.config/systemd/user','user':1000}

    def assertions(self,name,values):
        from ansible.template import Templar,trust_as_template
        expressions=self.tasks[name]['ansible.builtin.assert']['that']
        return all(Templar(variables=values).evaluate_expression(trust_as_template(expr)) for expr in expressions)

    def test_local_unit_install_has_no_become_and_uses_explicit_user_scope(self):
        self.assertIs(self.block['become'],False);self.assertEqual(self.block['delegate_to'],'localhost')
        self.assertEqual(self.block['environment'],'{{ backup_controller.environment }}')
        for row in self.tasks.values():self.assertNotIn('become',row)
        unit=self.tasks['Enable the declared schedule without running a backup during CD']['ansible.builtin.systemd_service']
        self.assertEqual(unit['scope'],'user');self.assertEqual(unit['state'],'started')
        self.assertEqual(unit['name'],'{{ backup_controller.name }}.timer')
        self.assertTrue(unit['enabled']);self.assertTrue(unit['daemon_reload'])
        loaded=self.tasks['Verify existing user units before changing declarations']['ansible.builtin.command']['argv']
        self.assertIn('--property=DropInPaths',loaded);self.assertIn('--user',loaded)
        self.assertNotIn('restart',repr(self.block))

    def test_first_repeat_partial_foreign_and_unsafe_schedule_records(self):
        names=('backup_service_before','backup_timer_before','backup_group_before','backup_schedule_owner_before')
        def values(exists):
            return {'backup_controller':self.spec,**{name:{'stat':{'exists':exists,'isreg':True,
                'islnk':False,'nlink':1,'uid':1000,'mode':'0644' if name in names[:2] else '0600'}} for name in names}}
        name='Refuse an unowned existing schedule'
        for exists in (False,True):self.assertTrue(self.assertions(name,values(exists)))
        for row in names:
            for key,value in [('exists',False),('uid',0),('islnk',True),('isreg',False),('nlink',2),('mode','0666')]:
                v=values(True);v[row]['stat'][key]=value
                self.assertFalse(self.assertions(name,v),(row,key))

    def test_explicit_empty_dropin_property_is_accepted_and_overrides_or_unknown_refuse(self):
        name='Refuse an unexpected effective user unit'
        lines=['FragmentPath=/home/runner/.config/systemd/user/homelab-backup-example.service','DropInPaths=','NeedDaemonReload=no']
        item={'stderr':'','stdout_lines':lines,'item':'service'}
        self.assertTrue(self.assertions(name,{'backup_controller':self.spec,'item':item}))
        for change in [{'stderr':'warning'}, {'stdout_lines':lines[:1]+['DropInPaths=/foreign','NeedDaemonReload=no']},
                {'stdout_lines':lines[:2]}, {'stdout_lines':['FragmentPath=/foreign',*lines[1:]]},
                {'stdout_lines':[*lines[:2],'NeedDaemonReload=yes']}]:
            self.assertFalse(self.assertions(name,{'backup_controller':self.spec,'item':{**item,**change}}))
