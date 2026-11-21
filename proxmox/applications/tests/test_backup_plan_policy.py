"""Only a new empty staging allocation may extend an owned mount list."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import plan_policy as policy


class BackupPlanTests(unittest.TestCase):
    def test_verified_growth_admits_only_the_observed_refresh(self):
        from test_plan import existing_fixture
        from test_backup_mount_reconciliation import mount

        plan = existing_fixture('no-op')
        change = plan['resource_changes'][0]['change']
        mounts = [mount(1, backup=True), mount(2)]
        grown = [mounts[0], dict(mounts[1], size='5G')]
        for side in ('before', 'after'):
            change[side]['mount_point'] = copy.deepcopy(grown)
        drift = copy.deepcopy(plan['resource_changes'][0])
        drift['change']['actions'] = ['update']
        drift['change']['before']['mount_point'] = mounts
        plan['resource_drift'] = [drift]
        options = {'existing': True, 'protected_guests': [],
                   'backup_selection': {'/srv/data': True, '/srv/stage': False},
                   'backup_staging': {'path': '/srv/stage', 'size': '5G', 'volume': 'local-zfs'}}
        with self.assertRaises(ValueError):
            policy.check_plan(plan, 'pve-lab', 6100, **options)
        policy.check_plan(plan, 'pve-lab', 6100, **options, staging_growth=(mounts, grown))
        drift['change']['before']['mount_point'] = [dict(mounts[0], size='7G'), mounts[1]]
        with self.assertRaises(ValueError):
            policy.check_plan(plan, 'pve-lab', 6100, **options, staging_growth=(mounts, grown))

    def test_append_only_exact_allocation_and_only_computed_name_unknown(self):
        stage={'path':'/srv/stage','size':'1G','volume':'local'}
        old=[{'path':'/srv/data','size':'8G','volume':'local','backup':True,'replicate':True}]
        new={**stage,'backup':False,'replicate':True}
        selection={'/srv/data':True,'/srv/stage':False}
        self.assertTrue(policy.backup_flags(old,old+[new],selection,stage))
        self.assertTrue(policy.backup_flags(None,[new],{'/srv/stage':False},stage))
        self.assertTrue(policy.backup_unknowns(old,old+[new],[{}, {'path_in_datastore':True}],stage))
        for key,value in [('volume','local:existing-disk'),('backup',True),('replicate',False),
            ('read_only',True),('mount_options',['bind']),('command','bad'),('path','/srv/foreign'),('size','2G')]:
            bad={**new,key:value}
            with self.subTest(field=key):self.assertFalse(policy.backup_flags(old,old+[bad],selection,stage))
        for selection in ({'/srv/data':True,'/srv/stage':True},{'/srv/data':True},{}):
            self.assertFalse(policy.backup_flags(old,old+[new],selection,stage))
        self.assertFalse(policy.backup_flags(old,[new]+old,{'/srv/data':True,'/srv/stage':False},stage))
        for unknown in ([{'id':True},{}],[{}, {'volume':True}], True, [{'id':True}]):
            self.assertFalse(policy.backup_unknowns(old,old+[new],unknown,stage))
        self.assertFalse(policy.backup_unknowns(old,old+[new],[{}, {'path_in_datastore':True}],None))
        # An empty after_unknown projection declares no deferred value.
        self.assertTrue(policy.backup_unknowns(old,old+[new],[{}],stage))
        for bad in (None,{},dict(stage,path='/srv/../outside'),dict(stage,volume='local:import')):
            self.assertFalse(policy.staging_mount(new,bad))

    def test_real_provider_caller_inspects_new_mount_before_mocked_apply_only(self):
        """Check the real provider caller's staging inspection order around fake apply."""
        from unittest.mock import patch
        import deployment_inputs
        import proxmox_guest as provider
        import backup_staging
        import test_component_deployment as fixture
        from test_plan import existing_fixture
        from private_io import encoded,write_new
        infrastructure=provider.infrastructure
        case=fixture.DeploymentIntegrationTests();case.setUp();self.addCleanup(case.doCleanups)
        cfg=copy.deepcopy(case.cfg)
        cfg['site']['node']='pve-lab';cfg['guest']['vmid']=6100;cfg['guest']['storage_id']='local'
        cfg['app']['backup']={'job':{'staging':{'path':'/srv/stage','size_bytes':1024**3}}}
        cfg['guest']['volumes']={'data':{'path':'/srv/data','size_gib':8,'backup':True},
                                'stage':{'path':'/srv/stage','size_gib':1,'backup':False}}
        cfg['paths']['api_token']=str(case.root/'token');write_new(case.root/'token',b'private synthetic token')
        work=case.root/'provider';work.mkdir(mode=0o700);write_new(work/'terraform.tfstate',b'opaque owned state')
        plan=existing_fixture('no-op');change=plan['resource_changes'][0]['change']
        old={'path':'/srv/data','size':'8G','volume':'local:existing','backup':True,'replicate':True}
        stage={'path':'/srv/stage','size':'1G','volume':'local','backup':False,'replicate':True}
        change.update(actions=['update']);change['before']['mount_point']=[old];change['after']['mount_point']=[old,stage]
        change['after_unknown']={'mount_point':[{}, {'path_in_datastore':True}]}
        seen=[]
        def quiet(argv,env,log):
            if 'plan' in argv:write_new(log.parent/'guest.tfplan',b'mock-provider saved plan')
            if 'apply' in argv:seen.append('apply')
        for existing_stage in (False,True):
            operation=case.root/('attempt-'+str(existing_stage));operation.mkdir(mode=0o700)
            if existing_stage:
                change['before']=copy.deepcopy(change['after']);change['actions']=['no-op'];change.pop('after_unknown')
            with patch.object(deployment_inputs,'binding',return_value={}),patch.object(provider,'backup'), \
                 patch.object(provider,'host_devices') as devices,patch.object(provider,'dhcp_admission'), \
                 patch.object(provider,'guest_trust') as trust,patch.object(provider,'quiet',side_effect=quiet), \
                 patch.object(provider,'api_get',return_value=[{'storage':'local','type':'zfspool','pool':'example/data'}]), \
                 patch.object(provider.subprocess,'check_output',return_value=encoded(plan)), \
                 patch.object(backup_staging,'original',return_value=True), \
                 patch.object(backup_staging,'verify',return_value={}) as verify, \
                 patch.object(backup_staging,'inspect',side_effect=lambda *args:seen.append('inspect')) as inspect:
                devices.attach.return_value=False
                result=infrastructure(cfg,case.root/'site',work,operation,{})
                self.assertEqual(inspect.call_count,0 if existing_stage else 1)
                self.assertEqual(trust.call_count,1)
                self.assertEqual(verify.call_count,2 if existing_stage else 0)
                if not existing_stage:
                    inspect.assert_called_once_with(cfg,'/srv/stage',operation/'infrastructure.log')
                    trust.assert_called_once_with(cfg,work,persist=False)
                self.assertFalse(result['created'])
                if existing_stage:
                    cfg['guest']['volumes']['data']['backup']=False
                    refused=case.root/'mismatched-no-op';refused.mkdir(mode=0o700)
                    with self.assertRaisesRegex(ValueError,'Preserve the guest identity and managed application data'):
                        infrastructure(cfg,case.root/'site',work,refused,{})
                    self.assertEqual(inspect.call_count,0)
        self.assertEqual(seen,['inspect','apply'])

    def test_growth_precedes_refresh_and_saved_plan_apply(self):
        from proxmox_guest import infrastructure

        for recording in (False, True):
            with self.subTest(recording=recording):
                self.exercise_infrastructure_growth(recording, infrastructure)

    def exercise_infrastructure_growth(self, recording, infrastructure):
        from unittest.mock import patch
        import backup_staging
        import component_generation
        import deployment_inputs
        import nfs_attachments
        import nfs_mounts
        import proxmox_guest as provider
        import test_component_deployment as fixture
        from private_io import encoded, write_new
        from test_backup_mount_reconciliation import mount
        from test_plan import existing_fixture

        case = fixture.DeploymentIntegrationTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        cfg = copy.deepcopy(case.cfg)
        cfg['site']['node'] = 'pve-lab'
        cfg['guest'].update(vmid=6100, storage_id='local-zfs', volumes={
            'data': {'path': '/srv/data', 'size_gib': 8, 'backup': True},
            'stage': {'path': '/srv/stage', 'size_gib': 5, 'backup': False}})
        cfg['app']['backup'] = {'job': {'staging': {'path': '/srv/stage', 'size_bytes': 5*1024**3}}}
        cfg['paths']['api_token'] = str(case.root/'token')
        write_new(case.root/'token', b'synthetic')
        work, operation = case.root/'provider', case.root/'attempt'
        for folder in (work, operation):
            folder.mkdir(mode=0o700)
        write_new(work/'terraform.tfstate', b'opaque owned state')
        mounts = [mount(1, backup=True), mount(2)]
        before_native = ('data-old', 'stage-old', 'recording-old')
        after_native = ('data-old', 'stage-grown', 'recording-old')
        if recording:
            cfg['guest']['recording_mount'] = {'path': '/srv/recordings', 'slot': 2,
                'source': '/mnt/approved/recordings', 'filesystem_source': 'fixture:/nvr',
                'filesystem': 'nfs4', 'filesystem_root': '/'}
            mounts.append(nfs_mounts.expected(cfg['guest']['recording_mount']))
        grown = [mounts[0], dict(mounts[1], size='5G'), *mounts[2:]]
        plan = existing_fixture('no-op')
        change = plan['resource_changes'][0]['change']
        for side in ('before', 'after'):
            change[side]['mount_point'] = grown
        drift = copy.deepcopy(plan['resource_changes'][0])
        drift['change']['before']['mount_point'] = mounts
        plan['resource_drift'] = [drift]
        calls = []

        def quiet(argv, env, log):
            calls.append(argv[2])
            if 'plan' in argv:
                write_new(log.parent/'guest.tfplan', b'fictional saved plan')

        def grow(selected, previous, growth, directory, read, resize):
            calls.append('grow')
            self.assertEqual(growth, (1, mounts))
            self.assertEqual(read('/fictional'), storage)
            resize('/nodes/pve-lab/lxc/6100/resize', {'disk': 'mp1', 'size': '5G'})
            return 1, {'inode': 9}, (mounts, grown), after_native[1]

        storage = [{'storage': 'local-zfs', 'type': 'zfspool', 'pool': 'example/data'}]
        with patch.object(deployment_inputs, 'binding', return_value={}), patch.object(provider, 'backup'), \
                patch.object(provider, 'host_devices') as devices, patch.object(provider, 'dhcp_admission'), \
                patch.object(provider, 'guest_trust'), patch.object(provider, 'quiet', side_effect=quiet), \
                patch.object(provider, 'api_get', return_value=storage), patch.object(provider, 'api_request') as request, \
                patch.object(component_generation, 'plan_identity'), \
                patch.object(provider.subprocess, 'check_output', return_value=encoded(plan)), \
                patch.object(backup_staging, 'original', return_value=(1, mounts)), \
                patch.object(backup_staging, 'grow', side_effect=grow), \
                patch.object(backup_staging, 'verify', return_value={'inode': 9}) as verify, \
                patch.object(nfs_attachments, 'attach', return_value=False), \
                patch.object(nfs_mounts, 'original', return_value=mounts), \
                patch.object(nfs_mounts, 'verify', side_effect=[(before_native, 'rootfs'),
                                                                (after_native, 'rootfs')]) as nfs_verify:
            devices.attach.return_value = False
            result = infrastructure(cfg, case.root/'site', work, operation, {}, state_identity={})
        self.assertTrue(result['changed'])
        self.assertEqual(calls, ['init', 'grow', 'plan', 'apply'])
        request.assert_called_once_with(cfg, '/nodes/pve-lab/lxc/6100/resize', resize={'disk': 'mp1', 'size': '5G'})
        self.assertEqual(verify.call_args.kwargs['mounts'], grown)
        if recording:
            self.assertEqual([call.args[1] for call in nfs_verify.call_args_list], [mounts, grown])
