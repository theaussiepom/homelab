"""Exact NAS append admission preserves existing owned mounts and native flags."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import scrypted_mount as mount
import backup_staging
import plan_policy
from test_plan import existing_fixture
from test_backup_mount_reconciliation import mount as allocated


def declaration():
    return {'source':'/mnt/example/recordings', 'path':'/srv/recordings', 'slot':2,
        'filesystem_source':'nas.example.invalid:/recordings', 'filesystem':'nfs4',
        'filesystem_root':'/camera'}


def cfg():
    return {'site':{'node':'pve-lab'}, 'guest':{'vmid':6100, 'hostname':'cameras',
        'recording_mount':declaration(), 'volumes':{'data':{}, 'stage':{}}},
        'app':{'address':'198.18.25.10'}, 'paths':{'known_hosts':'/private/known_hosts',
                                                'private_key':'/private/key'}}


def mounts():
    return [allocated(1, backup=True), allocated(2), mount.expected(declaration())]


def native(rows):
    result = {'hostname':'cameras', 'unprivileged':1, 'protection':1,
        'rootfs':'local-zfs:subvol-6100-disk-0,size=16G'}
    for slot, row in enumerate(rows):
        result['mp'+str(slot)] = row['volume']+',mp='+row['path']+(
            ',size='+row['size'] if row['size'] else '')+(
            ',backup='+str(int(row['backup']))+',replicate='+str(int(row['replicate'])))
    return result


class RecordingDeclaration(unittest.TestCase):
    def test_closed_literal_paths_nfs_metadata_and_slot(self):
        value = declaration(); before = copy.deepcopy(value)
        self.assertEqual(mount.declaration(value), before)
        for key in value:
            broken=copy.deepcopy(value); broken.pop(key)
            with self.subTest(missing=key), self.assertRaises(ValueError): mount.declaration(broken)
        changes = {'source':[None, '/etc/secret', '/mnt/../etc', '/mnt/a,mp=/sys', '/mnt/a b'],
            'path':['/etc/recordings', 'relative', '/srv/a/../b', '/srv/a/'],
            'slot':[True, -1, 256], 'filesystem':['ext4'],
            'filesystem_source':['bad', 'nas:/recordings,ro', 'nas:/recordings\n'],
            'filesystem_root':['relative', '/a/../b', '/a//b', '/a\n']}
        for key, values in changes.items():
            for item in values:
                broken={**value, key:item}
                with self.subTest(key=key, value=item), self.assertRaises(ValueError): mount.declaration(broken)
        with self.assertRaises(ValueError): mount.declaration({**value, 'command':'private'})
        mount.declaration({**value, 'filesystem_root':'/', 'filesystem':'nfs'})

    def test_provider_and_native_flags_cannot_capture_or_replicate_recordings(self):
        value=declaration(); row=mount.expected(value)
        self.assertTrue(mount.provider_row(row, value))
        self.assertTrue(mount.provider_row({**row, 'mount_options':None}, value))
        self.assertFalse(mount.provider_row(None, value))
        for key, item in {'volume':'/mnt/foreign', 'path':'/srv/foreign', 'size':'4G',
            'backup':True, 'replicate':True, 'acl':True, 'quota':True, 'read_only':True,
            'shared':True, 'mount_options':['ro'], 'path_in_datastore':'foreign', 'extra':True}.items():
            with self.subTest(key=key): self.assertFalse(mount.provider_row({**row,key:item},value))
        self.assertFalse(mount.provider_row({**row,'backup':0},value))
        raw=native([row])['mp0']
        self.assertEqual(backup_staging.native_row(raw,row),raw)
        for bad in [None,'x'*4097,raw+',backup=0',raw+',private',raw+',size=4G',
                    raw.replace('replicate=0','replicate=1'),raw.replace('/srv/recordings','/srv/other'),
                    raw+',ro=1',raw+',acl=1']:
            with self.subTest(raw=bad), self.assertRaises(ValueError): mount.native_row(bad,row)

    def test_prior_success_distinguishes_new_append_from_repeat_or_implicit_adoption(self):
        current=cfg(); rows=mounts(); previous={'guest':{}}
        with patch.object(backup_staging,'backend_mounts',return_value=rows[:-1]):
            self.assertEqual(mount.original(current,previous,Path('/unused')),rows)
            for bad in (None, {'guest':{'recording_mount':declaration()}}):
                with self.assertRaises(ValueError): mount.original(current,bad,Path('/unused'))
        with patch.object(backup_staging,'backend_mounts',return_value=rows):
            self.assertEqual(mount.original(current,current,Path('/unused')),rows)
            with self.assertRaises(ValueError): mount.original(current,previous,Path('/unused'))
        for change in (lambda r:r['guest']['recording_mount'].update(source='/mnt/changed'),
                       lambda r:r['guest']['volumes'].clear()):
            broken=copy.deepcopy(current); change(broken)
            with patch.object(backup_staging,'backend_mounts',return_value=rows), self.assertRaises(ValueError):
                mount.original(broken,current,Path('/unused'))


class RecordingPlanAdmission(unittest.TestCase):
    def test_unqualified_or_nonappend_recording_drift_remains_false(self):
        before=mounts()[:-1];after=mounts();after[-1]['volume']='/mnt/foreign'
        self.assertFalse(plan_policy.declared_backup_drift(before,after,None,None,6100,
                                                         recording_mount=declaration()))
        self.assertFalse(plan_policy.declared_backup_drift(before,[],None,None,6100,
                                                         recording_mount=declaration()))
    def plan(self):
        value=existing_fixture('no-op'); resource=value['resource_changes'][0]
        old=copy.deepcopy(resource['change']['before']);old['mount_point']=mounts()[:-1]
        new=copy.deepcopy(old);new['mount_point']=mounts()
        resource['change'].update(before=copy.deepcopy(new),after=copy.deepcopy(new))
        drift=copy.deepcopy(resource);drift['change'].update(actions=['update'],before=old,after=new)
        value['resource_drift']=[drift]
        return value

    def check(self,value,**kwargs):
        return plan_policy.check_plan(value,'pve-lab',6100,existing=True,protected_guests=[],
            recording_mount=declaration(),backup_selection={row['path']:row['backup'] for row in mounts()},**kwargs)

    def test_exact_append_then_ordinary_repeat_preserve_every_existing_mount(self):
        value=self.plan();before=copy.deepcopy(value);self.check(value);self.assertEqual(value,before)
        value.pop('resource_drift');self.check(value)
        for mutate in (
            lambda v:v['resource_drift'][0]['change']['before']['mount_point'].reverse(),
            lambda v:v['resource_drift'][0]['change']['after']['mount_point'][0].update(size='20G'),
            lambda v:v['resource_changes'][0]['change']['after']['mount_point'][-1].update(replicate=True),
            lambda v:v['resource_changes'][0]['change'].update(actions=['delete','create']),
            lambda v:v['resource_changes'][0]['change'].update(replace_paths=[['mount_point']]),
            lambda v:v['resource_drift'][0]['change']['after']['mount_point'].append(mounts()[-1])):
            value=self.plan();mutate(value)
            with self.subTest(mutate=mutate),self.assertRaises(ValueError): self.check(value)
        value=self.plan()
        with self.assertRaises(ValueError):
            plan_policy.check_plan(value,'pve-lab',6100,existing=True,protected_guests=[])
        with self.assertRaises(ValueError):
            plan_policy.check_plan(value,'pve-lab',6100,existing=False,protected_guests=[],recording_mount=declaration())


class RecordingNativeProof(unittest.TestCase):
    def test_api_and_guest_filesystem_must_match_before_and_after_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();current=native(mounts());pending=[]
            api=lambda path:pending if path.endswith('/pending') else current
            def probe(argv,env,proof,**kwargs):
                self.assertIn('root@198.18.25.10',argv)
                self.assertIn('--mount-only',argv[-1])
                self.assertIn(b'def validate_mount',kwargs['input_bytes'])
                proof.write_text(json.dumps({'status':'passed','state_initialized':False,
                    'recording_source_verified':True,'writes_performed':False}));proof.chmod(0o600)
            with patch.object(mount,'quiet',side_effect=probe):
                result=mount.verify(cfg(),mounts(),root/'infra.log',api,label='before')
                self.assertEqual(result[0],tuple(current['mp'+str(i)] for i in range(3)))
                self.assertEqual(mount.verify(cfg(),mounts(),root/'infra.log',api,label='after'),result)
                with self.assertRaises(ValueError):mount.verify(cfg(),mounts(),root/'infra.log',api,label='before')
            for index, mutate in enumerate((
                    lambda:current.update(hostname='foreign'),
                    lambda:current.update(mp3='extra'),
                    lambda:pending.append({'key':'mp2','pending':'other'}))):
                current=native(mounts());pending=[];mutate()
                with self.subTest(case=index),self.assertRaises(ValueError):
                    mount.verify(cfg(),mounts(),root/'failure.log',api,label='before')


class RecordingInfrastructureBoundary(unittest.TestCase):
    def test_normal_repeat_proves_mount_before_planning_and_after_apply_boundary(self):
        import deployment_inputs
        import proxmox_guest as pve
        from fixtures import guest
        from test_plan import fixture as plan_fixture
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();selected=guest(root)
            selected['guest'].update(vmid=6100,hostname='cameras',recording_mount=declaration(),
                volumes={'data':{'path':'/srv/data','size_gib':8},'stage':{'path':'/srv/stage','size_gib':4}})
            selected['app']['vmid']=6100;selected['site']['node']='pve-lab'
            work=root/'work';work.mkdir();state=work/'terraform.tfstate'
            state.write_bytes(b'existing authoritative backend')
            (root/'api').write_text('fixture@pve!deploy=synthetic');(root/'api').chmod(0o600)
            value=plan_fixture()
            for row in value['resource_changes']:
                row['change'].update(actions=['no-op'],before=copy.deepcopy(row['change']['after']))
            for side in ('before','after'):value['resource_changes'][0]['change'][side]['mount_point']=mounts()
            previous={'guest':{'recording_mount':declaration()}}
            commands=[]
            def quiet(argv,environment,log):
                commands.append(argv)
                if 'plan'in argv:(log.parent/'guest.tfplan').write_bytes(b'saved no-op plan')
            for mismatch in (False,True):
                operation=root/('mismatch'if mismatch else 'repeat');operation.mkdir()
                with patch.object(deployment_inputs,'binding',return_value={'approved':True}), \
                     patch.object(pve,'backup'),patch.object(pve,'quiet',side_effect=quiet), \
                     patch.object(pve,'guest_trust')as trust, \
                     patch.object(pve.subprocess,'check_output',return_value=json.dumps(value).encode()), \
                     patch.object(mount,'original',return_value=mounts())as original, \
                     patch.object(mount,'verify',side_effect=['proof','different'if mismatch else 'proof'])as verify:
                    if mismatch:
                        with self.assertRaises(ValueError):
                            pve.infrastructure(selected,root/'site',work,operation,{'approved':True},previous_configuration=previous)
                    else:
                        result=pve.infrastructure(selected,root/'site',work,operation,{'approved':True},previous_configuration=previous)
                        self.assertFalse(result['changed']);self.assertFalse(result['created'])
                    original.assert_called_once_with(selected,previous,work)
                    self.assertEqual([x.kwargs['label']for x in verify.call_args_list],['before','after'])
                    trust.assert_called_once_with(selected,work,persist=False)
            self.assertFalse(any('apply'in row for row in commands))
            self.assertEqual(state.read_bytes(),b'existing authoritative backend')
            state.unlink();operation=root/'fresh';operation.mkdir()
            with patch.object(pve,'quiet')as native,self.assertRaises(ValueError):
                pve.infrastructure(selected,root/'site',work,operation,{'approved':True})
            native.assert_not_called()


class RecordingPacketBoundary(unittest.TestCase):
    def test_receiver_links_the_exact_provider_mount_and_single_scrypted_app(self):
        import component_guest
        from test_component_inputs import StaticInputTests
        fixture=StaticInputTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        packet=copy.deepcopy(fixture.packet);cfg=json.loads(packet['files']['site.json'])
        cfg['guest']['volumes']={'state':{'path':'/srv/state','size_gib':16}}
        cfg['guest']['recording_mount']={**declaration(),'slot':1}
        row=cfg['deployment']['applications']['resolver'];row['adapter']='scrypted'
        row['services']=['resolver_a_scrypted']
        runtime=json.loads(packet['files']['component-runtime.json'])
        app=runtime['applications']['resolver_a'];app['adapter']='scrypted'
        app['identity']['services']={'scrypted':'resolver_a_scrypted'}
        app['storage_paths']={'recordings':{'source':'/srv/recordings','target':'/nvr','kind':'directory','read_only':False},
            'data':{'source':'/srv/state/scrypted','target':'/server/volume','kind':'directory','read_only':False}}
        app['settings']={'recording_mount':{'source':'nas.example.invalid:/recordings',
                                          'filesystem':'nfs4','root':'/camera'}}
        packet['files']['site.json']=json.dumps(cfg)
        packet['files']['component-runtime.json']=json.dumps(runtime)
        component_guest.packet(packet,fixture.inputs)
        for mutate in (lambda c:c['guest'].pop('recording_mount'),
                       lambda c:c['guest']['recording_mount'].update(slot=0),
                       lambda c:c['guest']['recording_mount'].update(path='/srv/foreign')):
            broken=copy.deepcopy(packet);value=json.loads(broken['files']['site.json']);mutate(value)
            broken['files']['site.json']=json.dumps(value)
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):component_guest.packet(broken,fixture.inputs)


if __name__ == '__main__': unittest.main()
