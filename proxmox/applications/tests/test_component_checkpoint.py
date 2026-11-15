"""Real failed infrastructure/phase provenance and fresh successor; native bodies fake."""
import copy
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import commands
import component_checkpoint as checkpoint
import component_inputs
import component_packet
import component_plan
import component_ownership
import deploy
import deployment_state
import nfs_mounts
from fixtures import github_source
from private_io import digest, encoded, read_json, sha, write_bytes, write_new
import test_component_deployment as integration


def inode(path):
    s=path.lstat()
    return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns]


class CheckpointSuccessorTests(unittest.TestCase):
    def setUp(self):
        real_ancestor=commands.is_ancestor
        self.case=integration.DeploymentIntegrationTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.source,self.revisions=github_source(self.case.root)
        for context in (patch.object(commands,'is_ancestor',side_effect=real_ancestor),
                patch.dict(os.environ,{'GITHUB_WORKSPACE':str(self.source),'GITHUB_SHA':self.revisions[0]})):
            context.start();self.addCleanup(context.stop)
        self.work=self.case.state/'610';self.case.all_phases()
        self.receipt=self.work/'ordinary-complete.json';self.previous=read_json(self.receipt,private=True)
        self.canonical=(inode(self.receipt),self.receipt.read_bytes())
    def failure(self, before_app_start=False):
        # A real new compiler packet adds infrastructure, while the old app keeps
        # its genuine prior owner. Only the provider/Ansible bodies remain fakes.
        source=self.case.root/'consumer/site.json';value=json.loads(source.read_text())
        key=self.case.root/'nfs-key';hosts=self.case.root/'nfs-hosts'
        write_new(key,b'synthetic-key');write_new(hosts,b'synthetic-pinned-host')
        value['secret_sources']['nfs']={'type':'file','path':str(key)}
        value['contexts']['lab']['capabilities']={'nfs':{'type':'nfs-attachment','ssh_private_key':'nfs','known_hosts':str(hosts)}}
        value['guests']['resolver']['root_paths']={'recordings':{'path':'/srv/recordings','host_bind':{
            'source':'/mnt/example/recordings','slot':0,'filesystem_source':'nas.example.invalid:/recordings',
            'filesystem':'nfs4','filesystem_root':'/'}}}
        source.write_text(json.dumps(value))
        plan=component_plan.resolve(self.case.root/'library',source)
        packet=component_packet.lower_plan(plan,inputs=self.case.inputs)['resolver']
        write_bytes(self.case.packet,encoded(packet));self.case.cfg=json.loads(packet['files']['site.json'])
        self.infrastructure_previous=[]
        def infrastructure(cfg,site,work,operation,binding,**kw):
            self.infrastructure_previous.append(copy.deepcopy(kw['previous_configuration']))
            mounts=nfs_mounts.original(cfg,kw['previous_configuration'],work)
            self.case.infrastructure(cfg,site,work,operation,binding,**kw)
            state=read_json(work/'terraform.tfstate',private=True)
            state['resources'][0]['instances'][0]['attributes']['mount_point']=mounts
            write_bytes(work/'terraform.tfstate',encoded(state))
            return {'changed':True,'created':False,'state_sha256':sha(work/'terraform.tfstate')}
        context=patch('proxmox_guest.infrastructure',side_effect=infrastructure);context.start();self.addCleanup(context.stop)
        self.failed=self.work/'ordinary-102-1'
        with self.epoch(102,11):
            deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs,environment={})
            deploy.run('preparation',self.case.packet,inputs=self.case.inputs,environment={})
            if before_app_start:
                with patch.object(component_ownership,'namespaces',side_effect=ValueError('synthetic pre-start refusal')),self.assertRaises(ValueError):
                    deploy.run('recursive_a',self.case.packet,inputs=self.case.inputs,environment={})
            else:
                with patch('component_ansible.quiet',side_effect=RuntimeError('synthetic app failure')),self.assertRaises(RuntimeError):
                    deploy.run('recursive_a',self.case.packet,inputs=self.case.inputs,environment={})
        self.backend=(inode(self.work/'terraform.tfstate'),(self.work/'terraform.tfstate').read_bytes())
        self.archive=self.work/'operator-recovery-102-1';self.archive.mkdir(mode=0o700)
        evidence={str(p.relative_to(self.failed)):{'identity':inode(p),'sha256':sha(p)}
                  for p in self.failed.rglob('*') if p.is_file()}
        item={'operation':str(self.failed),'archive':str(self.archive),
              'hold':{'identity':inode(self.work/'ORDINARY-HOLD.json'),'sha256':sha(self.work/'ORDINARY-HOLD.json')},
              'evidence':evidence,'guest_entries':sorted(p.name for p in self.work.iterdir())}
        write_new(self.archive/'original-evidence-inventory.json',encoded(item))
        self.failed.rename(self.archive/self.failed.name)
        (self.work/'ORDINARY-HOLD.json').rename(self.archive/'ORDINARY-HOLD.json')
        self.operation=self.archive/self.failed.name
        self.request={'schema':checkpoint.SCHEMA,'archive_directory':str(self.archive),
            'archive_inventory_sha256':sha(self.archive/'original-evidence-inventory.json'),
            'hold_sha256':sha(self.archive/'ORDINARY-HOLD.json'),
            'checkpoint_sha256':sha(self.operation/'infrastructure-complete.json'),
            'previous_ordinary_sha256':sha(self.receipt),
            'successor':{'after_run_id':103,'source_ancestor':self.revisions[1],
                         'input_identity':self.case.cfg['deployment']['input_identity']}}
        self.archived={p:(inode(p),p.read_bytes())for p in self.archive.rglob('*')if p.is_file()}

    def epoch(self,run=104,number=13,**env):
        return patch.dict(os.environ,{'GITHUB_RUN_ID':str(run),'GITHUB_RUN_NUMBER':str(number),
             'GITHUB_SHA':self.revisions[1],**env})

    def request_file(self):
        write_new(self.work/checkpoint.REQUEST,encoded(self.request))

    def assert_no_mutation(self):
        self.assertEqual((inode(self.receipt),self.receipt.read_bytes()),self.canonical)
        state=self.work/'terraform.tfstate'
        self.assertEqual((inode(state),state.read_bytes()),self.backend)
        self.assertFalse((self.work/'ordinary-104-1').exists())
        self.assertFalse((self.work/'ORDINARY-HOLD.json').exists())
        self.assertFalse((self.work/checkpoint.CLAIM).exists())

    def test_exact_reviewed_checkpoint_advances_infrastructure_but_keeps_app_owner_until_real_completion(self):
        self.failure()
        self.request_file();before={p:(inode(p),p.read_bytes())for p in Path(self.previous['operation']).rglob('*')if p.is_file()}
        with self.epoch():
            deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs,environment={})
            self.assertEqual((inode(self.receipt),self.receipt.read_bytes()),self.canonical)
            self.assertNotIn('recording_mount',self.infrastructure_previous[0]['guest'])
            self.assertEqual(self.infrastructure_previous[1]['guest']['recording_mount'],self.case.cfg['guest']['recording_mount'])
            new=self.work/'ordinary-104-1'
            self.assertEqual((new/checkpoint.REQUEST).read_bytes(),(self.work/checkpoint.REQUEST).read_bytes())
            claim=read_json(self.work/checkpoint.CLAIM,private=True)
            self.assertEqual(claim,{'schema':checkpoint.SCHEMA,'admission_sha256':sha(self.work/checkpoint.REQUEST),'operation':str(new)})
            for phase in self.case.cfg['deployment']['phases']:
                deploy.run(phase,self.case.packet,inputs=self.case.inputs,environment={})
        current=read_json(self.receipt,private=True)
        self.assertEqual(current['operation'],str(new));self.assertEqual(len(current['binding']),7)
        self.assertNotEqual(current['state_sha256'],self.previous['state_sha256'])
        self.assertEqual(self.archived,{p:(inode(p),p.read_bytes())for p in self.archived})
        self.assertEqual(before,{p:(inode(p),p.read_bytes())for p in before})
        self.assertEqual(self.case.calls,[False,True])
        with self.epoch(105,14):self.case.all_phases()  # Stale consumed recovery metadata is not a new authority.

    def test_failure_before_app_start_keeps_preparation_only_provenance(self):
        self.failure(True)
        self.assertFalse((self.operation/'recursive_a-started.json').exists())
        self.request_file()
        with self.epoch():self.case.all_phases()
        self.assertEqual(read_json(self.receipt,private=True)['operation'],str(self.work/'ordinary-104-1'))
        self.assertEqual(self.archived,{p:(inode(p),p.read_bytes())for p in self.archived})

    def test_matching_resource_ids_without_explicit_admission_are_not_enough(self):
        self.failure()
        with self.epoch(),self.assertRaisesRegex(ValueError,'backend changed'):deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs)
        self.assert_no_mutation()

    def test_request_is_closed_pinned_and_binds_new_run_source_and_exact_payload(self):
        self.failure()
        changes=[lambda r:r.update(extra=True),lambda r:r.update(schema='other'),
            lambda r:r.update(previous_ordinary_sha256='e'*64),lambda r:r.update(hold_sha256='e'*64),
            lambda r:r.update(checkpoint_sha256='e'*64),lambda r:r.update(archive_inventory_sha256='e'*64),
            lambda r:r.update(archive_directory=str(self.work.parent/'operator-recovery-102-1')),
            lambda r:r['successor'].update(after_run_id=True),lambda r:r['successor'].update(after_run_id=104),
            lambda r:r['successor'].update(after_run_id=101),lambda r:r['successor'].update(input_identity='e'*64),
            lambda r:r['successor'].update(source_ancestor='e'*40)]
        original=copy.deepcopy(self.request)
        for change in changes:
            self.request=copy.deepcopy(original);change(self.request);self.request_file()
            with self.subTest(change=change),self.epoch(),self.assertRaises((ValueError,OSError)):
                deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs)
            (self.work/checkpoint.REQUEST).unlink();self.assert_no_mutation()
        self.request=original
        self.request_file()
        with self.epoch(GITHUB_RUN_ATTEMPT='2'),self.assertRaises(ValueError):deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs)
        self.assert_no_mutation()

    def test_changed_backend_foreign_lineage_or_identity_never_admitted(self):
        self.failure()
        self.request_file();state=self.work/'terraform.tfstate';raw=state.read_bytes()
        for field in ('serial','lineage','provider-id'):
            value=json.loads(raw)
            if field=='provider-id':value['resources'][0]['instances'][0]['attributes']['id']='foreign'
            elif field=='serial':value['serial']+=1
            else:value['lineage']='foreign'
            write_bytes(state,encoded(value))
            with self.subTest(field=field),self.epoch(),self.assertRaises(ValueError):deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs)
            write_bytes(state,raw)
        self.assertFalse((self.work/'ordinary-104-1').exists())
        self.assertEqual((inode(self.receipt),self.receipt.read_bytes()),self.canonical)

    def test_checkpoint_hold_inventory_or_phase_tampering_and_missing_static_refuse(self):
        self.failure()
        self.request_file()
        paths=[self.operation/'infrastructure-complete.json',self.archive/'ORDINARY-HOLD.json',
               self.archive/'original-evidence-inventory.json',self.operation/'preparation-complete.json',
               self.operation/'recursive_a-started.json']
        for path in paths:
            raw=path.read_bytes();mtime=path.stat().st_mtime_ns;path.write_bytes(b'{}\n')
            with self.subTest(path=path.name),self.epoch(),self.assertRaises(ValueError):deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs)
            path.write_bytes(raw);os.utime(path,ns=(path.stat().st_atime_ns,mtime))
        cfg_binding=read_json(self.operation/'infrastructure-complete.json',private=True)['binding']
        manifest=Path(cfg_binding['app_inputs_directory']).parent/'component-prepared.json';raw=manifest.read_bytes()
        manifest.write_bytes(b'{}\n')
        with self.epoch(),self.assertRaises(ValueError):deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs)
        manifest.write_bytes(raw)
        self.assertFalse((self.work/'ordinary-104-1').exists())

    def test_missing_archived_phase_cannot_be_reclassified_as_never_started(self):
        self.failure()
        self.request_file();path=self.operation/'recursive_a-started.json'
        saved=self.case.root/'preserved-started.json';path.rename(saved)
        with self.epoch(),self.assertRaisesRegex(ValueError,'complete archived phase inventory'):
            deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs)
        saved.rename(path);self.assert_no_mutation()

    def test_preserved_completion_active_hold_and_prior_claim_refuse(self):
        self.failure()
        self.request_file()
        for path in (self.operation/'complete.json',self.work/'ORDINARY-HOLD.json',self.work/checkpoint.CLAIM):
            write_new(path,encoded({}))
            with self.subTest(path=path),self.epoch(),self.assertRaises(ValueError):deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs)
            path.unlink()
        self.assert_no_mutation()

    def test_claim_failure_keeps_new_hold_without_native_call_or_canonical_change(self):
        self.failure()
        self.request_file();calls=len(self.case.infra)
        real=checkpoint.write_new
        def fail(path,raw):
            if path.name==checkpoint.CLAIM:raise OSError('synthetic claim failure')
            return real(path,raw)
        with patch.object(checkpoint,'write_new',side_effect=fail),self.epoch(),self.assertRaisesRegex(OSError,'claim failure'):
            deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs)
        self.assertTrue((self.work/'ORDINARY-HOLD.json').exists());self.assertEqual(len(self.case.infra),calls)
        self.assertEqual((inode(self.receipt),self.receipt.read_bytes()),self.canonical)
        with self.epoch(105,14),self.assertRaises(ValueError):deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs)

    def test_foreign_hold_or_checkpoint_refuses_even_with_matching_reviewed_hashes(self):
        self.failure()
        inventory_path=self.archive/'original-evidence-inventory.json'
        inventory_raw=inventory_path.read_bytes()
        original=copy.deepcopy(self.request)
        changes=[('hold','workflow',['foreign/repo','foreign/repo/.github/workflows/deploy.yml']),
            ('hold','run_number',self.previous['run_number']),('hold','automatic_retry',True),
            ('hold','previous_ordinary_sha256','e'*64),('hold','operation',str(self.work/'ordinary-99-1')),
            ('checkpoint','created',True),('checkpoint','changed','yes'),
            ('checkpoint','state_sha256','e'*64),('checkpoint','state_identity',{})]
        for kind,field,value in changes:
            path=self.archive/'ORDINARY-HOLD.json' if kind=='hold' else self.operation/'infrastructure-complete.json'
            raw=path.read_bytes();mtime=path.stat().st_mtime_ns
            selected=json.loads(raw);selected[field]=value;path.write_bytes(encoded(selected))
            inventory=json.loads(inventory_raw)
            row={'identity':inode(path),'sha256':sha(path)}
            if kind=='hold':inventory['hold']=row
            else:inventory['evidence'][path.name]=row
            inventory_path.write_bytes(encoded(inventory))
            self.request=copy.deepcopy(original)
            self.request['hold_sha256' if kind=='hold' else 'checkpoint_sha256']=sha(path)
            self.request['archive_inventory_sha256']=sha(inventory_path)
            self.request_file()
            with self.subTest(kind=kind,field=field),self.epoch(),self.assertRaises(ValueError):
                deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs)
            (self.work/checkpoint.REQUEST).unlink()
            path.write_bytes(raw);os.utime(path,ns=(path.stat().st_atime_ns,mtime))
            inventory_path.write_bytes(inventory_raw)
            self.assert_no_mutation()
        self.request=original

    def test_changed_evidence_between_admission_and_claim_keeps_hold_without_native_execution(self):
        self.failure();self.request_file()
        site=Path(self.case.cfg['deployment']['input_directory'])/'site.json'
        binding=component_inputs.binding(self.case.cfg,site);calls=len(self.case.infra)
        with self.epoch(),deployment_state.DeploymentAttempt(self.case.cfg,binding,self.case.cfg['deployment']['phases']) as attempt:
            self.assertFalse(attempt.completed(commands.is_ancestor))
            path=self.work/checkpoint.REQUEST;path.write_bytes(path.read_bytes()+b' ')
            with self.assertRaisesRegex(ValueError,'Custody bytes changed'):attempt.begin_infrastructure()
        self.assertTrue((self.work/'ORDINARY-HOLD.json').exists())
        self.assertEqual(len(self.case.infra),calls)
        self.assertFalse((self.work/checkpoint.CLAIM).exists())
        self.assertEqual((inode(self.receipt),self.receipt.read_bytes()),self.canonical)

    def test_real_existing_locks_remain_exclusive(self):
        self.failure()
        self.request_file();site=Path(self.case.cfg['deployment']['input_directory'])/'site.json'
        binding=component_inputs.binding(self.case.cfg,site)
        with self.epoch(),deployment_state.DeploymentAttempt(self.case.cfg,binding,self.case.cfg['deployment']['phases']):
            with self.assertRaises(BlockingIOError):deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs)
        self.assert_no_mutation()


if __name__=='__main__':unittest.main()
