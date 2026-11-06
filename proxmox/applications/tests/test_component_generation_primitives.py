"""Permanent backend/plan/private-I/O guards extracted from mixed adoption tests."""
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

APP=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(APP),str(APP/'tests')]
import component_generation as generation
import custody_records as records
import deployment_state
from component_generation_fixtures import backend,save


class GenerationPrimitiveTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o700)

    def test_backend_projection_refuses_wrong_id_shape_node_and_plan_identity(self):
        member={'vmid':808,'node':'fixture-pve'};good=backend(808)
        mutations=[lambda v:v.update(version=3),lambda v:v.update(serial=True),lambda v:v.update(lineage=''),
            lambda v:v['resources'].pop(),lambda v:v['resources'][0].update(mode='data'),
            lambda v:v['resources'][0].update(module='foreign'),
            lambda v:v['resources'][0]['instances'].append({}),
            lambda v:v['resources'][0]['instances'][0].update(deposed='old'),
            lambda v:v['resources'][0]['instances'][0]['attributes'].update(vm_id=809),
            lambda v:v['resources'][0]['instances'][0]['attributes'].update(node_name='foreign'),
            lambda v:v['resources'][0]['instances'][0]['attributes'].update(id='')]
        state=self.root/'terraform.tfstate'
        for index,mutate in enumerate(mutations):
            bad=copy.deepcopy(good);mutate(bad);save(state,bad);before=state.read_bytes()
            with self.subTest(index=index),self.assertRaises(ValueError):generation.backend(self.root,member)
            self.assertEqual(state.read_bytes(),before)
        save(state,good);_,identity=generation.backend(self.root,member)
        plan={'resource_changes':[{'address':address,'change':{
            'before':{'id':row['id']},'after':{'id':row['id']}}}
            for address,row in identity['resources'].items()]}
        generation.plan_identity(plan,identity)
        for side in ('before','after','after_unknown'):
            bad=copy.deepcopy(plan)
            if side=='after_unknown':bad['resource_changes'][0]['change'][side]={'id':True}
            else:bad['resource_changes'][0]['change'][side]['id']='foreign'
            with self.subTest(side=side),self.assertRaises(ValueError):generation.plan_identity(bad,identity)

    def test_snapshot_and_closed_private_reads_refuse_changes_without_repair(self):
        path=self.root/'private.json';save(path,{'safe':True})
        snapshot=records.Snapshot();raw=snapshot.read(path);snapshot.finish();save(path,raw+b' ')
        with self.assertRaisesRegex(ValueError,'bytes changed'):snapshot.finish()
        directory=self.root/'race';directory.mkdir(mode=0o700);save(directory/'proof',raw)
        snapshot=records.Snapshot();snapshot.read(directory/'proof')
        directory.rename(self.root/'retained');directory.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError,'directory or mount changed'):snapshot.finish()
        for variant in ('mode','symlink','parent-symlink','large','fifo','relative','traversal'):
            save(path,raw);target=path
            if variant=='mode':path.chmod(0o644)
            if variant=='symlink':target=self.root/'link';target.symlink_to(path)
            if variant=='parent-symlink':
                target=self.root/'parent-link'/'proof';target.parent.symlink_to(self.root/'retained')
            if variant=='large':save(path,b'x'*(records.LIMIT+1))
            if variant=='fifo':target=self.root/'fifo';os.mkfifo(target,0o600)
            if variant=='relative':target=Path('relative')
            if variant=='traversal':target=self.root/'..'/'private.json'
            before={p.name for p in self.root.iterdir()}
            with self.subTest(variant=variant),self.assertRaises((OSError,ValueError)):records.read_existing(target)
            self.assertEqual(before,{p.name for p in self.root.iterdir()})
        for raw in (b'{"duplicate":1,"duplicate":2}',b'{'):
            with self.assertRaises(ValueError):records.decode(raw)


    def test_pending_hidden_and_bootstrap_markers_are_not_completion_exceptions(self):
        for scope in ('local','mirror','guest'):
            folder=self.root/scope;folder.mkdir(mode=0o700)
            for name in ('HOLD.json','.SERVICE-VERIFYING.json','ordinary-complete.json.pending','.ORDINARY-HOLD.json.pending'):
                marker=folder/name;save(marker,{})
                with self.subTest(scope=scope,name=name),self.assertRaises(ValueError):
                    records.no_markers(folder,own_ordinary=scope=='guest')
                self.assertTrue(marker.exists());marker.unlink()
        bootstrap=self.root/'bootstrap';bootstrap.mkdir(mode=0o700)
        deployment_state.bootstrap_closed(bootstrap)
        for name in ('CONFIGURING','.CONFIGURING.pending','HOLD.json'):
            marker=bootstrap/name;save(marker,{})
            with self.subTest(name=name),self.assertRaises(ValueError):deployment_state.bootstrap_closed(bootstrap)
            self.assertTrue(marker.exists());marker.unlink()
        bootstrap.rmdir();bootstrap.symlink_to(self.root)
        with self.assertRaises(ValueError):deployment_state.bootstrap_closed(bootstrap)


if __name__=='__main__':unittest.main()
