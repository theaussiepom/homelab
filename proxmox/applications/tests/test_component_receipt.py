"""Real local immutable payload/receipt fixtures; no compiler or native calls."""
import copy,json
from pathlib import Path
import sys,tempfile,types,unittest
F=Path(Path(__file__).resolve().parents[3]);sys.path[:0]=[str(F/'proxmox/applications'),str(F/'proxmox/applications/tests')]
import component_generation as generation
from component_generation_fixtures import backend,save
from component_payload import prepare,BINDING_SCHEMA
from private_io import digest,encoded

class ComponentReceiptTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
  self.work=self.root/'808';self.work.mkdir(mode=0o700);self.workflow=['example/private-site','example/private-site/.github/workflows/deploy.yml']
  self.state_hash=save(self.work/'terraform.tfstate',backend(808,2));self.identity=generation.backend(self.work,{'vmid':808,'node':'fixture-pve'})[1]
  self.binding=self.make_binding('b')
 def make_binding(self,char):
  directory=self.root/'inputs'/(char*64)/'apps';directory.mkdir(mode=0o700,parents=True)
  return {'schema':BINDING_SCHEMA,'vmid':808,'source_sha256':'7'*64,'site_sha256':'8'*64,'input_identity':char*64,'app_inputs_directory':str(directory),'input_hashes':{}}
 def success(self,number=200,binding=None,phase='app-phase',advance=True):
  binding=binding or self.binding
  if advance:self.state_hash=save(self.work/'terraform.tfstate',backend(808,number))
  operation=self.work/('ordinary-'+str(number)+'-1');operation.mkdir(mode=0o700)
  payload=prepare(Path(binding['app_inputs_directory']),binding['input_identity'],'widget',{'config.json':b'{"fixture":true}\n'});proof=payload.check()
  previous=digest((self.work/'ordinary-complete.json').read_bytes()) if (self.work/'ordinary-complete.json').exists() else None;common={'binding':binding,'operation':str(operation),'automatic_retry':False,'workflow':self.workflow,'run_number':number,'site_revision':'d'*40,'previous_ordinary_sha256':previous}
  phases={'preparation':None,phase:proof};result={'changed':False}
  save(operation/'infrastructure-complete.json',{'binding':binding,'state_sha256':self.state_hash,'state_identity':self.identity,'changed':advance,'created':False})
  for name,selected in phases.items():
   extra={} if selected is None else {'phase_inputs':selected};save(operation/(name+'-started.json'),{**common,**extra});save(operation/(name+'-complete.json'),{'binding':binding,'result':result,**extra})
  value={'schema':generation.COMPONENT_COMPLETE,'status':'passed','binding':binding,'state_sha256':self.state_hash,'state_identity':self.identity,'result':result,'workflow':self.workflow,'run_number':number,'site_revision':'d'*40,'operation':str(operation),'phase_inputs':phases}
  save(operation/'complete.json',value);save(self.work/'ordinary-complete.json',value);return value,operation
 def bytes(self):return {str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
 def test_unversioned_success_cannot_become_current_component_ownership(self):
  operation=self.work/'ordinary-200-1'
  value={'status':'passed','binding':{'vmid':808,'source_sha256':'a'*64},'state_sha256':self.state_hash,'state_identity':self.identity,'result':{'changed':False},'workflow':self.workflow,'run_number':200,'site_revision':'d'*40,'operation':str(operation)}
  save(operation/'complete.json',value);save(self.work/'ordinary-complete.json',value)
  before=self.bytes();self.assertFalse(generation.component_success(value,operation))
  attempt=types.SimpleNamespace(work=self.work,receipt=self.work/'ordinary-complete.json',vmid=808)
  with self.assertRaises(ValueError):generation.previous(attempt)
  self.assertEqual(before,self.bytes())
 def test_receipt_validates_its_immutable_phase_set(self):
  value,path=self.success(phase='owned-previous-phase')
  self.assertEqual(set(value['phase_inputs']),{'preparation','owned-previous-phase'})
  self.assertTrue(generation.component_success(value,path))
 def test_closed_schema_binding_and_new_receipt_fields_refuse(self):
  value,path=self.success()
  changes=[lambda v:v.pop('schema'),lambda v:v.update(schema='foreign'),lambda v:v['binding'].update(blueprint_sha256='a'*64),lambda v:v['binding'].update(initial_ordinary_sha256='a'*64,coordinated_custody_sha256='a'*64),lambda v:v['binding'].update(schema='foreign'),lambda v:v['binding'].pop('input_identity'),lambda v:v.update(extra=True)]
  for mutate in changes:
   with self.subTest(case=changes.index(mutate)):
    bad=copy.deepcopy(value);mutate(bad)
    with self.assertRaises(ValueError):generation.component_success(bad,path)
 def test_preparation_is_the_only_null_proof(self):
  value,path=self.success()
  for phase,proof in [('app-phase',None),('preparation',value['phase_inputs']['app-phase'])]:
   bad=copy.deepcopy(value);bad['phase_inputs'][phase]=proof
   with self.subTest(phase=phase),self.assertRaises(ValueError):generation.component_success(bad,path)
 def test_missing_foreign_or_changed_app_proofs_refuse(self):
  value,path=self.success()
  changes=[lambda p:p.update(identity='f'*64),lambda p:p.update(app='foreign-app'),lambda p:p.update(payload_sha256='f'*64),lambda p:p.update(schema='foreign'),lambda p:p.update(extra=True)]
  for mutate in changes:
   bad=copy.deepcopy(value);mutate(bad['phase_inputs']['app-phase'])
   with self.subTest(case=changes.index(mutate)),self.assertRaises((ValueError,OSError)):generation.component_success(bad,path)
 def test_actual_payload_byte_drift_refuses_without_modifying_history(self):
  value,path=self.success();payload=Path(self.binding['app_inputs_directory'])/'widget/config.json';payload.write_bytes(b'changed fixture\n');before=self.bytes()
  with self.assertRaises(ValueError):generation.component_success(value,path)
  self.assertEqual(before,self.bytes())
 def test_missing_started_complete_or_unmapped_extra_phase_refuses(self):
  value,path=self.success()
  for name in ['app-phase-started.json','app-phase-complete.json']:
   raw=(path/name).read_bytes();(path/name).unlink()
   with self.subTest(name=name),self.assertRaises(ValueError):generation.component_success(value,path)
   save(path/name,raw)
  save(path/'foreign-complete.json',{'fixture':True})
  with self.assertRaises(ValueError):generation.component_success(value,path)
 def test_changed_start_marker_and_complete_proof_refuse(self):
  value,path=self.success();file=path/'app-phase-started.json';original=json.loads(file.read_bytes())
  for key,item in [('run_number',999),('automatic_retry',True),('site_revision','e'*40),('previous_ordinary_sha256','e'*64)]:
   altered=copy.deepcopy(original);altered[key]=item;save(file,altered)
   with self.subTest(field=key),self.assertRaises(ValueError):generation.component_success(value,path)
  save(file,original);file=path/'app-phase-complete.json';row=json.loads(file.read_bytes());row['phase_inputs']['payload_sha256']='0'*64;save(file,row)
  with self.assertRaises(ValueError):generation.component_success(value,path)
 def test_infrastructure_checkpoint_must_agree(self):
  value,path=self.success();file=path/'infrastructure-complete.json';row=json.loads(file.read_bytes());row['state_sha256']='e'*64;save(file,row)
  with self.assertRaises(ValueError):generation.component_success(value,path)
 def test_pending_or_held_completed_operation_refuses_and_stays_unchanged(self):
  value,path=self.success()
  for name in ['.complete.json.pending','SERVICE-HOLD.json']:
   save(path/name,{'fixture':True});before=self.bytes()
   with self.subTest(name=name),self.assertRaises(ValueError):generation.component_success(value,path)
   self.assertEqual(before,self.bytes());(path/name).unlink()

if __name__=='__main__':unittest.main()
