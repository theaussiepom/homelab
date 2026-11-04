"""Real local immutable payload/receipt fixtures; no compiler or native calls."""
import copy,importlib.util,json,os
from pathlib import Path
import sys,tempfile,types,unittest
from unittest.mock import patch
F=Path(Path(__file__).resolve().parents[3]);sys.path[:0]=[str(F/'proxmox/applications'),str(F/'proxmox/applications/tests')]
import coordinated_generation as generation
from custody_fixtures import backend,save,legacy_canonical,legacy_immutable
from component_payload import prepare,BINDING_SCHEMA
from private_io import digest,encoded

class ComponentReceiptTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
  self.work=self.root/'808';self.work.mkdir(mode=0o700);self.binding_key='initial_ordinary_sha256';self.workflow=['example/private-site','example/private-site/.github/workflows/deploy.yml']
  self.state_hash=save(self.work/'terraform.tfstate',backend(808,2));self.identity=generation.backend(self.work,{'vmid':808,'node':'fixture-pve'})[1]
  anchor={'status':'passed','binding':{'vmid':808,'source_sha256':'a'*64},'state_sha256':self.state_hash,'result':{'changed':False}}
  immutable=legacy_immutable(anchor);canonical=legacy_canonical(anchor);save(self.work/'ordinary-100-1/complete.json',immutable);save(self.work/'ordinary-complete.json',canonical)
  self.baseline=immutable;self.original={str(p.relative_to(self.work)):p.read_bytes() for p in self.work.rglob('*.json')}
  self.member={'vmid':808,'node':'fixture-pve','initial_state_sha256':self.state_hash,'initial_ordinary':{'operation':'ordinary-100-1','sha256':digest(canonical),'immutable_sha256':digest(immutable),'source_sha256':'a'*64}}
  self.binding=self.make_binding('b')
 def make_binding(self,char):
  directory=self.root/'inputs'/(char*64)/'apps';directory.mkdir(mode=0o700,parents=True)
  return {'schema':BINDING_SCHEMA,'vmid':808,'source_sha256':'7'*64,'site_sha256':'8'*64,'input_identity':char*64,'app_inputs_directory':str(directory),'input_hashes':{},self.binding_key:'c'*64}
 def attempt(self,number=201,binding=None,phases=None):
  a=types.SimpleNamespace(work=self.work,receipt=self.work/'ordinary-complete.json',hold=self.work/'ORDINARY-HOLD.json',cfg={},binding=binding or self.binding,phases=phases or ['preparation','renamed','zabbix-agent'],workflow=self.workflow,run_number=number,site_revision='d'*40)
  def select():
   a.operation=self.work/('ordinary-'+str(number)+'-1');a.marker={'binding':a.binding,'operation':str(a.operation),'automatic_retry':False,'workflow':a.workflow,'run_number':number,'site_revision':a.site_revision}
   if hasattr(a,'previous_ordinary_sha256'):a.marker['previous_ordinary_sha256']=a.previous_ordinary_sha256
  a._select_run=select;select();return a
 def success(self,number=200,binding=None,phase='app-phase',advance=True):
  binding=binding or self.binding
  if advance:self.state_hash=save(self.work/'terraform.tfstate',backend(808,number))
  operation=self.work/('ordinary-'+str(number)+'-1');operation.mkdir(mode=0o700)
  payload=prepare(Path(binding['app_inputs_directory']),binding['input_identity'],'widget',{'config.json':b'{"fixture":true}\n'});proof=payload.check()
  previous=digest((self.work/'ordinary-complete.json').read_bytes());common={'binding':binding,'operation':str(operation),'automatic_retry':False,'workflow':self.workflow,'run_number':number,'site_revision':'d'*40,'previous_ordinary_sha256':previous}
  phases={'preparation':None,phase:proof};result={'changed':False}
  save(operation/'infrastructure-complete.json',{'binding':binding,'state_sha256':self.state_hash,'state_identity':self.identity,'changed':advance,'created':False})
  for name,selected in phases.items():
   extra={} if selected is None else {'phase_inputs':selected};save(operation/(name+'-started.json'),{**common,**extra});save(operation/(name+'-complete.json'),{'binding':binding,'result':result,**extra})
  value={'schema':generation.COMPONENT_COMPLETE,'status':'passed','binding':binding,'state_sha256':self.state_hash,'state_identity':self.identity,'result':result,'workflow':self.workflow,'run_number':number,'site_revision':'d'*40,'operation':str(operation),'phase_inputs':phases}
  save(operation/'complete.json',value);save(self.work/'ordinary-complete.json',value);return value,operation
 def classify(self,a):return generation.classify(a,self.member,self.identity['lineage'],self.baseline,binding_key=self.binding_key)
 def bytes(self):return {str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
 def test_initial_anchor_component_success_later_state_and_run_advance_and_repeat(self):
  a=self.attempt(200);self.assertEqual(self.classify(a),self.identity);self.assertEqual(a.initial_ordinary,self.original['ordinary-complete.json'])
  first,path=self.success();first_raw=(path/'complete.json').read_bytes();a=self.attempt(201);self.assertEqual(self.classify(a),self.identity)
  later_binding=self.make_binding('e');later_binding['source_sha256']='9'*64;later,later_path=self.success(201,later_binding,phase='different-phase');a=self.attempt(202,binding=later_binding,phases=['preparation','new-current-phase','zabbix-agent']);self.assertEqual(self.classify(a),self.identity)
  before=self.bytes();self.assertEqual(self.classify(self.attempt(202,binding=later_binding)),self.identity);self.assertEqual(before,self.bytes())
  self.assertEqual((path/'complete.json').read_bytes(),first_raw);self.assertEqual((self.work/'ordinary-100-1/complete.json').read_bytes(),self.baseline)
 def test_legacy_nine_field_success_is_separate_and_does_not_need_new_phase_payloads(self):
  a=self.attempt(200);value={'status':'passed','binding':{'vmid':808,self.binding_key:'c'*64},'state_sha256':self.state_hash,'state_identity':self.identity,'result':{'changed':False},'workflow':self.workflow,'run_number':200,'site_revision':'d'*40,'operation':str(a.operation)}
  save(a.operation/'complete.json',value);save(self.work/'ordinary-complete.json',value);self.assertFalse(generation.component_success(value,a.operation));self.assertEqual(self.classify(self.attempt()),self.identity)
 def test_receipt_uses_own_phase_set_not_current_source_phases(self):
  value,path=self.success();self.assertTrue(generation.component_success(value,path));self.assertEqual(self.classify(self.attempt(phases=['preparation','entirely-new'])),self.identity)
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
 def test_failed_unselected_later_operation_does_not_become_success(self):
  self.success();failed=self.work/'ordinary-201-1';failed.mkdir(mode=0o700);save(failed/'preparation-started.json',{'fixture':'failed'});before=self.bytes()
  with self.assertRaises((ValueError,OSError)):self.classify(self.attempt(202))
  self.assertEqual(before,self.bytes())
 def test_exact_same_run_hold_continuation_keeps_hold_and_previous_success(self):
  self.success();a=self.attempt(201);a.operation.mkdir(mode=0o700);save(a.hold,{**a.marker,'previous_ordinary_sha256':digest(a.receipt.read_bytes())});save(a.operation/'infrastructure-complete.json',{'binding':a.binding,'state_sha256':self.state_hash,'state_identity':self.identity});before=self.bytes()
  self.assertEqual(self.classify(a),self.identity);self.assertEqual(before,self.bytes());self.assertTrue(a.hold.exists())

if __name__=='__main__':unittest.main()
