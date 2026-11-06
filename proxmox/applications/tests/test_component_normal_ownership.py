"""Real ordinary receipts/static/AppPayload/Git with native bodies mocked only."""
import copy,json,os
from pathlib import Path
import sys,unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE.parent),str(HERE.parents[2]/'blueprints')]
import commands,component_generation,component_guest,deploy
import test_component_deployment as integration
from fixtures import github_source
from private_io import encoded,read_json,write_bytes,write_new

class NormalOwnershipIntegrationTests(unittest.TestCase):
 def setUp(self):
  real_ancestor=commands.is_ancestor
  self.case=integration.DeploymentIntegrationTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
  self.source,self.revisions=github_source(self.case.root)
  for context in(patch.object(commands,'is_ancestor',side_effect=real_ancestor),patch.dict(os.environ,{'GITHUB_WORKSPACE':str(self.source),'GITHUB_SHA':self.revisions[0]})):
   context.start();self.addCleanup(context.stop)
  self.work=self.case.state/'610';self.case.all_phases();self.receipt=self.work/'ordinary-complete.json'
  self.first=read_json(self.receipt,private=True);self.immutable=Path(self.first['operation'])/'complete.json'
 def next(self,number=11):
  return patch.dict(os.environ,{'GITHUB_RUN_ID':str(102+number-11),'GITHUB_RUN_NUMBER':str(number),'GITHUB_SHA':self.revisions[1]})
 def snapshot(self):
  return {p:(p.stat().st_ino,p.read_bytes())for p in Path(self.first['operation']).rglob('*')if p.is_file()}
 def test_real_normal_current_two_updates_and_next_cd_advance_without_authored_admission(self):
  self.assertFalse(set(self.case.cfg)&{'coordinated_custody','initial_ordinary','reviewed_ordinary_failures'})
  self.assertNotIn('exclusive_writer_confirmed',self.case.cfg['app']);old=self.snapshot()
  for number in(11,12):
   with self.next(number):self.case.all_phases()
   current=read_json(self.receipt,private=True)
   self.assertEqual(len(current['binding']),7);self.assertEqual(current['state_identity'],self.first['state_identity'])
   self.assertEqual(read_json(self.work/'terraform.tfstate',private=True)['serial'],number-9)
   self.assertEqual(self.snapshot(),old)
  self.assertEqual(self.case.calls,[False,True,True]);self.assertFalse((self.work/'ORDINARY-HOLD.json').exists())
 def test_old_inactive_history_stays_bytes_and_inodes_unchanged_without_success_claim(self):
  histories=[]
  for name,leaves in(('ordinary-90-1',{}),('ordinary-91-1',{'complete.json':b'opaque old historical bytes\n'}),
                       ('ordinary-92-1',{'preserved-failed-hold.json':b'preserved evidence, not an active HOLD\n'}),
                       ('ordinary-93-1',{'preparation-started.json':encoded({'binding':self.first['binding'],'workflow':self.first['workflow'],'run_number':1})}),
                       ('ordinary-94-1',{'preparation-started.json':encoded({'binding':{'old':True}})})):
   path=self.work/name;path.mkdir(mode=0o700)
   for leaf,raw in leaves.items():write_new(path/leaf,raw)
   histories.extend(path.iterdir())
  opaque=self.work/'database-history.txt';write_new(opaque,b'opaque inactive history, no active marker\n');histories.append(opaque)
  before={p:(p.stat().st_ino,p.read_bytes())for p in histories}
  with self.next():self.case.all_phases()
  self.assertEqual(before,{p:(p.stat().st_ino,p.read_bytes())for p in histories})
 def test_global_nested_operation_pending_and_newer_unknown_history_refuse_before_native(self):
  cases=[self.case.state/'HOLD.json',self.work/'.ORDINARY-HOLD.json.pending',
         self.work/'ordinary-90-1/VERIFYING.json',self.work/'database-manual/HOLD.json',
         self.case.state/'database-network-cutover-foreign/CONTINUATION-HOLD.json']
  before=self.receipt.read_bytes();calls=len(self.case.infra)
  for path in cases:
   if not path.parent.exists():path.parent.mkdir(mode=0o700)
   write_new(path,b'preserve active or pending evidence')
   try:
    with self.subTest(path=path.name),self.next(),self.assertRaises(ValueError):deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs,environment={})
    self.assertEqual(self.receipt.read_bytes(),before);self.assertEqual(len(self.case.infra),calls)
   finally:path.unlink()
  newer=self.work/'ordinary-900-1';newer.mkdir(mode=0o700)
  with self.next(),self.assertRaisesRegex(ValueError,'newer unresolved'):deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs,environment={})
  self.assertFalse((self.work/'ordinary-102-1').exists());self.assertEqual(self.receipt.read_bytes(),before)
 def test_older_component_history_cannot_claim_foreign_guest_workflow_or_newer_run(self):
  path=self.work/'ordinary-90-1';path.mkdir(mode=0o700)
  for field,value in(('vmid',999),('workflow',['foreign/repo','foreign/repo/.github/workflows/deploy.yml']),('run_number',999)):
   envelope={'binding':copy.deepcopy(self.first['binding']),'workflow':self.first['workflow'],'run_number':1}
   if field=='vmid':envelope['binding']['vmid']=value
   else:envelope[field]=value
   leaf=path/'preparation-started.json';write_bytes(leaf,encoded(envelope))
   with self.subTest(field=field),self.next(),self.assertRaisesRegex(ValueError,'foreign or newer'):deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs,environment={})
   leaf.unlink()
 def test_state_changed_canonical_pointer_rollback_foreign_owner_and_private_payload_refuse(self):
  state=self.work/'terraform.tfstate';original=state.read_bytes();before=self.receipt.read_bytes();calls=len(self.case.infra)
  changed=read_json(state,private=True);changed['serial']+=1;write_bytes(state,encoded(changed))
  with self.next(),self.assertRaisesRegex(ValueError,'backend changed'):deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs,environment={})
  write_bytes(state,original)
  foreign=copy.deepcopy(self.first);foreign['binding']['vmid']=999;write_bytes(self.receipt,encoded(foreign))
  with self.next(),self.assertRaisesRegex(ValueError,'guest binding'):deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs,environment={})
  write_bytes(self.receipt,before)
  app=Path(self.first['binding']['app_inputs_directory'])/'recursive_a/application.json';raw=app.read_bytes();write_bytes(app,b'{}')
  with self.next(),self.assertRaises(ValueError):deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs,environment={})
  write_bytes(app,raw);self.assertEqual(len(self.case.infra),calls)
  with self.next():self.case.all_phases()
  write_bytes(self.receipt,before);write_bytes(state,original)
  with self.next(12),self.assertRaisesRegex(ValueError,'newer unresolved'):deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs,environment={})
  self.assertFalse((self.work/'ordinary-103-1').exists())
 def test_owned_hold_and_backend_identity_cannot_be_replaced_between_phases(self):
  with self.next():
   deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs,environment={})
   hold=self.work/'ORDINARY-HOLD.json';raw=hold.read_bytes();write_bytes(hold,raw+b' ')
   with self.assertRaisesRegex(ValueError,'exact current run hold'):deploy.run('preparation',self.case.packet,inputs=self.case.inputs,environment={})
   write_bytes(hold,raw);state=self.work/'terraform.tfstate';value=read_json(state,private=True);value['resources'][0]['instances'][0]['attributes']['id']='foreign-provider-id';write_bytes(state,encoded(value))
   with self.assertRaises(ValueError):deploy.run('preparation',self.case.packet,inputs=self.case.inputs,environment={})
  self.assertFalse((self.work/'ordinary-102-1/preparation-started.json').exists())
 def test_real_compiler_cannot_repoint_existing_provider_authority_with_same_ids(self):
  import component_plan,component_packet
  source=self.case.root/'consumer/site.json';value=json.loads(source.read_text())
  value['external_endpoints']['api']['address']='192.0.2.11';source.write_text(json.dumps(value))
  plan=component_plan.resolve(self.case.root/'library',source)
  packet=component_packet.lower_plan(plan,inputs=self.case.inputs)['resolver']
  write_bytes(self.case.packet,encoded(packet));self.case.cfg=json.loads(packet['files']['site.json'])
  before=(self.receipt.stat().st_ino,self.receipt.read_bytes());state=(self.work/'terraform.tfstate').read_bytes();calls=len(self.case.infra)
  with self.next(),self.assertRaisesRegex(ValueError,'guest and phase owners'):deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs,environment={})
  self.assertEqual((self.receipt.stat().st_ino,self.receipt.read_bytes()),before);self.assertEqual((self.work/'terraform.tfstate').read_bytes(),state)
  self.assertEqual(len(self.case.infra),calls);self.assertFalse((self.work/'ORDINARY-HOLD.json').exists());self.assertFalse((self.work/'ordinary-102-1').exists())
 def test_prior_sealed_retired_fields_are_bytes_not_active_configuration(self):
  from private_io import digest
  old=copy.deepcopy(self.first);directory=Path(old['binding']['app_inputs_directory']).parent
  site=directory/'site.json';cfg=read_json(site,private=True)
  # These actual former component DTO fields remain sealed historical bytes.
  cfg['app']['exclusive_writer_confirmed']=True
  cfg['paths']['coordinated_custody_inputs']='/example/prior/custody.json'
  with self.assertRaises(ValueError):component_guest.validate(cfg)
  write_bytes(site,encoded(cfg));old['binding']['site_sha256']=digest(encoded(cfg))
  old['binding']['input_hashes'][str(site)]=digest(encoded(cfg))
  manifest=read_json(directory/'component-prepared.json',private=True)
  manifest['files']['site.json']=digest(encoded(cfg));write_bytes(directory/'component-prepared.json',encoded(manifest))
  operation=Path(old['operation'])
  for path in operation.glob('*.json'):
   value=read_json(path,private=True)
   if isinstance(value,dict)and'binding'in value:
    value['binding']=old['binding'];write_bytes(path,encoded(value))
  write_bytes(operation/'complete.json',encoded(old));write_bytes(self.receipt,encoded(old))
  before={p:(p.stat().st_ino,p.read_bytes())for base in(operation,directory)for p in base.rglob('*')if p.is_file()}
  import component_plan,component_packet
  source=self.case.root/'consumer/site.json';value=json.loads(source.read_text())
  value['apps']['recursive_a']['display_name']='Normal successor';source.write_text(json.dumps(value))
  plan=component_plan.resolve(self.case.root/'library',source)
  packet=component_packet.lower_plan(plan,inputs=self.case.inputs)['resolver']
  write_bytes(self.case.packet,encoded(packet));self.case.cfg=json.loads(packet['files']['site.json'])
  with self.next():self.case.all_phases()
  self.assertEqual(before,{p:(p.stat().st_ino,p.read_bytes())for p in before})
  self.assertEqual(len(read_json(self.receipt,private=True)['binding']),7)
  self.assertNotIn('exclusive_writer_confirmed',self.case.cfg['app'])
  self.assertNotIn('coordinated_custody_inputs',self.case.cfg['paths'])
 def test_canonical_replacement_after_entry_cannot_skip_component_proof(self):
  import component_inputs,deployment_state
  site=Path(self.case.cfg['deployment']['input_directory'])/'site.json'
  expected=component_inputs.binding(self.case.cfg,site);original=self.receipt.read_bytes();calls=len(self.case.infra)
  with self.next(),deployment_state.DeploymentAttempt(self.case.cfg,expected,self.case.cfg['deployment']['phases'])as attempt:
   write_bytes(self.receipt,encoded({'operation':self.first['operation'],'status':'passed'}))
   foreign=(self.receipt.stat().st_ino,self.receipt.read_bytes())
   try:
    with self.assertRaisesRegex(ValueError,'genuine component ordinary success'):attempt.completed(commands.is_ancestor)
    self.assertEqual((self.receipt.stat().st_ino,self.receipt.read_bytes()),foreign)
    self.assertFalse((self.work/'ORDINARY-HOLD.json').exists());self.assertFalse(attempt.operation.exists())
    self.assertEqual(len(self.case.infra),calls)
   finally:write_bytes(self.receipt,original)
 def test_same_run_cannot_rebind_source_after_success_or_publish_another_hold(self):
  import component_plan,component_packet
  before=(self.receipt.stat().st_ino,self.receipt.read_bytes());state=(self.work/'terraform.tfstate').read_bytes();calls=len(self.case.infra)
  source=self.case.root/'consumer/site.json';value=json.loads(source.read_text())
  value['apps']['recursive_a']['display_name']='Changed same-run source';source.write_text(json.dumps(value))
  plan=component_plan.resolve(self.case.root/'library',source)
  packet=component_packet.lower_plan(plan,inputs=self.case.inputs)['resolver']
  write_bytes(self.case.packet,encoded(packet));self.case.cfg=json.loads(packet['files']['site.json'])
  with self.assertRaisesRegex(ValueError,'completed run changed its binding'):
   deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs,environment={})
  self.assertEqual((self.receipt.stat().st_ino,self.receipt.read_bytes()),before)
  self.assertEqual((self.work/'terraform.tfstate').read_bytes(),state);self.assertEqual(len(self.case.infra),calls)
  self.assertFalse((self.work/'ORDINARY-HOLD.json').exists())
 def test_current_v1_without_top_identity_advances_from_exact_backend_proof(self):
  value=copy.deepcopy(self.first);value.pop('state_identity');operation=Path(value['operation'])
  ready=read_json(operation/'infrastructure-complete.json',private=True);ready.pop('state_identity')
  write_bytes(operation/'infrastructure-complete.json',encoded(ready))
  write_bytes(operation/'complete.json',encoded(value));write_bytes(self.receipt,encoded(value));before=self.snapshot()
  with self.next():self.case.all_phases()
  current=read_json(self.receipt,private=True)
  self.assertEqual(current['state_identity'],self.first['state_identity'])
  self.assertEqual(len(current['binding']),7);self.assertEqual(before,self.snapshot())
 def test_historical_current_v1_optional_binding_remains_read_only_and_new_binding_stays_seven(self):
  value=copy.deepcopy(self.first);value['binding']['initial_ordinary_sha256']='d'*64
  operation=Path(value['operation'])
  for path in operation.glob('*.json'):
   old=read_json(path,private=True)
   if isinstance(old,dict)and'binding'in old:
    old['binding']=value['binding'];write_bytes(path,encoded(old))
  write_bytes(operation/'complete.json',encoded(value));write_bytes(self.receipt,encoded(value));old=self.snapshot()
  with self.next():self.case.all_phases()
  self.assertEqual(len(read_json(self.receipt,private=True)['binding']),7);self.assertEqual(old,self.snapshot())

if __name__=='__main__':unittest.main()
