"""Direct normal binding contract; pure values only, no native/input reads."""
import copy
from pathlib import Path
import sys,unittest
ROOT=Path(__file__).resolve()
while not(ROOT/'proxmox/applications').is_dir():ROOT=ROOT.parent
sys.path.insert(0,str(ROOT/'proxmox/applications'))
import component_generation as generation

class NormalBindingTests(unittest.TestCase):
 def good(self):return {'schema':'homelab-component-deployment-binding-v1','vmid':610,'site_sha256':'a'*64,'source_sha256':'b'*64,'input_identity':'c'*64,'app_inputs_directory':'/example/inputs/guest/identity/applications','input_hashes':{'/example/inputs/guest/identity/site.json':'d'*64}}
 def test_exact_seven_fields_and_current_historical_binding_distinction(self):
  value=self.good();self.assertEqual(generation.binding(value),value)
  for key in('initial_ordinary_sha256','coordinated_custody_sha256'):
   old=dict(value,**{key:'f'*64});self.assertEqual(generation.component_binding(old),old)
   with self.subTest(key=key),self.assertRaises(ValueError):generation.binding(old)
 def test_controller_paths_use_the_shared_literal_canonical_receiver_contract(self):
  for path in('//etc','/tmp/$injected','/tmp/line\nbreak','relative/file','/tmp/../file','/tmp/link\\name'):
   for field in('app_inputs_directory','input_hashes'):
    value=self.good()
    if field=='app_inputs_directory':value[field]=path
    else:value[field]={path:'d'*64}
    with self.subTest(path=repr(path),field=field),self.assertRaises(ValueError):generation.binding(value)

 def test_closed_binding_requires_finite_types_and_exact_digests(self):
  changes=[lambda v:v.update(extra=True),lambda v:v.pop('site_sha256'),lambda v:v.update(schema='foreign'),
   lambda v:v.update(vmid=True),lambda v:v.update(vmid=0),lambda v:v.update(input_hashes=[]),
   lambda v:v.update(site_sha256='z'*64),lambda v:v.update(source_sha256='a'*63),
   lambda v:v.update(input_identity='b'*64+'\n'),lambda v:v['input_hashes'].update({'/example/file':'invalid'})]
  for number,change in enumerate(changes):
   value=self.good();change(value)
   with self.subTest(number=number),self.assertRaises(ValueError):generation.binding(value)
  for value in(None,[],False,'text'):
   with self.subTest(value=value),self.assertRaises(ValueError):generation.binding(value)
  for value in(None,{},'','a'*39,'g'*40,'a'*40+'\n'):
   with self.subTest(value=value),self.assertRaises(ValueError):generation.fingerprint(value,40)

class CurrentProviderCallerTests(unittest.TestCase):
 def test_plan_identity_precedes_apply_and_missing_existing_trust_is_never_created(self):
  import json
  from types import SimpleNamespace
  from unittest.mock import patch
  import proxmox_guest as provider, deployment_inputs
  import test_component_deployment as integration
  from test_plan import existing_fixture
  from private_io import encoded,write_new
  infrastructure,trust=provider.infrastructure,provider.guest_trust
  case=integration.DeploymentIntegrationTests();case.setUp();self.addCleanup(case.doCleanups)
  cfg=copy.deepcopy(case.cfg);work=case.root/'provider-work';work.mkdir(mode=0o700)
  hosts=case.root/'known-hosts';write_new(hosts,b'public synthetic host key\n');cfg['paths']['known_hosts']=str(hosts)
  with patch.object(provider.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=cfg['app']['address']+' ssh-ed25519 fixture\n'))as lookup,self.assertRaisesRegex(ValueError,'existing commissioned guest trust'):
   trust(cfg,work,persist=False)
  self.assertEqual(lookup.call_args.args[0][0],'ssh-keygen');self.assertFalse((work/'ssh-trust.json').exists())
  cfg['site']['node']='pve-lab';cfg['guest']['vmid']=cfg['app']['vmid']=6100
  cfg['paths']['api_token']=str(case.root/'provider-token');write_new(case.root/'provider-token',b'fixture@pve!deploy=synthetic')
  write_new(work/'terraform.tfstate',b'owned synthetic backend')
  plan=existing_fixture()
  for row in plan['resource_changes']:row['change']['before']['id']=row['change']['after']['id']='original'
  identity={'resources':{row['address']:{'id':'foreign'}for row in plan['resource_changes']}}
  operation=case.root/'provider-attempt';operation.mkdir(mode=0o700)
  def quiet(argv,environment,log):
   self.assertNotIn('apply',argv)
   if 'plan'in argv:write_new(operation/'guest.tfplan',b'fixture saved plan')
  with patch.object(deployment_inputs,'binding',return_value={}),patch.object(provider,'backup'),patch.object(provider,'dhcp_admission'),patch.object(provider,'quiet',side_effect=quiet)as command,patch.object(provider.subprocess,'check_output',return_value=encoded(plan)),self.assertRaisesRegex(ValueError,'admitted backend resource ID'):
   infrastructure(cfg,case.root/'site',work,operation,{},state_identity=identity)
  self.assertTrue(command.called);self.assertFalse((operation/'apply-window.json').exists())

class NormalPlanDriftTests(unittest.TestCase):
 def test_former_failed_update_refresh_has_no_ordinary_waiver(self):
  from test_plan import existing_fixture
  import plan_policy
  plan=existing_fixture();row=plan['resource_changes'][0]
  old=copy.deepcopy(row['change']['before']);new=copy.deepcopy(old)
  old.update(id='same-provider-id',memory=[{'dedicated':1024}]);new.update(id='same-provider-id',memory=[{'dedicated':768}])
  drift=copy.deepcopy(row);drift['change'].update(before=old,after=new)
  plan['resource_drift']=[drift];before=copy.deepcopy(plan)
  for existing in(True,False):
   with self.subTest(existing=existing),self.assertRaises(ValueError):
    plan_policy.check_plan(plan,'pve-lab',6100,existing=existing,protected_guests=[9900,9914,9915,9920])
  self.assertEqual(plan,before)
  self.assertFalse(hasattr(plan_policy,'reviewed_guest_drift'))

if __name__=='__main__':unittest.main()
