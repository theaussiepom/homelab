"""Exact prior-owned DNS retirement; real component receipts, no native target."""
import copy,json,os
from pathlib import Path
from types import SimpleNamespace
import sys,tempfile,unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE.parent),str(HERE.parents[2]/'blueprints')]
import commands,component_plan,component_packet,component_prepare,component_generation,deploy,dns_records as dns
import test_component_deployment as integration
from test_component_plan import library,site
from fixtures import github_source
from private_io import encoded,read_json,write_bytes

CURRENT='service.example.invalid';RETIRED='old-service.example.invalid';ADDRESS='198.18.30.6'

class DnsRetirementUnits(unittest.TestCase):
 def test_exact_retired_name_only_preserves_unrelated_aliases_addresses_order_and_repeat(self):
  old=['198.18.30.6 OLD-SERVICE.EXAMPLE.INVALID. unrelated.alias','198.18.99.1 other.example.invalid','198.18.30.6 service.example.invalid']
  previous={CURRENT:ADDRESS,RETIRED:ADDRESS};records={CURRENT:ADDRESS}
  expected=['198.18.30.6 unrelated.alias','198.18.99.1 other.example.invalid','198.18.30.6 service.example.invalid']
  self.assertEqual(dns.desired_hosts(old,records,previous),expected)
  self.assertEqual(dns.desired_hosts(expected,records,previous),expected)
  self.assertEqual(dns.desired_hosts(old,records,{}),[old[0],old[1],old[2]])
  self.assertEqual(dns.desired_hosts([],records,{}),[ADDRESS+' '+CURRENT])
 def test_changed_or_duplicate_retired_native_record_refuses_before_write(self):
  previous={RETIRED:ADDRESS};records={CURRENT:ADDRESS}
  for old in(['198.18.30.7 '+RETIRED],['::1 '+RETIRED],[ADDRESS+' '+RETIRED,ADDRESS+' '+RETIRED],
              [ADDRESS+' '+RETIRED+' '+RETIRED.upper()+'.']):
   with self.subTest(old=old),self.assertRaises(ValueError):dns.desired_hosts(old,records,previous)
   current='[ '+', '.join(old)+' ]'
   with patch.object(dns.subprocess,'run',return_value=SimpleNamespace(stdout=current))as call,self.assertRaises(ValueError):
    dns.reconcile(records,Path('/owned/compose.yml'),previous=previous)
   self.assertEqual(call.call_count,1)
 def test_closed_document_and_all_nested_record_contracts(self):
  value=dns.document({CURRENT:ADDRESS},{RETIRED:ADDRESS});self.assertEqual(dns.selection(value),({CURRENT:ADDRESS},{RETIRED:ADDRESS}))
  cases=[{},dict(value,schema='old'),dict(value,extra=True),{CURRENT:ADDRESS},dict(value,previous=None)]
  for records in({CURRENT:True},{CURRENT:'127.0.0.1'},{CURRENT:'224.0.0.1'},{CURRENT:'0.0.0.0'},{'BAD NAME':ADDRESS}):
   cases.extend([dict(value,previous=records),dict(value,records=records)])
  for changed in cases:
   with self.subTest(keys=list(changed)),self.assertRaises(ValueError):dns.selection(changed)
 def test_current_config_readback_and_selected_service_are_preserved(self):
  records={CURRENT:ADDRESS};previous={CURRENT:ADDRESS,RETIRED:ADDRESS}
  before='[ '+ADDRESS+' '+RETIRED+', '+ADDRESS+' '+CURRENT+' ]';after='[ '+ADDRESS+' '+CURRENT+' ]'
  with patch.object(dns.subprocess,'run',side_effect=[SimpleNamespace(stdout=before),SimpleNamespace(stdout=''),SimpleNamespace(stdout=after)])as call:
   self.assertTrue(dns.reconcile(records,Path('/owned/compose.yml'),service='owned-dns',previous=previous))
  self.assertEqual(call.call_count,3);self.assertEqual(call.call_args_list[0].args[0],['docker','compose','-f','/owned/compose.yml','exec','-T','owned-dns','pihole-FTL','--config','dns.hosts'])
  self.assertEqual(json.loads(call.call_args_list[1].args[0][-1]),[ADDRESS+' '+CURRENT])

class DnsRetirementIntegration(unittest.TestCase):
 def setUp(self):
  real_ancestor=commands.is_ancestor;self.case=integration.DeploymentIntegrationTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
  self.source,self.revisions=github_source(self.case.root)
  for context in(patch.object(commands,'is_ancestor',side_effect=real_ancestor),patch.dict(os.environ,{'GITHUB_WORKSPACE':str(self.source),'GITHUB_SHA':self.revisions[0]})):
   context.start();self.addCleanup(context.stop)
  self.stack=self.case.root/'library';self.file=self.case.root/'consumer/site.json'
  spec=library();source=site();profile=spec['app_profiles']['recursive']
  profile.update(adapter='pihole',interfaces={key:{'required':True,'accepts':['guest-interface']}for key in('service','upstream')},
   listeners={proto:{'service':'pihole','namespace':'host','interface':'service','bind':'wildcard','protocol':proto,'port':53}for proto in('tcp','udp')},
   endpoints={'dns':{'listener':'udp','protocol':'udp','via':'service'}},
   connections={'upstream':{'type':'dns','required':True}},storage={'config':{'required':True,'target':'/etc/pihole','kind':'directory','read_only':False}},
   software=['dns'],runtime=['dns'],health={'ready':{'type':'adapter','check':'readiness'}})
  spec['software']={'dns':{'images':{'pihole':'dns'}}};spec['runtime_profiles']={'dns':{'containers':{'pihole':{'memory_mib':256,'cpu_limit':1,'pids_limit':128}}}}
  source['contexts']['lab']['paths']['state_root']=str(self.case.state);source['contexts']['lab']['trust']['ca_file']=str(self.case.root/'ca.pem')
  guest=source['guests']['resolver'];guest['resources']={'memory_mib':1024};guest['root_paths']={'data':{'path':'/srv/example/dns'}}
  source['apps']['recursive_a'].update(interfaces={'service':{'interface':'backend'},'upstream':{'interface':'backend'}},storage={'config':{'root_path':'data','subpath':'config'}})
  source['external_endpoints']['service']={'protocol':'http','address':ADDRESS,'port':80}
  source['domains']={'service':CURRENT,'retired':RETIRED}
  source['exposures']={'service':{'type':'dns','endpoint':{'external':'service'},'domain':'service','resolver':'recursive_a','aliases':['retired']}}
  source['connections']={'dns':{'consumer':{'app':'recursive_a','connection':'upstream'},'target':{'external':'dns'},'source_interface':'upstream'}}
  source['policies']={'network':{'dns':{'rules':[{'direction':'out','proto':protocol,'destination':{'endpoint':'dns'},'port':'53','comment':'Selected synthetic upstream'}for protocol in('udp','tcp')]}}}
  guest['network_policy']=[{'policy':'dns','endpoints':{'dns':{'external':'dns'}}}]
  (self.stack/'stack.json').write_text(json.dumps(spec));(self.stack/'images.json').write_text(json.dumps({'dns':{'repository':'example/pihole','tag':None,'digest':'sha256:'+'a'*64}}));self.authored=source;self.compile()
 def compile(self):
  self.file.write_text(json.dumps(self.authored));plan=component_plan.resolve(self.stack,self.file)
  packet=component_packet.lower_plan(plan,inputs=self.case.inputs)['resolver'];write_bytes(self.case.packet,encoded(packet));self.case.cfg=json.loads(packet['files']['site.json'])
 def selected(self):
  receipt=read_json(self.case.state/'610/ordinary-complete.json',private=True);directory=Path(receipt['binding']['app_inputs_directory'])/'recursive_a'
  return receipt,directory,read_json(directory/'dns-records.json',private=True)
 def update(self):
  self.authored['exposures']['service'].pop('aliases');self.authored['domains'].pop('retired');self.compile()
 def test_actual_source_prior_sealed_payload_retirement_and_following_repeat_preserve_old_evidence(self):
  self.case.all_phases();receipt,directory,first=self.selected();self.assertEqual(first,dns.document({CURRENT:ADDRESS,RETIRED:ADDRESS},{}))
  before={p:(p.stat().st_ino,p.read_bytes())for p in directory.iterdir()};self.update()
  with patch.dict(os.environ,{'GITHUB_RUN_ID':'102','GITHUB_RUN_NUMBER':'11','GITHUB_SHA':self.revisions[1]}):self.case.all_phases()
  _,_,second=self.selected();self.assertEqual(second,dns.document({CURRENT:ADDRESS},{CURRENT:ADDRESS,RETIRED:ADDRESS}))
  self.assertEqual(dns.desired_hosts([ADDRESS+' '+RETIRED+' unrelated.alias',ADDRESS+' '+CURRENT],*dns.selection(second)),[ADDRESS+' unrelated.alias',ADDRESS+' '+CURRENT])
  self.assertEqual(before,{p:(p.stat().st_ino,p.read_bytes())for p in directory.iterdir()})
  with patch.dict(os.environ,{'GITHUB_RUN_ID':'103','GITHUB_RUN_NUMBER':'12','GITHUB_SHA':self.revisions[1]}):self.case.all_phases()
  _,_,third=self.selected();self.assertEqual(third,second)
  self.authored['apps']['recursive_a']['display_name']='Updated DNS label';self.compile()
  with patch.dict(os.environ,{'GITHUB_RUN_ID':'104','GITHUB_RUN_NUMBER':'13','GITHUB_SHA':self.revisions[1]}):self.case.all_phases()
  self.assertEqual(self.selected()[2],dns.document({CURRENT:ADDRESS},{CURRENT:ADDRESS}))
 def test_genuine_historical_flat_sidecar_is_only_read_as_sealed_previous_selection(self):
  with patch.object(component_prepare,'dns_document',side_effect=lambda cfg,app,attempt:copy.deepcopy(app['settings']['dns_records'])):self.case.all_phases()
  _,_,old=self.selected();self.assertEqual(old,{CURRENT:ADDRESS,RETIRED:ADDRESS});self.update()
  with patch.dict(os.environ,{'GITHUB_RUN_ID':'102','GITHUB_RUN_NUMBER':'11','GITHUB_SHA':self.revisions[1]}):self.case.all_phases()
  self.assertEqual(self.selected()[2],dns.document({CURRENT:ADDRESS},{CURRENT:ADDRESS,RETIRED:ADDRESS}))
 def test_changed_sealed_previous_sidecar_and_persistent_owner_refuse(self):
  self.case.all_phases();_,directory,_=self.selected();leaf=directory/'dns-records.json';raw=leaf.read_bytes();write_bytes(leaf,b'{}');self.update()
  with patch.dict(os.environ,{'GITHUB_RUN_ID':'102','GITHUB_RUN_NUMBER':'11','GITHUB_SHA':self.revisions[1]}),self.assertRaises(ValueError):deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs,environment={})
  write_bytes(leaf,raw)
  self.authored['apps']['recursive_a']['storage']['config']['subpath']='foreign-config';self.compile()
  with patch.dict(os.environ,{'GITHUB_RUN_ID':'102','GITHUB_RUN_NUMBER':'11','GITHUB_SHA':self.revisions[1]}):
   deploy.run('infrastructure',self.case.packet,inputs=self.case.inputs,environment={});deploy.run('preparation',self.case.packet,inputs=self.case.inputs,environment={})
   with self.assertRaisesRegex(ValueError,'ownership changed'):deploy.run('recursive_a',self.case.packet,inputs=self.case.inputs,environment={})
  self.assertFalse((self.case.state/'610/ordinary-102-1/recursive_a-started.json').exists())

if __name__=='__main__':unittest.main()
