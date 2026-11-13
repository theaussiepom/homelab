"""Direct small validators and guest orchestration with component collaborators mocked."""
from contextlib import ExitStack
import copy
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock,patch

F=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(F/'blueprints'))
import component_types as types
import component_monitoring
import component_secrets
import component_foundations
from component_errors import ComponentError


def context():
 return {'backend':'proxmox-lxc','node':'synthetic-node','api_endpoint':{'external':'provider'},
  'trust':{'ca_file':'/public/example-ca.pem','known_hosts':'/public/example-known-hosts'},
  'credentials':{'api_token':'provider_token','ssh_private_key':'controller_key'},
  'paths':{'state_root':'/var/lib/example-state','backup_directory':'/srv/example-backup/run','backup_mount':'/srv/example-backup','backup_source':'nas.example.invalid:/synthetic'},
  'protected_guests':[91001,91002],'ssh_public_keys':['ssh-ed25519 synthetic-public-key'],
  'dns_servers':[{'app':'resolver','endpoint':'dns_udp_endpoint'}],
  'capabilities':{'coordinator':{'type':'serial-device','ssh_private_key':'device_key','known_hosts':'/public/device-known-hosts'}},'timezone':'Etc/UTC'}


def nic(slot=0,mode='static',default=True):
 return {'network':'management','slot':slot,'mac':'02:00:00:00:00:'+str(slot+1).zfill(2),
         'address':{'mode':mode,**({'value':'198.18.25.20'}if mode=='static'else{'endpoint':'198.18.25.21'}if mode=='dhcp'else{})},
         'default_route':default,'ipv6':'manual'}


def guest():
 return {'context':'primary','template':'plain','lifecycle':'retained',
  'identity':{'vmid':91003,'hostname':'example-guest'},'template_file_id':'local:vztmpl/synthetic.tar.zst',
  'root_storage':'guest_pool','interfaces':{'control':nic()},'control_interface':'control'}


class DirectSmallTypesTests(unittest.TestCase):
 def bad(self,fn,values):
  for index,value in enumerate(values):
   with self.subTest(case=index),self.assertRaises(ComponentError)as caught:fn(copy.deepcopy(value))
   self.assertTrue(str(caught.exception).startswith('component.'));self.assertNotIn('DO_NOT_ECHO',str(caught.exception))
 def test_text_integer_and_timezone_boundaries(self):
  self.assertEqual(types.text('x'*4096),'x'*4096);self.assertEqual(types.integer(0),0);self.assertEqual(types.integer(2**31-1),2**31-1)
  self.bad(types.text,['','x'*4097,None,[],True,'DO_NOT_ECHO\0'])
  self.bad(types.integer,[True,False,-1,2**31,1.0,'1',None])
  for value in ('Etc/UTC','Australia/Brisbane','UTC+10','A_B/C-D'):types.timezone(value)
  self.bad(types.timezone,['','x'*129,'../UTC','UTC\n','A B',None,True])
 def test_paths_keep_absolute_relative_and_literal_boundaries(self):
  self.assertEqual(types.path('/srv/example-data'),'/srv/example-data');self.assertEqual(types.path('data/sub',relative=True),'data/sub')
  self.bad(types.path,['relative','//srv/data','/srv/../etc','/srv/./data','/srv//data','/srv/data/','/srv/${value}','/srv/a:b','/srv/a\\b','/srv/DO_NOT_ECHO\n'])
  for value in ('/absolute','../escape','./file','a//b',''):
   with self.subTest(relative=value),self.assertRaises(ComponentError):types.path(value,relative=True)
 def test_ip_strings_and_endpoint_refs_are_closed_primitives(self):
  self.assertEqual(types.ip('198.18.0.1'),'198.18.0.1');types.strings(['a','b'],ids=True);types.strings(['same','same'],unique=False)
  self.bad(types.ip,['198.18.00.1','::1','198.18.1.256',None,1])
  self.bad(types.strings,[['a','a'],[1],[''],['x'*4097],'a',['x']*1025])
  for value in ({'external':'api'},{'app':'resolver','endpoint':'dns_udp_endpoint'}):types.endpoint(value)
  self.bad(types.endpoint,[{},[],{'external':'api','app':'foreign'},{'app':'resolver'},{'app':'resolver','endpoint':'dns_endpoint','port':53},{'external':'DO_NOT_ECHO!'}])
 def test_resources_full_and_partial_preserve_numeric_floors(self):
  good={'cpu_cores':1,'memory_mib':256,'root_gib':4,'os_reserve_mib':0};types.resource(good);types.resource({},partial=True);types.resource({'memory_mib':512},partial=True)
  for key in good:
   bad=copy.deepcopy(good);bad.pop(key)
   with self.subTest(missing=key),self.assertRaises(ComponentError):types.resource(bad)
  self.bad(types.resource,[dict(good,extra=True),dict(good,cpu_cores=True),dict(good,cpu_cores=0),dict(good,memory_mib=255),dict(good,root_gib=3),dict(good,os_reserve_mib=-1)])
 def test_startup_security_and_template_components_have_closed_boolean_semantics(self):
  startup={'started':True,'start_on_boot':False,'boot_order':0};security={'unprivileged':True,'protection':True,'nesting':False,'keyctl':True}
  types.startup(startup);types.startup({},partial=True);types.security(security);types.security({},partial=True)
  self.bad(types.startup,[{},dict(startup,started=1),dict(startup,start_on_boot='yes'),dict(startup,boot_order=True),dict(startup,boot_order=-1),dict(startup,extra=True)])
  self.bad(types.security,[{},dict(security,unprivileged=False),dict(security,protection=False),dict(security,nesting=1),dict(security,keyctl='true'),dict(security,extra=True)])
  value={'resources':{'cpu_cores':1,'memory_mib':1024,'root_gib':4,'os_reserve_mib':256},'startup':startup,'security':security,'software':['linux'],'runtime':['native'],'monitoring':{'profile':'linux'}}
  with patch.object(types,'resource')as resource,patch.object(types,'startup')as start,patch.object(types,'security')as secure,patch.object(component_monitoring,'reference')as monitor:
   types.template(value)
  resource.assert_called_once_with(value['resources']);start.assert_called_once_with(startup);secure.assert_called_once_with(security);monitor.assert_called_once_with(value['monitoring'])
  self.bad(types.template,[{'resources':{}},dict(value,extra=True)])
 def test_context_success_requires_named_endpoint_trust_and_supplied_protected_ids(self):
  value=context();before=copy.deepcopy(value);types.context(value);self.assertEqual(value,before)
  value['api_endpoint']={'app':'provider_proxy','endpoint':'api_endpoint'};value.pop('capabilities');value.pop('timezone');types.context(value)
 def test_context_each_required_field_and_unknowns_are_refused_directly(self):
  value=context();required=set(value)-{'capabilities','timezone'}
  for key in required:
   bad=copy.deepcopy(value);bad.pop(key)
   with self.subTest(missing=key),self.assertRaises(ComponentError):types.context(bad)
  self.bad(types.context,[dict(value,extra='DO_NOT_ECHO'),dict(value,backend='other'),dict(value,node=''),dict(value,credentials={'api_token':'token'}),dict(value,trust={'ca_file':'/public/ca'}),dict(value,paths={}),dict(value,protected_guests=[91001,91001]),dict(value,protected_guests=[True]),dict(value,protected_guests='91001'),dict(value,dns_servers=[]),dict(value,dns_servers=[{'external':'bad!'}])])
 def test_context_trust_paths_and_serial_capability_are_finite(self):
  mutations=[lambda v:v['trust'].update(ca_file='../private'),lambda v:v['trust'].update(key_file='/private/DO_NOT_ECHO'),lambda v:v['credentials'].update(api_token='DO_NOT_ECHO!'),lambda v:v['paths'].update(state_root='relative'),lambda v:v['capabilities']['coordinator'].update(type='arbitrary-device'),lambda v:v['capabilities']['coordinator'].update(ssh_private_key='DO_NOT_ECHO!'),lambda v:v['capabilities']['coordinator'].update(known_hosts='relative'),lambda v:v['capabilities']['coordinator'].update(secret='DO_NOT_ECHO')]
  for index,mutate in enumerate(mutations):
   value=context();mutate(value)
   with self.subTest(case=index),self.assertRaises(ComponentError)as caught:types.context(value)
   self.assertNotIn('DO_NOT_ECHO',str(caught.exception))
 def test_device_success_is_typed_serial_declaration_without_registration_or_io(self):
  value={'type':'serial','context':'primary','path':'/dev/serial/by-id/usb-synthetic-example','capability':'coordinator'};before=copy.deepcopy(value);types.device(value);self.assertEqual(value,before)
 def test_device_missing_unknown_type_reference_and_path_fields_refuse(self):
  value={'type':'serial','context':'primary','path':'/dev/serial/by-id/usb-synthetic-example','capability':'coordinator'}
  for key in value:
   bad=copy.deepcopy(value);bad.pop(key)
   with self.subTest(missing=key),self.assertRaises(ComponentError):types.device(bad)
  for key,items in {'type':['usb','shell'], 'context':['bad!',None], 'capability':['bad!',{}], 'path':['/dev/ttyUSB0','relative','/dev/serial/by-id','/dev/serial/by-id/../DO_NOT_ECHO','/dev/serial/by-id/DO_NOT_ECHO\0']}.items():
   for item in items:
    bad=copy.deepcopy(value);bad[key]=item
    with self.subTest(field=key),self.assertRaises(ComponentError)as caught:types.device(bad)
    self.assertNotIn('DO_NOT_ECHO',str(caught.exception))
  self.bad(types.device,[dict(value,owner='DO_NOT_ECHO')])
 def test_network_success_preserves_vlan_null_and_explicit_gateway(self):
  for vlan in (None,1,4094):
   value={'context':'primary','cidr':'198.18.25.0/24','bridge':'br-example','vlan':vlan,'gateway':'198.18.25.1'};before=copy.deepcopy(value);types.network(value);self.assertEqual(value,before)
  types.network({'context':'primary','cidr':'198.18.25.0/24','bridge':'br-example','vlan':None})
 def test_network_missing_unknown_type_canonical_cidr_gateway_and_vlan_bounds(self):
  value={'context':'primary','cidr':'198.18.25.0/24','bridge':'br-example','vlan':25,'gateway':'198.18.25.1'}
  for key in ('context','cidr','bridge','vlan'):
   bad=copy.deepcopy(value);bad.pop(key)
   with self.subTest(missing=key),self.assertRaises(ComponentError):types.network(bad)
  for key,items in {'context':['bad!'], 'cidr':['198.18.25.1/24','198.18.25.0/99','198.18.25.0/255.255.255.0',[],None],'bridge':[''], 'vlan':[0,4095,True,'25'],'gateway':['198.18.26.1','198.18.25.0','198.18.25.255','not-ip']}.items():
   for item in items:
    bad=copy.deepcopy(value);bad[key]=item
    with self.subTest(field=key,type=type(item).__name__),self.assertRaises(ComponentError):types.network(bad)
  self.bad(types.network,[dict(value,enable=True)])
 def test_nic_success_preserves_static_dhcp_manual_ipv6_and_route_flags(self):
  for value in (nic(),nic(31),nic(mode='dhcp',default=False),nic(mode='manual',default=False)):
   before=copy.deepcopy(value);types.interface(value);self.assertEqual(value,before)
 def test_nic_missing_unknown_slot_mac_and_address_shapes_refuse(self):
  value=nic()
  for key in ('network','slot','mac','address'):
   bad=copy.deepcopy(value);bad.pop(key)
   with self.subTest(missing=key),self.assertRaises(ComponentError):types.interface(bad)
  mutations=[lambda v:v.update(network='bad!'),lambda v:v.update(slot=True),lambda v:v.update(slot=-1),lambda v:v.update(slot=32),lambda v:v.update(mac='bad'),lambda v:v.update(default_route=1),lambda v:v.update(ipv6='auto'),lambda v:v.update(extra=True),lambda v:v.update(address=[]),lambda v:v['address'].update(mode='unknown'),lambda v:v['address'].pop('value'),lambda v:v['address'].update(endpoint='198.18.25.20')]
  for index,mutate in enumerate(mutations):
   bad=copy.deepcopy(value);mutate(bad)
   with self.subTest(case=index),self.assertRaises(ComponentError):types.interface(bad)
  self.bad(types.interface,[nic(mode='dhcp',default=True),nic(mode='manual',default=True)])
 def test_software_success_and_missing_version_unknown_repository_and_image_refs(self):
  good={'packages':['curl=8.0-1','example:amd64=1.0+build'],'images':{'worker':'example-image'},'repositories':[{'name':'vendor','source':'deb [signed-by=/public/vendor.asc] https://vendor.example.invalid stable main','key_asset':'vendor_key'}]};before=copy.deepcopy(good);types.software(good);types.software({});self.assertEqual(good,before)
  self.bad(types.software,[dict(good,extra=True),dict(good,packages=['curl']),dict(good,packages=['curl=']),dict(good,packages=['curl=1 2']),dict(good,packages=['curl=1','curl=1']),dict(good,images={'worker':'bad!'}),dict(good,repositories={}),dict(good,repositories=[{'name':'vendor','source':'https://vendor.example.invalid'}]),dict(good,repositories=[{'name':'vendor','source':'https://vendor.example.invalid','key_asset':'key','token':'DO_NOT_ECHO'}])])
 def test_runtime_success_preserves_scope_requirements_native_and_container_policy(self):
  good={'packages':['docker'],'requirements':{'nesting':True,'keyctl':False,'os_reserve_mib':256},'native':{'memory_mib':768},'minimums':{'containers':{'service':{'memory_mib':64,'cpu_limit':0.5,'pids_limit':32}}},'containers':{'service':{'memory_mib':128,'pids_limit':64,'cpu_limit':1.5,'read_only':True,'no_new_privileges':True,'cap_drop':['ALL'],'cap_add':['NET_ADMIN'],'user':'1001:1001','tmpfs':['/tmp:rw,nosuid,nodev,size=16m']}}};before=copy.deepcopy(good);types.runtime(good);types.runtime({});self.assertEqual(good,before)
 def test_runtime_closed_requirement_native_and_allocation_failures(self):
  bads=[{'unknown':True},{'packages':['bad!']},{'requirements':{'nesting':1}},{'requirements':{'keyctl':'yes'}},{'requirements':{'os_reserve_mib':0}},{'requirements':{'unknown':True}},{'native':{}},{'native':{'memory_mib':0}},{'native':{'memory_mib':True}},{'native':{'memory_mib':1,'cpu':1}},{'minimums':{'other':{}}},{'minimums':{'containers':{'service':{}}}},{'minimums':{'containers':{'service':{'cpu_limit':0}}}}]
  self.bad(types.runtime,bads)
 def test_runtime_container_process_privilege_and_tmpfs_bounds(self):
  rows=[{'memory_mib':0},{'pids_limit':True},{'cpu_limit':0},{'cpu_limit':257},{'cpu_limit':float('nan')},{'read_only':1},{'no_new_privileges':'yes'},{'cap_drop':['NET_ADMIN']},{'cap_add':['SYS_ADMIN']},{'cap_drop':['ALL','ALL']},{'tmpfs':['/tmp:rw,nosuid,nodev,size=0m']},{'tmpfs':['/etc:rw,nosuid,nodev,size=16m']},{'user':''},{'command':'DO_NOT_ECHO'}]
  self.bad(types.runtime,[{'containers':{'service':row}}for row in rows])
 def test_health_success_and_closed_readiness_source_role_structure(self):
  types.health({'type':'adapter','check':'readiness'});types.health({'type':'adapter','check':'readiness','source_interface':'management_interface'})
  self.bad(types.health,[{}, {'type':'adapter'},{'type':'shell','check':'readiness'},{'type':'adapter','check':'command'},{'type':'adapter','check':'readiness','source_interface':'bad!_interface'},{'type':'adapter','check':'readiness','argv':['DO_NOT_ECHO']}])
 def test_policy_references_are_closed_without_free_configuration(self):
  types.policy_binding('common');types.policy_binding({'policy':'access','interfaces':{'local':'control','remote':{'app':'peer','interface':'service_interface'}},'networks':{'lan':'management'},'endpoints':{'database':{'app':'database','endpoint':'service_endpoint'}}})
  self.bad(types.policy_binding,['bad!',{'policy':'access','extra':True},{'policy':'access','interfaces':{'remote':{'app':'peer','interface':'bad!_interface'}}},{'policy':'access','endpoints':{'database':{'app':'database'}}}])
 def test_role_and_rule_address_references_have_no_free_configuration_bag(self):
  for value in ({'interface':'control'},{'scope':'app-network','network':'private'},{'scope':'guest-loopback'}):types.role(value)
  self.bad(types.role,[{},[],{'scope':'host'},{'interface':'control','source':'DO_NOT_ECHO'},{'scope':'app-network'},{'scope':'guest-loopback','network':'private'}])
  for value in ('198.18.25.1/32',{'network':'management'},{'interface':'control'},{'endpoint':'database'}):types.rule_address(value)
  self.bad(types.rule_address,['not-cidr',{}, {'network':'management','interface':'control'},{'host':'DO_NOT_ECHO'},{'endpoint':'bad!'}])


class DeviceRequirementUnitTests(unittest.TestCase):
 """Profile requirement metadata is distinct from the physical device declaration."""
 def profile(self):return {'adapter':'zigbee2mqtt','display_name':'Synthetic radio','interfaces':{},'devices':{'coordinator':{'type':'serial','required':True}}}
 def guards(self):
  stack=ExitStack();stack.enter_context(patch.object(types,'adapter',return_value={'services':[],'native':[]}));stack.enter_context(patch.object(component_secrets,'requirements'));stack.enter_context(patch.object(component_foundations,'validate'));return stack
 def test_device_requirement_success_is_metadata_with_other_components_mocked(self):
  value=self.profile();before=copy.deepcopy(value)
  with self.guards():types.profile(value)
  self.assertEqual(value,before)
 def test_compiler_validator_propagates_mocked_device_refusal_with_safe_subject_path(self):
  from component_plan import Resolver
  resolver=Resolver.__new__(Resolver)
  resolver.library={key:{}for key in('guest_templates','app_profiles','software','runtime_profiles','health_profiles','monitoring_profiles','backup_profiles')}
  resolver.site={key:{}for key in('contexts','networks','guests','apps','storage','secret_sources')}
  resolver.policy={'network':{}}
  resolver.site['devices']={'coordinator':{'type':'serial','context':'primary','path':'/dev/serial/by-id/usb-synthetic','capability':'registered'}}
  with patch.object(types,'device',side_effect=ComponentError('component.device'))as component,self.assertRaises(ComponentError)as caught:resolver.validate()
  component.assert_called_once_with(resolver.site['devices']['coordinator']);self.assertEqual(str(caught.exception),'component.device at devices.coordinator')
 def test_device_requirement_missing_unknown_type_and_boolean_fields_refuse(self):
  for row in ({},{'type':'serial'},{'required':True},{'type':'usb','required':True},{'type':'serial','required':1},{'type':'serial','required':True,'path':'/dev/DO_NOT_ECHO'}):
   value=self.profile();value['devices']['coordinator']=row
   with self.subTest(fields=list(row)),self.guards(),self.assertRaises(ComponentError)as caught:types.profile(value)
   self.assertNotIn('DO_NOT_ECHO',str(caught.exception))


class GuestWiringUnitTests(unittest.TestCase):
 def guards(self):
  stack=ExitStack();mocks={}
  for name in ('resource','startup','security','strings','endpoint','interface','volume','root_path','storage_layout','policy_binding','timezone'):
   mocks[name]=stack.enter_context(patch.object(types,name,Mock()))
  mocks['monitoring']=stack.enter_context(patch.object(component_monitoring,'reference',Mock()))
  return stack,mocks
 def run_guest(self,value):
  stack,mocks=self.guards()
  with stack:types.guest(value)
  return mocks
 def test_minimal_guest_wires_components_once_without_validating_their_internals(self):
  value=guest();before=copy.deepcopy(value);mocks=self.run_guest(value)
  mocks['interface'].assert_called_once_with(value['interfaces']['control']);mocks['storage_layout'].assert_called_once_with({},{});self.assertEqual(value,before)
 def test_guest_partial_resources_startup_security_and_named_ref_collaborators_are_forwarded(self):
  value=guest();value.update(resources={'memory_mib':512},startup={'boot_order':4},security={'keyctl':False},ssh_public_keys=['synthetic-key'],dns_servers=[{'app':'resolver','endpoint':'dns_endpoint'}],volumes={'data':{'storage':'pool','slot':0,'path':'/srv/example','size_gib':4}},root_paths={'config':{'path':'/srv/root-config'}},network_policy=[{'policy':'common'}],timezone='Etc/UTC',monitoring={'profile':'linux'},readiness=[{'stage':'preparation','target':{'app':'resolver','endpoint':'dns_endpoint'}}])
  mocks=self.run_guest(value)
  for name in ('resource','startup','security'):mocks[name].assert_called_once_with(value[name if name!='resource'else'resources'],partial=True)
  mocks['volume'].assert_called_once_with(value['volumes']['data']);mocks['root_path'].assert_called_once_with(value['root_paths']['config']);mocks['policy_binding'].assert_called_once_with(value['network_policy'][0]);mocks['timezone'].assert_called_once_with('Etc/UTC');mocks['monitoring'].assert_called_once_with(value['monitoring']);self.assertEqual(mocks['endpoint'].call_count,2)
 def test_required_guest_fields_unknowns_identity_and_selection_syntax_fail_at_guest_boundary(self):
  value=guest()
  for key in value:
   bad=copy.deepcopy(value);bad.pop(key)
   with self.subTest(missing=key),self.assertRaises(ComponentError):self.run_guest(bad)
  mutations=[lambda v:v.update(extra='DO_NOT_ECHO'),lambda v:v.update(context='bad!'),lambda v:v.update(template='bad!'),lambda v:v.update(root_storage='bad!'),lambda v:v.update(lifecycle='unknown'),lambda v:v['identity'].update(vmid=True),lambda v:v['identity'].update(vmid=0),lambda v:v['identity'].update(hostname='DO_NOT_ECHO!'),lambda v:v['identity'].update(owner='foreign'),lambda v:v.update(template_file_id=''),lambda v:v.update(display_name='')]
  for index,mutate in enumerate(mutations):
   bad=copy.deepcopy(value);mutate(bad)
   with self.subTest(case=index),self.assertRaises(ComponentError)as caught:self.run_guest(bad)
   self.assertNotIn('DO_NOT_ECHO',str(caught.exception))
 def test_control_selection_is_explicit_static_or_qualified_dhcp_not_interface_order(self):
  for mode in ('static','dhcp'):
   value=guest();value['interfaces']={'other':nic(0,default=False),'control':nic(1,mode=mode,default=mode=='static')};self.run_guest(value)
  for update in ('missing','manual','empty'):
   value=guest()
   if update=='missing':value['control_interface']='other'
   elif update=='manual':value['interfaces']['control']['address']={'mode':'manual'}
   else:value['interfaces']={}
   with self.subTest(case=update),self.assertRaises(ComponentError):self.run_guest(value)
 def test_slots_are_unique_contiguous_and_default_route_is_exactly_one_including_dhcp(self):
  mutations=[lambda v:v['interfaces']['control'].update(slot=1),lambda v:v['interfaces'].update(peer=nic(0,default=False)),lambda v:v['interfaces'].update(peer=nic(2,default=False)),lambda v:v['interfaces']['control'].update(default_route=False),lambda v:v['interfaces'].update(peer=nic(1,default=True)),lambda v:v['interfaces'].update(peer=nic(1,mode='dhcp',default=False))]
  for index,mutate in enumerate(mutations):
   value=guest();mutate(value)
   with self.subTest(case=index),self.assertRaises(ComponentError):self.run_guest(value)
 def test_source_policy_route_references_only_selected_static_secondary_interface(self):
  value=guest();value['interfaces']['secondary']=nic(1,default=False);value['source_policy_route']={'interface':'secondary'};self.run_guest(value)
  for route in ({'interface':'missing'},{'interface':'control'},{'interface':'secondary','table':10040}):
   bad=copy.deepcopy(value);bad['source_policy_route']=route
   with self.subTest(fields=list(route)),self.assertRaises(ComponentError):self.run_guest(bad)
  value['interfaces']['secondary']['address']={'mode':'dhcp','endpoint':'198.18.25.21'};value['interfaces']['control']['default_route']=False
  with self.assertRaises(ComponentError):self.run_guest(value)
 def test_project_files_are_safe_unique_stable_and_not_count_derived(self):
  value=guest();value['compose_projects']={'one':{'name':'project-one'}};self.run_guest(value)
  value['compose_projects']['two']={'name':'project-two','file':'compose.yml'};self.run_guest(value)
  for projects in ({'one':{'name':'project','file':'../escape.yml'}},{'one':{'name':'project','file':'not-json.json'}},{'one':{'name':'project','file':'same.yml'},'two':{'name':'other','file':'same.yml'}},{'one':{'name':'project','state':'foreign'}}):
   bad=guest();bad['compose_projects']=projects
   with self.subTest(keys=list(projects)),self.assertRaises(ComponentError):self.run_guest(bad)
 def test_preparation_readiness_is_explicit_managed_reference_and_wrong_stage_refuses(self):
  value=guest();value['readiness']=[{'stage':'preparation','target':{'app':'resolver','endpoint':'dns_endpoint'}}];mocks=self.run_guest(value);mocks['endpoint'].assert_called_once_with(value['readiness'][0]['target'])
  for rows in ({},[{'stage':'start','target':{'app':'resolver','endpoint':'dns_endpoint'}}],[{'stage':'preparation','target':{'external':'resolver'}}],[{'stage':'preparation','target':{'app':'resolver','endpoint':'dns_endpoint'},'source':'DO_NOT_ECHO'}]):
   bad=guest();bad['readiness']=rows
   with self.subTest(shape=type(rows).__name__),self.assertRaises(ComponentError):self.run_guest(bad)
 def test_collaborator_refusal_propagates_without_running_later_guest_components(self):
  value=guest();value['resources']={'memory_mib':512};stack,mocks=self.guards();sentinel=ComponentError('component.integer')
  mocks['resource'].side_effect=sentinel
  with stack,self.assertRaises(ComponentError)as caught:types.guest(value)
  self.assertIs(caught.exception,sentinel);mocks['interface'].assert_not_called();mocks['storage_layout'].assert_not_called()
 def test_interface_refusal_is_contextual_and_redacted_while_no_storage_or_policy_runs(self):
  value=guest();stack,mocks=self.guards();mocks['interface'].side_effect=ComponentError('component.type')
  with stack,self.assertRaises(ComponentError)as caught:types.guest(value)
  self.assertEqual(str(caught.exception),'component.type at interfaces.control');mocks['storage_layout'].assert_not_called();mocks['policy_binding'].assert_not_called()

if __name__=='__main__':unittest.main()
