"""Actual selected caller/payload integration with finite component/native fakes."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

import yaml

FRAMEWORK=Path(Path(__file__).resolve().parents[3]).resolve()
sys.path.insert(0,str(FRAMEWORK/'proxmox/applications'))
import application_contract
import component_ansible
import component_monitoring_inputs
import component_payload
import component_prepare
import monitoring_inputs
import monitoring_templates
from private_io import encoded,read_json,write_new


class MonitoringServerCallerTests(unittest.TestCase):
 def setUp(self):
  continuity=patch.object(component_prepare.component_continuity,'verify')
  continuity.start();self.addCleanup(continuity.stop)
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
  self.inputs=self.root/'inputs';self.inputs.mkdir(mode=0o700)
  self.state=self.root/'state';self.state.mkdir(mode=0o700)
  self.runtime=self.inputs/'component-runtime.json';self.parent=self.inputs/'applications'
  self.app_id='observer';self.phase='metrics';self.identity='a'*64
  self.app={'id':self.app_id,'guest':'example_guest','adapter':'zabbix','lifecycle':'retained',
   'identity':{'phase':self.phase,'runtime_id':'observer','project':'metrics','services':{
    'zabbix_server':'metrics-server','zabbix_web':'metrics-web'},'networks':{'default':'default'},
    'runtime_directory':'/opt/homelab-app/runtime/observer'},
   'project_name':'metrics-project','project_file':'compose-metrics.yml',
   'settings':{'database':{'name':'example_metrics','user':'example_metrics','host':'198.18.31.23','port':5432},
    'database_credential':{'type':'monitoring-owned','server':self.app_id}},
   'input_sources':{},'storage_paths':{},'software_selection':{'images':{
    role:{'image':'example.invalid/'+role+'@sha256:'+'b'*64}for role in('zabbix_server','zabbix_web')}}}
  self.app['runtime_files']={'app':self.app_id,'guest':'example_guest','directory':self.app['identity']['runtime_directory'],
   'files':sorted(application_contract.runtime_files(self.app)),'directory_mounts':[]}
  self.base={'name':self.app['project_name'],'services':{
   'metrics-server':{'image':self.app['software_selection']['images']['zabbix_server']['image'],'ports':['198.18.25.36:10051:10051']},
   'metrics-web':{'image':self.app['software_selection']['images']['zabbix_web']['image'],
    'ports':['198.18.30.36:8080:8080','127.0.0.1:8081:8080']},
   'peer-service':{'image':'example.invalid/peer@sha256:'+'c'*64}},'networks':{'default':{}}}
  self.cfg={'schema':'homelab-component-guest-v1','site':{'node':'synthetic-node','api_endpoint':'https://198.18.25.10:8006/'},
   'guest':{'vmid':91003,'hostname':'metrics-host','memory_mib':2048,'interfaces':[
    {'ipv4':'198.18.25.36/24','mac':'02:00:00:00:00:36'},{'ipv4':'manual','mac':'02:00:00:00:00:37'}]},
   'paths':{'state_root':str(self.state),'ca_file':str(self.root/'public-ca.pem')},
   'deployment':{'contract':3,'capabilities':['linux','docker'],'input_directory':str(self.inputs),
    'runtime_file':str(self.runtime),'input_identity':self.identity,
    'applications':{self.phase:{'id':self.app_id,'adapter':'zabbix','lifecycle':'retained',
      'runtime_id':'observer','project':self.app['project_name'],'compose_file':self.app['project_file'],
      'services':['metrics-server','metrics-web']}},'payload_phases':{self.phase:self.app_id,'zabbix-agent':'agent'},
    'phases':['preparation',self.phase,'zabbix-agent']},
   'app':{'hostname':'metrics-host','address':'198.18.25.36','memory_mib':2048,
    'health_checks':[{'name':'UI readiness','argv':['true']}],
    'service_health_checks':{self.phase:[{'name':'UI readiness','argv':['true']}]},
    'monitoring':{'hostname':'synthetic-node-91003','psk_identity':'synthetic-node-91003',
     'server_active':'198.18.25.36:10051','profiles':['linux','docker'],'server_vmid':91003,
     'server_hostname':'metrics-host','credential_file':str(self.parent/'agent/monitoring-agent.json'),
     'server_file':str(self.parent/self.app_id/'monitoring-server.json'),
     'members':[{'guest':'example_guest','vmid':91003,'guest_hostname':'metrics-host',
      'hostname':'synthetic-node-91003','psk_identity':'synthetic-node-91003','profiles':['linux','docker']}],
     'proxmox':{'hostname':'synthetic-node','endpoint':'https://198.18.25.10:8006/','ca_file':str(self.root/'public-ca.pem')},
     'postgresql_address':'198.18.31.23'}}}
  self.monitoring={'database-password':b'synthetic-password',
   'proxmox-ca.pem':b'-----BEGIN CERTIFICATE-----\nsynthetic-public-fixture\n-----END CERTIFICATE-----\n',
   'monitoring-server.json':encoded({'admin_password':'synthetic-admin','members':[{'psk':'d'*64}],
      'proxmox':{'token_id':'synthetic@pve!read','token_secret':'synthetic-token'}})}
  self.save_runtime();self.save(self.inputs/self.app['project_file'],self.base)
  self.save(self.inputs/'component-projects.json',{self.app['project_name']:{'file':self.app['project_file'],
   'applications':{self.app_id:['metrics-server','metrics-web'],'peer-app':['peer-service']}}})
 def save(self,path,value):
  raw=encoded(value)
  if path.exists():path.write_bytes(raw)
  else:write_new(path,raw)
  return raw
 def save_runtime(self):self.save(self.runtime,{'schema':'homelab-component-runtime-v1','applications':{self.app_id:self.app}})
 def prepare(self,*,values=None):
  supplied=self.monitoring if values is None else values
  with (patch.object(component_prepare.component_monitoring_inputs,'prepare',return_value=copy.deepcopy(supplied))as owned,
       patch.object(monitoring_templates,'prepared',side_effect=lambda name:{'selected_template':name})as template,
       patch.object(monitoring_inputs,'provider',side_effect=AssertionError('No credential/provider read')),
       patch.object(component_prepare.managed_credentials,'credential',side_effect=AssertionError('No account read'))):
   result=component_prepare.prepare(self.cfg,self.app_id,{},attempt=object())
  return result,owned,template
 def test_actual_prepare_materializes_exact_root_owned_files_templates_and_loopback_initial_compose(self):
  before=copy.deepcopy(self.base);selected,owned,templates=self.prepare();proof=selected.check()
  self.assertEqual(proof['app'],self.app_id);self.assertEqual(proof['identity'],self.identity)
  owned.assert_called_once_with(self.cfg,app=self.app)
  self.assertEqual([call.args[0]for call in templates.call_args_list],list(monitoring_templates.monitoring.VERSIONS['templates']))
  server=read_json(selected.directory/'monitoring-server.json',private=True)
  self.assertEqual(server['owner'],{'node':'synthetic-node','vmid':91003,'hostname':'metrics-host'})
  self.assertEqual(server['admin_password'],'synthetic-admin');self.assertEqual(server['members'],[{'psk':'d'*64}])
  self.assertEqual(server['templates'],[{'selected_template':name}for name in monitoring_templates.monitoring.VERSIONS['templates']])
  self.assertEqual((selected.directory/'database-password').read_bytes(),self.monitoring['database-password'])
  self.assertEqual((selected.directory/'proxmox-ca.pem').read_bytes(),self.monitoring['proxmox-ca.pem'])
  rows=read_json(selected.directory/'runtime-files.json',private=True)
  self.assertEqual({row['source']for row in rows},{'database-password','proxmox-ca.pem'})
  self.assertTrue(all((row['uid'],row['gid'],row['mode'])==(1997,1995,'0400')and'content'not in row for row in rows))
  self.assertEqual({row['destination']for row in rows},{self.app['identity']['runtime_directory']+'/'+name for name in ('database-password','proxmox-ca.pem')})
  initial=read_json(selected.directory/'initial-compose.yml',private=True)
  expected=copy.deepcopy(self.base);expected['services']['metrics-web']['ports']=['127.0.0.1:8081:8080']
  self.assertEqual(initial,expected);self.assertEqual(read_json(self.inputs/self.app['project_file'],private=True),before)
  self.assertFalse((self.state/'monitoring-credentials').exists())
 def test_actual_variables_bind_payload_owner_configuration_initial_copy_and_selected_services(self):
  selected,_,_=self.prepare();before=copy.deepcopy(self.cfg)
  variables=component_ansible.variables(self.cfg,self.phase,payload=selected,previously_owned=True)
  self.assertEqual(variables['monitoring_server_owner'],{'node':'synthetic-node','vmid':91003,'hostname':'metrics-host'})
  self.assertEqual(variables['monitoring_server_configuration_file'],str(selected.directory/'monitoring-server.json'))
  self.assertEqual(variables['component_initial_compose_source'],str(selected.directory/'initial-compose.yml'))
  self.assertEqual(variables['component_compose_source'],str(self.inputs/self.app['project_file']))
  self.assertEqual(variables['monitoring_compose_source'],variables['component_compose_source'])
  self.assertEqual(variables['monitoring_compose_file'],'/opt/homelab-app/compose-metrics.yml')
  self.assertEqual(variables['monitoring_services'],['metrics-server','metrics-web'])
  self.assertEqual(variables['component_preflight']['peers'],['peer-service'])
  self.assertEqual(variables['component_application'],self.app)
  self.assertEqual(variables['component_runtime_directory'],{'directory':self.app['identity']['runtime_directory'],'lifecycle':'retained','previously_owned':True})
  self.assertEqual(variables['network_ready_interfaces'],['eth0']);self.assertEqual(self.cfg,before)
 def test_fresh_and_retained_flags_are_explicit_without_inventing_a_receipt_decision(self):
  for lifecycle in ('fresh','retained'):
   with self.subTest(lifecycle=lifecycle),tempfile.TemporaryDirectory(dir=self.root)as temporary:
    # Distinct immutable inputs for each source identity, no payload replacement.
    self.inputs=Path(temporary).resolve();self.inputs.chmod(0o700);self.runtime=self.inputs/'component-runtime.json';self.parent=self.inputs/'applications'
    self.cfg['deployment'].update(input_directory=str(self.inputs),runtime_file=str(self.runtime))
    self.cfg['app']['monitoring']['server_file']=str(self.parent/self.app_id/'monitoring-server.json')
    self.app['lifecycle']=lifecycle;self.cfg['deployment']['applications'][self.phase]['lifecycle']=lifecycle
    self.save_runtime();self.save(self.inputs/self.app['project_file'],self.base)
    self.save(self.inputs/'component-projects.json',{self.app['project_name']:{'file':self.app['project_file'],'applications':{self.app_id:['metrics-server','metrics-web']}}})
    selected,_,_=self.prepare()
    for owned in (False,True):
     result=component_ansible.variables(self.cfg,self.phase,payload=selected,previously_owned=owned)
     self.assertIs(result['component_preflight']['previously_owned'],owned);self.assertEqual(result['component_preflight']['lifecycle'],lifecycle)
     self.assertEqual(result['component_fresh_directories'],{'previously_owned':owned,'directories':[]})
     self.assertNotIn('monitoring_first_install',result)
 def test_foreign_server_payload_location_refuses_before_monitoring_materialization(self):
  self.cfg['app']['monitoring']['server_file']=str(self.parent/'peer/monitoring-server.json')
  with patch.object(component_prepare.component_monitoring_inputs,'prepare')as owned,self.assertRaisesRegex(ValueError,'exact selected app payload'):
   component_prepare.prepare(self.cfg,self.app_id,{},attempt=object())
  owned.assert_not_called();self.assertFalse((self.parent/self.app_id).exists())
 def test_root_owned_return_contract_cannot_be_missing_extra_or_replaced_by_scalar_secret(self):
  for kind in ('missing','extra','scalar'):
   values=copy.deepcopy(self.monitoring)
   if kind=='missing':values.pop('database-password')
   elif kind=='extra':values['peer-secret']=b'foreign'
   with self.subTest(case=kind),patch.object(component_prepare.component_monitoring_inputs,'prepare',return_value=values),patch.object(component_prepare.component_input_secrets,'selected',return_value={'database_password':b'foreign'}if kind=='scalar'else{}),self.assertRaisesRegex(ValueError,'root-owned monitoring'):
    component_prepare.prepare(self.cfg,self.app_id,{},attempt=object())
   self.assertFalse((self.parent/self.app_id).exists())
 def test_nonroot_owned_zabbix_selection_cannot_mint_or_reuse_root_records(self):
  self.app['settings']['database_credential']={'type':'monitoring-owned','server':'peer'};self.save_runtime()
  with patch.object(monitoring_inputs,'provider',side_effect=AssertionError('No provider read')),patch.object(monitoring_inputs,'credential',side_effect=AssertionError('No credential creation')),self.assertRaisesRegex(ValueError,'root-owned monitoring'):
   component_prepare.prepare(self.cfg,self.app_id,{},attempt=object())
 def test_peer_private_env_and_missing_initial_loopback_refuse_before_payload_publication(self):
  for kind in ('peer-env','missing-loopback'):
   base=copy.deepcopy(self.base)
   if kind=='peer-env':base['services']['peer-service']['env_file']='/never-read-peer'
   else:base['services']['metrics-web']['ports']=['198.18.30.36:8080:8080']
   self.save(self.inputs/self.app['project_file'],base)
   with self.subTest(case=kind),self.assertRaises(ValueError):self.prepare()
   self.assertFalse((self.parent/self.app_id).exists())
 def test_foreign_payload_id_and_same_id_foreign_runtime_descriptor_are_rejected(self):
  selected,_,_=self.prepare();payload={path.name:path.read_bytes()for path in selected.directory.iterdir()if path.name!=component_payload.MANIFEST}
  foreign=component_payload.prepare(self.parent,self.identity,'peer',payload)
  with self.assertRaisesRegex(ValueError,'selected app payload'):component_ansible.variables(self.cfg,self.phase,payload=foreign)
  alternate=self.root/'alternate';alternate.mkdir(mode=0o700);other=copy.deepcopy(payload);descriptor=json.loads(other['application.json']);descriptor['project_name']='foreign-project';other['application.json']=encoded(descriptor)
  changed=component_payload.prepare(alternate,self.identity,self.app_id,other)
  with self.assertRaisesRegex(ValueError,'exact selected runtime'):component_ansible.variables(self.cfg,self.phase,payload=changed)
 def test_project_service_or_file_mismatch_is_not_a_monitoring_publication_bypass(self):
  selected,_,_=self.prepare()
  for kind in ('service','file'):
   projects={self.app['project_name']:{'file':self.app['project_file'],'applications':{self.app_id:['metrics-server','metrics-web']}}}
   if kind=='service':projects[self.app['project_name']]['applications'][self.app_id]=['peer-service']
   else:projects[self.app['project_name']]['file']='foreign.yml'
   self.save(self.inputs/'component-projects.json',projects)
   with self.subTest(case=kind),self.assertRaisesRegex(ValueError,'selected services'):component_ansible.variables(self.cfg,self.phase,payload=selected)
 def test_payload_tampering_is_rejected_by_the_real_bound_proof_before_variables(self):
  selected,_,_=self.prepare();path=selected.directory/'monitoring-server.json';path.write_bytes(b'{}\n')
  with self.assertRaisesRegex(ValueError,'input bytes changed'):component_ansible.variables(self.cfg,self.phase,payload=selected)


class MonitoringTaskOrderTests(unittest.TestCase):
 ROOT=FRAMEWORK/'proxmox/applications/ansible'
 def tasks(self,name):return yaml.safe_load((self.ROOT/'tasks'/name).read_text())
 def one(self,tasks,predicate):
  selected=[(index,row)for index,row in enumerate(tasks)if predicate(row)];self.assertEqual(len(selected),1);return selected[0]
 def test_existing_owner_guard_precedes_all_copy_start_and_loopback_selection(self):
  rows=self.tasks('component-compose.yml')
  guard,row=self.one(rows,lambda r:r.get('ansible.builtin.include_tasks')=='component-monitoring-ready.yml');self.assertEqual(row['when'],"component_application.adapter == 'zabbix'")
  full,ordinary=self.one(rows,lambda r:r.get('ansible.builtin.copy',{}).get('src')=='{{ component_compose_source }}')
  initial,restricted=self.one(rows,lambda r:r.get('ansible.builtin.copy',{}).get('src')=='{{ component_initial_compose_source }}')
  start,_=self.one(rows,lambda r:r.get('register')=='component_start')
  self.assertLess(guard,min(full,initial,start));self.assertEqual(ordinary['when'],"component_application.adapter != 'zabbix' or not monitoring_first_install | default(false)")
  self.assertEqual(restricted['when'],"component_application.adapter == 'zabbix' and monitoring_first_install")
  self.assertTrue(ordinary['no_log']and restricted['no_log'])
 def test_readonly_receipt_identity_gate_drives_first_install_not_lifecycle_guess(self):
  rows=self.tasks('component-monitoring-ready.yml')
  inspect,statrow=self.one(rows,lambda r:r.get('register')=='monitoring_server_receipt')
  self.assertEqual(statrow['ansible.builtin.stat'],{'path':'/var/lib/homelab-monitoring/server.json','follow':False})
  checks=[row['ansible.builtin.assert']['that']for row in rows if'ansible.builtin.assert'in row]
  self.assertEqual(len(checks),2);self.assertIn("monitoring_server_receipt.stat.nlink == 1",' '.join(checks[0]));self.assertIn("monitoring_server_receipt.stat.uid == 0",' '.join(checks[0]));self.assertIn("monitoring_server_receipt.stat.mode == '0600'",' '.join(checks[0]));self.assertIn('not monitoring_server_receipt.stat.islnk',' '.join(checks[0]))
  owner,row=self.one(rows,lambda r:r.get('ansible.builtin.assert',{}).get('that')=='(monitoring_owned_server.content | b64decode | from_json) == monitoring_server_owner')
  self.assertEqual(row['when'],'monitoring_server_receipt.stat.exists')
  selection,fact=self.one(rows,lambda r:'monitoring_first_install'in r.get('ansible.builtin.set_fact',{}))
  self.assertLess(inspect,owner);self.assertLess(owner,selection);self.assertEqual(fact['ansible.builtin.set_fact']['monitoring_first_install'],'{{ not monitoring_server_receipt.stat.exists }}')
  self.assertNotIn('lifecycle',json.dumps(rows));self.assertFalse(any('ignore_errors'in row for row in rows))
 def test_initial_service_start_is_scoped_and_configurator_precedes_listener_publication(self):
  compose=self.tasks('component-compose.yml');start,startrow=self.one(compose,lambda r:r.get('register')=='component_start')
  configure,row=self.one(compose,lambda r:r.get('ansible.builtin.include_tasks')=='monitoring-server.yml')
  self.assertLess(start,configure);self.assertEqual(row['when'],"component_application.adapter == 'zabbix'")
  argv=startrow['ansible.builtin.command']['argv'];self.assertIn("'--no-deps'",argv);self.assertIn("'--remove-orphans=false'",argv);self.assertTrue(argv.endswith('+ component_services }}'));self.assertTrue(startrow['no_log'])
  server=self.tasks('monitoring-server.yml')
  native,task=self.one(server,lambda r:'guest-local API'in r.get('name',''))
  self.assertEqual(task['ansible.builtin.command']['argv'],['python3','-I','-S','-B','/var/lib/homelab-monitoring/configure.py','--input','/var/lib/homelab-monitoring/configure.json']);self.assertTrue(task['no_log'])
  publish,pub=self.one(server,lambda r:r.get('ansible.builtin.copy',{}).get('src','').startswith('{{ monitoring_compose_source'))
  listener,up=self.one(server,lambda r:r.get('name')=='Start the configured browser listener')
  self.assertLess(native,publish);self.assertLess(publish,listener);self.assertEqual(pub['when'],up['when'],'monitoring_first_install | default(false)')
  self.assertEqual(pub['when'],'monitoring_first_install | default(false)');self.assertTrue(pub['no_log']and up['no_log']);self.assertIn("['--no-deps'] + monitoring_services",up['ansible.builtin.command']['argv'])
  self.assertFalse(any('ignore_errors'in row or row.get('failed_when')is False for row in server))
 def test_reconcile_checks_health_only_after_monitoring_configure_and_separate_storage_owner(self):
  rows=yaml.safe_load((self.ROOT/'component-reconcile.yml').read_text())[0]['tasks']
  reconcile,row=self.one(rows,lambda r:r.get('ansible.builtin.include_tasks')=='tasks/component-compose.yml')
  health,check=self.one(rows,lambda r:r.get('register')=='component_health');self.assertLess(reconcile,health);self.assertTrue(check['no_log']);self.assertEqual(check['failed_when'],"component_health.rc != 0 or (item.expect | default('')) not in component_health.stdout")
  _,storage=self.one(rows,lambda r:r.get('ansible.builtin.include_tasks')=='tasks/monitoring-storage.yml')
  self.assertEqual(storage['when'],"component_application.adapter == 'postgresql' and app.monitoring.storage_password_file is defined")

if __name__=='__main__':unittest.main()
