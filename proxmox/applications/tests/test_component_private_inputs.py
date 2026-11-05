"""Mocked app units and synthetic retained-parser boundary integrations."""
import copy,hashlib,importlib.util,io,json,os
from pathlib import Path
import sys,unittest
from unittest.mock import patch
import yaml
F=Path(__file__).resolve().parents[3];sys.path.insert(0,str(F/'proxmox/applications'))
import bitwarden as legacy_bitwarden
import bitwarden_runtime as legacy_runtime
import winet as legacy_winet

def vault():
 values={'BW_DB_PROVIDER':'mysql','BW_DB_SERVER':'198.18.32.35','BW_DB_DATABASE':'vault','BW_DOMAIN':'vault.example.invalid','PUID':'1000','PGID':'1000','BW_DB_USERNAME':'fixture-user','BW_DB_PASSWORD':'fixture-value','BW_INSTALLATION_ID':'fixture-id','BW_INSTALLATION_KEY':'fixture-installation','globalSettings__identityServer__certificatePassword':'fixture-certificate'}
 raw=json.dumps(values).encode();runtime={'schema':'homelab-bitwarden-runtime-v2','public_origin':'https://vault.example.invalid','issuer':'http://localhost'}
 settings={'schema':'homelab-bitwarden-runtime-v2','bind_address':'198.18.30.35','database_server':'198.18.32.35','database_provider':'mysql','database_name':'vault','data_uid':1000,'data_gid':1000}
 app={'adapter':'bitwarden','lifecycle':'retained','settings':{'runtime':runtime,'settings':settings}}
 return app,raw,values

def telemetry():
 settings={'configuration_file':'/var/lib/example/options.json','inverter_address':'198.18.80.9','mqtt_server':'mqtt://broker.example.invalid:1883','mqtt_prefix':'fixture/telemetry'}
 values={'winet_host':settings['inverter_address'],'winet_user':'fixture-user','winet_pass':'fixture-value','mqtt_url':'mqtt://fixture-user:fixture-value@broker.example.invalid:1883','mqtt_prefix':settings['mqtt_prefix'],'poll_interval':30,'analytics':False,'ssl':True,'site_totals':False,'additional_winets':[]}
 return {'adapter':'winet','lifecycle':'retained','settings':settings},json.dumps(values).encode(),values

class PrivateInputTests(unittest.TestCase):
 def test_supplied_mqtt_and_winet_bytes_retain_the_existing_duplicate_json_refusal(self):
  app,raw,_=telemetry()
  cases=[({'adapter':'mqtt','lifecycle':'retained'},'probe',
          b'{"username":"fixture","password":"first","password":"second"}'),
         (app,'options',b'{"winet_pass":"ignored",'+raw[1:])]
  for selected,role,value in cases:
   with self.subTest(adapter=selected['adapter']),self.assertRaisesRegex(ValueError,'Duplicate JSON field'):
    self.builder.bind(selected,{role:value})
 def test_broker_probe_parser_preserves_only_the_selected_retained_account(self):
  value={'username':'synthetic-probe','password':'synthetic-value'}
  result=self.builder.bind({'adapter':'mqtt','lifecycle':'retained'},{'probe':json.dumps(value).encode()})
  self.assertEqual(json.loads(result['files'][0]['content']),value)
  self.assertEqual(result['files'][0]['path'],'mqtt-probe.json')
  self.assertEqual(result['files'][0]['mode'],'0600')
  for wrong in ({},{'username':'probe','password':'x','foreign':'x'},{'username':'line\nbreak','password':'x'}):
   with self.subTest(keys=list(wrong)),self.assertRaises(ValueError):
    self.builder.bind({'adapter':'mqtt','lifecycle':'retained'},{'probe':json.dumps(wrong).encode()})
  with self.assertRaises(ValueError):self.builder.bind({'adapter':'mqtt','lifecycle':'fresh'},{'probe':json.dumps(value).encode()})

 def setUp(self):
  import component_private_inputs
  self.bitwarden=legacy_bitwarden;self.runtime=legacy_runtime;self.winet=legacy_winet
  self.builder=component_private_inputs
 def test_bitwarden_app_unit_delegates_once_and_never_invents_timezone_or_files(self):
  app,raw,_=vault();selected={'OWNED':'unchanged$literal'}
  with patch.object(self.runtime,'environment_bytes',return_value=selected) as parser:
   result=self.builder.bind(app,{'runtime_environment':raw})
  parser.assert_called_once_with(raw,app['settings']['runtime'],app['settings']['settings'])
  self.assertEqual(result,{'files':[],'environment':selected});self.assertNotIn('TZ',result['environment'])
 def test_winet_app_unit_delegates_once_and_keeps_fixed_private_row(self):
  app,raw,_=telemetry()
  with patch.object(self.winet,'options_bytes',return_value={'fixture':'value$literal'}) as parser:
   result=self.builder.bind(app,{'options':raw})
  parser.assert_called_once_with(raw,app['settings']);row,=result['files'];self.assertEqual({k:v for k,v in row.items() if k!='content'},{'path':'winet-options.json','uid':0,'gid':0,'mode':'0600'});self.assertEqual(json.loads(row['content']),{'fixture':'value$literal'});self.assertEqual(result['environment'],{})
 def test_pega_copies_raw_key_bytes_without_decode_strip_or_generation(self):
  raw=b'\xff\x80opaque fixture\n';result=self.builder.bind({'adapter':'pegaprox','lifecycle':'retained'},{'database_key':raw});row,=result['files']
  self.assertIs(row['content'],raw);self.assertEqual(row,{'path':'pegaprox-db-key','uid':999,'gid':999,'mode':'0600','content':raw});self.assertEqual(result['environment'],{})
 def test_missing_foreign_or_oversized_role_values_fail_before_parser(self):
  app,_,_=vault()
  for values in ({},{'options':b'foreign'},{'runtime_environment':'text'},{'runtime_environment':b''},{'runtime_environment':b'x'*(1024*1024+1)}):
   with self.subTest(case=type(next(iter(values.values()),None)).__name__),patch.object(self.runtime,'environment_bytes') as parser:
    with self.assertRaises(ValueError):self.builder.bind(app,values)
    parser.assert_not_called()
 def test_unknown_adapter_and_fresh_owned_state_do_not_become_commissioning(self):
  for app,values in [({'adapter':'unknown'},{'options':b'{}'}),({'adapter':[]},{}),({'adapter':'pegaprox','lifecycle':'fresh'},{'database_key':b'fixture'}),(dict(vault()[0],lifecycle='fresh'),{'runtime_environment':vault()[1]})]:
   with self.subTest(adapter=repr(app['adapter'])),self.assertRaises(ValueError):self.builder.bind(app,values)
 def test_pure_builders_do_not_read_configured_paths(self):
  app,raw,_=vault();other,options,_=telemetry()
  with patch.object(self.runtime.files,'regular',side_effect=AssertionError('No read')),patch('pathlib.Path.open',side_effect=AssertionError('No read')):
   self.builder.bind(app,{'runtime_environment':raw});self.builder.bind(other,{'options':options})
 def test_retained_bitwarden_supplied_bytes_preserve_the_exact_expected_environment(self):
  app,raw,expected=vault()
  with patch.object(self.runtime.files,'regular',side_effect=AssertionError('No private read')):
   new=self.builder.bind(app,{'runtime_environment':raw})['environment']
  self.assertEqual(new,expected);self.assertNotIn('TZ',new)
 def test_bitwarden_runtime_v2_is_closed_and_retired_duplicate_authorities_refuse(self):
  for extra,value in [('environment_sha256','a'*64),('runtime_env_file','/var/lib/old'),('extra',True),('schema','homelab-bitwarden-runtime-v1')]:
   app,raw,_=vault();app['settings']['runtime'][extra]=value
   with self.subTest(extra=extra),self.assertRaises(ValueError):self.builder.bind(app,{'runtime_environment':raw})
  app,raw,_=vault()
  self.assertEqual(self.builder.bind(app,{'runtime_environment':raw+b' '})['environment'],vault()[2])
 def test_bitwarden_retains_database_numeric_owner_and_installation_value_relationships(self):
  changes={'BW_DB_PROVIDER':'postgres','BW_DB_SERVER':'198.18.32.99','BW_DB_DATABASE':'other','BW_DOMAIN':'other.example.invalid','PUID':'1001','PGID':'1001','BW_DB_USERNAME':'','BW_DB_PASSWORD':'','BW_INSTALLATION_ID':'','BW_INSTALLATION_KEY':'','globalSettings__identityServer__certificatePassword':''}
  for key,value in changes.items():
   app,_,values=vault();values[key]=value;raw=json.dumps(values).encode()
   with self.subTest(key=key),self.assertRaises(ValueError):self.builder.bind(app,{'runtime_environment':raw})
 def test_bitwarden_private_settings_predicate_is_shared_not_dropped(self):
  for key,value in [('data_uid',True),('data_gid',0),('image_id','unbound'),('schema','homelab-bitwarden-runtime-v1'),('database_name','invalid-name'),('database_server','8.8.8.8'),('bind_address','8.8.8.8')]:
   app,raw,_=vault();app['settings']['settings'][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):self.builder.bind(app,{'runtime_environment':raw})
 def test_runtime_json_strings_and_secret_controls_remain_strict(self):
  for invalid in ({},[],{'x':1},{'x':'line\nbreak'}):
   app,_,_=vault();raw=json.dumps(invalid).encode()
   with self.subTest(invalid=type(invalid).__name__),self.assertRaises(ValueError):self.builder.bind(app,{'runtime_environment':raw})
 def test_winet_supplied_options_preserve_the_complete_fixed_private_row(self):
  app,raw,options=telemetry()
  expected=[{'path':'winet-options.json','uid':0,'gid':0,'mode':'0600',
             'content':json.dumps(options,sort_keys=True)+'\n'}]
  self.assertEqual(self.builder.bind(app,{'options':raw}),{'files':expected,'environment':{}})
 def test_winet_encrypted_single_inverter_credentials_and_broker_constraints_remain(self):
  mutations={'winet_host':'198.18.80.10','ssl':False,'additional_winets':['another'],'winet_user':'','winet_pass':'line\nbreak','mqtt_url':'mqtt://broker.example.invalid:1884','mqtt_prefix':'other','poll_interval':True,'analytics':1,'site_totals':None,'custom_ca':'not-supported'}
  for key,value in mutations.items():
   app,_,values=telemetry();values[key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):self.builder.bind(app,{'options':json.dumps(values).encode()})
 def test_winet_selected_metadata_remains_independent_but_closed(self):
  for key,value in [('configuration_file','relative'),('inverter_address','127.0.0.1'),('mqtt_server','mqtt://user:pass@broker.example.invalid:1883'),('mqtt_prefix','bad wildcard#')]:
   app,raw,_=telemetry();app['settings'][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):self.builder.bind(app,{'options':raw})
 def test_pega_row_matches_existing_retained_target_admission_metadata(self):
  tasks=yaml.safe_load((F/'proxmox/applications/ansible/tasks/pegaprox-runtime.yml').read_text());conditions=next(t['ansible.builtin.assert']['that'] for t in tasks if 'ansible.builtin.assert'in t)
  row=self.builder.bind({'adapter':'pegaprox','lifecycle':'retained'},{'database_key':b'fixture key'})['files'][0]
  self.assertIn('pegaprox_runtime_key.stat.checksum == pegaprox_source_key.stat.checksum',conditions)
  self.assertIn('pegaprox_runtime_key.stat.uid == '+str(row['uid']),conditions);self.assertIn('pegaprox_runtime_key.stat.gid == '+str(row['gid']),conditions);self.assertIn("pegaprox_runtime_key.stat.mode == '"+row['mode']+"'",conditions)

if __name__=='__main__':unittest.main()
