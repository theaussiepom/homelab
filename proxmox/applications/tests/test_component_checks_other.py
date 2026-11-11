from fixture_network_names import modernize
"""App readiness units mock helpers; one real public metadata integration."""
import copy,importlib.util,json,os
from pathlib import Path
import sys,unittest
from unittest.mock import patch
F=Path(Path(__file__).resolve().parents[3]);sys.path[:0]=[str(F/'blueprints'),str(F/'proxmox/applications')]
spec=importlib.util.spec_from_file_location('readiness_proposal_handlers',F/'proxmox/applications/component_checks.py');h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
from component_errors import ComponentError
DATA=modernize(json.loads(Path(__file__).with_name('public-retained-other-health.json').read_text()))
def case(name):return modernize(DATA['cases'][name])
def rows(name,v=None):
 v=v or case(name);return h.HANDLERS[name](v['app'],v['compose_file'])

class BackendUnits(unittest.TestCase):
 def test_auth_and_zabbix_use_only_the_selected_backend_helper(self):
  for name,port,path in [('authentik',9000,'/-/health/ready/'),('zabbix',8080,'/')]:
   with self.subTest(name=name),patch.object(h,'_backend',return_value='http://198.18.44.8:'+str(port)) as backend:
    v=case(name);r=rows(name,v)[0];backend.assert_called_once_with(v['app'],port);self.assertEqual(r['argv'][-1],'http://198.18.44.8:'+str(port)+path)
 def test_bitwarden_preserves_identifier_metadata_separate_from_backend(self):
  for issuer in ('http://localhost','https://issuer.example.invalid'):
   with self.subTest(issuer=issuer),patch.object(h,'_backend',return_value='http://198.18.44.8:8080'):
    v=case('bitwarden');v['app']['settings']['runtime']['issuer']=issuer;r=rows('bitwarden',v)[0]
    self.assertEqual(r['argv'][-3:],['--issuer',issuer,'--backend'])
 def test_backend_fixed_listener_and_role_must_agree(self):
  v=case('authentik');v['app']['listeners']['web_listener']['publish']['port']=8443
  with self.assertRaises(ComponentError):rows('authentik',v)
  v=case('zabbix');v['app']['listeners']['web_listener']['publication_address']='198.18.44.9'
  with self.assertRaises(ComponentError):rows('zabbix',v)
 def test_proxy_probe_is_the_declared_local_ping_not_public_dashboard(self):
  self.assertEqual(rows('traefik')[0]['argv'][-1],'http://127.0.0.1:8082/ping')
  r=rows('traefik')[0];self.assertEqual(r['expect'],'OK');self.assertNotIn('dashboard',repr(r))
  self.assertEqual(set(case('traefik')['app']['listeners']),{'http_listener','https_listener'})

class GatewayUnits(unittest.TestCase):
 def test_cloud_uses_selected_runtime_leaf_and_canonical_signin_budget(self):
  v=case('cloudbeaver')
  with patch.object(h,'_runtime_file',return_value='/opt/homelab-app/runtime/other/cloudbeaver-public.json') as runtime,patch.object(h,'_public',return_value=('https://db.example.invalid','db.example.invalid','198.18.44.9',{})):
   r=rows('cloudbeaver',v)
  runtime.assert_called_once_with(v['app'],'cloudbeaver-public.json');self.assertEqual(r[0]['argv'][-1],'/opt/homelab-app/runtime/other/cloudbeaver-public.json')
  self.assertIn('1200',r[1]['argv']);self.assertIn('2250',r[1]['argv']);self.assertEqual(r[1]['expect'],'302');self.assertNotIn('--location',r[1]['argv'])
 def test_explorer_uses_installed_path_and_owned_runtime_leaf(self):
  with patch.object(h,'_runtime_file',return_value='/opt/homelab-app/runtime/other/mqtt-explorer-public.json'):
   r=rows('mqtt_explorer')[0]
  self.assertEqual(r['argv'][1],'/usr/local/bin/homelab-mqtt-explorer.py');self.assertEqual(r['argv'][-1],'/opt/homelab-app/runtime/other/mqtt-explorer-public.json')
 def test_public_https_target_and_origin_are_explicit_and_query_free(self):
  for mutation in ('origin','target'):
   with self.subTest(mutation=mutation):
    v=case('cloudbeaver')
    if mutation=='origin':v['app']['origin_url']+='?'
    else:v['app']['resolved_connections']['public']['target']['protocol']='http'
    with self.assertRaises(ComponentError):rows('cloudbeaver',v)
 def test_runtime_path_cannot_escape_selected_runtime_tree(self):
  for path in ('/tmp/elsewhere','/opt/homelab-app/runtime/../other','/opt/homelab-app/runtime/secret\n'):
   v=case('mqtt_explorer');v['app']['identity']['runtime_directory']=path
   with self.subTest(path=path),self.assertRaises(ComponentError):rows('mqtt_explorer',v)

class OwnedHelperUnits(unittest.TestCase):
 def test_music_uses_owned_compose_service_and_same_home_source_for_https(self):
  v=case('music_assistant')
  with patch.object(h,'_compose_exec',return_value=['OWNED','COMPOSE']) as compose:
   r=rows('music_assistant',v)
  self.assertEqual(r[0]['argv'],['OWNED','COMPOSE']);self.assertEqual(compose.call_args.args[2:5],('music_assistant','python3','-c'))
  source=v['app']['role_addresses']['web_interface'];self.assertEqual(r[1]['argv'][r[1]['argv'].index('--interface')+1],source)
  v['app']['resolved_connections']['public']['source_address']='198.18.44.7'
  with self.assertRaises(ComponentError):rows('music_assistant',v)
 def test_winet_uses_selected_project_service_and_bounded_docker_json(self):
  v=case('winet');v['app']['project_name']='other-project';v['app']['identity']['services']['winet']='other-winet';code=rows('winet',v)[0]['argv'][-1]
  self.assertIn('other-project-other-winet-1',code);self.assertIn("len(d)==1",code);self.assertIn("get('Status')=='healthy'",code)
  v['app']['project_name']='--option'
  with self.assertRaises(ComponentError):rows('winet',v)
 def test_pega_passes_only_declared_project_and_service_to_parameterized_helper(self):
  v=case('pegaprox');v['compose_file']='/opt/homelab-app/compose-other.yml'
  v['app']['identity']['services']['pegaprox']='other'
  self.assertEqual(rows('pegaprox',v)[0]['argv'][-4:],[
   '--compose-file','/opt/homelab-app/compose-other.yml','--service','other'])
  for path in ('/etc/config.yml','/opt/homelab-app/${ENV}.yml'):
   v['compose_file']=path
   with self.subTest(path=path),self.assertRaises(ValueError):rows('pegaprox',v)
 def test_mqtt_probe_selected_namespace_is_explicit_and_retained_defaults_stay_exact(self):
  self.assertEqual(rows('mqtt')[0]['argv'][-1],'mqtt-broker')
  v=case('mqtt');v['app']['identity']['runtime_directory']='/opt/homelab-app/runtime/other'
  self.assertEqual(rows('mqtt',v)[0]['argv'][-2:],[
   '--mqtt-probe','/opt/homelab-app/runtime/other/mqtt-probe.json'])
  v['app']['lifecycle']='fresh'
  with self.assertRaises(ComponentError):rows('mqtt',v)
 def test_zigbee_selected_data_uses_existing_option_without_fresh_commissioning(self):
  v=case('zigbee2mqtt');v['app']['identity']['runtime_id']='other-radio'
  v['app']['storage_paths']['data']['source']='/srv/other/zigbee2mqtt'
  self.assertEqual(rows('zigbee2mqtt',v)[0]['argv'][-2:],['--data','/srv/other/zigbee2mqtt'])
  v['app']['lifecycle']='fresh'
  with self.assertRaises(ValueError):rows('zigbee2mqtt',v)
  for path in ('/','relative','/srv/../outside','/srv/${ENV}'):
   v=case('zigbee2mqtt');v['app']['storage_paths']['data']['source']=path
   with self.subTest(path=path),self.assertRaises(ValueError):rows('zigbee2mqtt',v)

class PublicMetadataIntegration(unittest.TestCase):
 def test_all_eleven_retained_public_arrays_are_exact_thirteen_rows(self):
  self.assertTrue(DATA['source_is_public_example']);self.assertEqual(len(DATA['cases']),11);total=0
  for name,v in DATA['cases'].items():
   with self.subTest(adapter=name):
    actual=rows(name,v);self.assertEqual(actual,v['expected']);total+=len(actual)
  self.assertEqual(total,13)

if __name__=='__main__':unittest.main()
