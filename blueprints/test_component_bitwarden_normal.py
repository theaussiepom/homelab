"""Public real compiler→canonical receiver→normal Bitwarden private-byte boundary."""
import copy,json
from pathlib import Path
import sys,tempfile,unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve()
while not (ROOT/'blueprints').is_dir():ROOT=ROOT.parent
sys.path[:0]=[str(ROOT/'blueprints'),str(ROOT/'proxmox/applications')]
import compile as compiler
import component_guest,component_private_inputs,component_packet
from test_component_explorer_latefiles import source_fixture,role,storage,listener

IMAGE='ghcr.io/bitwarden/lite@sha256:94484fe9382df51ad755151ea360663e922e60a32385500454dd1f38045bf6a6'

def selection():
 library,site=source_fixture()
 library['software']['vault']={'images':{'bitwarden':'vault'}}
 library['runtime_profiles']['vault']={'containers':{'bitwarden':{'memory_mib':1536,'pids_limit':256,'cpu_limit':1}}}
 library['app_profiles']['vault']={'adapter':'bitwarden','display_name':'Vault',
  'interfaces':{'web':role('guest-interface'),'database':role('guest-interface'),'private':role('app-network')},
  'listeners':{'web':listener('bitwarden','private',8080,namespace='app-network',publish={'scope':'guest-interface','interface':'web','port':8080})},
  'endpoints':{'web':{'listener':'web','protocol':'http','via':'web'}},
  'connections':{'database':{'type':'mariadb','required':True}},
  'storage':{'data':storage('/etc/bitwarden'),'logs':storage('/var/log/bitwarden')},
  'secrets':{'runtime_environment':{'required':True}},'software':['vault'],'runtime':['vault'],
  'health':{'ready':{'type':'adapter','check':'readiness'}}}
 site['secret_sources']['vault_environment']={'type':'file','path':'/never-read/vault-environment.json'}
 site['domains'].update(vault='vault.example.invalid',issuer='localhost')
 site['external_endpoints']['database']={'protocol':'tcp','address':'198.18.32.24','port':3306}
 site['guests']['resolver']['compose_projects']['vault']={'name':'owned-vault-project','file':'compose-vault.yml'}
 site['apps']['vault']={'profile':'vault','guest':'resolver','lifecycle':'retained',
  'identity':{'phase':'vault','runtime_id':'owned-vault','project':'vault','services':{'bitwarden':'owned-vault'},'networks':{'default':'owned-vault-network'}},
  'interfaces':{'web':{'interface':'backend'},'database':{'interface':'backend'},'private':{'scope':'app-network','network':'default'}},
  'storage':{key:{'root_path':'data','subpath':'vault/'+key}for key in('data','logs')},
  'secrets':{'runtime_environment':'vault_environment'},'origin':{'exposure':'vault'},
  'properties':{'issuer':{'protocol':'http','domain':'issuer'},'database_name':'owned_vault','data_uid':1000,'data_gid':1000}}
 site['connections']['vault_database']={'consumer':{'app':'vault','connection':'database'},'target':{'external':'database'},'source_interface':'database'}
 site['exposures']['vault']={'type':'http','target':{'app':'vault','endpoint':'web'},'domain':'vault','ingress':{'app':'ingress','endpoint':'https'},'tls':'public'}
 site['policies']['network']['selected_external']['rules'].append({'direction':'out','proto':'tcp','destination':{'endpoint':'database'},'port':{'endpoint':'database'},'comment':'Selected database'})
 site['guests']['resolver']['network_policy'][0]['endpoints']['database']={'external':'database'}
 return library,site

class NormalBitwardenCompilerTests(unittest.TestCase):
 def setUp(self):
  temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve();self.stack=self.root/'library';self.stack.mkdir()
  images={name:{'repository':'example/'+name,'tag':None,'digest':'sha256:'+'a'*64}for name in('broker','browser','gateway')}
  images['vault']={'repository':'ghcr.io/bitwarden/lite','tag':None,'digest':IMAGE.split('@')[1]}
  (self.stack/'images.json').write_text(json.dumps(images));self.source=self.root/'site.json'
 def packet(self,change=None):
  library,site=selection()
  if change:change(site)
  (self.stack/'stack.json').write_text(json.dumps(library));self.source.write_text(json.dumps(site))
  plan=compiler.resolve_plan(self.stack,self.source,admit=False);packet=component_packet.lower_plan(plan,inputs=self.root/'inputs')['resolver']
  packet=json.loads(json.dumps(packet,sort_keys=True));cfg,_=component_guest.packet(packet,self.root/'inputs')
  return cfg,packet,json.loads(packet['files']['component-runtime.json'])['applications']['vault']
 def test_actual_canonical_packet_preserves_normal_source_role_image_data_and_private_environment(self):
  with patch('subprocess.run',side_effect=AssertionError('No process')),patch('socket.create_connection',side_effect=AssertionError('No target')):
   cfg,packet,app=self.packet()
  self.assertEqual(app['settings']['runtime'],{'schema':'homelab-bitwarden-runtime-v2','public_origin':'https://vault.example.invalid','issuer':'http://localhost'})
  self.assertEqual(app['input_sources']['runtime_environment']['path'],'/never-read/vault-environment.json');self.assertNotIn('image_id',app['settings']['settings'])
  document=json.loads(packet['files'][app['project_file']]);service=document['services']['owned-vault']
  self.assertEqual(service['image'],IMAGE);self.assertEqual(service['pull_policy'],'missing');self.assertEqual(service['ports'],['198.18.21.10:8080:8080'])
  self.assertEqual([r['source']for r in service['volumes']],['/srv/example/apps/vault/data','/srv/example/apps/vault/logs'])
  values={'BW_DB_PROVIDER':'mysql','BW_DB_SERVER':'198.18.32.24','BW_DB_DATABASE':'owned_vault','BW_DOMAIN':'vault.example.invalid','PUID':'1000','PGID':'1000',
   **{key:'synthetic-only'for key in('BW_DB_USERNAME','BW_DB_PASSWORD','BW_INSTALLATION_ID','BW_INSTALLATION_KEY','globalSettings__identityServer__certificatePassword')}}
  raw=json.dumps(values).encode()
  with patch.object(Path,'open',side_effect=AssertionError('No private read')),patch('os.open',side_effect=AssertionError('No private FD')):
   self.assertEqual(component_private_inputs.bind(app,{'runtime_environment':raw}),{'files':[],'environment':values})
  self.assertEqual(cfg['deployment']['payload_phases']['vault'],'vault')
 def test_retired_properties_missing_file_role_bad_owner_and_fresh_commissioning_refuse_real_compiler(self):
  changes=[lambda s:s['apps']['vault']['properties'].update(image_id='sha256:'+'a'*64),lambda s:s['apps']['vault']['properties'].update(runtime_env_sha256='a'*64),
   lambda s:s['apps']['vault']['properties'].update(data_uid=True),lambda s:s['apps']['vault']['properties'].update(database_name='invalid;name'),
   lambda s:s['apps']['vault']['secrets'].clear(),lambda s:s['secret_sources']['vault_environment'].update(type='environment',name='FORBIDDEN'),
   lambda s:s['apps']['vault'].update(lifecycle='fresh')]
  for i,change in enumerate(changes):
   with self.subTest(case=i),self.assertRaises(ValueError):self.packet(change)

if __name__=='__main__':unittest.main()
