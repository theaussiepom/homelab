"""Normal immutable image and existing protocol/private-role boundaries, no Docker."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE.parent)]
import component_runtime
import component_continuity
import component_private_material
import test_component_continuity as continuity_tests
from test_component_edges import descriptor,guest

IMAGE='ghcr.io/bitwarden/lite@sha256:94484fe9382df51ad755151ea360663e922e60a32385500454dd1f38045bf6a6'

class NormalImageTests(unittest.TestCase):
 def render(self,image):
  app=descriptor('bitwarden');app['software_selection']['images']['bitwarden']={'image':image}
  return component_runtime._bitwarden(app,guest('bitwarden'))['bitwarden']
 def test_selected_official_digest_is_literal_with_common_missing_policy_and_no_local_mapper(self):
  for image in(IMAGE,'ghcr.io/bitwarden/lite:declared@sha256:'+'a'*64):
   with self.subTest(image=image):
    value=self.render(image);self.assertEqual(value['image'],image);self.assertEqual(value['pull_policy'],'missing')
    self.assertEqual(value['environment'],{});self.assertNotIn('user',value);self.assertNotIn('command',value)
 def test_mutable_bare_foreign_malformed_and_archive_selections_refuse(self):
  for image in('ghcr.io/bitwarden/lite:latest','sha256:'+'a'*64,'foreign/lite@sha256:'+'a'*64,
                'ghcr.io/bitwarden/lite@sha256:'+'a'*63,'ghcr.io/bitwarden/lite@sha256:'+'A'*64,
                'ghcr.io/bitwarden/lite@sha256:'+'a'*64+'\n',None,1):
   with self.subTest(image=image),self.assertRaises(ValueError):self.render(image)
  app=descriptor('bitwarden');app['software_selection']['images']['bitwarden'].update(archive='/fixture/old.tar',archive_sha256='a'*64)
  with self.assertRaises(ValueError):component_runtime._bitwarden(app,guest('bitwarden'))
 def test_historical_v1_payload_material_remains_readable_by_v2_without_parsing_old_settings(self):
  fixture=continuity_tests.PrivateContinuityUnits();fixture.setUp();self.addCleanup(fixture.doCleanups)
  current=descriptor('bitwarden');current.update(id='selected',input_sources={'runtime_environment':{'type':'file','path':'/selected/unchanged.json'}})
  old=copy.deepcopy(current);old['settings']={'settings':{'schema':'homelab-bitwarden-runtime-v1','image_id':'sha256:'+'b'*64},
    'runtime':{'schema':'homelab-bitwarden-runtime-v1','runtime_env_file':'/historical/never-read.json','environment_sha256':'c'*64}}
  raw=b'opaque exact private environment bytes\n';previous=fixture.previous(old,{'runtime_environment':raw})
  before={p:(p.stat().st_ino,p.read_bytes())for p in fixture.root.rglob('*')if p.is_file()}
  proof=lambda value:component_continuity.document(current,component_private_material.project(current,{'runtime_environment':value}))
  with patch.object(component_continuity.component_generation,'component_success',return_value=True), \
       patch('bitwarden_runtime.environment_bytes',side_effect=AssertionError('Historical DTO is not active runtime input')):
   component_continuity.verify(fixture.attempt,current,proof(raw))
   with self.assertRaisesRegex(ValueError,'cannot rotate'):component_continuity.verify(fixture.attempt,current,proof(raw+b' '))
  self.assertEqual(before,{p:(p.stat().st_ino,p.read_bytes())for p in fixture.root.rglob('*')if p.is_file()})

class FixtureProtocolTests(unittest.TestCase):
 def fixture(self,owner='1000:1000'):
  spec=importlib.util.spec_from_file_location('normal_bw_protocol_fixture',HERE/'bitwarden_runtime_fixture.py')
  module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  calls=[];cleanup=[];documents=[]
  def docker(*argv,**kwargs):
   calls.append((list(argv),kwargs))
   if argv[0]=='compose'and'config'in argv:
    documents.append(json.loads(Path(argv[argv.index('-f')+1]).read_text()))
  def output(argv,**kwargs):
   self.assertEqual(argv[0],'docker')
   self.assertEqual(argv[-4:],['stat','-c','%u:%g','/etc/bitwarden']);self.assertEqual(kwargs,{'text':True,'timeout':15});return owner+'\n'
  with patch.object(module,'docker',side_effect=docker),patch.object(module.subprocess,'check_output',side_effect=output), \
       patch.object(module.subprocess,'run',side_effect=lambda *a,**k:cleanup.append((a,k))), \
       patch('subprocess.Popen',side_effect=AssertionError('No native command')),patch('socket.create_connection',side_effect=AssertionError('No target')), \
       patch.object(sys,'argv',['fixture']),contextlib.redirect_stdout(io.StringIO()):
   error=None
   try:module.main()
   except ValueError as exc:error=exc
  return module,calls,cleanup,documents,error
 def test_actual_fixture_uses_same_declared_image_and_preserves_protocol_limits_and_cleanup(self):
  module,calls,cleanup,documents,error=self.fixture();self.assertIsNone(error);self.assertEqual(module.IMAGE,IMAGE)
  doc,=documents;service=doc['services']['bitwarden'];self.assertEqual(service['image'],IMAGE);self.assertEqual(service['pull_policy'],'missing')
  self.assertEqual(doc['networks'],{'default':{'internal':True}});self.assertEqual(set(doc['volumes']),{'data','logs','database'})
  self.assertNotIn('ports',service);self.assertEqual(service['depends_on'],{'database':{'condition':'service_healthy'}})
  self.assertEqual(service['volumes'],['data:/etc/bitwarden','logs:/var/log/bitwarden'])
  commands=[argv for argv,_ in calls];compose=[c[c.index('-f')+2:]for c in commands if c[0]=='compose']
  self.assertEqual(compose,[['config','--quiet'],['up','-d','--pull','never'],['restart','bitwarden'],['up','-d','--pull','never','--no-deps','--force-recreate','bitwarden'],['down','--volumes','--remove-orphans','--timeout','10']])
  # Fixture-only offline cached-image flags are not the production start policy.
  clients=[c for c in commands if c[0]=='run'and c[-1]=='--inside'];self.assertEqual(len(clients),3)
  for c in [c for c in commands if c[0]=='run']:
   self.assertIn('--read-only',c);self.assertEqual(c[c.index('--cap-drop')+1],'ALL');self.assertEqual(c[c.index('--memory')+1],'128m');self.assertEqual(c[c.index('--pids-limit')+1],'32')
  seeds=[c for c in commands if c[0]=='run'and'-c'in c];self.assertEqual(len(seeds),3)
  for c in seeds:self.assertEqual(c[c.index('--network')+1],'none');self.assertEqual(c[c.index('--user')+1],'1000:1000')
  self.assertEqual(sum('SYNTHETIC_ATTACHMENT_OK'in c[-1]for c in seeds),2)
  self.assertEqual(len(cleanup),1);self.assertEqual(cleanup[0][0][0][:3],['docker','rm','-f']);self.assertEqual(cleanup[0][1]['timeout'],30)
 def test_actual_fixture_invalid_numeric_owner_refuses_before_seed_restart_and_still_cleans_up(self):
  _,calls,cleanup,_,error=self.fixture(owner='foreign:owner');self.assertIsInstance(error,ValueError)
  commands=[argv for argv,_ in calls];self.assertFalse(any(c[0]=='run'and'-c'in c for c in commands));self.assertFalse(any('restart'in c for c in commands))
  self.assertEqual(len(cleanup),1);self.assertEqual(commands[-1][-5:],['down','--volumes','--remove-orphans','--timeout','10'])

if __name__=='__main__':unittest.main()
