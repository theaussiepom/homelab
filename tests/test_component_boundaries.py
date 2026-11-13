"""Boundary units mock resolver; one actual public stack source integration."""
import copy,importlib.util,json,os
from pathlib import Path
import subprocess,sys
from unittest.mock import patch
import pytest
F=Path(__file__).resolve().parents[1];sys.path[:0]=[str(F/'blueprints'),str(F/'proxmox/applications')]
spec=importlib.util.spec_from_file_location('component_boundary_proposal',F/'tools/check_boundaries.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
import component_plan

@pytest.fixture
def root(tmp_path):
 path=tmp_path.resolve();subprocess.run(['git','init','-q',str(path)],check=True)
 (path/'stack.json').write_text(json.dumps({'schema':'homelab-components-v1','kind':'library','guest_templates':{},'app_profiles':{}}))
 return path

def source(root,value):
 path=root/'site.example.yaml';path.write_text(json.dumps(value));return path

def library(root,**extra):
 value=json.loads((root/'stack.json').read_text());value.update(extra);(root/'stack.json').write_text(json.dumps(value))

def test_component_library_has_no_fake_flat_binding_manifest(root):
 report=b.check(root,'stack');assert report['status']=='passed' and report['findings']==[]
 assert report['targets_contacted'] is False and report['runtime_state_read'] is False

@pytest.mark.parametrize('field',['contexts','networks','guests','apps','values','required_site_bindings'])
def test_library_cannot_own_concrete_site_categories(root,field):
 library(root,**{field:{'site':'allocation'}})
 with pytest.raises(ValueError):b.check(root,'stack')

@pytest.mark.parametrize('extra',[{'identity':{'vmid':800}},{'storage':{'config':{'source':'/srv/private','target':'/app','kind':'directory','read_only':False,'required':True}}}])
def test_profile_placement_and_source_mounts_reach_central_closed_validator(root,extra):
 profile={'adapter':'unbound','display_name':'Unbound','interfaces':{},**extra};library(root,app_profiles={'unbound':profile})
 with pytest.raises(ValueError):b.check(root,'stack')

def test_real_library_template_validator_rejects_site_identity(root):
 library(root,guest_templates={'base':{'vmid':800}})
 with pytest.raises(ValueError):b.check(root,'stack')

def test_network_fragment_role_bindings_and_protocol_constants_remain_usable(root):
 row={'direction':'out','proto':'udp','source':{'interface':'source'},'destination':{'endpoint':'resolver'},'port':{'endpoint':'resolver'},'comment':'declared DNS'}
 library(root,policies={'network':{'dns':{'rules':[row]}}});assert b.check(root,'stack')['status']=='passed'
 for address in ('127.0.0.1/32','224.0.0.251/32','0.0.0.0/0','198.18.1.0/24','8.8.8.8/32'):
  changed=copy.deepcopy(row);changed['destination']=address;library(root,policies={'network':{'dns':{'rules':[changed]}}});assert b.check(root,'stack')['status']=='passed'
 changed=copy.deepcopy(row);changed['destination']='10.44.1.0/24';library(root,policies={'network':{'dns':{'rules':[changed]}}})
 assert b.check(root,'stack')['findings']==[{'path':'stack.json','line':1,'code':'concrete-network-policy'}]

def test_authentication_metadata_is_type_only_and_concrete_policy_is_consumer_owned(root):
 library(root,authentication_profiles={'oidc':{'type':'cloudbeaver-oidc','required':True}});assert b.check(root,'stack')['status']=='passed'
 library(root,authentication_profiles={'oidc':{'type':'cloudbeaver-oidc','required':True,'client_id':'synthetic-not-a-secret'}})
 with pytest.raises(ValueError):b.check(root,'stack')
 library(root,authentication_profiles={},policies={'authentication':{'selected':{'type':'cloudbeaver-oidc','provider':'site-provider'}}})
 assert b.check(root,'stack')['findings'][0]['code']=='public-site-policy-binding'

def test_generic_transport_and_headers_are_not_blanket_exempted_or_forbidden(root):
 library(root,policies={'transport':{'verified':{'type':'tls'}},'middlewares':{'headers':{'headers':{'contentTypeNosniff':True}}}})
 assert b.check(root,'stack')['status']=='passed'
 library(root,policies={'transport':{'verified':{'type':'tls','context':'site-context'}}})
 assert b.check(root,'stack')['findings'][0]['code']=='public-site-policy-binding'

@pytest.fixture
def example():return json.loads(Path(__file__).with_name('public-component-site-example.json').read_text())

def test_separate_synthetic_site_uses_confined_loader_and_shared_resolver(root,example):
 path=source(root,example)
 with patch.object(component_plan,'resolve') as resolver:
  assert b.check(root,'stack')['status']=='passed'
 resolver.assert_called_once_with(root,path,admit=False)

@pytest.mark.parametrize('kind',['network','mac','domain','alias'])
def test_public_example_rejects_actual_allocation_or_route_material(root,example,kind):
 value=copy.deepcopy(example)
 if kind=='network':
  network=next(iter(value['networks'].values()));network.update(cidr='10.44.20.0/24',gateway='10.44.20.1')
 elif kind=='mac':next(iter(next(iter(value['guests'].values()))['interfaces'].values()))['mac']='02:77:00:00:00:01'
 elif kind=='domain':value['domains']={'ui':'ui.company.internal'}
 else:value['host_aliases']={'database':{'hostname':'db.company_internal'}}
 source(root,value)
 with patch.object(component_plan,'resolve'):
  assert b.check(root,'stack')['status']=='failed'

@pytest.mark.parametrize('ref',['../outside.yaml','/tmp/outside.yaml'])
def test_source_definitions_do_not_escape_library_root(root,ref):
 library(root,app_profiles={'app':{'source':ref}})
 with pytest.raises(ValueError):b.check(root,'stack')

def test_ambiguous_or_invalid_component_source_uses_same_strict_reader(root,example):
 source(root,example);(root/'site.example.json').write_text('{}')
 with patch.object(component_plan,'resolve'),pytest.raises(ValueError):b.check(root,'stack')

def test_existing_private_material_target_and_offline_keygen_rules_are_unchanged(root):
 assert b.public_text('schema: '+b.CONSUMER_SCHEMA)==[]
 assert b.public_text(b.CONSUMER_PREFIX)==[(1,'private-repository-reference')]
 path=root/'script.py';path.write_text('import socket\n');assert b.check(root,'consumer')['status']=='failed';path.unlink()
 path=root/'job.yml';path.write_text('steps:\n  - run: ssh-keygen -lf key.pub\n');assert b.check(root,'consumer')['status']=='passed'
 path.write_text('steps:\n  - run: ssh example.invalid true\n');assert b.check(root,'consumer')['status']=='failed'
