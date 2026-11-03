"""Known ownership regressions fail in one offline checker, without targets."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

MODULE=Path(__file__).resolve().parents[1]/'tools/check_boundaries.py'
spec=importlib.util.spec_from_file_location('ownership_boundary',MODULE)
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)


def repo(tmp_path):
    subprocess.run(['git','init','-q',str(tmp_path)],check=True)
    return tmp_path


def write(root,name,text):
    p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text);return p


def test_one_schema_occurrence_does_not_exempt_private_paths_on_same_line():
    prefix=b.CONSUMER_PREFIX
    assert b.public_text('schema: '+b.CONSUMER_SCHEMA+'\n')==[]
    assert b.public_text('schema: '+b.CONSUMER_SCHEMA+'.\n')==[]
    for value in [prefix,prefix.upper(),'https://github.com/owner/'+prefix,'../'+prefix+'/site.json',b.CONSUMER_SCHEMA+'-private']:
        assert b.public_text('schema: '+b.CONSUMER_SCHEMA+'; '+value)==[(1,'private-repository-reference')]
    assert b.public_text('/'+'Users/person/project')==[(1,'personal-checkout-path')]
    assert b.python_rules('if socket.gethostname() != configured: pass',consumer=False,fixture=False)==[]
    assert b.python_rules("if socket.gethostname() != 'host-fixture': pass",consumer=False,fixture=False)==[(1,'literal-host-identity-policy')]
    assert b.python_rules("if row.get('hostname') == 'host-fixture': pass",consumer=False,fixture=False)==[(1,'literal-host-identity-policy')]
    assert b.python_rules("if row.get('hostname') == 'deploy': pass",consumer=False,fixture=False)==[]
    assert b.python_rules('invalid ! syntax',consumer=True,fixture=True)==[]


def test_consumer_known_target_sinks_refuse_but_source_wrapper_and_fixtures_work(tmp_path):
    root=repo(tmp_path)
    write(root,'tools/check.py','import json, pathlib\nprint(json.dumps({"valid":True}))\n')
    write(root,'.github/workflows/ci.yml','steps:\n  - run: python3 tools/check.py\n')
    write(root,'tests/test_fixture.py','import socket\nsocket.gethostname()\n')
    write(root,'.work/protected-operator.py','import socket\n')
    write(root,'framework-source/ignored.py','import socket\n')
    report=b.check(root,'consumer')
    assert report['status']=='passed' and report['source_files']==3
    assert report['targets_contacted'] is False and report['runtime_state_read'] is False
    for source in ['import socket','from urllib.request import urlopen',"subprocess.run(['ssh','fixed-host'])",
                   "import subprocess\ncommand=['ssh','example.invalid','true']\nsubprocess.run(command)"]:
        write(root,'operational.py',source)
        assert b.check(root,'consumer')['status']=='failed'
    (root/'operational.py').unlink()
    write(root,'operational.sh','sudo docker ps\n')
    assert b.check(root,'consumer')['findings'][0]['code']=='consumer-target-workflow'
    (root/'operational.sh').unlink()
    write(root,'readme.md',b.CONSUMER_PREFIX)
    assert b.check(root,'framework')['status']=='failed'
    with pytest.raises(ValueError):b.check(root,'other')
    with pytest.raises(SyntaxError):b.python_rules('invalid ! syntax',consumer=True,fixture=False)


def test_stack_default_concrete_and_finite_shared_network_patterns(tmp_path):
    root=repo(tmp_path)
    bindings={'vmids.web':'integer','hostnames.web':'string','storage.web':'string','templates.web':'string','bridges.backend':'string',
              'vlans.backend':['integer','null'],'addresses.web':'string','prefixes.backend':'integer','mac.web':'string'}
    spec={'values':{},'required_site_bindings':bindings,'guests':{'web':{}}}
    profile={'config':{'guest':{'vmid':'${vmids.web}','hostname':'${hostnames.web}','storage_id':'${storage.web}',
             'template_file_id':'${templates.web}','interfaces':[{'bridge':'${bridges.backend}','vlan':'${vlans.backend}',
             'ipv4':'${addresses.web}/${prefixes.backend}','mac':'${mac.web}'}]}}}
    write(root,'stack.json',json.dumps(spec));path=write(root,'guests/web/profile.json',json.dumps(profile))
    assert b.check(root,'stack')['status']=='passed'
    for value in [True,'10.44.1.2/24','${addresses.web}/24','${addresses.web}/${unknown.prefix}','${addresses.web}/${vmids.web}']:
        changed=json.loads(json.dumps(profile));changed['config']['guest']['interfaces'][0]['ipv4']=value
        path.write_text(json.dumps(changed))
        assert b.check(root,'stack')['status']=='failed'
    changed=json.loads(json.dumps(profile));changed['config']['guest']['interfaces'][0].update(ipv4='dhcp',ipv4_endpoint='${addresses.web}/${prefixes.backend}')
    path.write_text(json.dumps(changed));assert b.check(root,'stack')['status']=='passed'
    path.write_text(json.dumps(profile));spec['values']['addresses.web']='10.44.1.2';write(root,'stack.json',json.dumps(spec))
    assert b.check(root,'stack')['findings'][0]['code']=='public-site-binding-default'
    del spec['required_site_bindings'];write(root,'stack.json',json.dumps(spec))
    assert b.check(root,'stack')['findings'][0]['code']=='declare-site-bindings'


def test_source_scope_symlinks_bounds_and_cli_are_closed(tmp_path,capsys):
    root=repo(tmp_path)
    path=write(root,'source.py','pass\n')
    assert b.main(['--root',str(root),'--mode','framework'])==0
    assert json.loads(capsys.readouterr().out)['status']=='passed'
    path.write_text('invalid ! syntax')
    assert b.main(['--root',str(root),'--mode','framework'])==1
    assert json.loads(capsys.readouterr().out)['code']=='invalid-source-boundary-input'
    path.write_text('x'*(4*1024**2+1))
    with pytest.raises(ValueError,match='Bound source'):b.source_files(root)
    path.unlink();path.symlink_to(MODULE)
    with pytest.raises(ValueError,match='symlinks'):b.source_files(root)
    path.unlink();write(root,'notes.bin','ignored')
    missing=write(root,'deleted.py','pass\n')
    subprocess.run(['git','-C',str(root),'add','deleted.py'],check=True)
    missing.unlink()  # Deletions remain in the index, but are not published content.
    assert b.source_files(root)==[]
    # Script entry uses the same closed parser/result schema.
    result=subprocess.run([sys.executable,str(MODULE),'--root',str(root),'--mode','consumer'],capture_output=True,text=True)
    assert result.returncode==0 and json.loads(result.stdout)['status']=='passed'


def test_stack_firewall_frontend_and_route_policy_bindings_are_explicit(tmp_path):
    root=repo(tmp_path)
    bindings={'vmids.web':'integer','hostnames.web':'string','storage.web':'string','templates.web':'string',
              'addresses.frontend':'string','domains.web':'string','networks.clients':'string-list'}
    spec={'values':{},'required_site_bindings':bindings,'guests':{'web':{}},'routes':{
          'web':{'host':'ui.${domains.web}','aliases':['other.example.invalid'],'target':{'url':'http://${addresses.frontend}:9000'}}}}
    profile={'config':{'guest':{'vmid':'${vmids.web}','hostname':'${hostnames.web}','storage_id':'${storage.web}',
             'template_file_id':'${templates.web}','rules':[{'source':'${addresses.frontend}/32','destination':'224.0.0.251/32'}]},
             'app':{'frontend_routing':{'address':'${addresses.frontend}','gateway':'127.0.0.1'}}},
             'stack':{'routing':{'middlewares':{'clients':{'ipAllowList':{'sourceRange':'${networks.clients}'}}}}}}
    spec_path=write(root,'stack.json',json.dumps(spec));profile_path=write(root,'guests/web/profile.json',json.dumps(profile))
    assert b.check(root,'stack')['status']=='passed'
    for value in ['10.55.1.2/32','fd55::/64','02:00:00:00:01:02']:
        changed=json.loads(json.dumps(profile));changed['config']['guest']['rules'][0]['source']=value;profile_path.write_text(json.dumps(changed))
        assert any(row['code']=='concrete-network-policy' for row in b.check(root,'stack')['findings'])
    for key in ('address','gateway','mac'):
        changed=json.loads(json.dumps(profile));changed['config']['app']['frontend_routing'][key]='10.55.1.2';profile_path.write_text(json.dumps(changed))
        assert b.check(root,'stack')['status']=='failed'
    changed=json.loads(json.dumps(profile));changed['stack']['routing']['middlewares']['clients']['ipAllowList']['sourceRange']=['10.55.1.0/24'];profile_path.write_text(json.dumps(changed))
    assert b.check(root,'stack')['status']=='failed'
    profile_path.write_text(json.dumps(profile))
    for value in ['ui.company.internal','ui.company.internal.']:
        changed=json.loads(json.dumps(spec));changed['routes']['web']['host']=value;spec_path.write_text(json.dumps(changed))
        assert b.check(root,'stack')['findings'][0]['code']=='concrete-route-host'
    changed=json.loads(json.dumps(spec));changed['routes']['web']['target']['url']='https://10.55.1.2:9443';spec_path.write_text(json.dumps(changed))
    assert b.check(root,'stack')['findings'][0]['code']=='concrete-route-backend'
    # Protocol constants and explicit synthetic examples remain usable in examples.
    for value in ('0.0.0.0/0','127.0.0.1/32','239.255.255.250/32','198.18.1.0/24','8.8.8.8/32','not-a-network'):
        changed=json.loads(json.dumps(profile));changed['config']['guest']['rules'][0]['source']=value;profile_path.write_text(json.dumps(changed));spec_path.write_text(json.dumps(spec))
        assert b.check(root,'stack')['status']=='passed'


def test_cli_malformed_shape_and_nonrepository_return_only_fixed_error(tmp_path,capsys):
    root=repo(tmp_path)
    write(root,'stack.json',json.dumps({'required_site_bindings':{'x':'string'},'values':{},'guests':{},'routes':{'bad':{'host':3}}}))
    assert b.main(['--mode','stack','--root',str(root)])==1
    assert json.loads(capsys.readouterr().out)['code']=='invalid-source-boundary-input'
    foreign=tmp_path/'outside';foreign.mkdir()
    with patch.object(b.subprocess,'check_output',side_effect=subprocess.CalledProcessError(128,['git'])):
        assert b.main(['--mode','framework','--root',str(foreign)])==1
    assert json.loads(capsys.readouterr().out)['code']=='invalid-source-boundary-input'


def test_git_quoted_unicode_and_newline_names_are_scanned_intact(tmp_path):
    root=repo(tmp_path)
    subprocess.run(['git','-C',str(root),'config','core.quotePath','true'],check=True)
    for name in ('é.md','line\nbreak.md'):
        path=write(root,name,b.CONSUMER_PREFIX)
        subprocess.run(['git','-C',str(root),'add','--',name],check=True)
        assert b.check(root,'framework')['findings']==[{'path':name,'line':1,'code':'private-repository-reference'}]
        path.unlink()


def test_consumer_yaml_target_steps_include_list_marker_without_matching_plain_items(tmp_path):
    root=repo(tmp_path)
    path=write(root,'.github/workflows/operations.yml','')
    for command in ('ssh example.invalid true','docker ps','tofu apply','sudo ansible-playbook playbook.yml'):
        for prefix in ('  - run: ','    run: ','    '):
            path.write_text('steps:\n'+prefix+command+'\n')
            assert b.check(root,'consumer')['findings']==[{'path':'.github/workflows/operations.yml','line':2,'code':'consumer-target-workflow'}]
    for line in ('  - docker','  - ssh','  - run: python3 tools/check.py'):
        path.write_text('steps:\n'+line+'\n');assert b.check(root,'consumer')['status']=='passed'
