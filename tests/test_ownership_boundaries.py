"""Known ownership regressions fail in one offline checker, without targets."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest
import yaml

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


def component_fixture(root):
    """Standalone reusable library matching the current synthetic site fixture."""
    site=json.loads((MODULE.resolve().parents[1]/'tests/public-component-site-example.json').read_text())
    spec={'schema':'homelab-components-v1','kind':'library',
          'guest_templates':{'base':{
              'resources':{'cpu_cores':1,'memory_mib':512,'root_gib':8,'os_reserve_mib':128},
              'startup':{'started':True,'start_on_boot':True,'boot_order':30},
              'security':{'unprivileged':True,'protection':True,'nesting':True,'keyctl':False}}},
          'app_profiles':{'unbound':{'source':'apps/unbound.yaml'}}}
    profile={'schema':'homelab-components-v1','kind':'app-profile',
             'adapter':'unbound','display_name':'Unbound',
             'interfaces':{'service_interface':{'required':True,'accepts':['guest-loopback']},
                           'private_interface':{'required':True,'accepts':['app-network']}},
             'listeners':{'dns_listener':{'service':'unbound','namespace':'app-network',
                 'interface':'private_interface','bind':'wildcard','protocol':'udp','port':53,
                 'publish':{'scope':'guest-loopback','port':5335}}},
             'endpoints':{'dns_endpoint':{'listener':'dns_listener','protocol':'udp','via':'service_interface'}}}
    write(root,'stack.json',json.dumps(spec))
    path=write(root,'apps/unbound.yaml',yaml.safe_dump(profile))
    return spec,site,profile,path


def component_scan(root,spec,site):
    write(root,'stack.json',json.dumps(spec))
    write(root,'site.example.yaml',yaml.safe_dump(site))
    return b.check(root,'stack')


def test_stack_default_concrete_and_finite_shared_network_patterns(tmp_path):
    root=repo(tmp_path)
    spec,site,profile,path=component_fixture(root)
    # Two independent guests share one named network, with explicit distinct NICs.
    site['guests']['second']=json.loads(json.dumps(site['guests']['resolver']))
    other=site['guests']['second'];other['identity']={'vmid':611,'hostname':'example-second'}
    other['interfaces']['primary']['address']['value']='198.18.20.11'
    other['interfaces']['primary']['mac']='02:00:00:20:00:11'
    site['apps']['second']=json.loads(json.dumps(site['apps']['recursive_dns']))
    site['apps']['second']['guest']='second'
    assert component_scan(root,spec,site)['status']=='passed'
    # Former interpolation bags have no authority in the typed component source.
    for value in [True,'10.44.1.2/24','${addresses.web}/24',
                  '${addresses.web}/${unknown.prefix}','${addresses.web}/${vmids.web}']:
        changed=json.loads(json.dumps(site))
        changed['guests']['resolver']['interfaces']['primary']['address']['value']=value
        with pytest.raises(ValueError):component_scan(root,spec,changed)
    dhcp=json.loads(json.dumps(site))
    nic=dhcp['guests']['resolver']['interfaces']['primary']
    nic.update(address={'mode':'dhcp','endpoint':'198.18.20.10'},default_route=False)
    assert component_scan(root,spec,dhcp)['status']=='passed'
    # A valid consumer-owned real allocation still cannot become a public example.
    changed=json.loads(json.dumps(site))
    changed['networks']['services'].update(cidr='10.44.1.0/24',gateway='10.44.1.1')
    for index,guest in enumerate(changed['guests'].values(),2):
        guest['interfaces']['primary']['address']['value']='10.44.1.'+str(index)
    assert any(row['code']=='concrete-site-allocation' for row in component_scan(root,spec,changed)['findings'])
    for field in ('values','required_site_bindings','guests'):
        changed=json.loads(json.dumps(spec));changed[field]={'site':'allocation'}
        with pytest.raises(ValueError):component_scan(root,changed,site)
    assert component_scan(root,spec,site)['status']=='passed'


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
    spec,site,profile,path=component_fixture(root)
    row={'direction':'out','proto':'udp','source':{'interface':'source'},
         'destination':{'endpoint':'resolver'},'port':{'endpoint':'resolver'},'comment':'Declared DNS'}
    spec['policies']={'network':{'dns':{'rules':[row]}}}
    site['networks']['frontend']={'context':'lab','cidr':'198.18.21.0/24',
        'gateway':'198.18.21.1','bridge':'example-frontend','vlan':221}
    guest=site['guests']['resolver']
    guest['interfaces']['frontend']={'network':'frontend','slot':1,'mac':'02:00:00:21:00:10',
        'address':{'mode':'static','value':'198.18.21.10'},'default_route':False,'ipv6':'manual'}
    guest['source_policy_route']={'interface':'frontend'}
    guest['network_policy'].append({'policy':'dns','interfaces':{'source':'frontend'},
                                   'endpoints':{'resolver':{'external':'resolver'}}})
    assert component_scan(root,spec,site)['status']=='passed'
    # Role/endpoint policy remains explicit; a missing binding is not inferred.
    changed=json.loads(json.dumps(site));del changed['guests']['resolver']['network_policy'][-1]['endpoints']
    with pytest.raises(ValueError):component_scan(root,spec,changed)
    for value in ['10.55.1.2/32','fd55::/64','02:00:00:00:01:02']:
        changed=json.loads(json.dumps(spec));changed['policies']['network']['dns']['rules'][0]['source']=value
        selected=json.loads(json.dumps(site));del selected['guests']['resolver']['network_policy'][-1]['interfaces']
        if ':' in value:
            with pytest.raises(ValueError):component_scan(root,changed,selected)
        else:
            assert any(r['code']=='concrete-network-policy' for r in component_scan(root,changed,selected)['findings'])
    # Route policy uses a named physical interface; raw address/gateway/MAC bags refuse.
    for key in ('address','gateway','mac'):
        changed=json.loads(json.dumps(site));changed['guests']['resolver']['source_policy_route'][key]='10.55.1.2'
        with pytest.raises(ValueError):component_scan(root,spec,changed)
    changed=json.loads(json.dumps(spec));changed['policies']['middlewares']={
        'clients':{'type':'ip-allow-list','ranges':['10.55.1.0/24']}}
    assert any(r['code']=='concrete-network-policy' for r in component_scan(root,changed,site)['findings'])
    for value in ['ui.company.internal','ui.company.internal.']:
        changed=json.loads(json.dumps(site));changed['domains']={'web':value}
        if value.endswith('.'):
            with pytest.raises(ValueError):component_scan(root,spec,changed)
        else:
            assert any(r['code']=='concrete-route-host' for r in component_scan(root,spec,changed)['findings'])
    changed=json.loads(json.dumps(site));changed['external_endpoints']['backend']={
        'protocol':'https','address':'10.55.1.2','port':9443}
    assert any(r['code']=='concrete-site-allocation' for r in component_scan(root,spec,changed)['findings'])
    for value in ('0.0.0.0/0','127.0.0.1/32','239.255.255.250/32','198.18.1.0/24','8.8.8.8/32'):
        changed=json.loads(json.dumps(spec));changed['policies']['network']['dns']['rules'][0]['destination']=value
        assert component_scan(root,changed,site)['status']=='passed'
    changed=json.loads(json.dumps(spec));changed['policies']['network']['dns']['rules'][0]['source']='not-a-network'
    with pytest.raises(ValueError):component_scan(root,changed,site)


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
    for name in ('é.md','line\nbreak.md','report\r.md','report\r\n.md'):
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
    for line in ('  - run: ssh','  - run: docker|cat','  - run: tofu>plan.txt','  - run: ssh;true'):
        path.write_text('steps:\n'+line+'\n')
        assert b.check(root,'consumer')['findings']==[{'path':'.github/workflows/operations.yml','line':2,'code':'consumer-target-workflow'}]
    for line in ('  - docker','  - ssh','  - run: python3 tools/check.py',
                 '  - run: ssh-keygen -lf key.pub','    run: ssh-keygen -lf key.pub','    ssh-keygen -lf key.pub'):
        path.write_text('steps:\n'+line+'\n');assert b.check(root,'consumer')['status']=='passed'


def test_yaml_profiles_share_the_source_reader_and_keep_boundary_guards(tmp_path):
    root=repo(tmp_path)
    spec,site,profile,path=component_fixture(root)
    # Whole-definition YAML references exercise the same strict production reader.
    with patch.object(b.authored_config,'parse',wraps=b.authored_config.parse) as reader:
        assert component_scan(root,spec,site)['status']=='passed'
    assert any(call.args[1]=='.yaml' and b'kind: app-profile' in call.args[0]
               for call in reader.call_args_list)
    changed=json.loads(json.dumps(profile));changed['identity']={'vmid':123}
    path.write_text(yaml.safe_dump(changed))
    with pytest.raises(ValueError):component_scan(root,spec,site)
    path.write_text('adapter: unbound\nadapter: unbound\n')
    with pytest.raises(ValueError):component_scan(root,spec,site)
    path.write_text(yaml.safe_dump(profile))
    write(root,'apps/unbound.json','{}')
    with pytest.raises(ValueError):component_scan(root,spec,site)
