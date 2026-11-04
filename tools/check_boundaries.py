#!/usr/bin/env python3
"""Finite, offline ownership checks for framework, composition and consumers.

These rules catch known boundary regressions. They do not prove absence of
secrets, arbitrary target execution, or every form of site-specific policy.
"""
import argparse
import ast
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "blueprints"))
import authored_config
from urllib.parse import urlsplit

CONSUMER_SCHEMA = 'homelab-site-v3'
CONSUMER_PREFIX = CONSUMER_SCHEMA.rsplit('-v', 1)[0]
SOURCE_SUFFIXES = {'.py','.md','.json','.yml','.yaml','.sh','.service','.timer','.txt'}
TARGET_IMPORTS = {'fcntl','socket','paramiko','fabric','requests','http.client','urllib.request','subprocess'}
TARGET_COMMANDS = {'ssh','scp','rsync','docker','pct','pvesh','tofu','terraform','ansible-playbook'}
ROLE_HOSTS = {'deploy'}  # Existing bootstrap role identity, not a site hostname.


def source_files(root):
    names = [os.fsdecode(name) for name in subprocess.check_output(['git','-C',str(root),'ls-files','-z','--cached','--others','--exclude-standard'],stderr=subprocess.PIPE).split(b'\0') if name]
    result=[]
    for name in sorted(set(names)):
        path=Path(name)
        if path.parts[0] in {'.git','.work','framework-source','stack-source'} or path.suffix not in SOURCE_SUFFIXES:
            continue
        target=root/path
        if target.is_symlink() or any(parent.is_symlink() for parent in target.parents if parent != root):
            raise ValueError('Source files cannot be symlinks')
        if target.is_file():
            if target.stat().st_size>4*1024**2:raise ValueError('Bound source text files')
            result.append((name,target.read_text()))
    return result


def test_source(name):
    path=Path(name)
    return 'tests' in path.parts or path.name.startswith('test_') or path.name.endswith('_fixture.py')


def public_text(text):
    findings=[]
    token=re.compile(re.escape(CONSUMER_PREFIX)+r'[A-Za-z0-9_.-]*',re.IGNORECASE)
    for number,line in enumerate(text.splitlines(),1):
        if any(match.group(0).rstrip('.')!=CONSUMER_SCHEMA for match in token.finditer(line)):
            findings.append((number,'private-repository-reference'))
        if re.search(r'/Users/[A-Za-z0-9_.-]+/',line):
            findings.append((number,'personal-checkout-path'))
    return findings


def python_rules(text, *, consumer, fixture):
    if fixture:return []
    tree=ast.parse(text);findings=[]
    for node in ast.walk(tree):
        if consumer and isinstance(node,(ast.Import,ast.ImportFrom)):
            modules=[a.name for a in node.names] if isinstance(node,ast.Import) else [node.module or '']
            if any(module in TARGET_IMPORTS for module in modules):findings.append((node.lineno,'consumer-target-library'))
        if isinstance(node,ast.Compare) and not consumer:
            values=[node.left,*node.comparators]
            host=any(isinstance(v,ast.Call) and (isinstance(v.func,ast.Attribute) and
                     (v.func.attr=='gethostname' or v.func.attr=='get' and v.args and isinstance(v.args[0],ast.Constant) and v.args[0].value=='hostname')) for v in values)
            if host and any(isinstance(v,ast.Constant) and isinstance(v.value,str) and v.value not in ROLE_HOSTS for v in values):
                findings.append((node.lineno,'literal-host-identity-policy'))
        if consumer and isinstance(node,ast.Call):
            strings=[v.value for arg in [*node.args,*[k.value for k in node.keywords]] for v in ast.walk(arg)
                     if isinstance(v,ast.Constant) and isinstance(v.value,str)]
            if any(Path(v).name in TARGET_COMMANDS for v in strings):findings.append((node.lineno,'consumer-target-command'))
    return findings


def concrete_network(value):
    if not isinstance(value,str):return False
    if re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',value):return True
    try:network=ipaddress.ip_network(value,strict=False)
    except ValueError:return False
    address=network.network_address
    examples=map(ipaddress.ip_network,('192.0.2.0/24','198.51.100.0/24','203.0.113.0/24','198.18.0.0/15','2001:db8::/32'))
    if any(network.version==example.version and network.subnet_of(example) for example in examples):return False
    return network.prefixlen>0 and address.is_private and not (address.is_multicast or address.is_loopback or address.is_unspecified)


def _example_host(value):
    return isinstance(value,str) and any(value==suffix or value.endswith('.'+suffix)
        for suffix in ('invalid','example','test','localhost','example.com','example.net','example.org'))


def _network_values(value):
    if isinstance(value,dict):
        for child in value.values():yield from _network_values(child)
    elif isinstance(value,list):
        for child in value:yield from _network_values(child)
    elif isinstance(value,str):
        yield value
        if '://' in value:
            hostname=urlsplit(value).hostname
            if hostname is not None:yield hostname


def stack_allocations(root, files=None):
    """Library definitions cannot own allocations; public sites stay synthetic.

    This uses the central confined loader and component validators. It never
    reads a configured credential path, lowers a packet or contacts a target.
    """
    from types import SimpleNamespace
    import component_sources as sources
    import component_types as types
    import component_monitoring
    import component_auth
    import component_plan
    library,pins=sources.library(root)
    for collection,validate in (('guest_templates',types.template),('app_profiles',types.profile),
            ('software',types.software),('runtime_profiles',types.runtime),
            ('health_profiles',types.health),('monitoring_profiles',component_monitoring.profile)):
        for value in library[collection].values():validate(value)
    # Validate generic authentication requirements through the same binder,
    # with no selected apps, site policy or concrete provider/credential bindings.
    component_auth.authentication(SimpleNamespace(library=library,policy={'authentication':{}},apps={}),{})
    for value in library['policies']['network'].values():types.network_policy(value)
    findings=[]
    if library['policies']['authentication'] or any(
            set(row)&{'context','server_name'} for row in library['policies']['transport'].values()):
        findings.append(('stack.json',1,'public-site-policy-binding'))
    if any(concrete_network(value) for value in _network_values(library)):
        findings.append(('stack.json',1,'concrete-network-policy'))
    # Component schema confines definitions and rejects identity/placement fields
    # in the reusable library. Authored example sites are separate consumers.
    for name,text in (source_files(root) if files is None else files):
        if test_source(name) or Path(name).suffix not in {'.json','.yaml','.yml'}:continue
        document=authored_config.parse(text.encode(),Path(name).suffix)
        if not isinstance(document,dict) or document.get('schema')!=sources.SCHEMA or document.get('kind')!='site':continue
        source=root/name
        site,_=sources.site(source)
        # Full source resolution is offline and validates all named bindings,
        # including external references. Source admission is deliberately off.
        component_plan.resolve(root,source,admit=False)
        allocated=[]
        for row in site['networks'].values():allocated.extend(row.get(k) for k in ('cidr','gateway'))
        for row in site['external_endpoints'].values():allocated.append(row.get('address'))
        for guest in site['guests'].values():
            for nic in guest['interfaces'].values():
                allocated.append(nic['address'].get('value'))
                # Existing synthetic examples use only this explicit local MAC
                # prefix. The library never receives a concrete MAC exemption.
                mac=nic['mac']
                if not isinstance(mac,str) or not mac.lower().startswith('02:00:00:'):
                    findings.append((name,1,'concrete-site-allocation'))
        if any(concrete_network(value) for value in allocated):findings.append((name,1,'concrete-site-allocation'))
        if any(not _example_host(value) for value in site['domains'].values()) or any(
                not _example_host(row['hostname']) for row in site['host_aliases'].values()):
            findings.append((name,1,'concrete-route-host'))
        if any(concrete_network(value) for value in _network_values(site['policies'])):
            findings.append((name,1,'concrete-network-policy'))
    return findings

def check(root, mode):
    if mode not in {'framework','stack','consumer'}:raise ValueError('Use a declared ownership mode')
    root=root.resolve();findings=[];files=source_files(root)
    for name,text in files:
        if mode!='consumer':
            findings.extend({'path':name,'line':line,'code':code} for line,code in public_text(text))
        if name.endswith('.py'):
            findings.extend({'path':name,'line':line,'code':code} for line,code in python_rules(text,consumer=mode=='consumer',fixture=test_source(name)))
        if mode=='consumer' and name.endswith(('.yml','.yaml','.sh')):
            for line,value in enumerate(text.splitlines(),1):
                if re.match(r'^\s*(?:-\s+run:\s*|run:\s*)?(?:sudo\s+)?(?:ssh|scp|rsync|docker|pct|pvesh|tofu|terraform|ansible-playbook)(?=$|[\s;&|<>])',value):
                    findings.append({'path':name,'line':line,'code':'consumer-target-workflow'})
    if mode=='stack':findings.extend({'path':path,'line':line,'code':code} for path,line,code in stack_allocations(root,files))
    return {'status':'failed' if findings else 'passed','mode':mode,'source_files':len(files),
            'findings':findings,'targets_contacted':False,'runtime_state_read':False}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--mode',required=True,choices=('framework','stack','consumer'));parser.add_argument('--root',required=True,type=Path)
    args=parser.parse_args(argv)
    try:result=check(args.root,args.mode)
    except (OSError,ValueError,SyntaxError,KeyError,TypeError,AttributeError,subprocess.CalledProcessError):result={'status':'failed','code':'invalid-source-boundary-input','targets_contacted':False,'runtime_state_read':False}
    print(json.dumps(result,sort_keys=True));return 0 if result['status']=='passed' else 1

if __name__=='__main__':raise SystemExit(main())
