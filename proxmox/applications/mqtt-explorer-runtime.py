#!/usr/bin/env python3
"""Own only the new Explorer workspace and verify its gateway-only listener."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

sys.path.insert(0, '/opt/homelab-app')
import mqtt_explorer_state as state

DATA = Path('/srv/homelab/data/mqtt-explorer')
CUSTODY = Path('/var/lib/homelab-mqtt-explorer')
RUNTIME = Path('/opt/homelab-app/runtime')
SERVICES = {'mqtt_explorer', 'explorer_gateway'}


def need(ok):
    if not ok:
        raise ValueError('MQTT Explorer managed lifecycle refused')


def read(path, uid=0):
    return state.read_path(path,uid=uid,modes=(0o400,0o600))[0]


def owner_check(owner):
    need(isinstance(owner, dict) and set(owner) == {'node', 'vmid', 'hostname'}
         and type(owner['vmid']) is int and owner['vmid'] >= 100
         and all(isinstance(owner[k], str) and re.fullmatch('[A-Za-z0-9_.-]{1,128}', owner[k])
                 for k in ('node', 'hostname')))


def created_directory(proof,path,info):
    need(isinstance(proof,dict) and set(proof)=={'path','device','inode','uid','gid','mode'}
         and proof['path']==str(path) and proof['mode']=='0700'
         and all(type(proof[key]) is int for key in ('device','inode','uid','gid'))
         and proof['device']>0 and proof['inode']>0 and proof['uid']==proof['gid']==1001
         and stat.S_ISDIR(info.st_mode) and state.owner(info)==(1001,1001)
         and stat.S_IMODE(info.st_mode)==0o700
         and (info.st_dev,info.st_ino)==(proof['device'],proof['inode']))


def workspace(owner, config=None, proof=None):
    need(os.geteuid() == 0)
    owner_check(owner)
    selected=state.public_context(config) if config is not None else state.context()
    path=Path(selected['data_path'])
    with state.directory(path.parent) as parent:
        info=state.info(parent,path.name)
        if proof is not None:
            need(info is not None)
            created_directory(proof,path,info)
    with state.directory(path.parent) as parent,state.custody(selected,create=True) as cfd:
        receipt=state.info(cfd,'workspace.json')
        if receipt is not None:
            need(proof is None)
            need(state.workspace_owner(cfd,selected)==owner)
        else:
            info=state.info(parent,path.name)
            if info is not None:
                if proof is not None:created_directory(proof,path,info)
                else:need(stat.S_ISDIR(info.st_mode) and state.owner(info)==(0,0) and stat.S_IMODE(info.st_mode)==0o700)
            with state.directory(path,create=True) as data:
                need(not os.listdir(data))
                if proof is not None:created_directory(proof,path,os.fstat(data))
                else:os.fchown(data,1001,1001);os.fchmod(data,0o700)
                state.stable_directory(data,path)
            state.save(cfd,'workspace.json',state.workspace_document(owner,selected))
        with state.directory(path) as data:
            state.private_directory(data,uid=1001)
    return {'workspace':'owned'}


def docker(args):
    return subprocess.run(['docker', *args], text=True, capture_output=True, check=True, timeout=30).stdout


def health(config):
    need(os.geteuid() == 0)
    selected=state.public_context(config)
    need(isinstance(config, dict) and config.get('data_path') == selected['data_path']
         and set(config.get('images', {})) == SERVICES
         and set(config.get('runtime_sha256', {})) == {'explorer-traefik.json', 'explorer-routes.yml'}
         and ('broker_address' in config) == ('broker_connection' in config))
    with state.custody(selected) as cfd:
        owner=state.workspace_owner(cfd,selected);owner_check(owner)
    with state.directory(selected['data_path']) as data:
        state.private_directory(data,uid=1001)
    for name, expected in config['runtime_sha256'].items():
        need(isinstance(expected, str) and re.fullmatch('[0-9a-f]{64}', expected)
             and hashlib.sha256(read(Path(selected['runtime_directory'])/name,uid=65532)).hexdigest() == expected)
    rows = {}
    for name in sorted(SERVICES):
        ids = docker(['ps', '--all', '--quiet', '--no-trunc', '--filter', 'label=com.docker.compose.project='+selected['project'],
                      '--filter', 'label=com.docker.compose.service='+selected['services'][name]]).split()
        need(len(ids) == 1 and re.fullmatch('[0-9a-f]{64}', ids[0]))
        objects = json.loads(docker(['inspect', ids[0]])); need(isinstance(objects, list) and len(objects) == 1)
        row = objects[0]; need(row['Id'] == ids[0])
        need(row['Config']['Labels'].get('com.docker.compose.project') == selected['project']
             and row['Config']['Labels'].get('com.docker.compose.service') == selected['services'][name]
             and row['Config']['Image'] == config['images'][name]
             and row['State']['Running'] is True and row['State']['Health']['Status'] == 'healthy'
             and row['HostConfig']['ReadonlyRootfs'] is True
             and len(row['NetworkSettings']['Networks']) == 1
             and row['HostConfig']['NetworkMode'] not in ('host', 'bridge', 'default', 'none'))
        rows[name] = row
    app, gateway = rows['mqtt_explorer'], rows['explorer_gateway']
    aliases = ([config['broker_connection']['hostname'] + ':' + config['broker_address']]
               if 'broker_address' in config else [])
    actual_aliases = app['HostConfig'].get('ExtraHosts')
    need((actual_aliases == aliases or not aliases and actual_aliases is None)
         and gateway['HostConfig'].get('ExtraHosts') in (None, []))
    data_mounts = [m for m in app['Mounts'] if m.get('Destination') == '/app/data'
                   or m.get('Destination', '').startswith('/app/data/')]
    need(app['Config']['User'] == '1001:1001' and gateway['Config']['User'] == '65532:65532'
         and not app['HostConfig']['PortBindings']
         and gateway['HostConfig']['PortBindings'] == {'4180/tcp': [{'HostIp': config['bind_address'], 'HostPort': '80'}]}
         and app['NetworkSettings']['Networks'].keys() == gateway['NetworkSettings']['Networks'].keys()
         and app['Config']['Cmd'] == ['node', '-e', "process.umask(0o077);for(const level of ['log','info','debug','dir','table','trace'])console[level]=()=>{};console.warn=()=>process.stderr.write('MQTT Explorer warning\\n');console.error=()=>process.stderr.write('MQTT Explorer error\\n');require('./dist/src/server.js')"]
         and len(data_mounts) == 1 and data_mounts[0].get('Source') == selected['data_path']
         and data_mounts[0].get('Destination') == '/app/data'
         and data_mounts[0].get('Type') == 'bind' and data_mounts[0].get('RW') is True)
    env = app['Config'].get('Env', [])
    need('MQTT_EXPLORER_SKIP_AUTH=true' in env and not any(v.split('=', 1)[0].startswith((
        'OPENAI_', 'GEMINI_', 'LLM_', 'MQTT_AUTO_CONNECT_')) for v in env))
    if 'profile_id' in config.get('broker_connection',{}):
        state.verify_existing(config)
    return {'mqtt_explorer': 'passed', 'gateway_only_listener': True, 'sign_in': 'identity_provider_required'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('workspace', 'health'))
    parser.add_argument('--owner')
    parser.add_argument('--created-directory')
    parser.add_argument('--config', type=Path)
    args = parser.parse_args()
    try:
        config=json.loads(read(args.config)) if args.config is not None else None
        need(args.created_directory is None or args.action=='workspace')
        proof=json.loads(args.created_directory) if args.created_directory is not None else None
        result = workspace(json.loads(args.owner),config,proof) if args.action == 'workspace' else health(config)
    except Exception:
        raise SystemExit('MQTT Explorer deployment held; inspect privately.') from None
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
