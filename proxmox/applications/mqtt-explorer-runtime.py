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

DATA = Path('/srv/homelab/data/mqtt-explorer')
CUSTODY = Path('/var/lib/homelab-mqtt-explorer')
RUNTIME = Path('/opt/homelab-app/runtime')
SERVICES = {'mqtt_explorer', 'explorer_gateway'}


def need(ok):
    if not ok:
        raise ValueError('MQTT Explorer managed lifecycle refused')


def read(path, uid=0):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == uid
             and stat.S_IMODE(info.st_mode) in (0o400, 0o600) and info.st_size <= 1024*1024)
        raw = stream.read(1024*1024+1)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        key = lambda item: tuple(getattr(item, field) for field in fields)
        need(len(raw) == info.st_size and key(info) == key(os.fstat(stream.fileno())) == key(path.lstat()))
    return raw


def owner_check(owner):
    need(isinstance(owner, dict) and set(owner) == {'node', 'vmid', 'hostname'}
         and type(owner['vmid']) is int and owner['vmid'] >= 100
         and all(isinstance(owner[k], str) and re.fullmatch('[A-Za-z0-9_.-]{1,128}', owner[k])
                 for k in ('node', 'hostname')))


def workspace(owner):
    need(os.geteuid() == 0)
    owner_check(owner)
    need(stat.S_ISDIR(DATA.parent.lstat().st_mode))
    CUSTODY.mkdir(mode=0o700, exist_ok=True)
    info = CUSTODY.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700)
    receipt = CUSTODY/'workspace.json'
    if receipt.exists() or receipt.is_symlink():
        need(json.loads(read(receipt)) == owner)
    else:
        need(not DATA.is_symlink() and (not DATA.exists() or (stat.S_ISDIR(DATA.lstat().st_mode)
             and DATA.lstat().st_uid == 0 and stat.S_IMODE(DATA.lstat().st_mode) == 0o700 and not any(DATA.iterdir()))))
        DATA.mkdir(mode=0o700, exist_ok=True)
        os.chown(DATA, 1001, 1001); os.chmod(DATA, 0o700)
        fd = os.open(receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write((json.dumps(owner, sort_keys=True)+'\n').encode()); stream.flush(); os.fsync(stream.fileno())
        fd = os.open(CUSTODY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    data_info = DATA.lstat()
    need(stat.S_ISDIR(data_info.st_mode) and data_info.st_uid == data_info.st_gid == 1001
         and stat.S_IMODE(data_info.st_mode) == 0o700)
    return {'workspace': 'owned'}


def docker(args):
    return subprocess.run(['docker', *args], text=True, capture_output=True, check=True, timeout=30).stdout


def health(config):
    need(os.geteuid() == 0)
    need(isinstance(config, dict) and config.get('data_path') == str(DATA)
         and set(config.get('images', {})) == SERVICES
         and set(config.get('runtime_sha256', {})) == {'explorer-traefik.json', 'explorer-routes.yml'})
    owner = json.loads(read(CUSTODY/'workspace.json')); owner_check(owner)
    info = DATA.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 1001 and stat.S_IMODE(info.st_mode) == 0o700)
    for name, expected in config['runtime_sha256'].items():
        need(isinstance(expected, str) and re.fullmatch('[0-9a-f]{64}', expected)
             and hashlib.sha256(read(RUNTIME/name, uid=65532)).hexdigest() == expected)
    rows = {}
    for name in sorted(SERVICES):
        ids = docker(['ps', '--all', '--quiet', '--no-trunc', '--filter', 'label=com.docker.compose.project=homelab-mqtt',
                      '--filter', 'label=com.docker.compose.service='+name]).split()
        need(len(ids) == 1 and re.fullmatch('[0-9a-f]{64}', ids[0]))
        objects = json.loads(docker(['inspect', ids[0]])); need(isinstance(objects, list) and len(objects) == 1)
        row = objects[0]; need(row['Id'] == ids[0])
        need(row['Config']['Labels'].get('com.docker.compose.project') == 'homelab-mqtt'
             and row['Config']['Labels'].get('com.docker.compose.service') == name
             and row['Config']['Image'] == config['images'][name]
             and row['State']['Running'] is True and row['State']['Health']['Status'] == 'healthy'
             and row['HostConfig']['ReadonlyRootfs'] is True
             and len(row['NetworkSettings']['Networks']) == 1
             and row['HostConfig']['NetworkMode'] not in ('host', 'bridge', 'default', 'none'))
        rows[name] = row
    app, gateway = rows['mqtt_explorer'], rows['explorer_gateway']
    data_mounts = [m for m in app['Mounts'] if m.get('Destination') == '/app/data'
                   or m.get('Destination', '').startswith('/app/data/')]
    need(app['Config']['User'] == '1001:1001' and gateway['Config']['User'] == '65532:65532'
         and not app['HostConfig']['PortBindings']
         and gateway['HostConfig']['PortBindings'] == {'4180/tcp': [{'HostIp': config['bind_address'], 'HostPort': '80'}]}
         and app['NetworkSettings']['Networks'].keys() == gateway['NetworkSettings']['Networks'].keys()
         and app['Config']['Cmd'] == ['node', '-e', "process.umask(0o077);for(const level of ['log','info','debug','dir','table','trace'])console[level]=()=>{};console.warn=()=>process.stderr.write('MQTT Explorer warning\\n');console.error=()=>process.stderr.write('MQTT Explorer error\\n');require('./dist/src/server.js')"]
         and len(data_mounts) == 1 and data_mounts[0].get('Source') == str(DATA)
         and data_mounts[0].get('Destination') == '/app/data'
         and data_mounts[0].get('Type') == 'bind' and data_mounts[0].get('RW') is True)
    env = app['Config'].get('Env', [])
    need('MQTT_EXPLORER_SKIP_AUTH=true' in env and not any(v.split('=', 1)[0].startswith((
        'OPENAI_', 'GEMINI_', 'LLM_', 'MQTT_AUTO_CONNECT_')) for v in env))
    return {'mqtt_explorer': 'passed', 'gateway_only_listener': True, 'sign_in': 'identity_provider_required'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('workspace', 'health'))
    parser.add_argument('--owner')
    parser.add_argument('--config', type=Path)
    args = parser.parse_args()
    try:
        result = workspace(json.loads(args.owner)) if args.action == 'workspace' else health(json.loads(read(args.config)))
    except Exception:
        raise SystemExit('MQTT Explorer deployment held; inspect privately.') from None
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
