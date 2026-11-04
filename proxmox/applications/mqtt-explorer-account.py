#!/usr/bin/env python3
"""Add only the declared Explorer account; preserve retained broker identities."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import sys

sys.path.insert(0, '/opt/homelab-app')
import mqtt_explorer_state as state

CONFIG = Path('/srv/homelab/data/mqtt/config')
CUSTODY = Path('/var/lib/homelab-mqtt-explorer')
HEALTH = Path('/opt/homelab-app/automation-health.py')
DATA = Path('/srv/homelab/data/mqtt-explorer')


def need(ok):
    if not ok:
        raise ValueError('Dedicated Explorer account refused')


def fingerprint(secret, owner, purpose):
    return state.fingerprint(secret,owner,purpose)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_uid, info.st_gid, info.st_mode, info.st_nlink)


def attributes(path):
    path=Path(path)
    with state.directory(path.parent) as directory:
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        try:
            before=os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink==1)
            result={name:os.getxattr(fd,name) for name in os.listxattr(fd)}
            need(identity(before)==identity(os.fstat(fd))==identity(state.info(directory,path.name)))
            return result
        finally:
            os.close(fd)


def directory_identity(path=CONFIG):
    with state.directory(path) as fd:
        info=os.fstat(fd)
        return info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode


def read(path, private=False):
    return state.read_path(path,uid=0 if private else None,modes=(0o600,) if private else None)


def save_new(path, value):
    path=Path(path)
    with state.directory(path.parent) as fd:
        state.save(fd,path.name,value)


def sync(path):
    with state.directory(path) as fd:
        os.fsync(fd)


def docker(args, input=None):
    return subprocess.run(['docker', *args], input=input, text=True, capture_output=True,
                          check=True, timeout=30).stdout


def broker(image, *, runtime=None):
    selected=state.broker_context(runtime)
    ids = docker(['ps', '--all', '--quiet', '--no-trunc', '--filter', 'label=com.docker.compose.project='+selected['project'],
                  '--filter', 'label=com.docker.compose.service='+selected['service']]).split()
    need(len(ids) == 1 and re.fullmatch('[0-9a-f]{64}', ids[0]))
    rows = json.loads(docker(['inspect', ids[0]])); need(isinstance(rows, list) and len(rows) == 1)
    row = rows[0]
    need(row['Id'] == ids[0] and row['State']['Running'] is True and row['Config']['Image'] == image
         and row['Config']['Labels'].get('com.docker.compose.project') == selected['project']
         and row['Config']['Labels'].get('com.docker.compose.service') == selected['service']
         and row['Config']['Cmd'] == ['/usr/sbin/mosquitto', '-c', '/mosquitto/config/mosquitto.conf'])
    mounts = [m for m in row['Mounts'] if m['Destination'] == '/mosquitto/config'
              or m['Destination'].startswith('/mosquitto/config/')]
    need(len(mounts) == 1 and mounts[0]['Type'] == 'bind' and mounts[0]['RW'] is True
         and mounts[0]['Source'] == selected['config_path'] and mounts[0]['Destination'] == '/mosquitto/config')
    return ids[0]


def config(path, *, directory=CONFIG):
    raw, _ = read(Path(directory)/'mosquitto.conf')
    rows = [line.split('#', 1)[0].split() for line in raw.decode().splitlines()]
    rows = [row for row in rows if row]
    forbidden = {'acl_file', 'include_dir', 'plugin', 'auth_plugin', 'per_listener_settings', 'psk_file',
                 'password_file'}
    need([row for row in rows if row[0] == 'password_file'] == [['password_file', path]]
         and [row for row in rows if row[0] == 'allow_anonymous'] == [['allow_anonymous', 'false']]
         and all(row[0] not in forbidden - {'password_file'} and not row[0].startswith(('plugin_', 'auth_opt_')) for row in rows))
    return hashlib.sha256(raw).hexdigest()


def authenticate(username, password):
    spec = importlib.util.spec_from_file_location('retained_mqtt_health', HEALTH)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    for attempt in range(6):
        if module.connect(username, password) == 0:
            need(module.connect() in (4, 5)); return
        if attempt < 5:
            time.sleep(1)
    raise ValueError('Dedicated Explorer account cannot authenticate')


def _account(value, selected_context, selected_broker, config_fd, custody_fd):
    config_root=Path(selected_broker['config_path']);custody_root=Path(selected_context['custody'])
    need(os.geteuid() == 0 and isinstance(value, dict) and set(value)-{'runtime','broker_runtime'} == {'connection', 'credential', 'image'})
    selected, credential = value['connection'], value['credential']
    need(isinstance(selected, dict) and set(selected) == {'name', 'hostname', 'port', 'username', 'credential_id', 'password_file', 'access'}
         and selected['access'] == 'read-write-all' and type(selected['port']) is int and selected['port'] == 1883
         and isinstance(selected['username'], str) and re.fullmatch('[a-z][a-z0-9_]{2,31}', selected['username'])
         and isinstance(selected['credential_id'], str) and re.fullmatch('[a-z][a-z0-9-]{2,63}', selected['credential_id'])
         and isinstance(selected['password_file'], str) and re.fullmatch('/mosquitto/config/[A-Za-z0-9_.-]{1,100}', selected['password_file'])
         and Path(selected['password_file']).name not in {'.', '..'}
         and isinstance(value['image'], str) and re.fullmatch('(?:[A-Za-z0-9._:/-]+@)?sha256:[0-9a-f]{64}', value['image']))
    need(isinstance(credential, dict) and set(credential) == {'schema', 'owner', 'password'}
         and credential['schema'] == 'homelab-application-account-v1'
         and isinstance(credential['password'], str) and re.fullmatch('[0-9a-f]{64}', credential['password']))
    own = state.workspace_owner(custody_fd,selected_context)
    need(credential['owner'] == dict(own, purpose='mqtt-explorer', username=selected['username']))
    directory = os.fstat(custody_fd)
    need(stat.S_ISDIR(directory.st_mode) and state.owner(directory) == (0,0) and stat.S_IMODE(directory.st_mode) == 0o700)
    config_directory = directory_identity(config_root)
    cid = broker(value['image'],runtime=selected_broker); config_sha = config(selected['password_file'],directory=config_root)
    path = config_root/Path(selected['password_file']).name
    raw, info = read(path)
    attrs = attributes(path)
    need(identity(path.lstat()) == identity(info) and directory_identity(config_root) == config_directory)
    lines = [line for line in raw.splitlines() if line.split(b':', 1)[0] == selected['username'].encode()]
    receipt = custody_root/(selected['credential_id']+'-account.json')
    hold = custody_root/(selected['credential_id']+'-ACCOUNT-HOLD.json')
    need(not hold.exists() and not hold.is_symlink())
    expected = {'owner': credential['owner'], 'credential_fingerprint': fingerprint(credential['password'], credential['owner'], 'account'),
                'password_file': selected['password_file'], 'config_sha256': config_sha}
    if receipt.exists() or receipt.is_symlink():
        old = json.loads(read(receipt, True)[0])
        need(set(old) == {*expected, 'before_sha256', 'line_sha256'} and all(old[k] == v for k, v in expected.items())
             and len(lines) == 1 and hashlib.sha256(lines[0]).hexdigest() == old['line_sha256'])
    else:
        need(not lines)
        save_new(hold, dict(expected, before_sha256=hashlib.sha256(raw).hexdigest(), container_id=cid))
        command = 'umask 077; mosquitto_passwd -c /tmp/account '+selected['username']+' && cat /tmp/account'
        output = docker(['run', '--rm', '-i', '--pull=never', '--network', 'none', '--read-only', '--user', '1883:1883',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--memory', '64m', '--cpus', '0.25', '--pids-limit', '32',
            '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=1m,uid=1883,gid=1883,mode=0700',
            '--entrypoint', 'sh', value['image'], '-c', command], credential['password']+'\n'+credential['password']+'\n')
        rows = [line.encode() for line in output.splitlines() if line.startswith(selected['username']+':')]
        need(len(rows) == 1 and re.fullmatch(re.escape(selected['username'].encode())+rb':\$7\$[0-9]+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+', rows[0]))
        temporary = config_root/('.homelab-'+selected['credential_id']+'.pending')
        state.stable_directory(config_fd,config_root);state.stable_directory(custody_fd,custody_root)
        fd = os.open(temporary.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,dir_fd=config_fd)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw+(b'' if raw.endswith(b'\n') else b'\n')+rows[0]+b'\n')
            os.fchown(stream.fileno(), info.st_uid, info.st_gid); os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
            for name, data in attrs.items():
                os.setxattr(stream.fileno(), name, data)
            stream.flush(); os.fsync(stream.fileno())
        current_raw, current_info = read(path)
        need(current_raw == raw and identity(current_info) == identity(info) and attributes(path) == attrs
             and directory_identity(config_root) == config_directory
             and broker(value['image'],runtime=selected_broker) == cid and config(selected['password_file'],directory=config_root) == config_sha)
        state.stable_directory(config_fd,config_root);state.stable_directory(custody_fd,custody_root)
        state.replace(config_fd,temporary.name,path.name)
        docker(['kill', '--signal', 'HUP', cid])
        authenticate(selected['username'], credential['password'])
        save_new(receipt, dict(expected, before_sha256=hashlib.sha256(raw).hexdigest(), line_sha256=hashlib.sha256(rows[0]).hexdigest()))
        state.unlink(custody_fd,hold.name)
    authenticate(selected['username'], credential['password'])
    need(broker(value['image'],runtime=selected_broker) == cid)
    return {'account': 'verified', 'broker_container_preserved': True}



def account(value):
    need(os.geteuid()==0 and isinstance(value,dict)
         and ('runtime' not in value or isinstance(value['runtime'],dict))
         and ('broker_runtime' not in value or isinstance(value['broker_runtime'],dict)))
    selected=state.context(value.get('runtime'))
    selected_broker=state.broker_context(value.get('broker_runtime'))
    with state.custody(selected) as custody_fd,state.directory(selected_broker['config_path']) as config_fd:
        return _account(value,selected,selected_broker,config_fd,custody_fd)


def profile(value):
    """Retain the exact managed native profile and receipt identity."""
    need(os.geteuid()==0 and isinstance(value,dict) and set(value)-{'runtime','broker_runtime'}=={'connection','credential','image'})
    selected,credential=value['connection'],value['credential']
    need(isinstance(selected,dict) and set(selected)=={'name','hostname','port','username','credential_id','password_file','access'}
         and selected['access']=='read-write-all' and isinstance(selected['credential_id'],str)
         and re.fullmatch('[a-z][a-z0-9-]{2,63}',selected['credential_id']))
    need(isinstance(credential,dict) and set(credential)=={'schema','owner','password'}
         and credential['schema']=='homelab-application-account-v1'
         and isinstance(credential['password'],str) and re.fullmatch('[0-9a-f]{64}',credential['password']))
    context=state.context(value.get('runtime'))
    with state.custody(context) as cfd:
        need(credential['owner']==dict(state.workspace_owner(cfd,context),purpose='mqtt-explorer',username=selected['username']))
    connection={key:selected[key] for key in ('name','hostname','port','username')}
    expected=state.native_profile(connection,credential['password'],'managed-'+selected['credential_id'])
    return state.seed_profile(context,expected,credential['owner'],selected['credential_id'],docker)


def profile_existing(value):
    need(os.geteuid()==0)
    return state.profile_existing(value,docker)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    args = parser.parse_args()
    try:
        value = json.loads(read(args.config, True)[0])
        result = profile_existing(value) if value.get('schema')=='homelab-mqtt-explorer-existing-profile-v1' else dict(account(value), **profile(value))
    except Exception:
        raise SystemExit('MQTT Explorer account held; inspect privately.') from None
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
