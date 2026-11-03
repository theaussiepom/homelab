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

CONFIG = Path('/srv/homelab/data/mqtt/config')
CUSTODY = Path('/var/lib/homelab-mqtt-explorer')
HEALTH = Path('/opt/homelab-app/automation-health.py')
DATA = Path('/srv/homelab/data/mqtt-explorer')


def need(ok):
    if not ok:
        raise ValueError('Dedicated Explorer account refused')


def fingerprint(secret, owner, purpose):
    context = ('homelab-mqtt-custody-v1\0'+purpose+'\0'+json.dumps(owner, sort_keys=True, separators=(',', ':'))).encode()
    return hashlib.pbkdf2_hmac('sha256', secret.encode(), context, 600000).hex()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_uid, info.st_gid, info.st_mode, info.st_nlink)


def attributes(path):
    return {name: os.getxattr(path, name) for name in os.listxattr(path)}


def directory_identity():
    info = CONFIG.lstat()
    need(stat.S_ISDIR(info.st_mode))
    return info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode


def read(path, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 1024*1024)
        if private:
            need(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600)
        raw = stream.read(1024*1024+1)
        need(len(raw) == info.st_size and identity(info) == identity(os.fstat(stream.fileno())) == identity(path.lstat()))
    return raw, info


def save_new(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write((json.dumps(value, sort_keys=True)+'\n').encode()); stream.flush(); os.fsync(stream.fileno())
    sync(path.parent)


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def docker(args, input=None):
    return subprocess.run(['docker', *args], input=input, text=True, capture_output=True,
                          check=True, timeout=30).stdout


def broker(image):
    ids = docker(['ps', '--all', '--quiet', '--no-trunc', '--filter', 'label=com.docker.compose.project=homelab-mqtt',
                  '--filter', 'label=com.docker.compose.service=mqtt']).split()
    need(len(ids) == 1 and re.fullmatch('[0-9a-f]{64}', ids[0]))
    rows = json.loads(docker(['inspect', ids[0]])); need(isinstance(rows, list) and len(rows) == 1)
    row = rows[0]
    need(row['Id'] == ids[0] and row['State']['Running'] is True and row['Config']['Image'] == image
         and row['Config']['Labels'].get('com.docker.compose.project') == 'homelab-mqtt'
         and row['Config']['Labels'].get('com.docker.compose.service') == 'mqtt'
         and row['Config']['Cmd'] == ['/usr/sbin/mosquitto', '-c', '/mosquitto/config/mosquitto.conf'])
    mounts = [m for m in row['Mounts'] if m['Destination'] == '/mosquitto/config'
              or m['Destination'].startswith('/mosquitto/config/')]
    need(len(mounts) == 1 and mounts[0]['Type'] == 'bind' and mounts[0]['RW'] is True
         and mounts[0]['Source'] == str(CONFIG) and mounts[0]['Destination'] == '/mosquitto/config')
    return ids[0]


def config(path):
    raw, _ = read(CONFIG/'mosquitto.conf')
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


def account(value):
    need(os.geteuid() == 0 and isinstance(value, dict) and set(value) == {'connection', 'credential', 'image'})
    selected, credential = value['connection'], value['credential']
    need(isinstance(selected, dict) and set(selected) == {'name', 'hostname', 'port', 'username', 'credential_id', 'password_file', 'access'}
         and selected['access'] == 'read-write-all' and type(selected['port']) is int and selected['port'] == 1883
         and isinstance(selected['username'], str) and re.fullmatch('[a-z][a-z0-9_]{2,31}', selected['username'])
         and isinstance(selected['credential_id'], str) and re.fullmatch('[a-z][a-z0-9-]{2,63}', selected['credential_id'])
         and isinstance(selected['password_file'], str) and re.fullmatch('/mosquitto/config/[A-Za-z0-9_.-]{1,100}', selected['password_file'])
         and Path(selected['password_file']).name not in {'.', '..'}
         and isinstance(value['image'], str) and re.fullmatch('[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}', value['image']))
    need(isinstance(credential, dict) and set(credential) == {'schema', 'owner', 'password'}
         and credential['schema'] == 'homelab-application-account-v1'
         and isinstance(credential['password'], str) and re.fullmatch('[0-9a-f]{64}', credential['password']))
    own = json.loads(read(CUSTODY/'workspace.json', True)[0])
    need(credential['owner'] == dict(own, purpose='mqtt-explorer', username=selected['username']))
    directory = CUSTODY.lstat()
    need(stat.S_ISDIR(directory.st_mode) and directory.st_uid == 0 and stat.S_IMODE(directory.st_mode) == 0o700)
    config_directory = directory_identity()
    cid = broker(value['image']); config_sha = config(selected['password_file'])
    path = CONFIG/Path(selected['password_file']).name
    raw, info = read(path)
    attrs = attributes(path)
    need(identity(path.lstat()) == identity(info) and directory_identity() == config_directory)
    lines = [line for line in raw.splitlines() if line.split(b':', 1)[0] == selected['username'].encode()]
    receipt = CUSTODY/(selected['credential_id']+'-account.json')
    hold = CUSTODY/(selected['credential_id']+'-ACCOUNT-HOLD.json')
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
        temporary = CONFIG/('.homelab-'+selected['credential_id']+'.pending')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw+(b'' if raw.endswith(b'\n') else b'\n')+rows[0]+b'\n')
            os.fchown(stream.fileno(), info.st_uid, info.st_gid); os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
            for name, data in attrs.items():
                os.setxattr(temporary, name, data)
            stream.flush(); os.fsync(stream.fileno())
        current_raw, current_info = read(path)
        need(current_raw == raw and identity(current_info) == identity(info) and attributes(path) == attrs
             and directory_identity() == config_directory
             and broker(value['image']) == cid and config(selected['password_file']) == config_sha)
        os.replace(temporary, path); sync(CONFIG)
        docker(['kill', '--signal', 'HUP', cid])
        authenticate(selected['username'], credential['password'])
        save_new(receipt, dict(expected, before_sha256=hashlib.sha256(raw).hexdigest(), line_sha256=hashlib.sha256(rows[0]).hexdigest()))
        hold.unlink(); sync(CUSTODY)
    authenticate(selected['username'], credential['password'])
    need(broker(value['image']) == cid)
    return {'account': 'verified', 'broker_container_preserved': True}


def profile(value):
    """Seed one owned native profile; neither replace nor adopt user profiles."""
    selected, credential = value['connection'], value['credential']
    info = DATA.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 1001
         and stat.S_IMODE(info.st_mode) == 0o700)
    name = 'managed-'+selected['credential_id']
    expected = {'configVersion': 1, 'type': 'mqtt', 'id': name, 'name': selected['name'],
        'host': selected['hostname'], 'protocol': 'mqtt', 'port': 1883, 'encryption': False,
        'certValidation': True, 'username': selected['username'], 'password': credential['password'],
        'subscriptions': [{'topic': '#', 'qos': 0}, {'topic': '$SYS/#', 'qos': 0}]}
    path = DATA/'settings.json'
    if path.exists() or path.is_symlink():
        raw, info = read(path)
        need(info.st_uid == info.st_gid == 1001 and stat.S_IMODE(info.st_mode) == 0o600)
        document = json.loads(raw)
    else:
        document = {}
    need(isinstance(document, dict))
    connections = document.setdefault('ConnectionManager_connections', {})
    need(isinstance(connections, dict))
    receipt = CUSTODY/(selected['credential_id']+'-profile.json')
    hold = CUSTODY/(selected['credential_id']+'-PROFILE-HOLD.json')
    need(not hold.exists() and not hold.is_symlink())
    digest = fingerprint(json.dumps(expected, sort_keys=True), credential['owner'], 'profile')
    proof = {'owner': credential['owner'], 'profile_fingerprint': digest}
    if receipt.exists() or receipt.is_symlink():
        need(json.loads(read(receipt, True)[0]) == proof and connections.get(name) == expected)
    else:
        need(name not in connections)
        ids = docker(['ps', '--all', '--quiet', '--no-trunc', '--filter', 'label=com.docker.compose.project=homelab-mqtt',
                      '--filter', 'label=com.docker.compose.service=mqtt_explorer']).split()
        need(len(ids) <= 1 and all(re.fullmatch('[0-9a-f]{64}', cid) for cid in ids))
        save_new(hold, proof)
        if ids:
            rows = json.loads(docker(['inspect', ids[0]])); need(len(rows) == 1)
            row = rows[0]
            mounts = [m for m in row['Mounts'] if m.get('Destination') == '/app/data'
                      or m.get('Destination', '').startswith('/app/data/')]
            need(row['Id'] == ids[0] and row['Config']['User'] == '1001:1001'
                 and row['Config']['Labels'].get('com.docker.compose.project') == 'homelab-mqtt'
                 and row['Config']['Labels'].get('com.docker.compose.service') == 'mqtt_explorer'
                 and len(mounts) == 1 and mounts[0].get('Type') == 'bind' and mounts[0].get('Source') == str(DATA)
                 and mounts[0].get('Destination') == '/app/data' and mounts[0].get('RW') is True)
            if row['State']['Running']:
                docker(['stop', '--time', '30', ids[0]])
                need(json.loads(docker(['inspect', ids[0]]))[0]['State']['Running'] is False)
            # Read again after the application has flushed its own settings.
            if path.exists() or path.is_symlink():
                raw, info = read(path)
                need(info.st_uid == info.st_gid == 1001 and stat.S_IMODE(info.st_mode) == 0o600)
                document = json.loads(raw); need(isinstance(document, dict))
                connections = document.setdefault('ConnectionManager_connections', {})
                need(isinstance(connections, dict) and name not in connections)
        connections[name] = expected
        temporary = DATA/('.homelab-'+selected['credential_id']+'.pending')
        save_new(temporary, document)
        os.chown(temporary, 1001, 1001)
        os.replace(temporary, path); sync(DATA)
        save_new(receipt, proof)
        hold.unlink(); sync(CUSTODY)
    return {'saved_connection': 'verified'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    args = parser.parse_args()
    try:
        value = json.loads(read(args.config, True)[0])
        result = dict(account(value), **profile(value))
    except Exception:
        raise SystemExit('MQTT Explorer account held; inspect privately.') from None
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
