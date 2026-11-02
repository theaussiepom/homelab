#!/usr/bin/env python3
"""Own only the CloudBeaver workspace and exact managed pgAdmin retirement."""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess

WORKSPACE = Path('/srv/homelab/data/cloudbeaver')
CUSTODY = Path('/var/lib/homelab-db-tools')
PGADMIN = Path('/srv/homelab/data/pgadmin')
COMPOSE = '/opt/homelab-app/compose.yml'
PERMISSIONS = Path('/opt/homelab-app/runtime/cloudbeaver-permissions.json')


def need(value):
    if not value:
        raise ValueError('CloudBeaver managed lifecycle refused')


def private(path, uid=0, modes=(0o400, 0o600)):
    metadata = path.lstat()
    need(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == uid and metadata.st_nlink == 1
         and stat.S_IMODE(metadata.st_mode) in modes)
    with path.open('rb') as stream:
        raw = stream.read(1024 * 1024 + 1)
    need(len(raw) <= 1024 * 1024)
    return json.loads(raw)


def create(path, value, uid=0, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(json.dumps(value, sort_keys=True).encode() + b'\n')
        stream.flush()
        if uid:
            os.fchown(stream.fileno(), uid, uid)
        os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def workspace(owner):
    need(isinstance(owner, dict) and set(owner) == {'node', 'vmid', 'hostname'}
         and isinstance(owner['node'], str) and isinstance(owner['hostname'], str)
         and type(owner['vmid']) is int and owner['vmid'] >= 100)
    need(stat.S_ISDIR(WORKSPACE.parent.lstat().st_mode))
    CUSTODY.mkdir(mode=0o700, exist_ok=True)
    meta = CUSTODY.lstat()
    need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and stat.S_IMODE(meta.st_mode) == 0o700)
    receipt = CUSTODY / 'workspace.json'
    if receipt.exists() or receipt.is_symlink():
        need(private(receipt) == owner)
    else:
        need(not WORKSPACE.is_symlink() and (not WORKSPACE.exists() or not any(WORKSPACE.iterdir())))
        WORKSPACE.mkdir(mode=0o700, exist_ok=True)
        os.chown(WORKSPACE, 8978, 8978)
        os.chmod(WORKSPACE, 0o700)
        create(receipt, owner)
    metadata = WORKSPACE.lstat()
    need(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == metadata.st_gid == 8978
         and stat.S_IMODE(metadata.st_mode) == 0o700)
    for directory in (WORKSPACE / 'GlobalConfiguration', WORKSPACE / 'GlobalConfiguration/.dbeaver'):
        if not directory.exists() and not directory.is_symlink():
            directory.mkdir(mode=0o700)
            os.chown(directory, 8978, 8978)
        need(stat.S_ISDIR(directory.lstat().st_mode))
    return {'workspace': 'owned'}


def docker(args, *, input=None, timeout=90):
    return subprocess.run(['docker', *args], input=input, text=True, capture_output=True,
                          check=True, timeout=timeout).stdout


def retirement(config):
    """Gracefully retire one exact Compose service, preserving its bind and evidence."""
    ids = docker(['ps', '--all', '--quiet', '--filter', 'label=com.docker.compose.project=homelab-db-tools',
                  '--filter', 'label=com.docker.compose.service=pgadmin']).split()
    need(len(ids) <= 1)
    if not ids:
        return {'pgadmin': 'absent'}
    container = json.loads(docker(['inspect', ids[0]]))[0]
    mounts = [m for m in container['Mounts'] if m['Destination'] == '/var/lib/pgadmin']
    need(container['Id'].startswith(ids[0]) and container['Config']['Image'] == config['retained_pgadmin_image']
         and container['Config']['Labels'].get('com.docker.compose.project') == 'homelab-db-tools'
         and container['Config']['Labels'].get('com.docker.compose.service') == 'pgadmin'
         and len(mounts) == 1 and mounts[0]['Type'] == 'bind'
         and mounts[0]['Source'] == str(PGADMIN))
    source = PGADMIN
    metadata = source.lstat()
    need(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 5050)
    proof = {'container': container['Id'], 'image': config['retained_pgadmin_image'],
             'source': str(source), 'device': metadata.st_dev, 'inode': metadata.st_ino}
    receipt = CUSTODY / 'pgadmin-retirement.json'
    if receipt.exists() or receipt.is_symlink():
        need(private(receipt) == proof)
    else:
        create(receipt, proof)
    docker(['stop', '--time', '60', container['Id']])
    stopped = json.loads(docker(['inspect', container['Id']]))[0]
    need(stopped['Id'] == container['Id'] and stopped['State']['Running'] is False)
    docker(['rm', container['Id']])
    after = source.lstat()
    need(after.st_dev == metadata.st_dev and after.st_ino == metadata.st_ino and stat.S_ISDIR(after.st_mode))
    return {'pgadmin': 'retired', 'data': 'preserved'}


def templates(config, seed=True):
    """Seed only our initial template permissions; later verify without overwriting."""
    path = WORKSPACE / 'GlobalConfiguration/.dbeaver/data-sources-permissions.json'
    desired = {name: ['user'] for name in config['connections']}
    need(private(PERMISSIONS, uid=8978) == desired)
    if not path.exists() and not path.is_symlink():
        need(seed)
        create(path, desired, uid=8978, mode=0o400)
    current = private(path, uid=8978, modes=(0o400, 0o600, 0o640, 0o644))
    need(isinstance(current, dict) and all(current.get(key) == value for key, value in desired.items()))
    return {'templates': 'verified', 'additional_permissions': 'preserved'}


def prepare(config):
    need(config['workspace'] == str(WORKSPACE) and config['project'] == 'homelab-db-tools')
    workspace(private(CUSTODY / 'workspace.json'))
    return retirement(config)


def metadata(config):
    """Check only our template IDs; custom connections and per-user workspaces stay owned by the application."""
    current = private(WORKSPACE / 'GlobalConfiguration/.dbeaver/data-sources.json', uid=8978,
                      modes=(0o400, 0o600, 0o640, 0o644))['connections']
    for name, expected in config['connections'].items():
        value = current.get(name, {})
        connection = value.get('configuration', {})
        driver = {'postgresql': ('postgresql', 'postgres-jdbc'), 'mariadb': ('mysql', 'mariaDB')}[expected['driver']]
        need(value.get('provider') == driver[0] and value.get('driver') == driver[1]
             and value.get('name') == expected['name'] and connection.get('host') == expected['host']
             and str(connection.get('port')) == str(expected['port'])
             and connection.get('database') == expected['database']
             and not value.get('save-password') and not value.get('auth-properties')
             and not any(connection.get(key) for key in ('user', 'username', 'password', 'auth-properties')))
        if expected['driver'] == 'postgresql':
            need(connection.get('properties', {}).get('sslmode') == expected['sslmode'])
    return {'connections': 'verified'}


def health(config):
    templates(config, seed=False)
    metadata(config)
    prepare_owner = private(CUSTODY / 'workspace.json')
    workspace(prepare_owner)
    need(not docker(['ps', '--all', '--quiet', '--filter', 'label=com.docker.compose.project=homelab-db-tools',
                     '--filter', 'label=com.docker.compose.service=pgadmin']).strip())
    raw = docker(['compose', '-f', COMPOSE, 'ps', '--all', '--format', 'json'])
    containers = json.loads(raw) if raw.lstrip().startswith('[') else [json.loads(line) for line in raw.splitlines()]
    need(isinstance(containers, list) and {r['Service'] for r in containers} == {'cloudbeaver', 'auth_gateway'})
    rows = {r['Service']: json.loads(docker(['inspect', r['ID']]))[0] for r in containers}
    server, gateway = rows['cloudbeaver'], rows['auth_gateway']
    need(all(obj['State']['Running'] is True
             and ('Health' not in obj['State'] or obj['State']['Health']['Status'] == 'healthy')
             for obj in rows.values())
         and server['Config']['User'] == '8978:8978' and gateway['Config']['User'] == '65532:65532'
         and not server['HostConfig']['PortBindings']
         and set(gateway['HostConfig']['PortBindings']) == {'4180/tcp'}
         and gateway['HostConfig']['PortBindings']['4180/tcp'] == [{'HostIp': config['bind_address'], 'HostPort': '80'}]
         and len(server['NetworkSettings']['Networks']) == 1
         and server['HostConfig']['NetworkMode'] not in {'host', 'none', 'bridge', 'default'}
         and any(m['Source'] == str(WORKSPACE) and m['Destination'] == '/opt/cloudbeaver/workspace'
                 and m['Type'] == 'bind' and m['RW'] is True for m in server['Mounts'])
         and server['NetworkSettings']['Networks'].keys() == gateway['NetworkSettings']['Networks'].keys())
    raw = docker(['compose', '-f', COMPOSE, 'exec', '-T', 'cloudbeaver', '/opt/java/openjdk/bin/java', '-Xms8m', '-Xmx64m', '-Xss512k', '-XX:MaxMetaspaceSize=64m', '-XX:ReservedCodeCacheSize=16m', '-XX:ActiveProcessorCount=1', '-XX:CICompilerCount=2', '-XX:+UseSerialGC',
                  '/opt/cloudbeaver/conf/CloudBeaverHealth.java', '--configuration'], timeout=15)
    current = json.loads(raw)['data']['serverConfig']
    need(current['forceHttps'] is True and current['configurationMode'] is False and current['anonymousAccessEnabled'] is False
         and set(current['enabledAuthProviders']) == {'local', 'reverseProxy'})
    return {'cloudbeaver': 'passed', 'setup': 'closed', 'gateway_only_listener': True,
            'database_login': 'individual_credentials_required'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('workspace', 'templates', 'prepare', 'health'))
    parser.add_argument('--config', type=Path)
    parser.add_argument('--owner')
    args = parser.parse_args()
    if args.action == 'workspace':
        result = workspace(json.loads(args.owner))
    else:
        value = private(args.config)
        result = {'prepare': prepare, 'health': health, 'templates': templates}[args.action](value)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
