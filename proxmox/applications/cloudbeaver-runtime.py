#!/usr/bin/env python3
"""Own only the CloudBeaver workspace and selected managed connections."""
import argparse
from contextlib import contextmanager
from types import SimpleNamespace
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

WORKSPACE = Path('/srv/homelab/data/cloudbeaver')
CUSTODY = Path('/var/lib/homelab-db-tools')
COMPOSE = '/opt/homelab-app/compose.yml'
PERMISSIONS = Path('/opt/homelab-app/runtime/cloudbeaver-permissions.json')
MANAGED = Path('/opt/homelab-app/runtime/cloudbeaver-admin-connections.json')
RUNTIME = Path('/opt/homelab-app/runtime')


def need(value):
    if not value:
        raise ValueError('CloudBeaver managed lifecycle refused')


def _path(value):
    need(isinstance(value, str) and value.startswith('/') and str(Path(value)) == value
         and not any(part in ('.', '..') for part in value.split('/'))
         and not any(char in value for char in '$:\\')
         and not any(ord(char) < 32 or ord(char) == 127 for char in value))
    return Path(value)


@contextmanager
def _parent(path):
    """Anchor every parent from root, reject symlinks and path replacement."""
    path = _path(str(path)); need(path.name)
    descriptors = []
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptors.append(fd); anchors = []
    try:
        for name in path.parts[1:-1]:
            parent = fd
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            descriptors.append(fd)
            info = os.fstat(fd); need(stat.S_ISDIR(info.st_mode))
            anchors.append((parent, name, (info.st_dev, info.st_ino)))
        yield fd, path.name
        for parent, name, identity in anchors:
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            need(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == identity)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _bytes(path, uid, modes, *, same_gid=False):
    with _parent(path) as (parent, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            need(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1
                 and (not same_gid or info.st_gid == uid)
                 and stat.S_IMODE(info.st_mode) in modes and info.st_size <= 1024*1024)
            raw = stream.read(1024*1024+1)
            fields = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
                      'st_size', 'st_mtime_ns', 'st_ctime_ns')
            key = lambda row: tuple(getattr(row, field) for field in fields)
            need(len(raw) == info.st_size and key(info) == key(os.fstat(stream.fileno()))
                 == key(os.stat(name, dir_fd=parent, follow_symlinks=False)))
        return raw


def private(path, uid=0, modes=(0o400, 0o600)):
    return json.loads(_bytes(path, uid, modes))


def context(config=None):
    """Only compiler-owned identity metadata; old retained defaults stay exact."""
    if config is None:
        return SimpleNamespace(workspace=WORKSPACE, custody=CUSTODY, runtime=RUNTIME,
            permissions=PERMISSIONS, managed=MANAGED, compose=COMPOSE,
            project='homelab-db-tools', services={'cloudbeaver': 'cloudbeaver', 'auth_gateway': 'auth_gateway'},
            lifecycle='retained', runtime_id='cloudbeaver')
    need(isinstance(config, dict) and isinstance(config.get('project'), str)
         and re.fullmatch('[a-z0-9][a-z0-9_-]{0,127}', config['project']))
    lifecycle = config.get('lifecycle', 'retained')
    need(lifecycle in ('fresh', 'retained') and 'retained_pgadmin_image' not in config)
    services = config.get('services', {'cloudbeaver': 'cloudbeaver', 'auth_gateway': 'auth_gateway'})
    need(isinstance(services, dict) and set(services) == {'cloudbeaver', 'auth_gateway'}
         and all(isinstance(value, str) and re.fullmatch('[a-z0-9][a-z0-9_-]{0,127}', value) for value in services.values())
         and len(set(services.values())) == 2)
    runtime = _path(config.get('runtime_directory', str(RUNTIME)))
    need(runtime == RUNTIME or RUNTIME in runtime.parents)
    custody = _path(config.get('custody_directory', str(CUSTODY)))
    need(custody == CUSTODY or CUSTODY in custody.parents)
    runtime_id = config.get('runtime_id', 'cloudbeaver')
    need(isinstance(runtime_id, str) and re.fullmatch('[a-z][a-z0-9_-]{0,62}', runtime_id))
    if lifecycle == 'fresh':
        need({'lifecycle', 'custody_directory', 'runtime_id'} <= set(config))
    filename = config.get('project_file', Path(COMPOSE).name)
    need(isinstance(filename, str) and re.fullmatch(r'[a-z0-9][a-z0-9_.-]{0,127}\.ya?ml', filename))
    return SimpleNamespace(workspace=_path(config['workspace']), custody=custody, runtime=runtime,
        permissions=runtime/'cloudbeaver-permissions.json' if 'runtime_directory' in config else PERMISSIONS,
        managed=runtime/'cloudbeaver-admin-connections.json' if 'runtime_directory' in config else MANAGED,
        compose=str(Path(COMPOSE).parent/filename), project=config['project'], services=services, lifecycle=lifecycle, runtime_id=runtime_id)


def create(path, value, uid=0, mode=0o600):
    with _parent(path) as (parent, name):
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(json.dumps(value, sort_keys=True).encode() + b'\n')
            stream.flush()
            if uid:
                os.fchown(stream.fileno(), uid, uid)
            os.fsync(stream.fileno())
        os.fsync(parent)


def _workspace_receipt(ctx, owner):
    legacy = (ctx.lifecycle == 'retained' and ctx.workspace == WORKSPACE and ctx.custody == CUSTODY
        and ctx.project == 'homelab-db-tools' and ctx.services == {'cloudbeaver': 'cloudbeaver', 'auth_gateway': 'auth_gateway'}
        and ctx.runtime == RUNTIME and ctx.compose == COMPOSE and ctx.runtime_id == 'cloudbeaver')
    if legacy:
        return owner
    return {'schema': 'homelab-cloudbeaver-workspace-v1', 'owner': owner,
        'workspace': str(ctx.workspace), 'custody_directory': str(ctx.custody),
        'project': ctx.project, 'services': ctx.services, 'runtime_id': ctx.runtime_id,
        'runtime_directory': str(ctx.runtime), 'project_file': Path(ctx.compose).name}


def workspace_owner(config):
    ctx = context(config)
    value = private(ctx.custody/'workspace.json')
    owner = value.get('owner') if isinstance(value, dict) and 'schema' in value else value
    need(value == _workspace_receipt(ctx, owner))
    return owner


def workspace(owner, config=None):
    ctx = context(config)
    need(isinstance(owner, dict) and set(owner) == {'node', 'vmid', 'hostname'}
         and isinstance(owner['node'], str) and isinstance(owner['hostname'], str)
         and type(owner['vmid']) is int and owner['vmid'] >= 100)
    need(stat.S_ISDIR(ctx.workspace.parent.lstat().st_mode))
    ctx.custody.mkdir(mode=0o700, exist_ok=True)
    meta = ctx.custody.lstat()
    need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and stat.S_IMODE(meta.st_mode) == 0o700)
    receipt = ctx.custody / 'workspace.json'
    desired = _workspace_receipt(ctx, owner)
    if receipt.exists() or receipt.is_symlink():
        need(private(receipt) == desired)
    else:
        need(not ctx.workspace.is_symlink() and (not ctx.workspace.exists() or not any(ctx.workspace.iterdir())))
        ctx.workspace.mkdir(mode=0o700, exist_ok=True)
        os.chown(ctx.workspace, 8978, 8978)
        os.chmod(ctx.workspace, 0o700)
        create(receipt, desired)
    metadata = ctx.workspace.lstat()
    need(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == metadata.st_gid == 8978
         and stat.S_IMODE(metadata.st_mode) == 0o700)
    for directory in (ctx.workspace / 'GlobalConfiguration', ctx.workspace / 'GlobalConfiguration/.dbeaver'):
        if not directory.exists() and not directory.is_symlink():
            directory.mkdir(mode=0o700)
            os.chown(directory, 8978, 8978)
        need(stat.S_ISDIR(directory.lstat().st_mode))
    return {'workspace': 'owned'}


def docker(args, *, input=None, timeout=90):
    return subprocess.run(['docker', *args], input=input, text=True, capture_output=True,
                          check=True, timeout=timeout).stdout


def templates(config, seed=True):
    """Seed only our initial template permissions; later verify without overwriting."""
    ctx = context(config)
    path = ctx.workspace / 'GlobalConfiguration/.dbeaver/data-sources-permissions.json'
    desired = {name: ['user'] for name in config['connections']}
    need(private(ctx.permissions, uid=8978) == desired)
    if not path.exists() and not path.is_symlink():
        need(seed)
        create(path, desired, uid=8978, mode=0o400)
    current = private(path, uid=8978, modes=(0o400, 0o600, 0o640, 0o644))
    need(isinstance(current, dict) and all(current.get(key) == value for key, value in desired.items()))
    return {'templates': 'verified', 'additional_permissions': 'preserved'}


def managed_bytes(path, uid, modes):
    return _bytes(path, uid, modes, same_gid=True)


def managed_writer(config):
    """Flush only our existing server before its first owned datasource seed."""
    ctx = context(config)
    ids = docker(['ps', '--all', '--quiet', '--filter', 'label=com.docker.compose.project='+ctx.project,
                  '--filter', 'label=com.docker.compose.service='+ctx.services['cloudbeaver']]).split()
    need(len(ids) <= 1)
    if not ids:
        return
    row = json.loads(docker(['inspect', ids[0]]))[0]
    mounts = [item for item in row['Mounts'] if item['Destination'] == '/opt/cloudbeaver/workspace'
              or item['Destination'].startswith('/opt/cloudbeaver/workspace/')]
    need(row['Id'].startswith(ids[0]) and row['Config']['Image'] == config['cloudbeaver_image']
         and row['Config']['Labels'].get('com.docker.compose.project') == ctx.project
         and row['Config']['Labels'].get('com.docker.compose.service') == ctx.services['cloudbeaver']
         and len(mounts) == 1 and mounts[0]['Type'] == 'bind' and mounts[0]['Source'] == str(ctx.workspace)
         and mounts[0]['RW'] is True)
    if row['State']['Running']:
        docker(['stop', '--time', '30', row['Id']], timeout=45)
        after = json.loads(docker(['inspect', row['Id']]))[0]
        need(after['Id'] == row['Id'] and after['State']['Running'] is False)


def managed(config, seed=True):
    """Own one native credential file, keeping every other datasource and grant."""
    ctx = context(config)
    directory = ctx.workspace/'GlobalConfiguration/.dbeaver'
    path = directory/'data-sources-homelab-administrators.json'
    receipt, hold = ctx.custody/'managed-connections.json', ctx.custody/'MANAGED-CONNECTIONS-HOLD.json'
    selected = config.get('managed_connections')
    if not selected:
        need(not any(p.exists() or p.is_symlink() for p in (path, receipt, hold)))
        return {'managed_connections': 'absent'}
    need(isinstance(selected, dict) and 1 <= len(selected) <= 8 and os.geteuid() == 0)
    workspace(workspace_owner(config), config)
    for parent in (directory.parent, directory):
        info = parent.lstat(); need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 8978)
    raw = managed_bytes(ctx.managed, 0, (0o400, 0o600))
    need(hashlib.sha256(raw).hexdigest() == config['managed_sha256'])
    desired = json.loads(raw)
    need(isinstance(desired, dict) and set(desired) == {'folders', 'connections'} and desired['folders'] == {}
         and set(desired['connections']) == set(selected))
    proof = {'owners': {key: value['owner'] for key, value in selected.items()}, 'sha256': config['managed_sha256']}
    need(not hold.exists() and not hold.is_symlink())
    permissions = directory/'data-sources-permissions.json'
    old_permissions = managed_bytes(permissions, 8978, (0o400, 0o600, 0o640, 0o644))
    grants = json.loads(old_permissions); need(isinstance(grants, dict))
    own_grants = {key: ['user'] for key in selected}
    if receipt.exists() or receipt.is_symlink():
        need(private(receipt) == proof and managed_bytes(path, 8978, (0o600,)) == raw
             and all(grants.get(key) == value for key, value in own_grants.items()))
    else:
        need(seed and not path.exists() and not path.is_symlink() and not set(selected) & grants.keys())
        sources = list(directory.glob('data-sources*.json')); need(len(sources) <= 128)
        for source in sources:
            document = json.loads(managed_bytes(source, 8978, (0o400, 0o600, 0o640, 0o644)))
            need(isinstance(document, dict) and not set(selected) & document.get('connections', {}).keys())
        create(hold, proof)
        managed_writer(config)
        # A graceful stop can flush application-owned changes. Re-read them
        # before adding our IDs; no running server may race this first seed.
        need(not path.exists() and not path.is_symlink())
        old_permissions = managed_bytes(permissions, 8978, (0o400, 0o600, 0o640, 0o644))
        grants = json.loads(old_permissions); need(isinstance(grants, dict) and not set(selected) & grants.keys())
        sources = list(directory.glob('data-sources*.json')); need(len(sources) <= 128)
        for source in sources:
            document = json.loads(managed_bytes(source, 8978, (0o400, 0o600, 0o640, 0o644)))
            need(isinstance(document, dict) and not set(selected) & document.get('connections', {}).keys())
        create(path, desired, uid=8978, mode=0o600)
        # The exact native file format is private plaintext at rest. Community
        # consumes it; we never synthesize or claim an encrypted credential store.
        grants.update(own_grants)
        temporary = directory/'permissions.homelab-managed.pending'
        create(temporary, grants, uid=8978, mode=stat.S_IMODE(permissions.lstat().st_mode))
        need(managed_bytes(permissions, 8978, (0o400, 0o600, 0o640, 0o644)) == old_permissions)
        os.replace(temporary, permissions)
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        create(receipt, proof)
        hold.unlink()
        fd = os.open(ctx.custody, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return {'managed_connections': 'verified', 'private_native_file': True}


def metadata(config):
    """Check only our template IDs; custom connections and per-user workspaces stay owned by the application."""
    ctx = context(config)
    if not config['connections']:
        return {'connections': 'verified'}
    current = private(ctx.workspace / 'GlobalConfiguration/.dbeaver/data-sources.json', uid=8978,
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


def driver_health(config, server):
    ctx = context(config)
    artifact = config.get('mariadb_jdbc')
    needed = any(item.get('driver') == 'mariadb' for item in config.get('managed_connections', {}).values())
    need(bool(artifact) == needed)
    if not needed:
        return
    need(isinstance(artifact, dict) and set(artifact) == {'version','sha256','image_filename','source','target','url'})
    need(isinstance(artifact['version'], str) and re.fullmatch(r'3\.5\.[0-9]{1,3}', artifact['version'])
         and int(artifact['version'].split('.')[2]) >= 11
         and isinstance(artifact['sha256'], str) and re.fullmatch('[0-9a-f]{64}', artifact['sha256'])
         and isinstance(artifact['image_filename'], str)
         and artifact['image_filename'] in {'mariadb-java-client-'+artifact['version']+'.jar', 'mariadb-java-client-3.5.10.jar'})
    source = ctx.runtime/('mariadb-java-client-'+artifact['version']+'.jar')
    target = '/opt/cloudbeaver/drivers/mariadb/'+artifact['image_filename']
    need(artifact['source'] == str(source) and artifact['target'] == target
         and artifact['url'] == 'https://repo.maven.apache.org/maven2/org/mariadb/jdbc/mariadb-java-client/'
             +artifact['version']+'/'+source.name
         and hashlib.sha256(managed_bytes(source, 8978, (0o400,))).hexdigest() == artifact['sha256'])
    mounts = [row for row in server['Mounts'] if row['Destination'] == '/opt/cloudbeaver/drivers/mariadb'
              or row['Destination'].startswith('/opt/cloudbeaver/drivers/mariadb/')]
    need(len(mounts) == 1 and mounts[0]['Type'] == 'bind' and mounts[0]['Source'] == str(source)
         and mounts[0]['Destination'] == target and mounts[0]['RW'] is False)


def database_health(config):
    ctx = context(config)
    selected = config.get('managed_connections')
    if not selected:
        return 'individual_credentials_required'
    document = json.loads(managed_bytes(ctx.managed, 0, (0o400, 0o600)))
    for key, item in selected.items():
        password = document['connections'][key]['configuration']['auth-properties']['userPassword']
        artifact = config['mariadb_jdbc'] if item['driver'] == 'mariadb' else None
        extra = [artifact['version'], artifact['sha256'], artifact['image_filename']] if artifact else []
        raw = docker(['compose', '-f', ctx.compose, 'exec', '-T', ctx.services['cloudbeaver'], '/opt/java/openjdk/bin/java',
            '-Xms8m', '-Xmx64m', '-Xss512k', '-XX:MaxMetaspaceSize=64m', '-XX:ReservedCodeCacheSize=16m',
            '-XX:ActiveProcessorCount=1', '-XX:CICompilerCount=2', '-XX:+UseSerialGC', '--class-path',
            '/opt/cloudbeaver/drivers/postgresql/*:/opt/cloudbeaver/drivers/mariadb/*',
            '/opt/cloudbeaver/conf/CloudBeaverDatabaseHealth.java', item['driver'], item['host'],
            item['owner']['source_address'], item['username'], *extra], input=password+'\n', timeout=20)
        need(json.loads(raw) == {'database_administrator': 'verified', 'encrypted': True, 'source_match': True})
    return 'managed_tls_administrator_verified'


def health(config):
    ctx = context(config)
    templates(config, seed=False)
    managed(config, seed=False)
    metadata(config)
    prepare_owner = workspace_owner(config)
    workspace(prepare_owner, config)
    raw = docker(['compose', '-f', ctx.compose, 'ps', '--all', '--format', 'json'])
    containers = json.loads(raw) if raw.lstrip().startswith('[') else [json.loads(line) for line in raw.splitlines()]
    need(isinstance(containers, list) and len(containers) == 2
         and {r['Service'] for r in containers} == set(ctx.services.values()))
    rows = {r['Service']: json.loads(docker(['inspect', r['ID']]))[0] for r in containers}
    server, gateway = rows[ctx.services['cloudbeaver']], rows[ctx.services['auth_gateway']]
    need(all(obj['Config'].get('Labels', {}).get('com.docker.compose.project') == ctx.project
             and obj['Config']['Labels'].get('com.docker.compose.service') == name for name, obj in rows.items()))
    driver_health(config, server)
    if config.get('managed_connections'):
        mounts = [m for m in server['Mounts'] if m['Destination'] == '/opt/cloudbeaver/workspace'
                  or m['Destination'].startswith('/opt/cloudbeaver/workspace/')]
        need(len(mounts) == 1)
    need(all(obj['State']['Running'] is True
             and ('Health' not in obj['State'] or obj['State']['Health']['Status'] == 'healthy')
             for obj in rows.values())
         and server['Config']['User'] == '8978:8978' and gateway['Config']['User'] == '65532:65532'
         and not server['HostConfig']['PortBindings']
         and set(gateway['HostConfig']['PortBindings']) == {'4180/tcp'}
         and gateway['HostConfig']['PortBindings']['4180/tcp'] == [{'HostIp': config['bind_address'], 'HostPort': '80'}]
         and len(server['NetworkSettings']['Networks']) == 1
         and server['HostConfig']['NetworkMode'] not in {'host', 'none', 'bridge', 'default'}
         and any(m['Source'] == str(ctx.workspace) and m['Destination'] == '/opt/cloudbeaver/workspace'
                 and m['Type'] == 'bind' and m['RW'] is True for m in server['Mounts'])
         and server['NetworkSettings']['Networks'].keys() == gateway['NetworkSettings']['Networks'].keys())
    artifact = config.get('mariadb_jdbc')
    extra = [artifact['version'], artifact['sha256'], artifact['image_filename']] if artifact else []
    if any(item['driver'] == 'postgresql' for item in config.get('managed_connections', {}).values()):
        extra.insert(0, '--postgresql')
    raw = docker(['compose', '-f', ctx.compose, 'exec', '-T', ctx.services['cloudbeaver'], '/opt/java/openjdk/bin/java', '-Xms8m', '-Xmx64m', '-Xss512k', '-XX:MaxMetaspaceSize=64m', '-XX:ReservedCodeCacheSize=16m', '-XX:ActiveProcessorCount=1', '-XX:CICompilerCount=2', '-XX:+UseSerialGC',
                  '/opt/cloudbeaver/conf/CloudBeaverHealth.java', '--configuration', *extra], timeout=15)
    current = json.loads(raw)['data']['serverConfig']
    need(current['forceHttps'] is True and current['configurationMode'] is False and current['anonymousAccessEnabled'] is False
         and set(current['enabledAuthProviders']) == {'local', 'reverseProxy'})
    return {'cloudbeaver': 'passed', 'setup': 'closed', 'gateway_only_listener': True,
            'database_login': database_health(config)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('workspace', 'templates', 'managed', 'health'))
    parser.add_argument('--config', type=Path)
    parser.add_argument('--owner')
    args = parser.parse_args()
    if args.action == 'workspace':
        result = workspace(json.loads(args.owner), private(args.config) if args.config is not None else None)
    else:
        value = private(args.config)
        result = {'health': health, 'templates': templates, 'managed': managed}[args.action](value)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
