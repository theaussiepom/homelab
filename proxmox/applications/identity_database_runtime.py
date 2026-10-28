"""Finite Authentik target phases; the common caller owns all custody and locks.

No helper installation, local operation state, approval, backup, retry or restore
is implemented here. Inspect/preflight/verify only read. Source is passed by the
pinned playbook, never selected through a path or command in the runtime packet.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

import identity_database as identity

COMPOSE = Path('/opt/homelab-app/compose.yml')
IDENTITY = Path('/etc/homelab-application.json')
UID_MAP = Path('/proc/self/uid_map')
PVE = Path('/etc/pve')
SERVICES = ('server', 'worker', 'redis')
ACTIONS = {'inspect', 'preflight', 'quiesce', 'activate', 'verify'}
DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']
STABLE = {'id', 'image', 'image_id', 'config_sha256', 'host_config_sha256',
          'mounts_sha256', 'bind_sources_sha256'}
BINDING = STABLE | {'started_at', 'endpoint'}
FIELDS = {'app', 'before', 'after', 'compose_sha256', 'candidate_sha256',
          'runtime', 'client_vmids', 'allow_guest_restart'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def parsed(raw):
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        raise ValueError('Invalid private Authentik runtime input') from None


def private(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                and info.st_size <= 1024 * 1024, 'Expected a private owned Authentik input')
        raw = stream.read(1024 * 1024 + 1)
    require(len(raw) <= 1024 * 1024 and b'\x00' not in raw, 'Invalid Authentik input size or contents')
    return raw


def app_identity(app):
    require(isinstance(app, dict) and set(app) == {'kind','vmid','hostname','address','mac'}
            and app['kind'] == 'identity' and type(app['vmid']) is int and app['vmid'] >= 100
            and app['vmid'] not in {900,4914,4915,4920}
            and isinstance(app['hostname'], str) and re.fullmatch('[a-z][a-z0-9-]{0,62}', app['hostname'])
            and isinstance(app['mac'], str) and re.fullmatch(r'02(?::[0-9a-f]{2}){5}', app['mac']),
            'Select the exact commissioned Authentik identity')
    identity.endpoint({'address':app['address'], 'port':1})


def guest_guard(app):
    app_identity(app)
    require(os.geteuid() == 0 and not PVE.exists(), 'Use only the selected application guest')
    mapping = UID_MAP.read_text()
    require(re.search(r'(?m)^\s*0\s+[1-9][0-9]*\s+[1-9][0-9]*\s*$', mapping)
            and not re.search(r'(?m)^\s*[0-9]+\s+0\s+[1-9][0-9]*\s*$', mapping),
            'Refuse a privileged or host-root namespace')
    require(parsed(private(IDENTITY)) == {k:app[k] for k in ('kind','vmid','hostname','address')},
            'The installed Authentik identity differs')


class CommandFailed(RuntimeError):
    """Never expose captured Docker output in a public exception."""


def command(argv, data=None, timeout=180):
    result = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, timeout=timeout, cwd=COMPOSE.parent,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C.UTF-8',
             'LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'})
    if result.returncode:
        raise CommandFailed('Authentik runtime command failed; preserve caller custody')
    return result.stdout


def compose_command(*args, stdin=False):
    return DOCKER + ['compose','--project-directory',str(COMPOSE.parent),'-p','homelab-identity',
                     '-f','-' if stdin else str(COMPOSE),*args]


def environment(rows):
    require(isinstance(rows, list) and all(isinstance(v,str) and '=' in v for v in rows),
            'Invalid container environment shape')
    pairs = [v.split('=',1) for v in rows]
    require(len({k for k,v in pairs}) == len(pairs), 'Ambiguous container environment')
    return dict(pairs)


def endpoint_env(env):
    host, port = env.get(identity.HOST), env.get(identity.PORT, str(identity.DEFAULT_PORT))
    require(isinstance(port,str) and re.fullmatch(r'[1-9][0-9]{0,4}',port), 'Invalid SQL runtime port')
    result = {'address':host,'port':int(port)}
    identity.endpoint(result, private=False)
    return result


def source(raw):
    value = parsed(raw)
    require(isinstance(value,dict) and value.get('name') == 'homelab-identity'
            and isinstance(value.get('services'),dict) and set(value['services']) == set(SERVICES),
            'Select only the installed Authentik stack')
    for name, service in value['services'].items():
        require(isinstance(service,dict) and service.get('restart') == 'unless-stopped'
                and isinstance(service.get('image'),str)
                and re.fullmatch(r'(?:[A-Za-z0-9._:/-]+@)?sha256:[0-9a-f]{64}',service['image'])
                and not any(k in service for k in ('build','env_file','extends')),
                'Preserve pinned images and persistent manually stopped clients')
    for name in ('server','worker'):
        service = value['services'][name]
        require(service.get('command') == name and isinstance(service.get('environment'),dict)
                and service['environment'].get('AUTHENTIK_REDIS__HOST') == 'redis',
                'Preserve both Authentik modes and local Redis')
    require(value['services']['server']['image'] == value['services']['worker']['image'],
            'The Authentik image identities differ')
    before = endpoint_env(value['services']['server']['environment'])
    require(endpoint_env(value['services']['worker']['environment']) == before, 'Partial installed SQL endpoint')
    return value, before


def bind_sources(mounts):
    values = []
    for mount in mounts:
        if mount['Type'] != 'bind':
            continue
        path = Path(mount['Source']); info = path.lstat()
        require(path.is_absolute() and not stat.S_ISLNK(info.st_mode)
                and (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)),
                'A bound Authentik data or secret source changed shape')
        item = [str(path),info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)]
        if stat.S_ISREG(info.st_mode):
            require(info.st_size <= 1024 * 1024, 'Oversized bound configuration file')
            with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
                current = os.fstat(stream.fileno())
                require((current.st_dev,current.st_ino,current.st_size) == (info.st_dev,info.st_ino,info.st_size),
                        'A bound configuration file changed during inspection')
                item.append(sha(stream.read(1024*1024+1)))
        values.append(item)
    return sha(encoded(sorted(values)))


def binding(name, row):
    config, state, host = row['Config'], row['State'], row['HostConfig']
    labels = config.get('Labels',{})
    require(labels.get('com.docker.compose.project') == 'homelab-identity'
            and labels.get('com.docker.compose.service') == name
            and host.get('RestartPolicy',{}).get('Name') == 'unless-stopped'
            and re.fullmatch('[0-9a-f]{64}',row['Id'])
            and re.fullmatch('sha256:[0-9a-f]{64}',row['Image']), 'A bound container identity or restart policy differs')
    normalized = copy.deepcopy(config)
    if normalized.get('Hostname') == row['Id'][:12]:
        normalized.pop('Hostname')
    env = environment(config['Env'])
    endpoint = None
    if name != 'redis':
        require(config.get('Cmd') == [name], 'The running Authentik mode differs')
        endpoint = endpoint_env(env)
        env.pop(identity.HOST,None); env.pop(identity.PORT,None)
        normalized['Labels'].pop('com.docker.compose.config-hash',None)
        normalized['Labels'].pop('com.docker.compose.replace',None)
    normalized['Env'] = env
    mounts = sorted(row['Mounts'],key=lambda m:m['Destination'])
    require(len({m['Destination'] for m in mounts}) == len(mounts), 'Ambiguous Authentik mounts')
    return {'id':row['Id'],'image':config['Image'],'image_id':row['Image'],
        'config_sha256':sha(encoded(normalized)), 'host_config_sha256':sha(encoded(host)),
        'mounts_sha256':sha(encoded(mounts)), 'bind_sources_sha256':bind_sources(mounts),
        'started_at':state['StartedAt'],'endpoint':endpoint}



def declared_runtime(name,service,row):
    """Refuse a source/runtime secret, environment or data-mount disagreement."""
    image_env = parsed(command(DOCKER+['image','inspect','--format','{{json .Config.Env}}',row['Image']]))
    wanted = environment(image_env or [])
    declared = service.get('environment',{})
    require(isinstance(declared,dict) and all(isinstance(v,str) for v in declared.values()),
            'Use the installed literal environment')
    wanted.update({k:v.replace('$$','$') for k,v in declared.items()})
    require(environment(row['Config']['Env']) == wanted, 'Compose and actual container environment differ')
    mounts = []
    for mount in service.get('volumes',[]):
        if isinstance(mount,str):
            parts = mount.split(':')
            require(len(parts) in (2,3) and (len(parts)==2 or parts[2] in {'ro','rw'}),
                    'Review unsupported existing mount syntax')
            src,target = parts[:2]; writable = len(parts)==2 or parts[2]=='rw'
        else:
            require(isinstance(mount,dict) and mount.get('type')=='bind'
                    and type(mount.get('read_only',False)) is bool, 'Preserve existing bind mounts only')
            src,target,writable = mount.get('source'),mount.get('target'),not mount.get('read_only',False)
        require(isinstance(src,str) and src.startswith('/') and isinstance(target,str) and target.startswith('/'),
                'Use the existing absolute data/secret bind sources')
        mounts.append((src,target,writable))
    require(all(m.get('Type')=='bind' for m in row['Mounts'])
            and sorted(mounts)==sorted((m['Source'],m['Destination'],m['RW']) for m in row['Mounts']),
            'Compose and actual data/secret mounts differ')
    if name != 'redis':
        for key,target in (('AUTHENTIK_SECRET_KEY','/run/secrets/authentik-secret-key'),
                           ('AUTHENTIK_POSTGRESQL__PASSWORD','/run/secrets/postgresql-password')):
            require(wanted.get(key)=='file://'+target and any(dst==target and not rw
                    and Path(src).is_file() for src,dst,rw in mounts), 'Preserve the original file-backed credentials')


def observe(document):
    bindings, states, rows = {}, {}, {}
    for name in SERVICES:
        ids = command(compose_command('ps','--all','--quiet',name)).decode().split()
        require(len(ids) == 1 and re.fullmatch('[0-9a-f]{12,64}',ids[0]), 'Expected one bound container per service')
        row = parsed(command(DOCKER+['inspect','--format','{{json .}}',ids[0]]))
        declared_runtime(name,document['services'][name],row)
        current = binding(name,row)
        require(current['image'] == document['services'][name]['image'], 'Installed Compose and container image differ')
        bindings[name] = current; rows[name] = row
        states[name] = {'running':row['State']['Running'],'status':row['State']['Status'],
                        'health':row['State'].get('Health',{}).get('Status','')}
    return bindings, states, rows


def request_valid(request):
    require(isinstance(request,dict) and set(request) == FIELDS, 'Unsupported closed Authentik runtime request')
    app_identity(request['app']); identity.endpoint(request['before'],private=False); identity.endpoint(request['after'])
    require(type(request['allow_guest_restart']) is bool
            and request['before'] != request['after']
            and all(isinstance(request[k],str) and re.fullmatch('[0-9a-f]{64}',request[k])
                    for k in ('compose_sha256','candidate_sha256'))
            and request['compose_sha256'] != request['candidate_sha256']
            and isinstance(request['client_vmids'],list) and len(request['client_vmids']) == 2
            and all(type(v) is int for v in request['client_vmids'])
            and request['client_vmids'] == sorted(set(request['client_vmids']))
            and request['app']['vmid'] in request['client_vmids'], 'Invalid finite Authentik runtime bindings')
    require(isinstance(request['runtime'],dict) and set(request['runtime']) == set(SERVICES), 'Bind all three current containers')
    for name, row in request['runtime'].items():
        require(isinstance(row,dict) and set(row) == BINDING
                and isinstance(row['id'],str) and re.fullmatch('[0-9a-f]{64}',row['id'])
                and isinstance(row['image'],str) and re.fullmatch(r'(?:[A-Za-z0-9._:/-]+@)?sha256:[0-9a-f]{64}',row['image'])
                and isinstance(row['image_id'],str) and re.fullmatch('sha256:[0-9a-f]{64}',row['image_id'])
                and isinstance(row['started_at'],str) and 1 <= len(row['started_at']) <= 64
                and all(isinstance(row[k],str) and re.fullmatch('[0-9a-f]{64}',row[k])
                        for k in STABLE if k.endswith('_sha256'))
                and row['endpoint'] == (request['before'] if name != 'redis' else None),
                'Invalid original runtime binding')
    require(request['runtime']['server']['image'] == request['runtime']['worker']['image']
            and request['runtime']['server']['image_id'] == request['runtime']['worker']['image_id'],
            'Both Authentik modes must keep the same immutable image')
    return True


def validate_binding(runtime_packet,catalogue,client_vmids,legacy_address):
    request_valid(runtime_packet)
    require(isinstance(catalogue,dict) and catalogue.get('schema') == 'homelab-database-networks-v1',
            'Use the shared database catalogue')
    try:
        net = catalogue['networks']['postgresql']; members = {m['vmid']:m for m in net['clients']}
        app = runtime_packet['app']; member = members[app['vmid']]
    except (KeyError,TypeError):
        raise ValueError('The Authentik client is absent from the catalogue') from None
    require(len(members) == len(net['clients']) and isinstance(client_vmids,list)
            and all(type(v) is int for v in client_vmids) and len(set(client_vmids)) == len(client_vmids) == 2
            and runtime_packet['client_vmids'] == sorted(client_vmids) and set(client_vmids) <= members.keys()
            and member['hostname'] == app['hostname']
            and runtime_packet['before'] == {'address':legacy_address,'port':identity.DEFAULT_PORT}
            and runtime_packet['after'] == {'address':net['server']['address'],'port':identity.DEFAULT_PORT},
            'Authentik runtime/catalogue/client-group binding differs')
    identity.endpoint(runtime_packet['before'])
    return True


def prepare(catalogue,inspected,client_vmids,legacy_address,*,allow_guest_restart=True):
    require(isinstance(inspected,dict) and inspected.get('status') == 'passed' and inspected.get('action') == 'inspect'
            and all(inspected['states'][n] == {'running':True,'status':'running','health':'healthy'} for n in SERVICES),
            'Inspect the running commissioned Authentik stack first')
    before = inspected['before']
    after = {'address':catalogue['networks']['postgresql']['server']['address'],'port':identity.DEFAULT_PORT}
    require(inspected['after'] == after, 'Inspection used another candidate endpoint')
    request = {'app':copy.deepcopy(inspected['app']),'before':copy.deepcopy(before),'after':after,
        'compose_sha256':inspected['compose_sha256'],'candidate_sha256':inspected['candidate_sha256'],
        'runtime':copy.deepcopy(inspected['runtime']),'client_vmids':sorted(client_vmids),
        'allow_guest_restart':allow_guest_restart}
    validate_binding(request,catalogue,client_vmids,legacy_address)
    return request


def match_runtime(current,expected,endpoint,*,recreated=False,lifecycle=False):
    for name in SERVICES:
        old, actual = expected[name], current[name]
        for key in STABLE:
            if key == 'id' and recreated and name != 'redis':
                require(actual[key] != old[key], 'Both Authentik clients must be recreated once')
            else:
                require(actual[key] == old[key], 'Current image/configuration/data binding differs')
        require(actual['endpoint'] == (endpoint if name != 'redis' else None), 'A runtime SQL endpoint differs')
        if (name == 'redis' and not lifecycle) or (name != 'redis' and not recreated):
            require(actual['started_at'] == old['started_at'], 'An unapproved container lifecycle occurred')


def replacement_history(rows,previous):
    for name in ('server','worker'):
        require(rows[name]['Config']['Labels'].get('com.docker.compose.replace') == previous[name]['id'],
                'The recreated client does not name its exact original container')


def health(rows,states):
    require(all(states[n] == {'running':True,'status':'running','health':'healthy'} for n in SERVICES),
            'All three runtime health checks must pass')
    for name in ('server','worker'):
        command(DOCKER+['exec',rows[name]['Id'],'ak','healthcheck'],timeout=30)
    require(command(DOCKER+['exec',rows['redis']['Id'],'redis-cli','ping'],timeout=10).strip() == b'PONG',
            'Local Redis did not answer PONG')


def run(action,app,request):
    require(action in ACTIONS, 'Unsupported Authentik runtime action'); guest_guard(app)
    current_raw = private(COMPOSE); document,_ = source(current_raw)
    if action == 'inspect':
        require(isinstance(request,dict) and set(request) == {'after'},
                'Inspect with only the finite contract-derived after endpoint')
        identity.endpoint(request['after'])
        before = source(current_raw)[1]
        wanted = identity.candidate(current_raw,before,request['after'])
        observed,states,_ = observe(document)
        return {'status':'passed','action':action,'changed':False,'app':app,
                'before':before,'after':request['after'],'compose_sha256':sha(current_raw),
                'candidate_sha256':sha(wanted),'runtime':observed,'states':states}
    request_valid(request)
    require(request['app'] == app, 'Runtime packet selects another application')
    expected_hash = request['candidate_sha256'] if action == 'verify' else request['compose_sha256']
    require(sha(current_raw) == expected_hash, 'Current Compose differs from the bound runtime phase')
    if action == 'verify':
        wanted = current_raw
    else:
        wanted = identity.candidate(current_raw,request['before'],request['after'])
        require(sha(wanted) == request['candidate_sha256'], 'The locally derived candidate hash differs')
    observed,states,rows = observe(document)
    match_runtime(observed,request['runtime'],request['after'] if action == 'verify' else request['before'],
                  recreated=action == 'verify',lifecycle=action in {'activate','verify'} and request['allow_guest_restart'])
    if action in {'preflight','verify'}:
        if action == 'verify': replacement_history(rows,request['runtime'])
        health(rows,states)
        return {'status':'passed','action':action,'changed':False,'compose_sha256':sha(current_raw),
                'runtime':observed,'states':states}
    require(all(states[n]['running'] is (action == 'quiesce') and states[n]['status'] ==
                ('running' if action == 'quiesce' else 'exited') for n in ('server','worker'))
            and states['redis']['running'] is True, 'Require both original SQL clients in the selected stopped/running phase')
    if action == 'quiesce':
        command(compose_command('stop','--timeout','60','server','worker'),timeout=150)
    else:
        require(states['redis']['health'] == 'healthy', 'Redis must remain healthy before activation')
        command(compose_command('config','--quiet',stdin=True),data=wanted,timeout=30)
        with os.fdopen(os.open(COMPOSE,os.O_RDWR|os.O_NOFOLLOW),'r+b') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                    and stream.read() == current_raw and COMPOSE.lstat().st_ino == info.st_ino,
                    'Compose changed before the endpoint-only write')
            stream.seek(0);stream.write(wanted);stream.truncate();stream.flush();os.fsync(stream.fileno())
        command(compose_command('up','-d','--no-deps','--no-build','--force-recreate','--pull','never',
                                '--wait','--wait-timeout','120','server','worker'),timeout=150)
    require(private(COMPOSE) == (wanted if action == 'activate' else current_raw), 'Compose phase readback differs')
    after,after_states,after_rows = observe(parsed(wanted) if action == 'activate' else document)
    match_runtime(after,observed,request['after'] if action == 'activate' else request['before'],
                  recreated=action == 'activate')
    if action == 'activate':
        replacement_history(after_rows,observed)
        health(after_rows,after_states)
    else:
        require(all(after_states[n] == states[n] for n in ('redis',))
                and all(after_states[n]['running'] is False and after_states[n]['status'] == 'exited'
                        for n in ('server','worker')), 'Both SQL clients did not stay stopped')
    return {'status':'passed','action':action,'changed':True,'compose_sha256':sha(private(COMPOSE)),
            'runtime':after,'states':after_states}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=sorted(ACTIONS))
    args = parser.parse_args()
    try:
        import sys
        envelope = parsed(sys.stdin.buffer.read(1024*1024+1))
        require(isinstance(envelope,dict) and set(envelope)=={'app','request'}, 'Unsupported runtime envelope')
        print(json.dumps(run(args.action,envelope['app'],envelope['request'])))
    except Exception:
        raise SystemExit('Authentik runtime phase held; preserve caller evidence. No automatic retry.') from None
