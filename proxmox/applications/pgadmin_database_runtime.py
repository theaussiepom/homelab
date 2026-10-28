"""Bounded pgAdmin runtime phases, called only by the shared CD coordinator.

No provider/network action, workflow, installer, restore, locks, approval or hold
manager lives here. Trusted playbook source is sent through python -c. Requests
cannot choose commands or guest paths. Saved-profile SQL needs its actual user
session; a separate administrator connection is never called profile acceptance.
"""
import argparse
from contextlib import contextmanager
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import time
from urllib.request import build_opener, ProxyHandler, HTTPRedirectHandler

import pgadmin_endpoint as endpoint

COMPOSE = Path('/opt/homelab-app/compose.yml')
IDENTITY = Path('/etc/homelab-application.json')
CONFIG = Path('/opt/homelab-app/runtime/pgadmin-config.py')
PROFILE = Path('/srv/homelab/data/pgadmin/pgadmin4.db')
BACKUPS = Path('/var/lib/homelab-database-network/pgadmin')
DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']
INSPECT = {'compose_sha256','identity_sha256','config_sha256','image','http_address','selector','target'}
PREPARED = INSPECT | {'identity','container_id','image_id','container_started_at','restart_count',
                     'profile_identity','profile_sha256','before','replacement'}
QUIESCED = {'request_sha256','backup_sha256','profile_sha256','profile_identity',
            'container_started_at','container_finished_at','restart_count'}


def require(value, message):
    if not value: raise ValueError(message)


def sha(value): return hashlib.sha256(value).hexdigest()


def encoded(value): return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def hash_value(value):
    require(isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value), 'Use exact SHA256 bindings')


def file_info(path):
    require(path.resolve(strict=True)==path.absolute(), 'Refuse linked component paths')
    info=path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink==1, 'Require the existing regular component file')
    return info


def private_bytes(path, *, root_owned=True):
    info=file_info(path)
    require(not stat.S_IMODE(info.st_mode)&0o077 and info.st_size<=4*1024*1024
            and (not root_owned or info.st_uid==os.getuid()), 'Require private original component inputs')
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        current=os.fstat(stream.fileno())
        require((current.st_dev,current.st_ino)==(info.st_dev,info.st_ino),'Component input changed during read')
        content=stream.read(4*1024*1024+1)
        require(len(content)<=4*1024*1024,'Oversized component input')
        return content


def file_sha(path):
    file_info(path); result=hashlib.sha256()
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),'rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''): result.update(block)
    return result.hexdigest()


def profile_identity():
    info=file_info(PROFILE)
    attrs=[(name,os.getxattr(PROFILE,name).hex()) for name in sorted(os.listxattr(PROFILE))]
    return dict(device=info.st_dev,inode=info.st_ino,uid=info.st_uid,gid=info.st_gid,
                mode=format(stat.S_IMODE(info.st_mode),'04o'),xattrs_sha256=sha(encoded(attrs)))


@contextmanager
def database(path, *, writable=False):
    file_info(path)
    connection=sqlite3.connect(path.as_uri()+('?mode=rw' if writable else '?mode=ro'),uri=True,timeout=10)
    try:
        if not writable:
            connection.execute('PRAGMA query_only=ON');connection.execute('BEGIN')
        yield connection
    finally:
        connection.close()


def fingerprint(connection, selector=None):
    """Hash a consistent logical snapshot, including WAL; never expose rows."""
    result=hashlib.sha256()
    schema=connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name").fetchall()
    result.update(repr(schema).encode())
    for name, in connection.execute("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name"):
        quoted='"'+name.replace('"','""')+'"'
        columns=[r[1] for r in connection.execute('PRAGMA table_info('+quoted+')')]
        result.update(repr((name,columns)).encode())
        for values in connection.execute('SELECT * FROM '+quoted+' ORDER BY rowid'):
            row=list(values)
            if name=='server' and selector is not None and row[columns.index('id')]==selector['server_id'] \
                    and row[columns.index('user_id')]==selector['user_id']:
                row[columns.index('host')]=None;row[columns.index('port')]=None
            result.update(repr(row).encode());result.update(b'\n')
    return result.hexdigest()


def selected_row(connection, selector):
    endpoint.selection(selector)
    rows=connection.execute('SELECT host,port FROM server WHERE id=? AND user_id=?',
                            (selector['server_id'],selector['user_id'])).fetchall()
    require(len(rows)==1,'Select the exact existing saved server and owner')
    value=dict(zip(('host','port'),rows[0]));endpoint.origin(value);return value


def command(argv):
    environment={k:v for k,v in os.environ.items() if not k.startswith('DOCKER_')}
    result=subprocess.run(argv,capture_output=True,timeout=120,env=environment)
    require(result.returncode==0,'Component command failed; retain the common hold')
    return result.stdout


def app_identity(app):
    require(isinstance(app,dict) and app.get('kind')=='db-tools' and type(app.get('vmid')) is int
            and app['vmid']>=100 and app['vmid'] not in {900,4914,4915,4920},'Select the commissioned db-tools guest')
    return {key:app[key] for key in ('kind','vmid','hostname','address')}


def runtime(app, request, *, running):
    for key in ('compose_sha256','identity_sha256','config_sha256'): hash_value(request[key])
    require(re.fullmatch(r'dpage/pgadmin4@sha256:[0-9a-f]{64}',request['image']),'Retain the exact immutable pgAdmin image')
    address=ipaddress.IPv4Address(request['http_address'])
    require(not(address.is_unspecified or address.is_loopback or address.is_multicast),'Retain the selected HTTP backend')
    raw=private_bytes(COMPOSE);identity_raw=private_bytes(IDENTITY)
    require(sha(raw)==request['compose_sha256'] and sha(identity_raw)==request['identity_sha256']
            and sha(private_bytes(CONFIG,root_owned=False))==request['config_sha256'],'Original component files drifted')
    identity=app_identity(app)
    require(json.loads(identity_raw)==identity,'Commissioned application identity differs')
    compose=json.loads(raw);services=compose.get('services',{})
    require(compose.get('name')=='homelab-db-tools' and set(services)=={'pgadmin'},'Select only the original pgAdmin stack')
    service=services['pgadmin']
    require(service.get('image')==request['image'] and service.get('restart')=='unless-stopped'
            and service.get('ports')==[str(address)+':80:80'],'Retain image, restart policy and HTTP binding')
    ids=command(DOCKER+['compose','-f',str(COMPOSE),'ps','-aq','pgadmin']).decode().split()
    require(len(ids)==1 and re.fullmatch('[0-9a-f]{12,64}',ids[0]),'Require one existing pgAdmin container')
    rows=json.loads(command(DOCKER+['inspect',ids[0]]));require(len(rows)==1,'Ambiguous pgAdmin runtime')
    row=rows[0];state=row['State'];labels=row['Config'].get('Labels',{})
    require(re.fullmatch('[0-9a-f]{64}',row['Id']) and re.fullmatch('sha256:[0-9a-f]{64}',row['Image'])
            and row['Config']['Image']==request['image'] and row['Config'].get('User','')==str(service.get('user',''))
            and labels.get('com.docker.compose.project')=='homelab-db-tools'
            and labels.get('com.docker.compose.service')=='pgadmin'
            and row['HostConfig']['RestartPolicy']['Name']=='unless-stopped'
            and state['Running'] is running and not any(state.get(k,False) for k in ('Paused','Restarting','OOMKilled')),
            'Container identity, state, image or persistent stop policy differs')
    mounts=row.get('Mounts',[])
    require(any(m.get('Type')=='bind' and m.get('Source')==str(PROFILE.parent)
                and m.get('Destination')=='/var/lib/pgadmin' and m.get('RW') is True for m in mounts)
            and any(m.get('Type')=='bind' and m.get('Source')==str(CONFIG)
                and m.get('Destination')=='/pgadmin4/config_local.py' and m.get('RW') is False for m in mounts),
            'Existing profile or OAuth configuration mount differs')
    require(isinstance(state.get('StartedAt'),str) and state['StartedAt']
            and type(row.get('RestartCount')) is int,'Missing runtime lifecycle identity')
    return dict(identity=identity,container_id=row['Id'],image_id=row['Image'],
                container_started_at=state['StartedAt'],restart_count=row['RestartCount']),row


def prepare(target, inspected, selector, legacy_address):
    """Pure endpoint-normalized equivalent of a catalogue compiler."""
    require(isinstance(inspected,dict) and set(inspected)=={'status','action','bindings','selector','before'}
            and inspected['status']=='passed' and inspected['action']=='inspect'
            and inspected['selector']==selector,'Bind the selected inspection and owner')
    endpoint.selection(selector);endpoint.origin(inspected['before']);endpoint.destination(target)
    cutover_origin(inspected['before'],target,legacy_address)
    require(inspected['bindings'].get('target')==target,'Keep the inspected catalogue target')
    request=dict(inspected['bindings'],selector=dict(selector),before=dict(inspected['before']),target=dict(target))
    require(set(request)==PREPARED,'Unexpected inspection fields')
    return request


def cutover_origin(before, target, legacy_address):
    """The saved hostname is an observed literal, separate from the old NIC IP.

    Do not resolve it or substitute an inferred address. Its exact value remains
    in the inspected request and is compared again inside the update transaction.
    """
    endpoint.origin(before);endpoint.destination(target)
    legacy=ipaddress.IPv4Address(legacy_address)
    require(str(legacy)!=target['address'] and before['port']==5432,
            'Bind the distinct legacy network endpoint and saved PostgreSQL port')


def validate_request(request):
    """Own the complete component shape without requiring guest catalogue files."""
    require(isinstance(request,dict) and set(request)==PREPARED,'Use the closed pre-quiescence runtime request')
    require(isinstance(request['identity'],dict) and set(request['identity'])=={'kind','vmid','hostname','address'},
            'Use the original projected application identity')
    identity=app_identity(request['identity'])
    require(isinstance(identity['hostname'],str) and re.fullmatch('[a-z][a-z0-9-]{0,62}',identity['hostname'])
            and isinstance(identity['address'],str),'Bind the commissioned identity')
    ipaddress.IPv4Address(identity['address'])
    endpoint.selection(request['selector']);endpoint.origin(request['before']);endpoint.destination(request['target'])
    replacement=request['replacement']
    require(isinstance(replacement,dict) and set(replacement)=={'selector','before','after','removed_servers',
            'created_server_id','server_sequence','database_rows_count','name','owner_auth_source','profile_rows_sha256'},'Bind the closed registration replacement')
    require(replacement['selector']==request['selector'] and replacement['before']==request['before']
            and replacement['after']==endpoint.destination(request['target']) and replacement['name']=='PostgreSQL'
            and replacement['owner_auth_source']=='oauth2','Bind the approved OAuth settings and new endpoint')
    removed=replacement['removed_servers']
    require(isinstance(removed,list) and 0<len(removed)<=100,'Bind the bounded complete old registration inventory')
    ids=[]
    for row in removed:
        require(isinstance(row,dict) and set(row)=={'server_id','user_id','host','port'},'Bind exact old registration fields')
        endpoint.selection({k:row[k] for k in ('server_id','user_id')});endpoint.origin({k:row[k] for k in ('host','port')})
        ids.append(row['server_id'])
    require(ids==sorted(set(ids)) and type(replacement['created_server_id']) is int
            and type(replacement['server_sequence']) is int and replacement['server_sequence']>=0
            and replacement['created_server_id']==max(*ids,replacement['server_sequence'])+1
            and dict(request['selector'],**request['before']) in removed,'Bind a fresh registration and its original settings owner')
    hash_value(replacement['profile_rows_sha256'])
    require(type(replacement['database_rows_count']) is int and replacement['database_rows_count']>=0,
            'Bind the selected registration database-settings count')
    for key in ('compose_sha256','identity_sha256','config_sha256','profile_sha256'): hash_value(request[key])
    require(isinstance(request['image'],str) and re.fullmatch(r'dpage/pgadmin4@sha256:[0-9a-f]{64}',request['image'])
            and isinstance(request['image_id'],str) and re.fullmatch('sha256:[0-9a-f]{64}',request['image_id'])
            and isinstance(request['container_id'],str) and re.fullmatch('[0-9a-f]{64}',request['container_id'])
            and type(request['restart_count']) is int and request['restart_count']>=0
            and isinstance(request['container_started_at'],str) and request['container_started_at'],
            'Bind immutable image/container and observed lifecycle identity')
    metadata=request['profile_identity']
    require(isinstance(metadata,dict) and set(metadata)=={'device','inode','uid','gid','mode','xattrs_sha256'}
            and all(type(metadata[k]) is int and metadata[k]>=0 for k in ('device','inode','uid','gid'))
            and isinstance(metadata['mode'],str) and re.fullmatch('0[0-7]{3}',metadata['mode']), 'Bind exact profile identity')
    hash_value(metadata['xattrs_sha256']);ipaddress.IPv4Address(request['http_address'])
    return True


def validate_binding(request, catalogue, client_vmids, legacy_address):
    """Pure controller gate using the common catalogue validator, not a copy."""
    import database_networks as networks
    networks.validate(catalogue);validate_request(request)
    identity=request['identity']
    require(isinstance(client_vmids,list) and client_vmids and all(type(v) is int for v in client_vmids)
            and len(set(client_vmids))==len(client_vmids) and identity['vmid'] in client_vmids,'Select the exact client group')
    members={m['vmid']:m for m in catalogue['networks']['postgresql']['clients']}
    require(set(client_vmids)<=set(members) and members[identity['vmid']]['hostname']==identity['hostname'],
            'Client identity or PostgreSQL membership differs')
    require(request['target']==networks.endpoint(catalogue,'postgresql'),'Target differs from the selected cutover')
    cutover_origin(request['before'],request['target'],legacy_address)
    return True


def base_request(request): return {k:v for k,v in request.items() if k!='quiesced'}


def backup_location(request):
    """Pure fixed guest location, also usable by common NAS-custody wiring."""
    validate_request(base_request(request))
    return BACKUPS/sha(encoded(base_request(request)))/'profile.sqlite'


def admit(app, request, *, running, old=True):
    expected=PREPARED if 'quiesced' not in request else PREPARED|{'quiesced'}
    require(isinstance(request,dict) and set(request)==expected,'Use only the finite prepared component request')
    validate_request(base_request(request))
    bound,row=runtime(app,request,running=running)
    require(all(bound[k]==request[k] for k in ('identity','container_id','image_id'))
            and profile_identity()==request['profile_identity'],'Runtime or profile identity drifted')
    if old:
        require(bound['container_started_at']==request['container_started_at']
                and bound['restart_count']==request['restart_count'],'Container restarted after inspection')
        with database(PROFILE) as connection:
            require(endpoint.replacement_plan(connection,request['selector'],request['before'],request['target'])
                    ==request['replacement'],'Registration replacement or settings drifted')
            require(fingerprint(connection)==request['profile_sha256'],'Profile changed after inspection')
    return bound,row


def backup_path(request, *, create=False):
    operation=backup_location(request).parent
    if create:
        # Walk the fixed namespace before creating anything: an unexpected
        # parent symlink must not redirect even a directory creation.
        descriptor=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
        current=Path('/')
        try:
            for part in BACKUPS.parts[1:]:
                current=current/part
                try:
                    child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=descriptor)
                except FileNotFoundError:
                    require(current in (BACKUPS.parent,BACKUPS),'Missing fixed backup parent')
                    os.mkdir(part,mode=0o700,dir_fd=descriptor)
                    child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=descriptor)
                os.close(descriptor);descriptor=child
        finally:
            os.close(descriptor)
    for directory in (BACKUPS,):
        info=directory.lstat()
        require(directory.resolve()==directory and stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid()
                and stat.S_IMODE(info.st_mode)==0o700,'Require the fixed private guest backup directory')
    if create: operation.mkdir(mode=0o700)  # Preserve an existing/failed backup, never overwrite it.
    info=operation.lstat()
    require(operation.resolve()==operation and stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid()
            and stat.S_IMODE(info.st_mode)==0o700,'Guest backup custody differs')
    return operation/'profile.sqlite'


def quiesced(request):
    receipt=request.get('quiesced')
    require(isinstance(receipt,dict) and set(receipt)==QUIESCED,'Bind the exact common quiesce result')
    for key in ('request_sha256','backup_sha256','profile_sha256'): hash_value(receipt[key])
    require(all(isinstance(receipt[k],str) and receipt[k] for k in
                ('container_started_at','container_finished_at'))
            and type(receipt['restart_count']) is int and receipt['restart_count']>=0
            and receipt['container_started_at']==request['container_started_at']
            and receipt['restart_count']==request['restart_count'],'Bind the original stopped lifecycle receipt')
    require(receipt['request_sha256']==sha(encoded(base_request(request)))
            and receipt['profile_sha256']==request['profile_sha256']
            and receipt['profile_identity']==request['profile_identity'],'Quiesce result does not bind this request')
    path=backup_path(request);private_bytes_info=file_info(path)
    require(private_bytes_info.st_uid==os.getuid() and stat.S_IMODE(private_bytes_info.st_mode)==0o600
            and file_sha(path)==receipt['backup_sha256'],'Coherent backup differs')
    with database(path) as connection:
        require(fingerprint(connection)==request['profile_sha256'],'Backup profile differs from inspection')
        expected=sqlite3.connect(':memory:')
        try:
            connection.backup(expected)
            endpoint.replacement_apply(expected,request['replacement'])
            protected=fingerprint(expected)
        finally: expected.close()
    return receipt,protected


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): raise ValueError('Unexpected HTTP redirect')


def http_ready(address):
    opener=build_opener(ProxyHandler({}),NoRedirect())
    for attempt in range(30):
        try:
            with opener.open('http://'+address+':80/misc/ping',timeout=5) as response:
                if response.status==200 and response.read(64).strip()==b'PING': return
        except (OSError,ValueError): pass
        if attempt<29: time.sleep(1)
    raise ValueError('Retained pgAdmin HTTP listener did not become ready')


def execute(action, app, request):
    if action=='inspect':
        require(isinstance(request,dict) and set(request)==INSPECT,'Use only fixed inspection arguments')
        endpoint.selection(request['selector']);bound,_=runtime(app,request,running=True)
        metadata=profile_identity()
        with database(PROFILE) as connection:
            before=selected_row(connection,request['selector']);digest=fingerprint(connection)
            replacement=endpoint.replacement_plan(connection,request['selector'],before,request['target'])
        require(profile_identity()==metadata,'Profile identity changed during inspection')
        return dict(status='passed',action='inspect',bindings=dict(bound,**{k:request[k] for k in INSPECT-{'selector'}},
                    profile_identity=metadata,profile_sha256=digest,replacement=replacement),selector=dict(request['selector']),before=before)
    require(action in ('preflight','quiesce','activate','verify'),'Select a finite component action')
    validate_request(base_request(request))
    if action in ('preflight','quiesce'):
        require('quiesced' not in request,'Do not replay a quiesced request')
        _,row=admit(app,request,running=True)
        operation=backup_location(request).parent
        require(not operation.exists() and not operation.is_symlink(),'Preserve the existing or failed component backup')
        if BACKUPS.exists() or BACKUPS.is_symlink():
            info=BACKUPS.lstat()
            require(BACKUPS.resolve()==BACKUPS and stat.S_ISDIR(info.st_mode)
                    and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700,'Backup namespace custody differs')
        if action=='preflight': return dict(status='passed',action=action,changed=False)
        path=backup_path(request,create=True)
        command(DOCKER+['stop','--time','60',row['Id']])
        _,stopped=admit(app,request,running=False)
        with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb'): pass
        deadline=time.monotonic()+60
        def progress(*args): require(time.monotonic()<deadline,'Coherent profile backup timed out')
        with database(PROFILE) as source, database(path,writable=True) as destination:
            source.backup(destination,pages=128,progress=progress,sleep=0.05)
            require(destination.execute('PRAGMA integrity_check').fetchall()==[('ok',)]
                    and fingerprint(destination)==request['profile_sha256'],'Coherent backup validation failed')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
        directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try: os.fsync(directory)
        finally: os.close(directory)
        require(profile_identity()==request['profile_identity'],'Profile metadata changed while quiescing')
        receipt=dict(request_sha256=sha(encoded(request)),backup_sha256=file_sha(path),
            profile_sha256=request['profile_sha256'],profile_identity=profile_identity(),
            container_started_at=stopped['State']['StartedAt'],container_finished_at=stopped['State']['FinishedAt'],
            restart_count=stopped['RestartCount'])
        return dict(status='passed',action=action,changed=True,quiesced=receipt,backup_path=str(path))
    receipt,protected=quiesced(request)
    bound,row=admit(app,request,running=action=='verify',old=action=='activate')
    if action=='activate':
        require(row['State']['StartedAt']==receipt['container_started_at']
                and row['State']['FinishedAt']==receipt['container_finished_at']
                and row['RestartCount']==receipt['restart_count'],'pgAdmin did not remain stopped across the provider cycle')
        def guard(connection):
            require(fingerprint(connection)==protected
                    and profile_identity()==request['profile_identity'],'Unapproved profile values or metadata changed')
        with database(PROFILE,writable=True) as connection:
            endpoint.replacement_apply(connection,request['replacement'],validate_update=guard)
        command(DOCKER+['start',bound['container_id']])
        bound,_=admit(app,request,running=True,old=False)
    with database(PROFILE) as connection:
        after=dict(host=request['target']['address'],port=request['target']['port'])
        selected=dict(server_id=request['replacement']['created_server_id'],user_id=request['selector']['user_id'])
        endpoint.plan(connection,selected,after,request['target'])
        require(fingerprint(connection)==protected,'Unapproved profile values changed')
    http_ready(request['http_address'])
    return dict(status='passed',action=action,changed=action=='activate',
                profile_verified=True,database_verified=False,
                server_id=request['replacement']['created_server_id'],user_id=request['selector']['user_id'],
                database_verification_reason='existing_authenticated_profile_session_required',
                container_started_at=bound['container_started_at'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--action',required=True,choices=('inspect','preflight','quiesce','activate','verify'))
    args=parser.parse_args()
    try:
        require(os.geteuid()==0,'Run only through the admitted guest maintenance playbook')
        content=sys.stdin.buffer.read(65537);require(len(content)<=65536,'Oversized component input')
        values=json.loads(content);require(set(values)=={'app','request'},'Unexpected component input')
        print(json.dumps(execute(args.action,values['app'],values['request']),sort_keys=True))
    except Exception:
        raise SystemExit('pgAdmin runtime maintenance held; preserve common evidence. No implicit resume, restore or retry.') from None
