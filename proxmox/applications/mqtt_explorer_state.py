"""Closed Explorer identities and descriptor-anchored owned state operations."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import stat

DATA = '/srv/homelab/data/mqtt-explorer'
CUSTODY = '/var/lib/homelab-mqtt-explorer'
RUNTIME = '/opt/homelab-app/runtime'
PROJECT = 'homelab-mqtt'
SERVICES = {'mqtt_explorer': 'mqtt_explorer', 'explorer_gateway': 'explorer_gateway'}
BROKER = {'project': PROJECT, 'service': 'mqtt', 'config_path': '/srv/homelab/data/mqtt/config'}
MAX_FILE = 1024 * 1024


def need(ok):
    if not ok:
        raise ValueError('MQTT Explorer owned state refused')


def owner(info):
    return info.st_uid, info.st_gid


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_uid, info.st_gid, info.st_mode, info.st_nlink)


def name(value):
    need(isinstance(value, str) and re.fullmatch('[a-z0-9][a-z0-9_-]{0,127}', value))
    return value


def path(value, *, runtime=False):
    need(isinstance(value, str) and value.startswith('/') and not value.startswith('//')
         and str(Path(value)) == value and not any(part in ('', '.', '..') for part in value.split('/')[1:]))
    need(not any(ord(c) < 32 or ord(c) == 127 or c in '$:\\' for c in value))
    if runtime:
        need(value == RUNTIME or re.fullmatch(re.escape(RUNTIME)+'/[a-z0-9_-]+(?:/[a-z0-9_-]+)*',value))
    else:
        need(value.startswith('/srv/') or value.startswith('/var/lib/'))
        need(not any(value == p or value.startswith(p+'/') or p.startswith(value+'/')
                     for p in (CUSTODY, '/var/lib/homelab-inputs', '/var/lib/homelab-state', '/var/lib/homelab-bootstrap')))
    return value


def context(value=None):
    """Read finite compiled metadata only; legacy omission retains exact paths."""
    value = {} if value is None else value
    need(isinstance(value, dict) and set(value) <= {'project', 'services', 'data_path', 'runtime_directory', 'runtime_id', 'custody_directory'})
    services = value.get('services', SERVICES)
    need(isinstance(services, dict) and set(services) == set(SERVICES)
         and all(isinstance(row, str) for row in services.values()) and len(set(services.values())) == 2)
    services = {key: name(row) for key,row in services.items()}
    selected = {'project': name(value.get('project', PROJECT)), 'services': services,
        'data_path': path(value.get('data_path', DATA)),
        'runtime_directory': path(value.get('runtime_directory', RUNTIME), runtime=True),
        'runtime_id': name(value.get('runtime_id', 'mqtt_explorer'))}
    custody=value.get('custody_directory',CUSTODY)
    need(isinstance(custody,str) and (custody==CUSTODY or re.fullmatch(re.escape(CUSTODY)+'/[a-z0-9_-]+(?:/[a-z0-9_-]+)*',custody)))
    selected['custody']=custody
    return selected


def public_context(value):
    need(isinstance(value, dict))
    return context({key: value[key] for key in ('project','services','data_path','runtime_directory','runtime_id','custody_directory') if key in value})


def broker_context(value=None):
    value = BROKER if value is None else value
    need(isinstance(value, dict) and set(value) == set(BROKER))
    return {'project': name(value['project']), 'service': name(value['service']), 'config_path': path(value['config_path'])}


@contextmanager
def directory(value, *, create=False, uid=None, gid=None, mode=0o700):
    """Walk from / using NOFOLLOW on every component; never follow ancestors."""
    value = str(value)
    need(value.startswith('/') and not value.startswith('//') and str(Path(value)) == value
         and not any(part in ('', '.', '..') for part in value.split('/')[1:]))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = Path(value).parts[1:]
        for index, part in enumerate(parts):
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                need(create and index == len(parts)-1)
                os.mkdir(part, mode, dir_fd=fd)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    if uid is not None:
                        os.fchown(child, uid, uid if gid is None else gid)
                    os.fchmod(child, mode);os.fsync(fd)
                except BaseException:
                    os.close(child);raise
            os.close(fd);fd = child
        need(stat.S_ISDIR(os.fstat(fd).st_mode))
        yield fd
    finally:
        os.close(fd)


def leaf(value):
    need(isinstance(value, str) and re.fullmatch('[A-Za-z0-9_.-]{1,160}', value) and value not in ('.','..'))
    return value


def info(fd, value):
    try:
        return os.stat(leaf(value), dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def read(fd, value, *, uid=None, gid=None, modes=None):
    value = leaf(value)
    opened = os.open(value, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    with os.fdopen(opened, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= MAX_FILE)
        if uid is not None:
            need(owner(before) == (uid, uid if gid is None else gid))
        if modes is not None:
            need(stat.S_IMODE(before.st_mode) in modes)
        raw = stream.read(MAX_FILE+1)
        after = info(fd,value)
        need(after is not None and len(raw) == before.st_size and identity(before) == identity(os.fstat(stream.fileno())) == identity(after))
        return raw, before


def read_path(value, **kwargs):
    value = Path(value)
    with directory(value.parent) as fd:
        return read(fd,value.name,**kwargs)


def save(fd, value, document, *, uid=0, gid=0):
    value = leaf(value);raw = (json.dumps(document,sort_keys=True)+'\n').encode()
    need(len(raw) <= MAX_FILE)
    opened = os.open(value,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
    with os.fdopen(opened,'wb') as stream:
        os.fchown(stream.fileno(),uid,gid);os.fchmod(stream.fileno(),0o600)
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    os.fsync(fd)


def unlink(fd,value):
    os.unlink(leaf(value),dir_fd=fd);os.fsync(fd)


def replace(fd,source,target):
    os.replace(leaf(source),leaf(target),src_dir_fd=fd,dst_dir_fd=fd);os.fsync(fd)


def private_directory(fd, *, uid=0):
    value = os.fstat(fd)
    need(stat.S_ISDIR(value.st_mode) and owner(value) == (uid,uid) and stat.S_IMODE(value.st_mode) == 0o700)


@contextmanager
def custody(selected, *, create=False):
    # Only the explicitly compiled directory selects state identity. Stable app
    # labels/runtime IDs never imply another persisted receipt path.
    with directory(CUSTODY,create=create,uid=0,gid=0) as parent:
        private_directory(parent)
        if selected['custody']==CUSTODY:
            yield parent
        else:
            relative=Path(selected['custody']).relative_to(CUSTODY)
            current=Path(CUSTODY)
            for part in relative.parts:
                current=current/part
                with directory(current,create=create,uid=0,gid=0) as child:
                    private_directory(child)
            with directory(selected['custody']) as child:
                private_directory(child);yield child


def legacy_workspace(selected):
    return (selected['data_path']==DATA and selected['custody']==CUSTODY
        and selected['project']==PROJECT and selected['services']==SERVICES
        and selected['runtime_directory']==RUNTIME and selected['runtime_id']=='mqtt_explorer')


def workspace_document(owned,selected):
    need(isinstance(owned,dict) and set(owned)=={'node','vmid','hostname'})
    if legacy_workspace(selected):
        return dict(owned)
    return {'schema':'homelab-mqtt-explorer-workspace-v1','owner':dict(owned),
        'data_path':selected['data_path'],'custody_directory':selected['custody'],
        **{key:selected[key] for key in ('project','services','runtime_directory','runtime_id')}}


def workspace_owner(fd,selected):
    value = json.loads(read(fd,'workspace.json',uid=0,modes=(0o600,))[0])
    need(isinstance(value,dict))
    owned=value if set(value)=={'node','vmid','hostname'} else value.get('owner')
    need(isinstance(owned,dict) and set(owned)=={'node','vmid','hostname'}
         and type(owned['vmid']) is int and owned['vmid']>=100
         and all(isinstance(owned[k],str) and re.fullmatch('[A-Za-z0-9_.-]{1,128}',owned[k]) for k in ('node','hostname')))
    need(value==workspace_document(owned,selected))
    return owned


def native_profile(connection,password,profile_id):
    need(isinstance(connection,dict) and set(connection) == {'name','hostname','port','username'}
         and all(isinstance(connection[k],str) and connection[k] and len(connection[k].encode()) <= 256
                 and not any(ord(c)<32 or ord(c)==127 for c in connection[k]) for k in ('name','hostname','username'))
         and type(connection['port']) is int and connection['port'] == 1883)
    need(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,252}',connection['hostname']))
    need(isinstance(password,str) and 0 < len(password.encode()) <= 65536 and password.strip()
         and not any(c in password for c in '\r\n\x00'))
    name(profile_id)
    return {'configVersion':1,'type':'mqtt','id':profile_id,'name':connection['name'],
        'host':connection['hostname'],'protocol':'mqtt','port':1883,'encryption':False,
        'certValidation':True,'username':connection['username'],'password':password,
        'subscriptions':[{'topic':'#','qos':0},{'topic':'$SYS/#','qos':0}]}


def fingerprint(secret, owned, purpose):
    import hashlib
    context = ('homelab-mqtt-custody-v1\0'+purpose+'\0'+json.dumps(owned,sort_keys=True,separators=(',',':'))).encode()
    return hashlib.pbkdf2_hmac('sha256',secret.encode(),context,600000).hex()


def stable_directory(fd,value):
    with directory(value) as current:
        a,b=os.fstat(fd),os.fstat(current)
        need((a.st_dev,a.st_ino,a.st_mode,owner(a)) == (b.st_dev,b.st_ino,b.st_mode,owner(b)))


def settings(fd):
    if info(fd,'settings.json') is None:
        return {}
    raw,_=read(fd,'settings.json',uid=1001,modes=(0o600,))
    value=json.loads(raw);need(isinstance(value,dict))
    return value


def seed_profile(selected,expected,owned,receipt_id,docker,*,verify_only=False):
    """Own one profile under the existing lock; preserve unrelated settings."""
    name(receipt_id)
    with custody(selected) as cfd,directory(selected['data_path']) as data:
        private_directory(data,uid=1001)
        need(isinstance(owned,dict) and all(key in owned for key in ('node','vmid','hostname'))
             and {key:owned[key] for key in ('node','vmid','hostname')}==workspace_owner(cfd,selected))
        document=settings(data);connections=document.setdefault('ConnectionManager_connections',{})
        need(isinstance(connections,dict))
        receipt,hold=receipt_id+'-profile.json',receipt_id+'-PROFILE-HOLD.json'
        need(info(cfd,hold) is None)
        proof={'owner':owned,'profile_fingerprint':fingerprint(json.dumps(expected,sort_keys=True),owned,'profile')}
        if info(cfd,receipt) is not None:
            need(json.loads(read(cfd,receipt,uid=0,modes=(0o600,))[0]) == proof
                 and connections.get(expected['id']) == expected)
        else:
            need(not verify_only and expected['id'] not in connections)
            service=selected['services']['mqtt_explorer'];project=selected['project']
            ids=docker(['ps','--all','--quiet','--no-trunc','--filter','label=com.docker.compose.project='+project,
                        '--filter','label=com.docker.compose.service='+service]).split()
            need(len(ids)<=1 and all(re.fullmatch('[0-9a-f]{64}',cid) for cid in ids))
            row=None
            if ids:
                rows=json.loads(docker(['inspect',ids[0]]));need(isinstance(rows,list) and len(rows)==1)
                row=rows[0]
                mounts=[m for m in row['Mounts'] if m.get('Destination')=='/app/data' or m.get('Destination','').startswith('/app/data/')]
                need(row['Id']==ids[0] and row['Config']['User']=='1001:1001'
                     and row['Config']['Labels'].get('com.docker.compose.project')==project
                     and row['Config']['Labels'].get('com.docker.compose.service')==service
                     and len(mounts)==1 and mounts[0].get('Type')=='bind' and mounts[0].get('Source')==selected['data_path']
                     and mounts[0].get('Destination')=='/app/data' and mounts[0].get('RW') is True)
            stable_directory(data,selected['data_path']);stable_directory(cfd,selected['custody'])
            save(cfd,hold,proof)
            if row is not None and row['State']['Running']:
                docker(['stop','--time','30',ids[0]])
                need(json.loads(docker(['inspect',ids[0]]))[0]['State']['Running'] is False)
            document=settings(data);connections=document.setdefault('ConnectionManager_connections',{})
            need(isinstance(connections,dict) and expected['id'] not in connections)
            connections[expected['id']]=expected
            stable_directory(data,selected['data_path']);stable_directory(cfd,selected['custody'])
            temporary='.homelab-'+receipt_id+'.pending'
            save(data,temporary,document,uid=1001,gid=1001)
            replace(data,temporary,'settings.json')
            save(cfd,receipt,proof);unlink(cfd,hold)
        stable_directory(data,selected['data_path']);stable_directory(cfd,selected['custody'])
    return {'saved_connection':'verified'}


def existing_document(value):
    need(isinstance(value,dict) and set(value)-{'runtime'} == {'schema','profile_id','connection','password'}
         and value['schema']=='homelab-mqtt-explorer-existing-profile-v1'
         and ('runtime' not in value or isinstance(value['runtime'],dict)))
    selected=context(value.get('runtime'))
    need(value['profile_id']==selected['runtime_id'])
    expected=native_profile(value['connection'],value['password'],'existing-'+name(value['profile_id']))
    with custody(selected) as cfd:
        owned=dict(workspace_owner(cfd,selected),purpose='mqtt-explorer-existing-profile',profile_id=value['profile_id'],
                   broker_hostname=value['connection']['hostname'],broker_port=1883,username=value['connection']['username'])
    return selected,expected,owned,'existing-'+value['profile_id']


def profile_existing(value,docker):
    selected,expected,owned,receipt=existing_document(value)
    return seed_profile(selected,expected,owned,receipt,docker)


def verify_existing(public):
    selected=public_context(public);connection=public['broker_connection']
    need(isinstance(connection,dict) and set(connection)=={'name','hostname','port','username','profile_id'}
         and connection['profile_id']==selected['runtime_id'])
    with directory(selected['data_path']) as data:
        private_directory(data,uid=1001)
        document=settings(data);rows=document.get('ConnectionManager_connections',{})
        need(isinstance(rows,dict) and 'existing-'+selected['runtime_id'] in rows)
        row=rows['existing-'+selected['runtime_id']];need(isinstance(row,dict) and isinstance(row.get('password'),str))
        password=row['password']
    value={'schema':'homelab-mqtt-explorer-existing-profile-v1','profile_id':connection['profile_id'],
           'connection':{k:v for k,v in connection.items() if k!='profile_id'},'password':password,
           'runtime':{**{k:selected[k] for k in ('project','services','data_path','runtime_directory','runtime_id')},
                      'custody_directory':selected['custody']}}
    selected,expected,owned,receipt=existing_document(value)
    return seed_profile(selected,expected,owned,receipt,lambda args: (_ for _ in ()).throw(ValueError('Readiness cannot mutate Explorer')),verify_only=True)
