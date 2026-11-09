"""Read-only allocation and mounted-filesystem proof for declared backup staging."""
import shlex
import re
import hashlib
from urllib.parse import quote

from commands import quiet
from private_io import require, read_json, regular, decode_json
from plan_policy import GUEST_RESOURCE, prepared_staging_mount

SCRIPT = b'''import os, stat, sys
path = sys.argv[1]
def mount_id(descriptor):
    with open('/proc/self/fdinfo/' + str(descriptor), encoding='ascii') as info:
        raw = info.read(4097)
    values = [line.split(':', 1)[1].strip() for line in raw.splitlines() if line.startswith('mnt_id:')]
    if len(raw) > 4096 or len(values) != 1 or not values[0].isdigit() or int(values[0]) < 1:
        raise RuntimeError('Unqualified staging mount identity')
    return int(values[0])
fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
try:
    parts = path.split('/')[1:]
    target_mount = False
    for index, part in enumerate(parts):
        try:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        except FileNotFoundError:
            print('Backup staging target is absent')
            raise SystemExit(0)
        try:
            if index == len(parts)-1:
                target_mount = mount_id(child) != mount_id(fd)
        except BaseException:
            os.close(child)
            raise
        os.close(fd); fd = child
        info = os.fstat(fd)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise RuntimeError('Unowned or writable staging ancestor')
    if target_mount or os.listdir(fd):
        raise RuntimeError('Foreign mount or nonempty staging target')
    print('Backup staging target is an empty owned directory')
finally:
    os.close(fd)
'''


def newly_allocated(plan, path):
    row = next(row for row in plan['resource_changes'] if row['type'] == 'proxmox_virtual_environment_container')
    before = row['change'].get('before') or {}
    return path not in {item['path'] for item in before.get('mount_point') or []}


def inspect(cfg, path, log):
    require(isinstance(path, str) and re.fullmatch(r'/srv/[a-z0-9][a-z0-9_-]*(?:/[a-z0-9][a-z0-9_-]*)*', path),
            'Use the exact admitted staging target')
    argv = ['ssh', '-F', '/dev/null', '-o', 'StrictHostKeyChecking=yes', '-o', 'BatchMode=yes',
        '-o', 'IdentitiesOnly=yes', '-o', 'ControlMaster=no', '-o', 'GlobalKnownHostsFile=/dev/null',
        '-o', 'VerifyHostKeyDNS=no', '-o', 'UpdateHostKeys=no',
        '-o', 'UserKnownHostsFile='+cfg['paths']['known_hosts'], '-i', cfg['paths']['private_key'],
        'root@'+cfg['app']['address'], 'python3 - '+shlex.quote(path)]
    quiet(argv, {'PATH': '/usr/bin:/bin'}, log, input_bytes=SCRIPT, timeout=30)


MOUNTED_SCRIPT = b'''import hashlib,json,os,re,stat,sys
path,dataset,capacity,first=sys.argv[1:]
capacity=int(capacity);first=first=='true'
def require(value):
    if not value:raise ValueError('Unverified declared staging filesystem')
def proc(path,bound):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        raw=os.read(fd,bound+1);require(len(raw)<=bound);return raw
    finally:os.close(fd)
def mount_id(fd):
    values=re.findall(r'(?m)^mnt_id:\\s*([0-9]+)\\s*$',proc('/proc/self/fdinfo/'+str(fd),8192).decode('ascii'))
    require(len(values)==1);return int(values[0])
def unescape(value):
    return re.sub(r'\\\\(040|011|012|134)',lambda m:chr(int(m[1],8)),value)
def mounts():
    rows=[]
    for line in proc('/proc/self/mountinfo',1048576).decode('utf-8').splitlines():
        left,separator,right=line.partition(' - ');a,b=left.split(),right.split()
        require(separator and len(a)>=6 and len(b)>=3)
        require(not unescape(a[4]).startswith(path+'/'))
        if unescape(a[4]) in ('/',path) or unescape(b[1])==dataset:
            require(a[0].isdigit() and re.fullmatch('[0-9]+:[0-9]+',a[2]))
            rows.append((int(a[0]),tuple(map(int,a[2].split(':'))),unescape(a[3]),unescape(a[4]),b[0],unescape(b[1])))
    selected=[r for r in rows if r[3]==path];roots=[r for r in rows if r[3]=='/']
    require(len(selected)==len(roots)==1 and sum(r[5]==dataset for r in rows)==1)
    row,root=selected[0],roots[0]
    require(row[2]=='/' and row[4]=='zfs' and row[5]==dataset and row[0]!=root[0] and row[5]!=root[5])
    return row,root
def identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_mtime_ns,info.st_ctime_ns)
fds=[];links=[]
try:
    require(os.geteuid()==0)
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);fds.append(fd)
    for part in path.split('/')[1:]:
        parent=fd;fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NOATIME|os.O_CLOEXEC,dir_fd=parent);fds.append(fd)
        info=os.fstat(fd);require(info.st_uid==0 and info.st_gid==0 and not stat.S_IMODE(info.st_mode)&0o022)
        links.append((parent,part,fd,identity(info)))
    before=os.fstat(fd);row,root=mounts()
    require(row[0]==mount_id(fd) and row[0]!=mount_id(parent) and row[1]==(os.major(before.st_dev),os.minor(before.st_dev)))
    names=set()
    with os.scandir(fd) as entries:
        for entry in entries:
            names.add(entry.name);require(names<=(set() if first else {'.homelab-backup'}))
            info=entry.stat(follow_symlinks=False)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and info.st_gid==0 and not stat.S_IMODE(info.st_mode)&0o077)
    size=os.fstatvfs(fd);size=size.f_blocks*size.f_frsize;require(0<size<=capacity)
    require(identity(before)==identity(os.fstat(fd)) and (row,root)==mounts())
    require(all(identity(os.fstat(child))==old==identity(os.stat(name,dir_fd=parent,follow_symlinks=False))for parent,name,child,old in links))
    print(json.dumps({'device':list(row[1]),'inode':before.st_ino,'uid':before.st_uid,'gid':before.st_gid,
        'mode':stat.S_IMODE(before.st_mode),'mtime_ns':before.st_mtime_ns,'ctime_ns':before.st_ctime_ns,
        'bytes':size,'source':hashlib.sha256(dataset.encode()).hexdigest(),'mount_id':row[0]}))
finally:
    for fd in reversed(fds):os.close(fd)
'''


def selection(cfg):
    """Project the declared operational staging path, quota and storage ID."""
    stage = cfg['app']['backup']['job']['staging']
    return {'path': stage['path'], 'size': str(stage['size_bytes']//1024**3)+'G',
            'volume': cfg['guest']['storage_id']}


def original(cfg, previous, work):
    """First ownership comes from the genuine prior source/backend, not refresh."""
    require(isinstance(previous, dict), 'Preserve genuine prior staging ownership')
    mounts = backend_mounts(work)
    selected = selection(cfg)
    matches = [row for row in mounts if row.get('path') == selected['path']]
    old_job = previous['app'].get('backup', {}).get('job')
    if old_job is None:
        require(not matches, 'An existing mount cannot acquire staging ownership implicitly')
        return True
    require(old_job['staging'] == cfg['app']['backup']['job']['staging']
            and previous['guest']['storage_id'] == cfg['guest']['storage_id']
            and len(matches) == 1 and prepared_staging_mount(matches[0], selected, cfg['guest']['vmid']),
            'Preserve the successful staging path, capacity and allocated identity')
    return False


def backend_mounts(work):
    """Read only this already-admitted backend's container mount projection."""
    state = read_json(work/'terraform.tfstate', private=True)
    rows = [row for row in state['resources'] if '.'.join(str(row.get(k, ''))
            for k in ('module', 'type', 'name')) == GUEST_RESOURCE]
    require(len(rows) == 1, 'Preserve one prior managed guest')
    mounts = rows[0]['instances'][0]['attributes'].get('mount_point') or []
    return mounts


def applied(cfg, work):
    """New creation must expose one allocated staging identity after real apply."""
    rows = backend_mounts(work)
    selected = selection(cfg)
    matches = [(row, index) for index, row in enumerate(rows) if row.get('path') == selected['path']]
    require(len(matches) == 1 and prepared_staging_mount(matches[0][0], selected, cfg['guest']['vmid']),
            'Bind the applied new staging subvolume identity')
    return matches[0]


def stage_row(plan, path):
    """Find the unique refreshed mount at the declared staging path."""
    mounts = planned_mounts(plan, 'before')
    rows = [item for item in mounts if item.get('path') == path]
    require(len(rows) == 1, 'Bind one refreshed staging mount')
    return rows[0], mounts.index(rows[0])


def planned_mounts(plan, side):
    """Read this guest's mount sequence from one admitted plan side."""
    row = next(row for row in plan['resource_changes'] if row['address'] == GUEST_RESOURCE)
    return row['change'][side].get('mount_point') or []


def storage(rows, selected):
    """Bind one bounded isolated ZFS pool and its exact host mountpoint."""
    require(isinstance(rows, list) and len(rows) <= 32, 'Bound the authorized ZFS storage index')
    matches = [row for row in rows if isinstance(row, dict) and row.get('storage') == selected]
    require(len(matches) == 1, 'Bind one selected storage configuration')
    value = matches[0]
    pool = value.get('pool')
    require(value.get('type') == 'zfspool'
            and (value.get('shared') is None or type(value['shared']) in (int, bool) and value['shared'] == 0)
            and isinstance(pool, str) and len(pool) <= 256
            and re.fullmatch(r'[A-Za-z0-9_.:-]+(?:/[A-Za-z0-9_.:-]+)*', pool)
            and not {'.', '..'} & set(pool.split('/')), 'Bind an isolated declared ZFS pool')
    mount = value.get('mountpoint')
    if mount is None:
        mount = '/' + pool
    require(isinstance(mount, str) and len(mount) <= 1024
            and re.fullmatch(r'/[A-Za-z0-9_.:-]+(?:/[A-Za-z0-9_.:-]+)*', mount)
            and not {'.', '..'} & set(mount.split('/')), 'Bind the exact ZFS host mountpoint')
    return pool, mount


def native_row(raw, row):
    """Compare actual API options with the provider's retained mount attributes."""
    require(isinstance(raw, str), 'Read the exact current native mount slot')
    require(len(raw) <= 4096, 'Bound native staging options')
    parts = [part.strip() for part in raw.split(',')]; options = {}
    for item in parts[1:]:
        key, separator, field = item.partition('=')
        require(separator and key not in options, 'Use unique native staging options')
        options[key] = field
    flags = {'acl': ('acl', False), 'backup': ('backup', False), 'quota': ('quota', False),
             'ro': ('read_only', False), 'replicate': ('replicate', True), 'shared': ('shared', False)}
    require(parts[0] == row['volume'] and options.get('mp') == row['path']
            and options.get('size') == row['size']
            and all(type(row.get(field, default)) is bool and
                    options.get(key, str(int(default))) == str(int(row.get(field, default)))
                    for key, (field, default) in flags.items())
            and (options['mountoptions'].split(';') if options.get('mountoptions') else []) ==
                (row.get('mount_options') or [])
            and row.get('path_in_datastore', parts[0]) == parts[0]
            and set(options) <= {'mp', 'size', 'backup', 'replicate', 'acl', 'quota', 'ro', 'shared', 'mountoptions'},
            'Preserve every current native mount attribute and backup flag')
    return raw


def native_mount(value, row, slot, mounts):
    """Match the complete active mount sequence and isolated stage allocation."""
    require(isinstance(value, dict) and isinstance(mounts, list)
            and type(slot) is int and 0 <= slot < len(mounts) and mounts[slot] == row
            and {key for key in value if re.fullmatch(r'mp[0-9]+', key)} ==
                {'mp'+str(index) for index in range(len(mounts))},
            'Read the exact current managed mount sequence')
    rows = tuple(native_row(value['mp'+str(index)], expected) for index, expected in enumerate(mounts))
    require(isinstance(value.get('rootfs'), str) and value['rootfs'].split(',')[0].strip() != row['volume']
            and sum(isinstance(v, str) and v.split(',')[0].strip() == row['volume']
                    for k, v in value.items() if re.fullmatch(r'mp[0-9]+', k)) == 1,
            'Preserve the exact isolated staging allocation and options')
    return rows, value['rootfs'], value.get('digest')


def verify(cfg, row, slot, log, api_get, *, first, label, mounts):
    """Bind current native allocation to an owned FD/mountinfo filesystem proof."""
    require(type(first) is bool and label in ('before', 'after')
            and prepared_staging_mount(row, selection(cfg), cfg['guest']['vmid']),
            'Verify only the selected known staging allocation')
    node = quote(cfg['site']['node'], safe='')
    config_path = '/nodes/'+node+'/lxc/'+str(cfg['guest']['vmid'])+'/config?current=1'
    info_path = '/nodes/'+node+'/storage/'+quote(cfg['guest']['storage_id'], safe='')+'/content/'+quote(row['volume'], safe='')
    def projection():
        """Join active mount options, selected storage and exact volume information."""
        native = native_mount(api_get(config_path), row, slot, mounts)
        pool, mount = storage(api_get('/storage?type=zfspool'), cfg['guest']['storage_id'])
        name = row['volume'].split(':', 1)[1]
        volume = api_get(info_path)
        require(isinstance(volume, dict) and volume.get('format') == 'subvol'
                and volume.get('path') == mount+'/'+name
                and type(volume.get('size')) is int
                and volume['size'] == cfg['app']['backup']['job']['staging']['size_bytes'],
                'Bind exact allocated staging format, path and capacity')
        return native, pool+'/'+name, volume['size']
    before = projection()
    proof = log.parent/('backup-staging-'+label+'.json')
    require(not proof.exists() and not proof.is_symlink(), 'Preserve prior staging inspection evidence')
    argv = ['ssh', '-F', '/dev/null', '-o', 'StrictHostKeyChecking=yes', '-o', 'BatchMode=yes',
        '-o', 'IdentitiesOnly=yes', '-o', 'ControlMaster=no', '-o', 'GlobalKnownHostsFile=/dev/null',
        '-o', 'VerifyHostKeyDNS=no', '-o', 'UpdateHostKeys=no',
        '-o', 'UserKnownHostsFile='+cfg['paths']['known_hosts'], '-i', cfg['paths']['private_key'],
        'root@'+cfg['app']['address'], '/usr/bin/python3 - '+ ' '.join(shlex.quote(x) for x in
            (row['path'], before[1], str(before[2]), 'true' if first else 'false'))]
    quiet(argv, {'PATH': '/usr/bin:/bin'}, proof, input_bytes=MOUNTED_SCRIPT, timeout=30)
    raw = regular(proof, private=True, limit=4096)
    value = decode_json(raw)
    fields = {'device', 'inode', 'uid', 'gid', 'mode', 'mtime_ns', 'ctime_ns', 'bytes', 'source', 'mount_id'}
    require(isinstance(value, dict) and set(value) == fields
            and all(type(value[key]) is int and value[key] >= 0 for key in fields-{'device', 'source'})
            and isinstance(value['device'], list) and len(value['device']) == 2
            and all(type(x) is int and x >= 0 for x in value['device'])
            and value['uid'] == value['gid'] == 0 and not value['mode'] & 0o022
            and value['mode'] <= 0o7777
            and value['inode'] > 0 and value['mount_id'] > 0 and 0 < value['bytes'] <= before[2]
            and value['source'] == hashlib.sha256(before[1].encode()).hexdigest()
            and before == projection(), 'Preserve the stable current staging filesystem proof')
    # Namespace mount IDs and Linux device numbers may change on a reboot.
    # Each probe binds them internally; persistent ownership uses the dataset
    # and filesystem-root identity instead.
    return {key: value[key] for key in fields-{'mount_id', 'device', 'mtime_ns', 'ctime_ns'}}
