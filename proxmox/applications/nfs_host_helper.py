#!/usr/bin/env python3
"""Forced-command host capability: append one declared real NFS bind, never replace."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import signal
import stat
import subprocess
import sys

SCHEMA = 'homelab-nfs-attachment-v1'


def require(ok):
    if not ok:
        raise ValueError('Preserve the guest and its declared NFS attachment')


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def decode(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value)
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique)


def implementation_digest():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def command(argv):
    return subprocess.check_output(argv, text=True, timeout=60, env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL':'C'})


def validate(request):
    require(type(request) is dict and set(request) == {'schema','node','vmid','hostname','mac','mount','rootfs','mounts'}
            and request['schema'] == SCHEMA and type(request['vmid']) is int and 100 <= request['vmid'] <= 999999999)
    require(all(isinstance(request[k], str) and re.fullmatch(r'[a-z][a-z0-9-]{0,62}', request[k]) for k in ('node','hostname'))
            and isinstance(request['mac'], str) and re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', request['mac']))
    selected = request['mount']
    require(type(selected) is dict and set(selected) == {'source','path','slot','filesystem_source','filesystem','filesystem_root'})
    for name in ('source','path','filesystem_root'):
        require(isinstance(selected[name], str) and re.fullmatch(r'/(?:[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)?', selected[name])
                and not {'.','..'} & set(selected[name].split('/')))
    require(selected['source'].startswith('/mnt/') and selected['path'].startswith('/srv/')
            and type(selected['slot']) is int and 0 <= selected['slot'] <= 255
            and selected['filesystem'] in ('nfs','nfs4') and isinstance(selected['filesystem_source'], str)
            and re.fullmatch(r'[A-Za-z0-9_.-]+:/(?:[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)?', selected['filesystem_source']))
    require(isinstance(request['rootfs'], str) and 0 < len(request['rootfs']) <= 4096
            and type(request['mounts']) is dict and set(request['mounts']) == {'mp'+str(i) for i in range(selected['slot'])}
            and all(isinstance(v,str) and 0 < len(v) <= 4096 for v in request['mounts'].values()))
    return request


def directory(path):
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in Path(path).parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def mount(path, execute):
    result = decode(execute(['/usr/bin/findmnt','--json','--nofsroot','--target',path,'--output','SOURCE,FSTYPE,FSROOT,OPTIONS,TARGET']))
    rows = result['filesystems']
    require(type(rows) is list and len(rows) == 1)
    row = rows[0]
    require(row['fstype'] in ('nfs','nfs4') and 'rw' in row['options'].split(','))
    return row


def source(selected, execute):
    descriptor = directory(selected['source'])
    try:
        row = mount(selected['source'], execute)
        relative = str(Path(selected['source']).relative_to(row['target']))
        relative = '' if relative == '.' else '/' + relative
        projected = row['source'].rstrip('/') + relative
        root = row['fsroot'].rstrip('/') + relative or '/'
        require(row['fstype'] == selected['filesystem'] and
                (selected['filesystem_source'], selected['filesystem_root']) in ((projected, '/'), (row['source'], root))
                and not os.fstatvfs(descriptor).f_flag & os.ST_RDONLY)
        return descriptor, os.fstat(descriptor)
    except BaseException:
        os.close(descriptor)
        raise


def perform(request, action, execute=command):
    validate(request)
    require(action in ('check','attach') and socket.gethostname() == request['node'])
    selected = request['mount']; vmid = str(request['vmid'])
    base = '/nodes/' + request['node'] + '/lxc/' + vmid
    def read():
        value = decode(execute(['/usr/bin/pvesh','get',base+'/config','--current','1','--output-format','json']))
        require(value.get('hostname') == request['hostname'] and value.get('unprivileged') == 1
                and value.get('protection') == 1 and not value.get('lock') and value.get('rootfs') == request['rootfs'])
        networks = [dict(part.split('=',1) for part in row.split(',') if '=' in part)
                    for key,row in value.items() if re.fullmatch(r'net[0-9]+',key)]
        require(sum(row.get('hwaddr','').lower() == request['mac'] for row in networks) == 1)
        return value
    def pending():
        rows = decode(execute(['/usr/bin/pvesh','get',base+'/pending','--output-format','json']))
        require(type(rows) is list and all(type(row) is dict and not ('pending' in row or row.get('delete',0)) for row in rows))
    current = read(); pending()
    slot = 'mp' + str(selected['slot'])
    wanted = selected['source'] + ',mp=' + selected['path'] + ',backup=0,replicate=0'
    def binding(raw):
        if not isinstance(raw,str):
            return False
        parts = raw.split(','); options = {}
        for item in parts[1:]:
            key, separator, value = item.partition('=')
            require(separator and key not in options)
            options[key] = value
        return parts[0] == selected['source'] and options == {'mp':selected['path'],'backup':'0','replicate':'0'}
    prior = {k:v for k,v in current.items() if re.fullmatch(r'mp[0-9]+',k)}
    attached = slot in prior
    require({k:v for k,v in prior.items() if k != slot} == request['mounts']
            and set(prior) == set(request['mounts']) | ({slot} if attached else set())
            and (not attached or binding(prior[slot])))
    for raw in request['mounts'].values():
        fields = raw.split(',')
        options = dict(part.split('=',1) for part in fields[1:] if '=' in part)
        target = options.get('mp')
        require(isinstance(target,str) and target.startswith('/'))
        left, right = Path(target), Path(selected['path'])
        require(left != right and left not in right.parents and right not in left.parents)
    descriptor, identity = source(selected, execute)
    def stable_source():
        check_fd, found = source(selected, execute)
        try:
            require((found.st_dev,found.st_ino) == (identity.st_dev,identity.st_ino))
        finally:
            os.close(check_fd)
    result = {'schema':SCHEMA,'vmid':request['vmid'],'request_sha256':hashlib.sha256(encoded(request)).hexdigest(),
              'helper_sha256':implementation_digest(),'changed':False}
    try:
        status = execute(['/usr/sbin/pct','status',vmid]).strip()
        require(status in ('status: running','status: stopped'))
        if action == 'attach' and not attached:
            require(re.fullmatch('[0-9a-f]{40}',current.get('digest','')))
            if status == 'status: running':
                execute(['/usr/sbin/pct','shutdown',vmid,'--timeout','30'])
                require(execute(['/usr/sbin/pct','status',vmid]).strip() == 'status: stopped')
            require(read() == current); pending()
            try:
                execute(['/usr/sbin/pct','set',vmid,'--protection','0','--digest',current['digest']])
                unlocked = decode(execute(['/usr/bin/pvesh','get',base+'/config','--current','1','--output-format','json']))
                require(unlocked.get('protection') == 0 and {k:v for k,v in unlocked.items() if k not in ('digest','protection')}
                        == {k:v for k,v in current.items() if k not in ('digest','protection')})
                stable_source()
                execute(['/usr/sbin/pct','set',vmid,'--'+slot,wanted,'--digest',unlocked['digest']])
            finally:
                execute(['/usr/sbin/pct','set',vmid,'--protection','1'])
                read()
            after = read(); pending()
            require(binding(after.get(slot)) and {k:v for k,v in after.items() if k not in ('digest',slot)}
                    == {k:v for k,v in current.items() if k != 'digest'})
            result['changed'] = True
            stable_source()
            if status == 'status: running':
                execute(['/usr/sbin/pct','start',vmid])
        if action == 'attach':
            require(binding(read().get(slot)))
            if status == 'status: running':
                pid = execute(['/usr/bin/lxc-info','-n',vmid,'-p','-H']).strip()
                require(re.fullmatch('[1-9][0-9]*',pid))
                target = Path('/proc')/pid/'root'/selected['path'].lstrip('/')
                found = os.stat(target)
                require((found.st_dev, found.st_ino) == (identity.st_dev, identity.st_ino))
                raw = execute(['/usr/sbin/pct','exec',vmid,'--','findmnt','--json','--nofsroot','--mountpoint',selected['path'],
                               '--output','SOURCE,FSTYPE,FSROOT,OPTIONS,TARGET'])
                rows = decode(raw)['filesystems']
                require(len(rows) == 1 and rows[0]['source'] == selected['filesystem_source']
                        and rows[0]['fsroot'] == selected['filesystem_root'] and rows[0]['fstype'] == selected['filesystem']
                        and rows[0]['target'] == selected['path'] and 'rw' in rows[0]['options'].split(','))
        latest = os.stat(selected['source'], follow_symlinks=False)
        require((latest.st_dev,latest.st_ino) == (identity.st_dev,identity.st_ino))
        return result
    finally:
        os.close(descriptor)


def main():
    try:
        require(os.getuid() == 0 and len(sys.argv) == 1)
        action = os.environ.get('SSH_ORIGINAL_COMMAND','')
        if action == 'version':
            print(encoded({'schema':SCHEMA,'helper_sha256':implementation_digest(),'changed':False}).decode(),end='')
            return 0
        raw = sys.stdin.buffer.read(65537)
        require(len(raw) <= 65536)
        request = validate(decode(raw))
        descriptor = os.open('/run/lock/homelab-nfs-'+str(request['vmid'])+'.lock', os.O_CREAT|os.O_NOFOLLOW|os.O_RDWR, 0o600)
        try:
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX|fcntl.LOCK_NB)
            print(encoded(perform(request,action)).decode(),end='')
        finally:
            os.close(descriptor)
        return 0
    except Exception:
        print('{"status":"blocked","reason":"nfs_attachment_refused"}')
        return 1


def interrupted(signum, frame):
    raise RuntimeError('NFS attachment interrupted; restore protection and preserve the attempt')


if __name__ == '__main__':
    for signum in (signal.SIGHUP, signal.SIGTERM):
        signal.signal(signum, interrupted)
    raise SystemExit(main())
