#!/usr/bin/env python3
"""Create only declared fresh app directories beneath an owned provider mount."""
from contextlib import contextmanager
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

ROOT_UID = 0
ROOT_GID = 0
RUNTIME_ROOT = '/opt/homelab-app'
ROOT_PATTERN = r'(/srv/[a-z0-9_-]+|/var/lib/(mysql|postgresql|influxdb))(/[a-z0-9_-]+)*'
FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def require(ok):
    if not ok:
        raise ValueError('Preserve component storage identity and permissions')


def path(value):
    require(isinstance(value,str) and value.startswith('/') and not value.startswith('//')
            and PurePosixPath(value).as_posix()==value and
            not any(part in ('.','..') for part in value.split('/'))
            and not any(char in value for char in '$:\\')
            and not any(ord(char)<32 or ord(char)==127 for char in value))
    return PurePosixPath(value)


@contextmanager
def directory(value):
    selected=path(value)
    descriptor=os.open('/',FLAGS)
    try:
        for part in selected.parts[1:]:
            child=os.open(part,FLAGS,dir_fd=descriptor)
            os.close(descriptor);descriptor=child
        yield descriptor
    finally:
        os.close(descriptor)


def mount(value):
    with open('/proc/self/mountinfo','rb') as stream:
        raw=stream.read(2*1024*1024+1)
    require(len(raw)<=2*1024*1024)
    points=[]
    for line in raw.decode('utf-8').splitlines():
        fields=line.split()
        require(len(fields)>=10 and '-' in fields)
        points.append(fields[4])
    return value in points


def ownership(info):
    return info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)


def specification(value):
    require(isinstance(value,dict) and set(value)=={'root','path','uid','gid','mode'})
    root,selected=path(value['root']),path(value['path'])
    require(re.fullmatch(ROOT_PATTERN,str(root))
            and root in selected.parents and len(selected.relative_to(root).parts)<=64
            and type(value['uid']) is int and 0<=value['uid']<=65535
            and type(value['gid']) is int and 0<=value['gid']<=65535 and value['mode']=='0700')
    return root,selected


def initialize(value):
    require(os.geteuid()==ROOT_UID and isinstance(value,dict) and
            set(value)=={'directories','previously_owned'} and type(value['previously_owned']) is bool
            and isinstance(value['directories'],list) and len(value['directories'])<=64)
    initialized=0
    created=[]
    seen=set()
    for row in value['directories']:
        new_leaf=False
        root,selected=specification(row)
        require(str(selected) not in seen);seen.add(str(selected))
        require(mount(str(root)))
        with directory(str(root)) as root_fd:
            root_info=os.fstat(root_fd)
            require(root_info.st_uid==ROOT_UID and not stat.S_IMODE(root_info.st_mode)&0o022)
            current=os.dup(root_fd)
            try:
                parts=selected.relative_to(root).parts
                for index,part in enumerate(parts):
                    leaf=index==len(parts)-1
                    try:
                        child=os.open(part,FLAGS,dir_fd=current)
                    except FileNotFoundError:
                        require(not value['previously_owned'])
                        os.mkdir(part,0o700,dir_fd=current)
                        child=os.open(part,FLAGS,dir_fd=current)
                        try:
                            before=os.fstat(child)
                            require(before.st_uid==ROOT_UID and (before.st_dev,before.st_ino)==
                                (os.stat(part,dir_fd=current,follow_symlinks=False).st_dev,
                                 os.stat(part,dir_fd=current,follow_symlinks=False).st_ino))
                            if leaf:
                                # Ownership is set only on our newly created FD.
                                # Existing/retained directory inodes never reach this block.
                                if (before.st_uid,before.st_gid)!=(row['uid'],row['gid']):
                                    os.fchown(child,row['uid'],row['gid'])
                                os.fchmod(child,0o700)
                                initialized+=1
                                new_leaf=True
                            os.fsync(child);os.fsync(current)
                        except BaseException:
                            os.close(child)
                            raise
                    else:
                        if leaf and not value['previously_owned']:
                            os.close(child)
                            require(False)
                    info=os.fstat(child)
                    try:
                        require(stat.S_ISDIR(info.st_mode))
                        require(ownership(info)==(row['uid'],row['gid'],0o700) if leaf else
                                info.st_uid==ROOT_UID and not stat.S_IMODE(info.st_mode)&0o022)
                    except BaseException:
                        os.close(child)
                        raise
                    os.close(current);current=child
                final=os.fstat(current)
                with directory(str(selected)) as check:
                    actual=os.fstat(check)
                    require((final.st_dev,final.st_ino)==(actual.st_dev,actual.st_ino))
                if new_leaf:
                    created.append({'path':str(selected),'device':final.st_dev,'inode':final.st_ino,
                                    'uid':row['uid'],'gid':row['gid'],'mode':row['mode']})
            finally:
                os.close(current)
    return {'initialized':initialized,'verified':len(value['directories'])-initialized,
            'created_directories':created}


def runtime(value):
    """Create the selected runtime namespace without adopting an existing leaf."""
    require(os.geteuid()==ROOT_UID and isinstance(value,dict) and set(value)=={
        'directory','lifecycle','previously_owned'} and value['lifecycle'] in ('fresh','retained')
        and type(value['previously_owned']) is bool)
    selected=path(value['directory']);base=path(RUNTIME_ROOT)
    require(re.fullmatch(re.escape(RUNTIME_ROOT)+'/runtime(?:/[a-z0-9_-]+)*',str(selected)))
    created=0
    with directory(str(base)) as root:
        require(ownership(os.fstat(root))==(ROOT_UID,ROOT_GID,0o700))
        current=os.dup(root)
        try:
            parts=selected.relative_to(base).parts
            for index,part in enumerate(parts):
                leaf=index==len(parts)-1
                try:
                    child=os.open(part,FLAGS,dir_fd=current)
                except FileNotFoundError:
                    require(value['lifecycle']=='fresh' and not value['previously_owned'])
                    os.mkdir(part,0o700,dir_fd=current)
                    child=os.open(part,FLAGS,dir_fd=current)
                    os.fsync(child);os.fsync(current);created+=1
                else:
                    if leaf and value['lifecycle']=='fresh' and not value['previously_owned']:
                        os.close(child);require(False)
                try:
                    require(ownership(os.fstat(child))==(ROOT_UID,ROOT_GID,0o700))
                except BaseException:
                    os.close(child);raise
                os.close(current);current=child
            final=os.fstat(current)
            with directory(str(selected)) as check:
                actual=os.fstat(check)
                require((final.st_dev,final.st_ino)==(actual.st_dev,actual.st_ino))
        finally:
            os.close(current)
    return {'initialized':created,'verified':1}


def identity_data(value):
    """Introduce the modern file volume only from the proved old media layout."""
    require(value['previously_owned'] is True and len(value['services']) == 2)
    row = {key:value[key] for key in ('root','path')}
    row.update(uid=1000,gid=1000,mode='0700')
    root, selected = specification(row)
    media = path(value['media'])
    require(root in media.parents and media != selected and selected not in media.parents and media not in selected.parents)
    compose = Path(value['compose'])
    require(compose.parent == Path('/opt/homelab-app') and re.fullmatch('[a-z][a-z0-9_-]{0,62}\\.ya?ml', compose.name))
    info = compose.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == ROOT_UID and not info.st_mode & 0o022 and info.st_size <= 1024*1024)
    old = json.loads(compose.read_bytes())
    require(old['name'] == value['project'])
    current = []
    for service, role in zip(value['services'], ('server','worker'), strict=True):
        previous = old['services'][service]
        require(previous['command'] == role)
        mounts = [item.split(':')[:2] for item in previous['volumes'] if isinstance(item,str)]
        state = [item for item in mounts if item[1] in ('/data','/data/media','/media')]
        modern = [[str(selected),'/data'],[str(media),'/data/media']]
        require(state == [[str(media),'/media']] or sorted(state) == sorted(modern))
        current.append(sorted(state) == sorted(modern))
    require(current[0] == current[1])
    try:
        with directory(value['path']) as descriptor:
            require(current[0] or not os.listdir(descriptor))
    except FileNotFoundError:
        require(not current[0])
        return initialize({'directories':[row],'previously_owned':False})
    return initialize({'directories':[row],'previously_owned':True})


if __name__=='__main__':
    try:
        raw=sys.stdin.buffer.read(1024*1024+1);require(len(raw)<=1024*1024)
        operations={():initialize,('runtime',):runtime,('authentik-data',):identity_data}
        require(tuple(sys.argv[1:]) in operations)
        operation=operations[tuple(sys.argv[1:])]
        print(json.dumps(operation(json.loads(raw)),sort_keys=True))
    except Exception:
        raise SystemExit('Component storage preparation held; preserve existing data.') from None
