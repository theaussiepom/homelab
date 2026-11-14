#!/usr/bin/env python3
"""Read-only Scrypted recording-source admission before its managed writer starts."""
import argparse
import json
import os
from pathlib import PurePosixPath
import stat
import subprocess


def require(ok):
    if not ok:
        raise ValueError('Preserve the admitted Scrypted state and recording mount')


def directory(path):
    require(isinstance(path, str) and path.startswith('/')
            and PurePosixPath(path).as_posix() == path
            and all(part not in ('.', '..') for part in path.split('/')))
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in PurePosixPath(path).parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def validate_mount(recordings, source, filesystem, root):
    require(filesystem in ('nfs', 'nfs4') and isinstance(source, str)
            and source and ':' in source and not any(c.isspace() for c in source))
    nvr_fd = directory(recordings)
    try:
        found = subprocess.run(
            ['findmnt', '--json', '--nofsroot', '--mountpoint', recordings,
             '--output', 'SOURCE,FSTYPE,FSROOT,OPTIONS,TARGET'],
            capture_output=True, timeout=5, check=True)
        require(len(found.stdout) <= 65536)
        mounts = json.loads(found.stdout)['filesystems']
        require(isinstance(mounts, list) and len(mounts) == 1)
        mount = mounts[0]
        require(mount['source'] == source and mount['fstype'] == filesystem
                and mount['target'] == recordings and mount['fsroot'] == root
                and 'rw' in mount['options'].split(',')
                and not os.fstatvfs(nvr_fd).f_flag & os.ST_RDONLY
                and os.access(recordings, os.W_OK | os.X_OK, effective_ids=True))
        # A path replaced during inspection is not the inspected directory.
        current = os.stat(recordings, follow_symlinks=False)
        opened = os.fstat(nvr_fd)
        require((current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino))
        return {'status': 'passed', 'state_initialized': False,
                'recording_source_verified': True, 'writes_performed': False}
    finally:
        os.close(nvr_fd)


def validate(data, recordings, source, filesystem, root):
    data_fd = directory(data)
    try:
        # Existing state is mandatory; never initialise or restore a database.
        db = os.stat('scrypted.db', dir_fd=data_fd, follow_symlinks=False)
        require(stat.S_ISDIR(db.st_mode))
        return validate_mount(recordings, source, filesystem, root)
    finally:
        os.close(data_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data')
    parser.add_argument('--mount-only', action='store_true')
    for name in ('recordings', 'source', 'filesystem', 'root'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    try:
        require(args.mount_only == (args.data is None))
        result = (validate_mount(args.recordings, args.source, args.filesystem, args.root)
                  if args.mount_only else
                  validate(args.data, args.recordings, args.source, args.filesystem, args.root))
    except Exception:
        print(json.dumps({'status': 'blocked', 'reason': 'scrypted_storage_admission_failed'}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
