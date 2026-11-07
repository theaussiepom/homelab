"""Read-only preimage check before allocating a new dedicated staging volume."""
import shlex
import re

from commands import quiet
from private_io import require

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
