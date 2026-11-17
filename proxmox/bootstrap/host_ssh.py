"""Add root public keys to the existing single-node Proxmox key store."""
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess

import component_control
import component_ssh

TARGET = '/etc/pve/priv/authorized_keys'
LINK = '/root/.ssh/authorized_keys'
LOCK = '/run/lock/homelab-personal-ssh.lock'


def require(ok):
    if not ok:
        raise ValueError('Proxmox root SSH custody or request changed')


def request(value):
    require(isinstance(value, dict) and set(value) == {'node', 'keys'}
            and isinstance(value['node'], str)
            and re.fullmatch('[a-z][a-z0-9-]{0,62}', value['node'])
            and isinstance(value['keys'], list) and 1 <= len(value['keys']) <= 64)
    component_ssh.declarations(value['keys'])


def platform(node):
    require(os.geteuid() == 0 and socket.gethostname().split('.')[0] == node
            and os.path.ismount('/etc/pve')
            and Path('/etc/pve/local').resolve(strict=True) == Path('/etc/pve/nodes')/node
            and sorted(p.name for p in Path('/etc/pve/nodes').iterdir()) == [node])


def inspect():
    link = os.lstat(LINK)
    require(stat.S_ISLNK(link.st_mode) and link.st_uid == 0 and link.st_gid == 0
            and os.readlink(LINK) == TARGET)
    for path, gid, mode in [('/root', 0, 0o700), ('/root/.ssh', 0, 0o700),
                            ('/etc/pve', 33, 0o755), ('/etc/pve/priv', 33, 0o700)]:
        info = os.lstat(path)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                and info.st_gid == gid and stat.S_IMODE(info.st_mode) == mode)
    snapshot = component_control.capture_file(TARGET)
    component_control.validate_file(snapshot)
    require(snapshot['exists'] and snapshot['uid'] == 0 and snapshot['gid'] == 33
            and snapshot['mode'] == 0o600)
    identity = [link.st_dev, link.st_ino, link.st_uid, link.st_gid, link.st_mtime_ns]
    return snapshot, identity


@contextmanager
def locked():
    descriptor = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


# Proxmox itself uses this writer for the cluster's authorized_keys file.
# Preserve the pmxcfs link and fixed root:www-data/0600 file ownership instead
# of replacing root's link or applying a POSIX-file chown to pmxcfs.
WRITE = r'''use strict; use warnings;
use JSON; use MIME::Base64 qw(decode_base64); use Digest::SHA qw(sha256_hex);
use PVE::Cluster; use PVE::Tools;
local $/; my $p = decode_json(<STDIN>);
my $f = '/etc/pve/priv/authorized_keys';
my @s = lstat($f);
die "key custody changed\n" unless @s && -f _ && !-l _ && $s[3] == 1
 && $s[4] == 0 && $s[5] == 33 && ($s[2] & 07777) == 0600;
die "key link changed\n" unless readlink('/root/.ssh/authorized_keys') eq $f;
PVE::Cluster::check_cfs_quorum();
my $before = PVE::Tools::file_get_contents($f);
my $after = decode_base64($p->{content});
die "key preimage changed\n" unless sha256_hex($before) eq $p->{before}
 && index($after, $before) == 0 && length($after) <= 524288;
PVE::Tools::file_set_contents($f, $after, 0600);
'''


def store(before, raw):
    payload = {'before': before['sha256'], 'content': base64.b64encode(raw).decode()}
    result = subprocess.run(['perl', '-e', WRITE], input=json.dumps(payload),
                            capture_output=True, text=True, timeout=20)
    require(result.returncode == 0)


def run(value, source, apply=''):
    request(value)
    require(isinstance(source, str) and re.fullmatch('[0-9a-f]{64}', source))
    platform(value['node'])
    with locked():
        before, link = inspect()
        raw = component_control.validate_file(before)
        updated = component_ssh.append(raw, value['keys'])
        identity = {'request': value, 'source_sha256': source, 'before':
                    {k: v for k, v in before.items() if k != 'content'}, 'link': link,
                    'after_sha256': hashlib.sha256(updated).hexdigest()}
        fingerprint = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        require(not apply or apply == fingerprint)
        changed = updated != raw
        if apply and changed:
            store(before, updated)
        actual, actual_link = inspect()
        require(actual_link == link and actual == (dict(before, content=base64.b64encode(updated).decode(),
                sha256=hashlib.sha256(updated).hexdigest()) if apply else before))
        return {'status': 'ready', 'node': value['node'], 'plan_sha256': fingerprint,
                'changed': changed, 'applied': bool(apply), 'before_sha256': before['sha256'],
                'after_sha256': identity['after_sha256'], 'preserved_existing_bytes': True,
                'key_writes': int(bool(apply) and changed), 'declared_keys': len(value['keys'])}
