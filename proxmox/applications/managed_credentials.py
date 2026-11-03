"""Create once for one declared application account, without rotation or adoption."""
import fcntl
import os
from pathlib import Path
import re
import secrets
import stat

from private_io import encoded, private_directory, read_json, require, write_new


def identifier(value):
    require(isinstance(value, str) and re.fullmatch('[a-z][a-z0-9-]{2,63}', value),
            'Use a bounded declared managed credential identifier')
    return value


def credential(state, name, owner):
    """Serialize only creation/read of this record, never guest or service work."""
    identifier(name)
    require(isinstance(owner, dict) and owner and all(isinstance(key, str) for key in owner),
            'Bind the exact application account owner')
    root = Path(state) / 'managed-credentials'
    private_directory(root.parent)
    root.mkdir(mode=0o700, exist_ok=True)
    private_directory(root)
    fd = os.open(root / (name+'.lock'), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'rb') as lock:
        info = os.fstat(lock.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o600, 'Preserve private account credential custody')
        fcntl.flock(lock, fcntl.LOCK_EX)
        path = root / (name+'.json')
        if not path.exists() and not path.is_symlink():
            write_new(path, encoded({'schema': 'homelab-application-account-v1', 'owner': owner,
                'password': secrets.token_hex(32)}))
        require(path.lstat().st_nlink == 1, 'Refuse a linked account credential record')
        value = read_json(path, private=True)
        require(isinstance(value, dict) and set(value) == {'schema', 'owner', 'password'}
                and value['schema'] == 'homelab-application-account-v1' and value['owner'] == owner
                and isinstance(value['password'], str) and re.fullmatch('[0-9a-f]{64}', value['password']),
                'Account credential differs; preserve the original without rotation')
        return value


def input_name(name):
    return 'managed-'+identifier(name)+'.json'


def payload(state, name, owner, destination):
    """The immutable ordinary input holds the same controller-owned credential."""
    filename = input_name(name)
    return str(destination / filename), {filename: encoded(credential(state, name, owner))}
