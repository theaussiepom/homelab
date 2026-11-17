"""Add declared root SSH keys without replacing existing authorizations.

Runs inside the existing protected Ansible phase. Fixed paths and public keys
only: no private-key transport, account creation, sshd changes or key removal.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import sys

import component_control

ROOT_KEYS = '/root/.ssh/authorized_keys'
ROOT_UID = 0
ROOT_GID = 0
WIRE_PREFIX = b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'


def require(value):
    if not value:
        raise ValueError('Root SSH key custody or declaration is invalid')


def identity(value):
    require(isinstance(value, str) and len(value) <= 128)
    fields = value.split(' ')
    require(len(fields) == 2 and fields[0] == 'ssh-ed25519')
    try:
        raw = base64.b64decode(fields[1], validate=True)
    except ValueError:
        raise ValueError('Declare a valid Ed25519 public key') from None
    require(len(raw) == 51 and raw.startswith(WIRE_PREFIX)
            and base64.b64encode(raw).decode() == fields[1])
    return fields[1]


def declarations(keys):
    require(isinstance(keys, list) and keys)
    identities = [identity(key) for key in keys]
    require(len(identities) == len(set(identities)))
    return identities


def installed(raw):
    found = set()
    for line in raw.splitlines():
        try:
            fields = shlex.split(line.decode('utf-8', 'surrogateescape'), comments=True)
        except ValueError:
            continue  # Preserve unrecognised lines byte-for-byte.
        index = 0 if fields and fields[0] == 'ssh-ed25519' else 1
        if len(fields) >= index + 2 and fields[index] == 'ssh-ed25519':
            try:
                found.add(identity(' '.join(fields[index:index + 2])))
            except ValueError:
                pass
    return found


def contents(snapshot):
    raw = component_control.validate_file(snapshot)
    require(raw is not None and snapshot['uid'] == ROOT_UID and snapshot['gid'] == ROOT_GID
            and snapshot['mode'] in (0o600, 0o640, 0o644))
    return raw


def updated(snapshot, keys):
    raw = contents(snapshot)
    wanted = declarations(keys)
    known = installed(raw)
    missing = [key for key, public in zip(keys, wanted, strict=True) if public not in known]
    if missing:
        raw += (b'\n' if raw and not raw.endswith(b'\n') else b'') + ('\n'.join(missing) + '\n').encode()
    require(len(raw) <= component_control.MAX_BYTES)
    return {**snapshot, 'content': base64.b64encode(raw).decode(),
            'sha256': hashlib.sha256(raw).hexdigest()}


def verify(snapshot, keys):
    raw = contents(snapshot)
    require(set(declarations(keys)) <= installed(raw))


def inspect():
    # The existing file is shared custody. Refuse a new namespace or metadata
    # that the bounded managed-file transaction cannot preserve.
    with component_control.parent(ROOT_KEYS) as (directory, name):
        info = os.fstat(directory)
        mode = stat.S_IMODE(info.st_mode)
        require(info.st_uid == ROOT_UID and info.st_gid == ROOT_GID
                and mode & 0o700 == 0o700 and mode & ~0o755 == 0)
        leaf = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            require(not os.listxattr(leaf))
        finally:
            os.close(leaf)
    snapshot = component_control.capture_file(ROOT_KEYS)
    contents(snapshot)
    return snapshot


def run(value):
    fields = {'mode', 'keys'}
    require(isinstance(value, dict) and (set(value) == fields
            or set(value) == fields | {'metadata'} and value['mode'] == 'verify')
            and value['mode'] in ('install', 'verify'))
    before = inspect()
    if 'metadata' in value:
        metadata = value['metadata']
        require(isinstance(metadata, dict) and set(metadata) == {'uid', 'gid', 'mode'}
                and all(type(item) is int for item in metadata.values())
                and metadata == {key: before[key] for key in metadata})
    if value['mode'] == 'install':
        after = updated(before, value['keys'])
        changed = component_control.restore_file(ROOT_KEYS, after, [before['sha256']])
    else:
        after, changed = before, False
    actual = inspect()
    require(actual == after)
    verify(actual, value['keys'])
    return {'changed': changed, 'declared_keys': len(value['keys'])}


def transport(keys, *, mode, metadata=None):
    """Package the existing control writer and this fixed-path operation."""
    control = base64.b64encode(Path(component_control.__file__).read_bytes()).decode()
    helper = base64.b64encode(Path(__file__).read_bytes()).decode()
    program = (
        "import base64,sys,types\n"
        "control=types.ModuleType('component_control')\n"
        f"exec(compile(base64.b64decode('{control}'),'<homelab-controls>','exec'),control.__dict__)\n"
        "sys.modules['component_control']=control\n"
        f"exec(compile(base64.b64decode('{helper}'),'<homelab-root-keys>','exec'))\n"
    )
    request = {'mode': mode, 'keys': keys.copy()}
    if metadata is not None:
        request['metadata'] = metadata.copy()
    return {'program': base64.b64encode(program.encode()).decode(), 'request': request}


def main():
    raw = sys.stdin.buffer.read(2 * component_control.MAX_BYTES + 1)
    require(len(raw) <= 2 * component_control.MAX_BYTES)
    print(json.dumps(run(json.loads(raw)), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Root SSH key maintenance held; preserve private diagnostics.') from None
