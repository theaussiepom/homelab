#!/usr/bin/env python3
"""Create/read one native guest key under the caller's ordinary deployment locks."""
import base64
import os
from pathlib import Path
import subprocess
import sys

import backup_identity
import backup_policy
from private_io import decode_json, digest, encoded, private_directory, regular, require, sync, write_new


def key_bytes(path):
    require(path.lstat().st_nlink == 1, 'Preserve the single owned client key')
    raw = regular(path, private=True, limit=16384)
    value = decode_json(raw)
    backup_policy.exact(value, ('kdf', 'created', 'modified', 'data', 'fingerprint'))
    require(value['kdf'] is None and isinstance(value['data'], str)
            and len(base64.b64decode(value['data'], validate=True)) == 32,
            'Require the native unattended client key, never a replacement')
    return raw


def native(argv):
    """The client generates the key; no inherited token/passphrase providers or logs."""
    subprocess.run(argv, check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, timeout=60, env={'PATH':'/usr/bin:/bin', 'HOME':'/root', 'LANG':'C'})


def client_key(request, *, root=Path('/etc/homelab-backup'), run=native):
    backup_policy.exact(request, ('action', 'identity'))
    require(request['action'] in ('create', 'read'), 'Use the finite client-key operation')
    private_directory(root)
    value = decode_json(regular(root/'coverage.json', private=True))
    job = backup_policy.validate(value['job'])
    owner, identity = backup_identity.identity(job['destination'], value['owner'], job['group']['name'])
    require(request['identity'] == identity, 'Bind the native key to the deployed coverage owner')
    key = root/'pbs-key'; receipt = root/'client-key.json'; pending = root/'client-key-pending.json'
    require(not pending.exists() and not pending.is_symlink(),
            'Preserve interrupted client-key generation; no automatic retry')
    if request['action'] == 'read':
        require(receipt.lstat().st_nlink == 1, 'Preserve the single client-key ownership record')
        proof = decode_json(regular(receipt, private=True))
        raw = key_bytes(key)
        require(proof == {'schema':'homelab-pbs-native-key-v1', 'identity':identity,
                          'owner':owner, 'sha256':digest(raw)}, 'Preserve exact native key ownership')
        return raw
    require(not any(path.exists() or path.is_symlink() for path in (key, receipt)),
            'Refuse adoption or replacement of an existing guest key')
    intent = encoded({'schema':'homelab-pbs-native-key-attempt-v1', 'identity':identity, 'owner':owner})
    write_new(pending, intent)
    # Native create uses exclusive creation. An interruption leaves our durable marker.
    run(['/usr/bin/proxmox-backup-client', 'key', 'create', str(key), '--kdf', 'none'])
    raw = key_bytes(key)
    run(['/usr/bin/proxmox-backup-client', 'key', 'show', str(key), '--output-format', 'json'])
    require(key_bytes(key) == raw, 'The native key changed during validation')
    with key.open('rb') as stream:
        os.fsync(stream.fileno())
    write_new(receipt, encoded({'schema':'homelab-pbs-native-key-v1', 'identity':identity,
                               'owner':owner, 'sha256':digest(raw)}))
    require(regular(pending, private=True) == intent, 'Preserve an unexpected native key marker')
    pending.unlink(); sync(root)
    return raw


def main():
    os.umask(0o077)
    require(os.geteuid() == 0 and len(sys.argv) == 1, 'Run only the fixed root client-key helper')
    raw = sys.stdin.buffer.read(4097)
    require(len(raw) <= 4096, 'Bound the client-key request')
    result = client_key(decode_json(raw))
    # This protected SSH pipe is consumed directly into the controller record, never a CI log.
    sys.stdout.buffer.write(result)


if __name__ == '__main__':
    main()
