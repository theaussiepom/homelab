"""Stable public PBS ownership; no secret generation or filesystem access."""
import hashlib
import json
from pathlib import PurePosixPath

import backup_policy


def identity(destination, guest, group):
    """Certificate and recovery-key renewal must not create a new PBS account."""
    backup_policy.owner(guest)
    value = {'schema': 'homelab-pbs-client-owner-v1', 'guest': guest,
             'group': group, 'destination': {key: destination[key] for key in
                 ('server', 'port', 'datastore', 'namespace', 'backup_id')}}
    digest = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return value, digest


def binding(destination, guest, group, state_root):
    """Derive only this client's closed controller record and native identity."""
    owner, digest = identity(destination, guest, group)
    directory = str(PurePosixPath(state_root) / 'pbs-clients' / digest)
    return {'owner': owner, 'identity': digest, 'directory': directory,
            'user': 'hl-' + digest[:32] + '@pbs',
            'auth_id': 'hl-' + digest[:32] + '@pbs!backup',
            'namespace': destination['namespace'] + '/' + destination['backup_id'],
            'secrets': {field: {'type': 'file', 'path': directory + '/' + leaf}
                for field, leaf in (('password', 'pbs-password'), ('encryption_key', 'pbs-key'))}}
