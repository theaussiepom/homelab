"""Closed recovery-group metadata and bounded worker barrier messages."""
import copy
import datetime
import json
import re
import os
import select
import time
from pathlib import PurePosixPath
import ipaddress

from private_io import digest, encoded, require

LIMIT = 1024*1024
STAGES = [('prepared', 'pause'), ('paused', 'capture'), ('captured', 'resume'),
          ('resumed', 'upload'), ('uploaded', 'finish')]


def identifier(value):
    return isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value)


def inventory_digest(value):
    selected = copy.deepcopy(value)
    return digest(encoded(selected))


def member(value):
    require(isinstance(value, dict) and set(value) == {'name', 'member'}
            and identifier(value['name']) and identifier(value['member']), 'Bind the stable backup group member')
    return value


def configuration(value):
    require(isinstance(value, dict) and set(value) == {'name', 'members'}
            and identifier(value['name']) and isinstance(value['members'], dict)
            and 0 < len(value['members']) <= 64, 'Bind the closed backup group')
    scopes = set()
    for name, row in value['members'].items():
        require(identifier(name) and isinstance(row, dict) and set(row) == {
            'state_root', 'node', 'vmid', 'hostname', 'api_address', 'api_port'},
            'Preserve the finite configured backup membership')
        require(isinstance(row['state_root'], str) and row['state_root'].startswith('/') and str(PurePosixPath(row['state_root'])) == row['state_root']
                and '..' not in PurePosixPath(row['state_root']).parts and row['state_root'] != '/'
                and not any(ord(char) < 32 for char in row['state_root'])
                and isinstance(row['node'], str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}', row['node'])
                and type(row['vmid']) is int and 100 <= row['vmid'] <= 999999999
                and isinstance(row['api_address'], str) and str(ipaddress.IPv4Address(row['api_address'])) == row['api_address']
                and type(row['api_port']) is int and 1 <= row['api_port'] <= 65535
                and isinstance(row['hostname'], str) and identifier(row['hostname']),
                'Preserve backup member identities and immutable inventory pins')
        scope = (row['state_root'], row['vmid'])
        require(scope not in scopes, 'Backup members cannot share a custody directory')
        scopes.add(scope)
    return value


def message(stream, timeout=None):
    if timeout is None:
        raw = stream.readline(LIMIT+1)
    else:
        end = time.monotonic()+timeout; raw = b''
        while b'\n' not in raw:
            remaining = end-time.monotonic()
            require(remaining > 0 and select.select([stream], [], [], remaining)[0],
                    'The backup coordinator lease expired')
            chunk = os.read(stream.fileno(), min(65536, LIMIT+1-len(raw)))
            require(chunk, 'The backup coordinator disconnected')
            raw += chunk
            require(len(raw) <= LIMIT, 'The backup protocol message exceeds its bound')
        require(raw.count(b'\n') == 1, 'Do not pipeline backup protocol commands')
    require(raw and len(raw) <= LIMIT and raw.endswith(b'\n'), 'Use bounded complete backup protocol messages')
    def unique(pairs):
        result = dict(pairs)
        require(len(result) == len(pairs), 'Duplicate backup protocol fields refuse')
        return result
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
    require(isinstance(value, dict), 'Use a named backup protocol message')
    return value


def send(stream, value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()+b'\n'
    require(len(raw) <= LIMIT, 'The backup protocol message exceeds its bound')
    stream.write(raw); stream.flush()


def recovery_set(group, generation, stamp, captures, destinations):
    configuration(group)
    require(isinstance(generation, str) and re.fullmatch('[0-9a-f]{32}', generation)
            and type(stamp) is int and stamp > 0 and set(captures) == set(group['members'])
            and set(destinations) == set(group['members']),
            'Require every member of the coordinated capture window')
    members = {}
    for name, row in group['members'].items():
        sha = captures[name]
        require(isinstance(sha, str) and re.fullmatch('[0-9a-f]{64}', sha), 'Bind completed native capture manifests')
        time = datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        target = destinations[name]
        require(isinstance(target, dict) and set(target) == {'server', 'port', 'datastore', 'namespace'},
                'Bind each independently protected PBS destination')
        require(isinstance(target['server'], str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', target['server'])
                and type(target['port']) is int and 1 <= target['port'] <= 65535
                and isinstance(target['datastore'], str) and re.fullmatch(r'[A-Za-z0-9_-]+', target['datastore'])
                and isinstance(target['namespace'], str) and len(target['namespace']) <= 257
                and re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+){1,6}', target['namespace']),
                'Use literal independently verified recovery destinations')
        members[name] = {**target, 'snapshot': 'host/'+name+'/'+time, 'data_manifest_sha256': sha}
    return {'schema': 'homelab-pbs-recovery-set-v1', 'name': group['name'],
        'generation': generation, 'backup_time': stamp, 'members': members,
        'coordinated_window': True, 'distributed_database_transaction': False}


def received_set(group, generation, stamp, value):
    require(isinstance(value, dict) and isinstance(value.get('members'), dict), 'Use the complete recovery set')
    expected = recovery_set(group, generation, stamp,
        {key: row.get('data_manifest_sha256') for key, row in value['members'].items()},
        {key: {field: row.get(field) for field in ('server', 'port', 'datastore', 'namespace')}
            for key, row in value['members'].items()})
    require(value == expected, 'Refuse a partial, foreign or rewritten recovery set')
    return value
