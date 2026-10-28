"""Create one persistent per-guest PSK for CD; never print a secret or rotate it."""
import argparse
import fcntl
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys

from foundation_cd import encoded, private_directory, regular, sync, write_new

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bootstrap'))
from bootstrap_cd import check_backup


def require(value):
    if not value:
        raise ValueError('Agent credential binding, protected storage or retained state differs; hold for review')


def subject(hostname, machine_id):
    require(isinstance(hostname, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,63}', hostname))
    require(isinstance(machine_id, str) and re.fullmatch(r'[0-9a-f]{32}', machine_id))
    return hostname + '.' + machine_id


def load(path, hostname, machine_id):
    identity = subject(hostname, machine_id)
    require(path.is_absolute())
    private_directory(path.parent)
    require(not (path.parent / 'PSK-HOLD.json').exists())
    record = json.loads(regular(path, private=True))
    require(set(record) == {'schema', 'hostname', 'machine_id', 'psk_identity', 'psk'})
    require(record['schema'] == 'homelab-agent-credential-v1' and record['hostname'] == hostname
            and record['machine_id'] == machine_id and record['psk_identity'] == identity)
    require(isinstance(record['psk'], str) and re.fullmatch(r'[0-9a-f]{64}', record['psk']))
    return record


def provision(c):
    require(set(c) == {'schema', 'hostname', 'machine_id', 'store', 'recovery', 'backup_source', 'allow_create'})
    require(c['schema'] == 'homelab-agent-secret-v1' and type(c['allow_create']) is bool)
    identity = subject(c['hostname'], c['machine_id'])
    roots = [Path(c[key]) for key in ('store', 'recovery')]
    require(all(p.is_absolute() for p in roots))
    require(roots[0].resolve() != roots[1].resolve()
            and roots[0].resolve() not in roots[1].resolve().parents
            and roots[1].resolve() not in roots[0].resolve().parents)
    for root in roots: private_directory(root)
    check_backup(c, roots[1])
    fd = os.open(roots[0] / 'psk.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+') as lock:
        info = os.fstat(lock.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        directories = [root / c['hostname'] for root in roots]
        require(directories[0].exists() == directories[1].exists())
        if directories[0].exists():
            records = [load(p / 'credential.json', c['hostname'], c['machine_id']) for p in directories]
            require(hmac.compare_digest(encoded(records[0]), encoded(records[1])))
            created = False
        else:
            require(c['allow_create'])
            for path in directories:
                private_directory(path, create=True)
                sync(path.parent)
                write_new(path / 'PSK-HOLD.json', encoded({'automatic_retry': False}))
            record = {'schema': 'homelab-agent-credential-v1', 'hostname': c['hostname'],
                'machine_id': c['machine_id'], 'psk_identity': identity, 'psk': secrets.token_hex(32)}
            for path in directories: write_new(path / 'credential.json', encoded(record))
            require(hmac.compare_digest(regular(directories[0] / 'credential.json', private=True),
                                        regular(directories[1] / 'credential.json', private=True)))
            for path in reversed(directories):
                (path / 'PSK-HOLD.json').unlink(); sync(path)
            created = True
        return {'created': created, 'hostname': c['hostname'], 'psk_identity': identity,
                'credential_file': str(directories[0] / 'credential.json')}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--provision', type=Path)
    mode.add_argument('--check', type=Path)
    parser.add_argument('--hostname')
    parser.add_argument('--machine-id')
    args = parser.parse_args()
    try:
        if args.provision:
            config = json.loads(regular(args.provision, private=True))
            require(config['hostname'] == args.hostname and config['machine_id'] == args.machine_id)
            print(json.dumps(provision(config)))
        else:
            load(args.check, args.hostname, args.machine_id)
            print('Agent credential binding verified.')
    except Exception:
        raise SystemExit('Agent secret CD stopped; preserve protected state and holds. No automatic rotation.') from None
