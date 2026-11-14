"""Admit one separately commissioned NFS recording bind into owned guest state.

No host mutation or state editing is performed here. Existing genuine component
success, exact native configuration and a guest filesystem check are required.
"""
from pathlib import Path
import re
import shlex
from urllib.parse import quote

from commands import quiet
from private_io import require, regular, decode_json


def declaration(value):
    require(isinstance(value, dict) and set(value) == {
        'source', 'path', 'slot', 'filesystem_source', 'filesystem', 'filesystem_root'},
        'Use the closed Scrypted recording mount declaration')
    for key in ('source', 'path'):
        require(isinstance(value[key], str) and re.fullmatch(
            r'/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', value[key])
            and not {'.', '..'} & set(value[key].split('/')),
            'Use literal recording bind paths')
    require(value['source'].startswith('/mnt/') and value['path'].startswith('/srv/')
            and type(value['slot']) is int and 0 <= value['slot'] <= 255
            and value['filesystem'] in ('nfs', 'nfs4')
            and isinstance(value['filesystem_source'], str)
            and re.fullmatch(r'[A-Za-z0-9_.-]+:/(?:[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)?',
                             value['filesystem_source'])
            and isinstance(value['filesystem_root'], str)
            and re.fullmatch(r'/(?:[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)?', value['filesystem_root'])
            and not {'.', '..'} & set(value['filesystem_root'].split('/'))
            and str(Path(value['filesystem_root'])) == value['filesystem_root'],
            'Bind the exact declared NAS source and appended guest slot')
    return value


def expected(value):
    value = declaration(value)
    return {'path': value['path'], 'volume': value['source'],
        'path_in_datastore': value['source'], 'size': '', 'backup': False,
        'replicate': False, 'acl': False, 'quota': False, 'read_only': False,
        'shared': False, 'mount_options': []}


def provider_row(row, selected):
    wanted = expected(selected)
    return (isinstance(row, dict) and set(row) == set(wanted)
            and all((row[key] in (None, []) if key == 'mount_options' else row.get(key) == value)
                    and (type(row[key]) is bool if type(value) is bool else True)
                    for key, value in wanted.items()))


def native_row(raw, row):
    require(isinstance(raw, str) and len(raw) <= 4096, 'Read bounded native bind options')
    parts = raw.split(','); options = {}
    for item in parts[1:]:
        key, separator, value = item.partition('=')
        require(separator and key not in options, 'Use unique native bind options')
        options[key] = value
    require(parts[0] == row['volume'] and options.get('mp') == row['path']
            and row['size'] == '' and row['path_in_datastore'] == row['volume']
            and all(type(row[key]) is bool and row[key] is False
                    for key in ('backup', 'replicate', 'acl', 'quota', 'read_only', 'shared'))
            and row['mount_options'] in (None, [])
            and all(options.get(key, default) == '0' for key, default in (
                ('backup', '0'), ('replicate', '1'), ('acl', '0'), ('quota', '0'), ('ro', '0'), ('shared', '0')))
            and set(options) <= {'mp', 'backup', 'replicate', 'acl', 'quota', 'ro', 'shared'},
            'Preserve the exact writable unprotected nonreplicated NAS bind')
    return raw


def original(cfg, previous, work):
    from backup_staging import backend_mounts
    selected = declaration(cfg['guest']['recording_mount'])
    require(isinstance(previous, dict) and selected['slot'] == len(cfg['guest']['volumes']),
            'Commission recording storage only after a genuine guest success')
    mounts = backend_mounts(work)
    old = previous['guest'].get('recording_mount')
    if old is None:
        require(len(mounts) == selected['slot'] and not any(
            row.get('path') == selected['path'] or row.get('volume') == selected['source'] for row in mounts),
            'An existing bind cannot silently acquire recording ownership')
        return mounts + [expected(selected)]
    require(old == selected and len(mounts) == selected['slot'] + 1
            and provider_row(mounts[-1], selected), 'Preserve the successful recording bind identity')
    return mounts


def verify(cfg, mounts, log, api_get, *, label):
    import backup_staging
    selected = declaration(cfg['guest']['recording_mount'])
    require(label in ('before', 'after') and len(mounts) == selected['slot'] + 1
            and provider_row(mounts[-1], selected), 'Verify one exact appended recording bind')
    base = '/nodes/' + quote(cfg['site']['node'], safe='') + '/lxc/' + str(cfg['guest']['vmid'])
    def projection():
        current = api_get(base + '/config?current=1')
        require(current.get('hostname') == cfg['guest']['hostname']
                and current.get('unprivileged') == 1 and current.get('protection') == 1
                and {key for key in current if re.fullmatch(r'mp[0-9]+', key)} == {
                    'mp' + str(i) for i in range(len(mounts))},
                'Preserve guest identity and its complete active mount sequence')
        rows = tuple(backup_staging.native_row(current['mp'+str(i)], row)
                     for i, row in enumerate(mounts))
        pending = api_get(base + '/pending')
        require(isinstance(pending, list) and all(isinstance(row, dict)
            and isinstance(row.get('key'), str)
            and not ((re.fullmatch(r'mp[0-9]+', row['key']) or row['key'] == 'rootfs')
                     and ('pending' in row or row.get('delete', 0))) for row in pending),
            'Preserve pending native mount changes')
        return rows, current['rootfs']
    before = projection()
    proof = log.parent / ('scrypted-recording-mount-' + label + '.json')
    require(not proof.exists() and not proof.is_symlink(), 'Preserve existing recording mount evidence')
    argv = ['ssh', '-F', '/dev/null', '-o', 'StrictHostKeyChecking=yes', '-o', 'BatchMode=yes',
        '-o', 'IdentitiesOnly=yes', '-o', 'ControlMaster=no', '-o', 'GlobalKnownHostsFile=/dev/null',
        '-o', 'VerifyHostKeyDNS=no', '-o', 'UpdateHostKeys=no', '-o', 'ConnectTimeout=10',
        '-o', 'UserKnownHostsFile='+cfg['paths']['known_hosts'], '-i', cfg['paths']['private_key'],
        'root@'+cfg['app']['address'], '/usr/bin/python3 - --mount-only ' + ' '.join(shlex.quote(x)
            for x in ('--recordings', selected['path'], '--source', selected['filesystem_source'],
                      '--filesystem', selected['filesystem'], '--root', selected['filesystem_root']))]
    quiet(argv, {'PATH':'/usr/bin:/bin'}, proof,
          input_bytes=Path(__file__).with_name('scrypted_runtime.py').read_bytes(), timeout=30)
    require(decode_json(regular(proof, private=True, limit=4096)) == {
        'status':'passed', 'state_initialized':False,
        'recording_source_verified':True, 'writes_performed':False}
        and projection() == before, 'Require stable native and guest NAS mount evidence')
    return before
