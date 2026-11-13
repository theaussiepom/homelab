"""Create one owned PBS client once; preserve uncertain remote mutations."""
from pathlib import Path
import re

import backup_identity
import backup_policy
from private_io import digest, encoded, private_directory, read_json, regular, require, sync, write_new


def remote_owner(api, selected):
    """Account metadata and effective privileges must both match, including parents."""
    rows = [row for row in api.users() if row['userid'] == selected['user']]
    marker = 'homelab:' + selected['identity']
    require(len(rows) == 1 and rows[0].get('comment') == marker
            and rows[0].get('enable', True) is True and rows[0].get('expire', 0) == 0,
            'Preserve the existing PBS client account owner')
    tokens = rows[0].get('tokens', [])
    require(isinstance(tokens, list) and len(tokens) == 1
            and isinstance(tokens[0], dict) and tokens[0].get('tokenid') == selected['auth_id']
            and tokens[0].get('comment') == marker
            and tokens[0].get('enable', True) is True and tokens[0].get('expire', 0) == 0,
            'Preserve the exact owned PBS client token')
    path = '/datastore/' + api.store + '/' + selected['namespace']
    for auth_id in (selected['user'], selected['auth_id']):
        require(api.permission(auth_id) == {path: {'Datastore.Backup': True}},
                'PBS client effective permissions differ from its own backup namespace')
    require(selected['namespace'] in api.namespaces(), 'The owned PBS namespace is missing')


def grants(api, selected):
    path = '/datastore/' + api.store + '/' + selected['namespace']
    require(len(path) <= 128, 'The complete PBS ACL path exceeds its native bound')
    for auth_id in (selected['user'], selected['auth_id']):
        current = api.request('GET', '/access/acl')
        require(isinstance(current.get('digest'), str) and re.fullmatch('[0-9a-f]{64}', current['digest']),
                'Bind the current PBS ACL generation before adding a grant')
        api.request('PUT', '/access/acl', {'path': path, 'role': 'DatastoreBackup',
            'auth-id': auth_id, 'propagate': 1, 'digest': current['digest']})


def provision(job, guest, state_root, api, key, *, allow_create=True):
    """Caller holds ordinary guest locks; key(create=...) uses the native guest client."""
    require(type(allow_create) is bool, 'Select explicit client enrollment authority')
    backup_policy.validate(job)
    selected = backup_identity.binding(job['destination'], guest, job['group']['name'], state_root)
    require(selected['auth_id'] == job['destination']['auth_id'] and selected['secrets'] == job['secrets'],
            'Bind generated credentials to the compiled PBS owner')
    root = Path(selected['directory']); parent = root.parent
    private_directory(parent.parent)
    if allow_create:
        parent.mkdir(mode=0o700, exist_ok=True)
    private_directory(parent)
    if root.exists() or root.is_symlink():
        private_directory(root)
        require(not any((root/name).exists() or (root/name).is_symlink() for name in ('PENDING.json', 'FAILED.json')),
                'Preserve interrupted PBS enrollment; no automatic retry or adoption')
        require((root/'complete.json').lstat().st_nlink == 1, 'Preserve the single owned PBS credential record')
        record = read_json(root/'complete.json', private=True)
        backup_policy.exact(record, ('schema', 'identity', 'owner', 'files'))
        backup_policy.exact(record['files'], ('pbs-password', 'pbs-key'))
        require(record.get('owner') == selected['owner'] and record.get('identity') == selected['identity']
                and record.get('schema') == 'homelab-pbs-client-record-v1', 'Preserve PBS credential ownership')
        for name in ('pbs-password', 'pbs-key'):
            require((root/name).lstat().st_nlink == 1
                    and digest(regular(root/name, private=True, limit=16384)) == record['files'][name],
                    'Preserve exact stored PBS credential bytes')
        remote_owner(api, selected)
        require(digest(key(create=False)) == record['files']['pbs-key'],
                'The deployed PBS encryption key differs; never replace it')
        return selected
    require(allow_create, 'Enable this guest for its initial backup enrollment; disabled guests are read-only')
    existing_users = api.users(); namespaces = api.namespaces()
    acl = api.request('GET', '/access/acl')['data']
    require(not any(row['userid'] == selected['user'] for row in existing_users)
            and selected['namespace'] not in namespaces
            and isinstance(acl, list) and all(isinstance(row, dict) for row in acl)
            and not any(row.get('ugid') in (selected['user'], selected['auth_id']) for row in acl),
            'An unowned PBS account, token, grant or namespace already exists')
    private_directory(root, create=True)
    pending = encoded({'schema': 'homelab-pbs-enrollment-attempt-v1', 'owner': selected['owner']})
    write_new(root/'PENDING.json', pending)
    try:
        parts = selected['namespace'].split('/')
        for end in range(1, len(parts)+1):
            name = '/'.join(parts[:end])
            if name not in namespaces:
                api.request('POST', '/admin/datastore/' + api.store + '/namespace',
                    {'parent': '/'.join(parts[:end-1]), 'name': parts[end-1]})
                namespaces.add(name)
        marker = 'homelab:' + selected['identity']
        api.request('POST', '/access/users', {'userid': selected['user'], 'comment': marker, 'enable': 1, 'expire': 0})
        token = api.request('POST', '/access/users/' + selected['user'] + '/token/backup',
            {'comment': marker, 'enable': 1, 'expire': 0})['data']
        require(isinstance(token, dict) and token.get('tokenid') == selected['auth_id']
                and isinstance(token.get('value'), str) and re.fullmatch(r'[A-Za-z0-9_.-]{16,512}', token['value']),
                'PBS token creation returned an invalid identity or secret; preserve the attempt')
        write_new(root/'pbs-password', token['value'].encode())
        grants(api, selected)
        remote_owner(api, selected)
        raw_key = key(create=True)
        require(isinstance(raw_key, bytes) and 1 <= len(raw_key) <= 16384,
                'Require a bounded native PBS encryption key')
        write_new(root/'pbs-key', raw_key)
        write_new(root/'complete.json', encoded({'schema': 'homelab-pbs-client-record-v1',
            'identity': selected['identity'], 'owner': selected['owner'],
            'files': {name: digest(regular(root/name, private=True, limit=16384))
                      for name in ('pbs-password', 'pbs-key')}}))
        require(regular(root/'PENDING.json', private=True) == pending, 'Preserve a foreign PBS enrollment marker')
        (root/'PENDING.json').unlink(); sync(root)
    except Exception as error:
        write_new(root/'FAILED.json', encoded({'error_type': type(error).__name__, 'automatic_retry': False}))
        raise
    return selected
