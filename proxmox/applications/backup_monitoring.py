"""Create the selected PBS audit credential in protected backup CD."""
from pathlib import Path
import re

from backup_api import MONITOR_TOKEN, MONITOR_USER
from private_io import digest, encoded, private_directory, read_json, regular, require, sync, write_new

MARKER = 'HomeLab Zabbix PBS monitoring'
GRANTS = {('/system/status', 'Audit', False), ('/system/tasks', 'Audit', False),
          ('/datastore', 'DatastoreAudit', True)}
AUDIT = {'Sys.Audit': False, 'Datastore.Audit': False}
DATASTORE = {'Datastore.Audit': True}


def owned(row, name, key):
    return (row.get(key) == name and row.get('comment') == MARKER and
            row.get('enable', True) is True and row.get('expire', 0) == 0)


def verify(api, monitor):
    users = [row for row in api.users() if row['userid'] == MONITOR_USER]
    require(len(users) == 1 and owned(users[0], MONITOR_USER, 'userid'), 'Preserve the PBS monitoring owner')
    tokens = users[0].get('tokens', [])
    require(len(tokens) == 1 and owned(tokens[0], MONITOR_TOKEN, 'tokenid'),
            'Preserve the exact PBS monitoring token')
    for rights in (api.permission(MONITOR_USER), monitor.permission(MONITOR_TOKEN)):
        require(rights.get('/system/status') == rights.get('/system/tasks') == AUDIT
                and rights.get('/datastore') == DATASTORE
                and all((path in ('/system/status', '/system/tasks') and privileges == AUDIT)
                        or ((path == '/datastore' or path.startswith('/datastore/')) and privileges == DATASTORE)
                        for path, privileges in rights.items()), 'PBS monitoring access must be audit only')


def provision(api, destination, token_file, api_factory):
    token = Path(token_file)
    private_directory(token.parent)
    pending = token.with_name(token.name + '.pending.json')
    complete = token.with_name(token.name + '.owner.json')
    owner = {key: destination[key] for key in ('server', 'port', 'fingerprint')}
    owner['identity'] = MONITOR_TOKEN
    require(not (pending.exists() or pending.is_symlink()), 'Preserve interrupted PBS monitoring provisioning')
    if token.exists() or token.is_symlink() or complete.exists() or complete.is_symlink():
        secret = regular(token, private=True, limit=64)
        require(read_json(complete, private=True) == {'owner': owner, 'sha256': digest(secret)},
                'Preserve the existing PBS monitoring credential')
        verify(api, api_factory(destination, MONITOR_TOKEN + ':' + secret.decode('ascii')))
        return

    acl = api.request('GET', '/access/acl')['data']
    require(not any(row['userid'] == MONITOR_USER for row in api.users())
            and isinstance(acl, list) and not any(row['ugid'] in (MONITOR_USER, MONITOR_TOKEN) for row in acl),
            'Preserve an existing unowned PBS monitoring user, token or grant')
    write_new(pending, encoded(owner))
    api.request('POST', '/access/users', {'userid': MONITOR_USER, 'comment': MARKER, 'enable': 1, 'expire': 0})
    value = api.request('POST', '/access/users/' + MONITOR_USER + '/token/monitoring',
                        {'comment': MARKER, 'enable': 1, 'expire': 0})['data']
    require(isinstance(value, dict) and value.get('tokenid') == MONITOR_TOKEN
            and isinstance(value.get('value'), str)
            and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value['value']),
            'PBS returned an unexpected monitoring token')
    secret = value['value'].encode('ascii')
    write_new(token, secret)
    for auth_id in (MONITOR_USER, MONITOR_TOKEN):
        for path, role, propagate in sorted(GRANTS):
            current = api.request('GET', '/access/acl').get('digest', '')
            require(isinstance(current, str) and re.fullmatch('[0-9a-f]{64}', current),
                    'Bind the current PBS ACL generation')
            api.request('PUT', '/access/acl', {'path': path, 'role': role, 'auth-id': auth_id,
                        'propagate': int(propagate), 'digest': current})
    verify(api, api_factory(destination, MONITOR_TOKEN + ':' + value['value']))
    write_new(complete, encoded({'owner': owner, 'sha256': digest(secret)}))
    pending.unlink()
    sync(token.parent)
