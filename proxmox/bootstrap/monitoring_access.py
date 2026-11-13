"""Bootstrap CD ownership of the dedicated, read-only Zabbix API identity.

Uses the existing bootstrap API client, private receipt writer and NAS check.
A partial attempt is retained and cannot be automatically replayed.
"""
import json
from pathlib import Path
import re

from bootstrap_cd import API, check_backup
from provider_access import address, private_directory, read_private, save_new
from host_api import normalized, same_allowance

USER = 'homelab-zabbix@pve'
TOKEN = 'monitoring'
IDENTITY = USER + '!' + TOKEN
ROLE = 'HomeLabZabbixRead'
PRIVILEGES = {'Sys.Audit', 'VM.Audit', 'Datastore.Audit'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(c):
    require(set(c) == {'schema', 'endpoint', 'node', 'address', 'backup_source'}
            and c['schema'] == 'homelab-zabbix-access-v1'
            and re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,62}', c['node']), 'Use the closed monitoring access packet')
    address(c['address'])
    require(c['endpoint'].startswith('https://') and c['endpoint'].endswith(':8006/'), 'Use the trusted Proxmox API endpoint')


def bootstrap_configuration(c):
    """Derive the existing access transaction from one declared new guest."""
    selected = c['monitoring']
    require(isinstance(selected, dict) and set(selected) == {'vmid', 'address'}
            and type(selected['vmid']) is int
            and {'vmid': selected['vmid'], 'hostname': 'zabbix'} in c['applications'],
            'Bind monitoring access to the declared Zabbix guest')
    value = {key: c[key] for key in ('endpoint', 'node', 'backup_source')}
    value.update(schema='homelab-zabbix-access-v1', address=selected['address'])
    validate(value)
    return value


def rule(c):
    from urllib.parse import urlsplit
    return {'type': 'in', 'action': 'ACCEPT', 'enable': 1, 'source': address(c['address']) + '/32',
            'dest': address(urlsplit(c['endpoint']).hostname) + '/32', 'proto': 'tcp', 'dport': '8006',
            'comment': 'HomeLab Zabbix API audit only'}


def inspect(api, c):
    validate(c)
    users = [row for row in api.call('/access/users')['data'] if row['userid'] == USER]
    roles = [row for row in api.call('/access/roles')['data'] if row['roleid'] == ROLE]
    tokens = api.call('/access/users/' + USER + '/token')['data'] if users else []
    acls = [row for row in api.call('/access/acl')['data']
            if row.get('ugid') in {USER, IDENTITY} or row.get('roleid') == ROLE]
    base = '/nodes/' + c['node'] + '/firewall'
    rules = api.call(base + '/rules')['data']
    options = {k: v for k, v in api.call(base + '/options')['data'].items() if k != 'digest'}
    return {'users': users, 'roles': roles, 'tokens': tokens, 'acl': acls,
            'rules': normalized(rules), 'options': options}


def verify(api, c, saved, before_rules):
    after = inspect(api, c)
    require(len(after['users']) == 1 and after['users'][0].get('enable') == 1
            and after['users'][0].get('expire', 0) == 0 and not after['users'][0].get('groups'), 'Monitoring user drift')
    require(len(after['roles']) == 1 and not after['roles'][0].get('special')
            and set(after['roles'][0].get('privs', '').split(',')) == PRIVILEGES, 'Monitoring role drift')
    require(len(after['tokens']) == 1 and after['tokens'][0].get('tokenid') == TOKEN
            and after['tokens'][0].get('privsep') == 1 and after['tokens'][0].get('expire') == 0, 'Monitoring token drift')
    expected = {('user', USER, '/', ROLE, 1), ('token', IDENTITY, '/', ROLE, 1)}
    actual = {(r['type'], r['ugid'], r['path'], r['roleid'], int(r.get('propagate', 1))) for r in after['acl']}
    require(actual == expected and len(after['acl']) == 2, 'Monitoring ACL drift')
    wanted = rule(c)
    require(after['rules'] and same_allowance(after['rules'][0], wanted)
            and after['rules'][0].get('comment') == wanted['comment']
            and normalized(after['rules'][1:]) == before_rules, 'Monitoring firewall readback differs')
    reader = API.__new__(API)
    reader.configure(c['endpoint'], saved['token'], api.ca)
    effective = {p: v for p, v in reader.call('/access/permissions')['data'].items() if v}
    # Proxmox expands a propagated root ACL over existing child ACL paths.
    # Every reported path must retain exactly the three audit privileges.
    require('/' in effective and all(set(privileges) == PRIVILEGES
            and all(flag == 1 for flag in privileges.values())
            for privileges in effective.values()), 'Effective monitoring permissions differ')
    return after


def initialize(api, c, root, backup):
    """Call only from the separately approved monitoring bootstrap CD phase."""
    validate(c)
    check_backup(c, backup)
    private_directory(root)
    private_directory(backup)
    local, remote = root / 'monitoring-access', backup / 'monitoring-access'
    require(local.exists() == remote.exists(), 'Monitoring access state and NAS copy differ')
    if local.exists():
        for directory in (local, remote):
            private_directory(directory)
            require(not (directory / 'HOLD.json').exists(), 'Partial monitoring access attempt is held; no replay')
        for name in ('owner.json', 'before.json', 'token.json', 'READY.json'):
            require(read_private(local / name) == read_private(remote / name), 'Monitoring receipts differ from NAS')
        require(json.loads(read_private(local / 'owner.json')) == c, 'Monitoring access input drift')
        saved = json.loads(read_private(local / 'token.json'))
        before = json.loads(read_private(local / 'before.json'))
        after = verify(api, c, saved, before['rules'])
        require(after['options'] == before['options'], 'Monitoring firewall option drift')
        return {'created': False, 'identity': IDENTITY}
    before = inspect(api, c)
    require(not any(before[k] for k in ('users', 'roles', 'tokens', 'acl'))
            and not any(r.get('comment') == rule(c)['comment'] or same_allowance(r, rule(c))
                        for r in before['rules']), 'Monitoring identity or firewall already exists; no adoption')
    for directory in (local, remote):
        private_directory(directory, create=True)
        save_new(directory / 'owner.json', c)
        save_new(directory / 'before.json', before)
        save_new(directory / 'HOLD.json', {'automatic_retry': False})
    require(inspect(api, c) == before, 'Monitoring access changed after inspection')
    api.call('/access/users', 'POST', {'userid': USER, 'enable': 1, 'expire': 0,
                                      'comment': 'Dedicated Zabbix monitoring; no password login'})
    api.call('/access/roles', 'POST', {'roleid': ROLE, 'privs': ','.join(sorted(PRIVILEGES))})
    minted = api.call('/access/users/' + USER + '/token/' + TOKEN, 'POST',
                      {'privsep': 1, 'expire': 0, 'comment': 'HomeLab Zabbix API audit only'})['data']
    try:
        require(isinstance(minted, dict) and minted.get('full-tokenid') == IDENTITY
                and re.fullmatch(r'[A-Za-z0-9-]+', minted.get('value', '')),
                'Mint response differs; retain the private response without replay')
    except Exception:
        # Preserve a once-returned unexpected response under the existing hold.
        # Successful setup retains only token.json, avoiding a redundant secret.
        for directory in (local, remote):
            save_new(directory / 'minted-response.json', minted)
        raise
    saved = {'identity': IDENTITY, 'token': IDENTITY + '=' + minted['value']}
    for directory in (local, remote):
        save_new(directory / 'token.json', saved)
    for field, identity in [('users', USER), ('tokens', IDENTITY)]:
        api.call('/access/acl', 'PUT', {'path': '/', field: identity, 'roles': ROLE, 'propagate': 1})
    base = '/nodes/' + c['node'] + '/firewall'
    current = inspect(api, c)
    require(current['rules'] == before['rules'] and current['options'] == before['options'], 'Host firewall changed; hold')
    api.call(base + '/rules', 'POST', rule(c))
    after = verify(api, c, saved, before['rules'])
    require(after['options'] == before['options'], 'Host firewall options changed; hold')
    for directory in (local, remote):
        save_new(directory / 'READY.json', {'identity': IDENTITY, 'read_only': True})
    for directory in (remote, local):
        (directory / 'HOLD.json').unlink()
    return {'created': True, 'identity': IDENTITY}
