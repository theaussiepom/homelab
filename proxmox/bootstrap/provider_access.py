"""Own one read-only Proxmox discovery identity and its host API allowance.

Only bootstrap CD calls the write methods. The retained provider credential is
never part of a plan, result, exception message or ordinary evidence artifact.
"""
import ipaddress
import copy
import hashlib
import json
import os
import re
import stat
from urllib.parse import urlsplit

from host_api import normalized, same_allowance

PRIVILEGES = {'Sys.Audit', 'VM.Audit'}
SCHEMA = 'homelab-service-discovery-v1'


class ProviderAccessError(ValueError):
    """A fixed refusal safe to show in CD output."""


def require(condition, message):
    if not condition:
        raise ProviderAccessError(message)


def address(value):
    require(isinstance(value, str), 'Use individual private IPv4 discovery addresses')
    try:
        result = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise ProviderAccessError('Use individual private IPv4 discovery addresses') from None
    require(result.is_private and not (result.is_loopback or result.is_link_local
            or result.is_unspecified or result.is_multicast or result.is_reserved),
            'Use individual private IPv4 discovery addresses')
    return str(result)


def validate(c):
    s = c['service_discovery']
    require(isinstance(s, dict) and set(s) == {'vmid', 'address', 'guests'},
            'Use the closed service discovery configuration')
    apps = {a['vmid'] for a in c['applications']}
    require(type(s['vmid']) is int and s['vmid'] in apps,
            'Discovery must belong to a declared application guest')
    require(isinstance(s['guests'], list) and 1 <= len(s['guests']) <= 32
            and all(type(v) is int and v in apps for v in s['guests'])
            and len(set(s['guests'])) == len(s['guests']) and s['vmid'] in s['guests'],
            'Discovery may read only a finite list of declared application guests')
    require(address(s['address']) != address(urlsplit(c['endpoint']).hostname),
            'Discovery guest and host API addresses must differ')


def identity(c):
    token_id = 'homelab-traefik-' + str(c['service_discovery']['vmid'])
    return token_id, 'root@pam!' + token_id, 'HomelabTraefikRead' + str(c['service_discovery']['vmid'])


def acl_rows(c):
    role = identity(c)[2]
    return {(path, role, 0) for path in ['/nodes/' + c['node']] +
            ['/vms/' + str(v) for v in c['service_discovery']['guests']]}


def allowance(c):
    return {'type': 'in', 'action': 'ACCEPT', 'enable': 1,
            'source': address(c['service_discovery']['address']) + '/32',
            'dest': address(urlsplit(c['endpoint']).hostname) + '/32',
            'proto': 'tcp', 'dport': '8006',
            'comment': 'Homelab service discovery API for traefik ' + str(c['service_discovery']['vmid'])}


def owner(c):
    return {'schema': SCHEMA, 'node': c['node'], 'endpoint': c['endpoint'],
            'configuration': c['service_discovery'], 'identity': identity(c)[1], 'role': identity(c)[2]}


def validate_extension(c):
    """An explicit packet may add guest reads, preserving every other capability."""
    packet = c['service_discovery_extension']
    require(isinstance(packet, dict) and set(packet) == {'previous_guests'},
            'Use only the exact previous discovery guest list for an extension')
    previous = packet['previous_guests']
    require(isinstance(previous, list) and previous and all(type(v) is int for v in previous)
            and len(previous) == len(set(previous)) and previous == sorted(previous)
            and c['service_discovery']['guests'] == sorted(c['service_discovery']['guests'])
            and set(previous) < set(c['service_discovery']['guests'])
            and c['service_discovery']['vmid'] in previous,
            'A reviewed discovery extension may only append declared guest reads')


def inspection_config(c, root, backup):
    """Read the original exact scope until the separately declared extension commits."""
    if 'service_discovery_extension' not in c:
        return c
    validate_extension(c)
    local, remote = root / 'service-discovery', backup / 'service-discovery'
    raw = read_private(local / 'owner.json')
    require(raw == read_private(remote / 'owner.json'), 'Discovery owner and NAS copy differ')
    if json.loads(raw) == owner(c):
        return c
    previous = copy.deepcopy(c)
    previous['service_discovery']['guests'] = c['service_discovery_extension']['previous_guests']
    require(json.loads(raw) == owner(previous),
            'The exact previous discovery scope differs; no adoption or permission rewrite')
    return previous


def extend(api, c, before, root, backup):
    """Add only reviewed read ACLs; no token, role, firewall or lifecycle changes."""
    previous = inspection_config(c, root, backup)
    require(previous != c and before['exists']
            and inspect(api, previous, root, backup) == before,
            'The retained discovery scope changed after the saved extension plan')
    secret = retained(previous, root, backup)
    old_rows, new_rows = acl_rows(previous), acl_rows(c)
    require(old_rows < new_rows, 'Only additive read-only discovery extensions are supported')
    local, remote = root / 'service-discovery', backup / 'service-discovery'
    original = read_private(local / 'owner.json')
    archive = 'owner-' + hashlib.sha256(original).hexdigest() + '.previous.json'
    # Parent bootstrap CD has already persisted its one-use mutation hold.
    # Keep both old records before the first grant, including partial failures.
    for directory in (local, remote):
        require(not (directory / archive).exists(), 'A prior extension needs review; no replay')
    for directory in (local, remote):
        save_new(directory / archive, json.loads(original))
    for path, role, propagate in sorted(new_rows - old_rows):
        api.call('/access/acl', 'PUT', {'path': path, 'roles': role,
                                      'tokens': identity(c)[1], 'propagate': propagate})
    verify_secret(api, c, secret)
    for directory in (local, remote):
        require(read_private(directory / 'owner.json') == original, 'Discovery owner changed during its extension')
        pending = directory / 'owner.extension.pending'
        save_new(pending, owner(c))
        os.replace(pending, directory / 'owner.json')
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    inspect(api, c, root, backup)
    return {'status': 'ready', 'created': False, 'extended': True,
            'new_acl_rows': len(new_rows - old_rows), 'token_id': identity(c)[1],
            'firewall_rule_created': False, 'secret_rotated': False}


def private_directory(path, create=False):
    if create:
        path.mkdir(mode=0o700)
    require(path.is_dir() and not path.is_symlink(), 'Discovery state must be a private directory')
    info = path.stat()
    require(stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid(),
            'Discovery state directory ownership or mode differs')


def read_private(path):
    require(path.is_file() and not path.is_symlink(), 'Missing private discovery receipt; no adoption')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_uid == os.getuid(), 'Private discovery receipt ownership or mode differs')
        raw = stream.read(65537)
        require(len(raw) <= 65536, 'Oversized private discovery receipt')
    return raw


def save_new(path, value):
    """Persist a newly returned secret without replacing any previous receipt."""
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    require(read_private(path) == raw, 'Private discovery receipt readback failed')


def retained(c, root, backup):
    local, remote = root / 'service-discovery', backup / 'service-discovery'
    require(local.exists() == remote.exists(), 'Discovery state or NAS copy is missing; no adoption')
    if not local.exists():
        require(not local.is_symlink() and not remote.is_symlink(), 'Discovery state cannot be a symlink')
        return None
    private_directory(local)
    private_directory(remote)
    for name in ('owner.json', 'token.json', 'READY.json'):
        require(read_private(local / name) == read_private(remote / name),
                'Private discovery state and NAS copy differ')
    require(json.loads(read_private(local / 'owner.json')) == owner(c),
            'Discovery configuration changed; no permission expansion or token rotation')
    require(json.loads(read_private(local / 'READY.json')) == {'schema': SCHEMA, 'status': 'ready'},
            'Partial discovery setup needs review; no automatic continuation')
    value = json.loads(read_private(local / 'token.json'))
    require(set(value) == {'schema', 'identity', 'token'} and value['schema'] == SCHEMA
            and value['identity'] == identity(c)[1] and isinstance(value['token'], str)
            and re.fullmatch(re.escape(identity(c)[1]) + r'=[A-Za-z0-9-]+', value['token']),
            'Retained discovery credential identity differs')
    return value['token']


def inspect(api, c, root, backup):
    validate(c)
    secret = retained(c, root, backup)
    token_id, token, role_id = identity(c)
    roles = [r for r in api.call('/access/roles')['data'] if r['roleid'] == role_id]
    tokens = [r for r in api.call('/access/users/root@pam/token')['data'] if r['tokenid'] == token_id]
    all_acls = api.call('/access/acl')['data']
    selected = [r for r in all_acls if r.get('ugid') == token]
    require(all(r.get('type') == 'token' for r in selected), 'Discovery ACL identity type differs')
    require(not any(r.get('roleid') == role_id and r.get('ugid') != token for r in all_acls),
            'Discovery role is used by another identity; no rewrite')
    actual = {(r['path'], r['roleid'], int(r.get('propagate', 1))) for r in selected}
    require(len(actual) == len(selected), 'Duplicate discovery ACL needs review')
    rule_path = '/nodes/' + c['node'] + '/firewall'
    rules = api.call(rule_path + '/rules')['data']
    options = {key: value for key, value in api.call(rule_path + '/options')['data'].items() if key != 'digest'}
    rule = allowance(c)
    owned = [r for r in rules if r.get('comment') == rule['comment']]
    require(not any(same_allowance(r, rule) and r.get('comment') != rule['comment'] for r in rules),
            'Equivalent unmanaged discovery firewall rule; no adoption')
    if secret is None:
        require(not roles and not tokens and not selected and not owned,
                'Discovery identity or owned rule already exists; no adoption or rotation')
    else:
        require(len(roles) == 1 and not roles[0].get('special')
                and set(roles[0].get('privs', '').split(',')) == PRIVILEGES,
                'Discovery read-only role privileges differ')
        require(len(tokens) == 1 and tokens[0].get('privsep') == 1 and tokens[0].get('expire') == 0
                and tokens[0].get('comment') == rule['comment'], 'Discovery token metadata differs')
        require(actual == acl_rows(c), 'Discovery token scope differs; no automatic rewrite')
        require(len(owned) == 1 and rules[0] == owned[0] and same_allowance(owned[0], rule),
                'Discovery firewall rule differs or moved; no automatic rewrite')
        verify_secret(api, c, secret)
    return {'exists': secret is not None, 'role': roles, 'metadata': tokens,
            'acl': [list(r) for r in sorted(actual)], 'rules': normalized(rules), 'options': options}


def verify_secret(api, c, secret):
    """Prove the saved secret still authenticates with only the declared grants."""
    reader = api.discovery(secret)
    permissions = reader.call('/access/permissions')['data']
    effective = {path: value for path, value in permissions.items() if value}
    require(set(effective) == {path for path, _, _ in acl_rows(c)}
            and all(set(values) == PRIVILEGES and all(value == 0 for value in values.values())
                    for values in effective.values()), 'Discovery effective permissions differ')


def reconcile(api, c, before, root, backup):
    require(inspect(api, c, root, backup) == before, 'Discovery changed after the saved plan')
    token_id, token, role = identity(c)
    rule = allowance(c)
    if before['exists']:
        return {'status': 'ready', 'created': False, 'token_id': token,
                'secret_file': 'service-discovery/token.json', 'new_acl_rows': 0, 'firewall_rule_created': False}
    local, remote = root / 'service-discovery', backup / 'service-discovery'
    private_directory(local, create=True)
    private_directory(remote, create=True)
    save_new(local / 'owner.json', owner(c))
    save_new(remote / 'owner.json', owner(c))
    api.call('/access/roles', 'POST', {'roleid': role, 'privs': ','.join(sorted(PRIVILEGES))})
    minted = api.call('/access/users/root@pam/token/' + token_id, 'POST',
                      {'privsep': 1, 'expire': 0, 'comment': rule['comment']})['data']
    # PVE returns this value once. Preserve the raw result before any ACL write,
    # even if its metadata fails the next validation. Never send it to evidence.
    save_new(local / 'minted-response.json', minted)
    save_new(remote / 'minted-response.json', minted)
    validate_minted(c, minted)
    return finish_minted(api, c, before, root, backup, minted)


def validate_minted(c, minted):
    token = identity(c)[1]
    info = minted.get('info') if isinstance(minted, dict) else None
    require(isinstance(minted, dict) and minted.get('full-tokenid') == token
            and isinstance(minted.get('value'), str) and re.fullmatch(r'[A-Za-z0-9-]+', minted['value'])
            and isinstance(info, dict) and type(info.get('privsep')) in (int, str)
            and type(info.get('expire')) in (int, str)
            and str(info['privsep']) == '1' and str(info['expire']) == '0',
            'Created discovery token response differs; preserve its private partial receipt')


def finish_minted(api, c, before, root, backup, minted):
    """Finish a newly minted identity after its exact private evidence is admitted."""
    validate_minted(c, minted)
    token = identity(c)[1]
    rule = allowance(c)
    local, remote = root / 'service-discovery', backup / 'service-discovery'
    credential = {'schema': SCHEMA, 'identity': token, 'token': token + '=' + minted['value']}
    save_new(local / 'token.json', credential)
    save_new(remote / 'token.json', credential)
    for path, role_id, propagate in sorted(acl_rows(c)):
        api.call('/access/acl', 'PUT', {'path': path, 'roles': role_id, 'tokens': token, 'propagate': propagate})
    verify_secret(api, c, credential['token'])
    path = '/nodes/' + c['node'] + '/firewall'
    require(normalized(api.call(path + '/rules')['data']) == before['rules']
            and {key: value for key, value in api.call(path + '/options')['data'].items() if key != 'digest'}
            == before['options'], 'Host firewall changed after the saved plan')
    api.call(path + '/rules', 'POST', rule)
    after_rules = api.call(path + '/rules')['data']
    require(after_rules and after_rules[0].get('comment') == rule['comment']
            and same_allowance(after_rules[0], rule) and normalized(after_rules[1:]) == before['rules']
            and {key: value for key, value in api.call(path + '/options')['data'].items() if key != 'digest'}
            == before['options'], 'Discovery firewall readback did not preserve existing rules and options')
    ready = {'schema': SCHEMA, 'status': 'ready'}
    save_new(local / 'READY.json', ready)
    save_new(remote / 'READY.json', ready)
    inspect(api, c, root, backup)
    return {'status': 'ready', 'created': True, 'token_id': token,
            'secret_file': 'service-discovery/token.json', 'new_acl_rows': len(acl_rows(c)),
            'firewall_rule_created': True}


def admit_minted_continuation(api, c, before, root, backup, response_sha256):
    """Read-only admission of the specific pre-ACL failure, never general adoption."""
    local, remote = root / 'service-discovery', backup / 'service-discovery'
    for folder in (local, remote):
        private_directory(folder)
        require({p.name for p in folder.iterdir()} == {'owner.json', 'minted-response.json'},
                'Only the preserved pre-ACL mint failure can continue')
    for name in ('owner.json', 'minted-response.json'):
        require(read_private(local / name) == read_private(remote / name),
                'Partial discovery receipt and NAS copy differ')
    require(json.loads(read_private(local / 'owner.json')) == owner(c),
            'Partial discovery owner differs')
    raw = read_private(local / 'minted-response.json')
    require(hashlib.sha256(raw).hexdigest() == response_sha256, 'Partial mint response digest differs')
    minted = json.loads(raw)
    validate_minted(c, minted)
    token_id, token, role = identity(c)
    roles = [r for r in api.call('/access/roles')['data'] if r['roleid'] == role]
    tokens = [r for r in api.call('/access/users/root@pam/token')['data'] if r['tokenid'] == token_id]
    require(len(roles) == 1 and not roles[0].get('special')
            and set(roles[0].get('privs', '').split(',')) == PRIVILEGES,
            'Partial discovery role differs')
    require(len(tokens) == 1 and tokens[0].get('privsep') == 1 and tokens[0].get('expire') == 0
            and tokens[0].get('comment') == allowance(c)['comment'], 'Partial discovery token metadata differs')
    acls = api.call('/access/acl')['data']
    require(not any(r.get('ugid') == token or r.get('roleid') == role for r in acls),
            'Partial discovery already has ACLs; no continuation')
    permissions = api.discovery(token + '=' + minted['value']).call('/access/permissions')['data']
    require(not any(permissions.values()),
            'Partial discovery effective permissions differ; no continuation')
    path = '/nodes/' + c['node'] + '/firewall'
    require(not before['exists'] and not before['role'] and not before['metadata'] and not before['acl']
            and normalized(api.call(path + '/rules')['data']) == before['rules']
            and {k:v for k,v in api.call(path + '/options')['data'].items() if k != 'digest'} == before['options'],
            'Host firewall changed after the failed mint')
    return minted
