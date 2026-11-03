"""Closed server-administrator accounts and native Community datasource inputs."""
import ipaddress
import json
from pathlib import Path
import re

import managed_credentials
from private_io import encoded, read_json, require

KINDS = {'postgresql': 5432, 'mariadb': 3306}
RAW_ACCOUNT = {'username', 'source_guest', 'credential_id', 'credential_file', 'access', 'transport'}
RAW_CONNECTION = {'name', 'driver', 'database', 'account_id'}
RESOLVED_CONNECTION = {'host', 'port', 'username', 'credential_id', 'credential_file', 'transport', 'owner'}


def name(value):
    require(isinstance(value, str) and re.fullmatch('[a-z][a-z0-9_-]{0,62}', value),
            'Use a literal named administration account or connection')


def owner(value):
    require(isinstance(value, dict) and set(value) == {'node', 'engine', 'database_vmid', 'source_vmid',
            'server_address', 'source_address', 'username', 'purpose'}
            and isinstance(value['engine'], str) and value['engine'] in KINDS
            and value['purpose'] == 'database-administration'
            and all(type(value[key]) is int and value[key] >= 100 for key in ('database_vmid', 'source_vmid'))
            and isinstance(value['node'], str) and re.fullmatch('[A-Za-z0-9_.-]{1,128}', value['node']),
            'Bind the exact database and client guest identities')
    name(value['username'])
    for key in ('server_address', 'source_address'):
        require(isinstance(value[key], str), 'Bind literal database and client IPv4 addresses')
        try:
            address = ipaddress.IPv4Address(value[key])
        except ValueError:
            raise ValueError('Bind literal database and client IPv4 addresses') from None
        require(address.is_private and not (address.is_unspecified or address.is_loopback or address.is_link_local
                or address.is_multicast), 'Bind private assigned database and client addresses')
    return value


def credential_path(value):
    managed_credentials.identifier(value['credential_id'])
    path = value['credential_file']
    require(isinstance(path, str) and (path.startswith('${inputs}/') or Path(path).is_absolute())
            and '..' not in Path(path).parts and Path(path).name == managed_credentials.input_name(value['credential_id']),
            'Bind the fixed immutable account credential input')


def accounts(cfg, *, compiled=False):
    app = cfg['app']
    if 'database_administrators' not in app:
        return {}
    values = app['database_administrators']
    require(app['kind'] in KINDS and isinstance(values, dict) and 1 <= len(values) <= 8,
            'Declare finite native database server-administrator accounts')
    for key, value in values.items():
        name(key)
        require(isinstance(value, dict) and set(value) == RAW_ACCOUNT | ({'owner'} if compiled else set())
                and value['access'] == 'server-administration' and value['transport'] == 'tls',
                'Use the closed TLS server-administration account configuration')
        name(value['username']); name(value['source_guest']); credential_path(value)
        if compiled:
            actual = owner(value['owner'])
            require(actual['engine'] == app['kind'] and actual['database_vmid'] == cfg['guest']['vmid']
                    and actual['node'] == cfg['site']['node'] and actual['username'] == value['username'],
                    'Preserve this database account owner')
    require(len({v['username'] for v in values.values()}) == len(values)
            and len({v['credential_id'] for v in values.values()}) == len(values),
            'Use independent credentials for distinct database accounts')
    return values


def connections(value, *, compiled=False):
    if 'managed_connections' not in value:
        return {}
    values = value['managed_connections']
    require(isinstance(values, dict) and 1 <= len(values) <= 8
            and not values.keys() & value['connections'].keys(),
            'Keep new owned administrator connections separate from retained metadata')
    for key, item in values.items():
        name(key)
        require(isinstance(item, dict) and set(item) == RAW_CONNECTION | (RESOLVED_CONNECTION if compiled else set())
                and isinstance(item['driver'], str) and item['driver'] in KINDS
                and isinstance(item['name'], str) and 1 <= len(item['name']) <= 100
                and isinstance(item['database'], str) and len(item['database']) <= 128
                and not any(c in item['name']+item['database'] for c in '\r\n\x00'),
                'Use a named supported administrator datasource')
        name(item['account_id'])
        if compiled:
            credential_path(item)
            actual = owner(item['owner'])
            require(item['host'] == actual['server_address'] and item['port'] == KINDS[item['driver']]
                    and item['username'] == actual['username'] and item['driver'] == actual['engine']
                    and item['transport'] == 'tls', 'Bind the datasource to its dedicated TLS account')
    return values


def prepare(cfg, stack, destination):
    selected = list(accounts(cfg, compiled=True).values())
    if stack is not None and stack.get('variant') == 'cloudbeaver':
        selected += list(connections(stack['cloudbeaver'], compiled=True).values())
    result = {}
    for item in selected:
        expected, payload = managed_credentials.payload(cfg['paths']['state_root'], item['credential_id'], item['owner'], destination)
        require(item['credential_file'] == expected and not result.keys() & payload.keys(),
                'Bind one immutable input per independent administrator account')
        result.update(payload)
    return result


def hba(cfg, files):
    values = accounts(cfg, compiled=True)
    if cfg['app']['kind'] != 'postgresql' or not values:
        return
    selections = [row for row in cfg['app']['database']['config_files'] if row['destination'].endswith('/pg_hba.conf')]
    require(len(selections) == 1 and selections[0]['source'].startswith('${inputs}/'),
            'Keep one declared PostgreSQL HBA source')
    filename = Path(selections[0]['source']).name
    require(filename in files and '# homelab managed administrator accounts' not in files[filename],
            'Preserve the original HBA source outside the owned account prefix')
    rows = ['# homelab managed administrator accounts']
    for key, item in sorted(values.items()):
        user, source = item['username'], item['owner']['source_address']
        rows.extend([f'hostssl all,replication {user} {source}/32 scram-sha-256', f'local all,replication {user} reject',
                     f'host all,replication {user} 0.0.0.0/0 reject', f'host all,replication {user} ::/0 reject'])
    files[filename] = '\n'.join(rows)+'\n'+files[filename]


def document(value):
    result = {}
    for key, item in connections(value, compiled=True).items():
        record = read_json(Path(item['credential_file']), private=True)
        require(isinstance(record, dict) and set(record) == {'schema', 'owner', 'password'}
                and record['schema'] == 'homelab-application-account-v1' and record['owner'] == item['owner']
                and isinstance(record['password'], str) and re.fullmatch('[0-9a-f]{64}', record['password']),
                'Use only the dedicated owned administrator credential')
        postgres = item['driver'] == 'postgresql'
        result[key] = {'provider': 'postgresql' if postgres else 'mysql', 'driver': 'postgres-jdbc' if postgres else 'mariaDB',
            'name': item['name'], 'save-password': True, 'show-system-objects': True,
            'configuration': {'host': item['host'], 'port': str(item['port']), 'database': item['database'],
                'configurationType': 'MANUAL', 'type': 'dev', 'auth-model': 'native',
                'properties': {'sslmode': 'require'} if postgres else {'sslMode': 'trust'},
                'auth-properties': {'userName': item['username'], 'userPassword': record['password']}}}
    return encoded({'folders': {}, 'connections': result})
