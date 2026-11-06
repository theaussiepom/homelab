"""Closed server-administrator accounts and native Community datasource inputs."""
import ipaddress
import json
from pathlib import Path
import re

import managed_credentials
from private_io import encoded, require

KINDS = {'postgresql': 5432, 'mariadb': 3306}
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




def connections(value):
    if 'managed_connections' not in value:
        return {}
    values = value['managed_connections']
    require(isinstance(values, dict) and 1 <= len(values) <= 8
            and not values.keys() & value['connections'].keys(),
            'Keep new owned administrator connections separate from retained metadata')
    for key, item in values.items():
        name(key)
        require(isinstance(item, dict) and set(item) == RAW_CONNECTION | RESOLVED_CONNECTION
                and isinstance(item['driver'], str) and item['driver'] in KINDS
                and isinstance(item['name'], str) and 1 <= len(item['name']) <= 100
                and isinstance(item['database'], str) and len(item['database']) <= 128
                and not any(c in item['name']+item['database'] for c in '\r\n\x00'),
                'Use a named supported administrator datasource')
        name(item['account_id'])
        credential_path(item)
        actual = owner(item['owner'])
        require(item['host'] == actual['server_address'] and item['port'] == KINDS[item['driver']]
                and item['username'] == actual['username'] and item['driver'] == actual['engine']
                and item['transport'] == 'tls', 'Bind the datasource to its dedicated TLS account')
    return values






def document_from_records(value, records):
    """Render prepared records without private reads or credential generation."""
    selected = connections(value)
    require(isinstance(records, dict) and set(records) == {item['credential_id'] for item in selected.values()},
            'Supply exactly the selected owned administrator records')
    result = {}
    for key, item in selected.items():
        record = records[item['credential_id']]
        require(isinstance(record, dict) and set(record) == {'schema', 'owner', 'password'}
                and record['schema'] == 'homelab-application-account-v1' and record['owner'] == item['owner']
                and isinstance(record['password'], str) and re.fullmatch('[0-9a-f]{64}', record['password']),
                'Use only the dedicated owned administrator credential')
        postgres = item['driver'] == 'postgresql'
        result[key] = {'provider': 'postgresql' if postgres else 'mysql', 'driver': 'postgres-jdbc' if postgres else 'mariaDB',
            'name': item['name'], 'save-password': True, 'show-system-objects': True,
            'configuration': {'host': item['host'], 'port': str(item['port']), 'database': item['database'],
                'configurationType': 'MANUAL', 'type': 'dev', 'auth-model': 'native',
                'properties': {'sslmode': 'require', 'channelBinding': 'require',
                    'requireAuth': 'scram-sha-256'} if postgres else {'sslMode': 'verify-full'},
                'auth-properties': {'userName': item['username'], 'userPassword': record['password']}}}
    return encoded({'folders': {}, 'connections': result})
