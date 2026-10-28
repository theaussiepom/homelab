"""Closed clean Zabbix stack and active-only native agent configuration."""
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re

ROOT = Path(__file__).with_name('monitoring')
VERSIONS = json.loads((ROOT / 'versions.json').read_text())


def require(value, message):
    if not value:
        raise ValueError(message)


def text(value):
    require(isinstance(value, str) and bool(value) and not any(c in value for c in '\r\n\x00'),
            'Expected a single nonempty monitoring value')
    return value


def validate(cfg):
    require(set(cfg) <= {'kind', 'guest_memory_mib', 'timezone', 'services', 'monitoring'}
            and cfg['kind'] == 'monitoring', 'Use the closed clean monitoring configuration')
    m = cfg['monitoring']
    require(set(m) == {'version', 'bind_address', 'postgresql_host', 'postgresql_database',
                       'postgresql_user', 'secret_files'} and m['version'] == VERSIONS['version'],
            'Select the tested matching Zabbix release')
    address = ipaddress.IPv4Address(m['bind_address'])
    require(not (address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local),
            'Bind monitoring only to its selected guest backend address')
    require(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]*', text(m['postgresql_host'])), 'Invalid database host')
    for key in ('postgresql_user', 'postgresql_database'):
        require(re.fullmatch(r'[a-z][a-z0-9_]{0,62}', text(m[key])), 'Use a dedicated database and owner')
        require(m[key] not in {'postgres', 'template0', 'template1'}, 'Do not use a cluster administrator or system database')
    require(set(m['secret_files']) == {'database_password', 'proxmox_ca'}, 'Supply only the two selected runtime files')
    for path in m['secret_files'].values():
        require(Path(text(path)).is_absolute(), 'Runtime inputs must use absolute private paths')
    require(set(cfg['services']) == {'zabbix_server', 'zabbix_web'}, 'Select only the server and frontend')
    memory = 256
    for name, service in cfg['services'].items():
        require(set(service) == {'image', 'memory_mib', 'cpus', 'pids_limit', 'restart'}
                and service['image'] == VERSIONS[name] and service['restart'] in {'no', 'unless-stopped'},
                'Use matching pinned official images and bounded resources')
        for key in ('memory_mib', 'cpus', 'pids_limit'):
            value = service[key]
            require(type(value) in (int, float) and math.isfinite(value) and value > 0, 'Invalid resource limit')
        memory += service['memory_mib']
    require(type(cfg['guest_memory_mib']) is int and memory <= cfg['guest_memory_mib'], 'Reserve 256 MiB for the guest OS')
    text(cfg.get('timezone', 'Etc/UTC'))
    check_templates()
    return m


def check_templates():
    for name, expected in VERSIONS['templates'].items():
        require(hashlib.sha256((ROOT / 'templates' / name).read_bytes()).hexdigest() == expected,
                'The pinned official template changed; review its source and digest')


def source_files(cfg):
    return list(validate(cfg)['secret_files'].values())


def files(cfg):
    m = validate(cfg)
    result = []
    for key, filename in [('database_password', 'database-password'), ('proxmox_ca', 'proxmox-ca.pem')]:
        value = Path(m['secret_files'][key]).read_text()
        require(bool(value.strip()) and '\x00' not in value and len(value.encode()) <= 65536, 'Invalid runtime file')
        if key == 'database_password':
            text(value.rstrip('\n'))
        else:
            require(value.count('-----BEGIN CERTIFICATE-----') == 1 and value.count('-----END CERTIFICATE-----') == 1,
                    'Supply the single trusted Proxmox root CA certificate')
        result.append({'path': filename, 'content': value, 'uid': 1997, 'gid': 1995, 'mode': '0400'})
    return result


def compose(cfg):
    m = validate(cfg)
    database = {'DB_SERVER_HOST': m['postgresql_host'], 'DB_SERVER_PORT': '5432',
                'POSTGRES_USER': m['postgresql_user'], 'POSTGRES_DB': m['postgresql_database'],
                'POSTGRES_PASSWORD_FILE': '/run/secrets/database-password',
                'TZ': cfg.get('timezone', 'Etc/UTC').replace('$', '$$')}
    result = {'name': 'homelab-monitoring', 'services': {}}
    for name, value in cfg['services'].items():
        service = {'image': value['image'], 'pull_policy': 'missing', 'restart': value['restart'],
                   'mem_limit': str(value['memory_mib']) + 'm', 'cpus': value['cpus'],
                   'pids_limit': value['pids_limit'], 'stop_grace_period': '60s',
                   'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}},
                   'environment': dict(database), 'volumes': [
                       {'type': 'bind', 'source': '/opt/homelab-app/runtime/database-password',
                        'target': '/run/secrets/database-password', 'read_only': True,
                        'bind': {'create_host_path': False}}]}
        result['services'][name] = service
    server, web = result['services']['zabbix_server'], result['services']['zabbix_web']
    server['environment'].update({'ZBX_STARTREPORTWRITERS': '0', 'ZBX_STARTBROWSERPOLLERS': '0'})
    server['volumes'].append({'type': 'bind', 'source': '/opt/homelab-app/runtime/proxmox-ca.pem',
        'target': '/var/lib/zabbix/ssl/ssl_ca/proxmox-ca.pem', 'read_only': True, 'bind': {'create_host_path': False}})
    server['ports'] = [m['bind_address'] + ':10051:10051']
    web['environment'].update({'ZBX_SERVER_HOST': 'zabbix_server', 'ZBX_SERVER_PORT': '10051',
                               'PHP_TZ': cfg.get('timezone', 'Etc/UTC')})
    web['ports'] = [m['bind_address'] + ':8080:8080']
    web['depends_on'] = {'zabbix_server': {'condition': 'service_started'}}
    return result


def agent_config(value):
    require(set(value) == {'hostname', 'server_active', 'psk_identity', 'psk_path'}, 'Use the closed active agent configuration')
    for key in value:
        text(value[key])
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', value['hostname']), 'Invalid agent hostname')
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', value['psk_identity']), 'Invalid PSK identity')
    require(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]*:10051', value['server_active']), 'Use one active server on TCP 10051')
    require(value['psk_path'] == '/etc/zabbix/agent.psk', 'Use the selected agent PSK path')
    return ('LogType=system\nHostname=' + value['hostname'] + '\nServerActive=' + value['server_active']
            + '\nTLSConnect=psk\nTLSPSKIdentity=' + value['psk_identity']
            + '\nTLSPSKFile=' + value['psk_path'] + '\nDenyKey=system.run[*]\n'
            'ControlSocket=/run/zabbix/agent.sock\n')


if __name__ == '__main__':
    import argparse
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent-config', type=Path, required=True)
    args = parser.parse_args()
    print(agent_config(json.loads(sys.stdin.read() if str(args.agent_config) == '-' else args.agent_config.read_text())), end='')
