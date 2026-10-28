"""Maintain only an existing MariaDB/InfluxDB listener, with caller-owned holds.

Sent by the fixed playbook, not installed. Never restore data, change an account,
read a token/password, enable a firewall, or resume an interrupted operation.
"""
import argparse
import configparser
import hashlib
import ipaddress
import json
import os
import pwd
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import urllib.request

SCHEMA = 'homelab-database-server-network-runtime-v1'
CHANGE = 'homelab-database-server-network-change-v1'
FILES = {'mariadb': Path('/etc/mysql/mariadb.conf.d/99-homelab.cnf'),
         'influxdb': Path('/etc/influxdb/config.toml')}
FILE_KEYS = {'mariadb': 'homelab.cnf', 'influxdb': 'config.toml'}
PORTS = {'mariadb': 3306, 'influxdb': 8086}
LIMIT = 131072


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def command(argv, timeout=30):
    return subprocess.run(argv, check=True, capture_output=True, timeout=timeout,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C', 'LC_ALL': 'C'}).stdout.decode()


def identity(value):
    require(isinstance(value, dict) and set(value) == {'kind', 'vmid', 'hostname', 'address', 'mac'}
            and value['kind'] in FILES and type(value['vmid']) is int
            and value['vmid'] >= 100 and value['vmid'] not in {900,4914,4915,4920}
            and isinstance(value['hostname'], str) and re.fullmatch('[a-z][a-z0-9-]{0,62}', value['hostname'])
            and isinstance(value['mac'], str) and re.fullmatch(r'02(?::[0-9a-f]{2}){5}', value['mac']),
            'Bind one exact existing server identity')
    ipaddress.IPv4Address(value['address'])
    return value


def guard(value):
    identity(value)
    require(os.geteuid() == 0 and not Path('/etc/pve').exists(), 'Never target the hypervisor')
    mapping = Path('/proc/self/uid_map').read_text()
    require(re.search(r'(?m)^\s*0\s+[1-9][0-9]*\s+[1-9][0-9]*\s*$', mapping)
            and not re.search(r'(?m)^\s*[0-9]+\s+0\s+[1-9][0-9]*\s*$', mapping), 'Require unprivileged LXC')
    original = read(Path('/etc/homelab-application.json'))
    require(original['uid'] == 0 and original['gid'] == 0, 'Root must own the installed identity')
    saved = json.loads(original['text'])
    require(saved == {k: value[k] for k in ('kind', 'vmid', 'hostname', 'address')}, 'Installed identity changed')


def read(path):
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Refuse symlinked configuration')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_size <= LIMIT,
                'Require original private regular configuration')
        raw = stream.read(LIMIT + 1)
        after = os.fstat(stream.fileno())
        stable = lambda s: (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        require(stable(after) == stable(before) and len(raw) == before.st_size and b'\0' not in raw,
                'Configuration changed or is oversized')
    return {'text': raw.decode('utf8'), 'sha256': sha(raw), 'uid': before.st_uid,
            'gid': before.st_gid, 'mode': stat.S_IMODE(before.st_mode)}


def candidate(kind, text, address):
    """Exact one-line substitution, preserving all data/authentication settings."""
    ipaddress.IPv4Address(address)
    if kind == 'mariadb':
        parser = configparser.ConfigParser(interpolation=None, allow_no_value=True)
        parser.read_string(text)
        require(parser.sections() == ['mysqld'] and not parser.defaults()
                and set(parser['mysqld']) <= {'bind-address', 'port', 'skip-name-resolve', 'max_connections',
                    'innodb_buffer_pool_size', 'character-set-server', 'collation-server', 'datadir', 'socket'}
                and not any(parser.has_option('mysqld', k) for k in ('bind_address', 'skip-networking', 'skip_networking'))
                and parser.get('mysqld', 'port', fallback='3306') == '3306', 'Unsupported MariaDB configuration')
        pattern = r'(?m)^([ \t]*bind-address[ \t]*=[ \t]*)([0-9.]+)([ \t]*)$'
        current = parser.get('mysqld', 'bind-address')
        replacement = address
        require(current in {'0.0.0.0', address}, 'Only replace original wildcard or verify exact new listener')
    else:
        import tomllib
        parsed = tomllib.loads(text)
        require(set(parsed) == {'bolt-path', 'engine-path', 'http-bind-address', 'reporting-disabled'}
                and parsed['bolt-path'] == '/var/lib/influxdb/influxd.bolt'
                and parsed['engine-path'] == '/var/lib/influxdb/engine'
                and parsed['reporting-disabled'] is True, 'Preserve the exact existing Influx data configuration')
        current = parsed['http-bind-address']
        replacement = address + ':8086'
        require(current in {':8086', replacement}, 'Unsupported InfluxDB listener')
        pattern = r'(?m)^([ \t]*http-bind-address[ \t]*=[ \t]*")([^"\r\n]+)("[ \t]*)$'
    matches = list(re.finditer(pattern, text))
    require(len(matches) == 1, 'Require one exact listener assignment')
    match = matches[0]
    return text[:match.start(2)] + replacement + text[match.end(2):]


def process(kind, execute=command, active=True):
    value = dict(line.split('=', 1) for line in execute(['systemctl', 'show', kind + '.service',
        '--property=MainPID,ActiveState,ActiveEnterTimestampMonotonic']).splitlines())
    require(set(value) == {'MainPID', 'ActiveState', 'ActiveEnterTimestampMonotonic'}
            and all(re.fullmatch('[0-9]+', value[k]) for k in ('MainPID', 'ActiveEnterTimestampMonotonic')),
            'Unexpected server process metadata')
    if active:
        require(value['ActiveState'] == 'active' and int(value['MainPID']) > 0, 'Server must already be active')
    return value


def sockets(kind, execute=command):
    rows = execute(['ss', '-H', '-ltn', 'sport', '=', ':' + str(PORTS[kind])]).splitlines()
    require(rows and len(rows) <= 8 and all(len(row.split()) == 5 for row in rows), 'Missing or unexpected TCP listener')
    return sorted(row.split()[3] for row in rows)


def no_clients(kind, execute=command):
    require(not execute(['ss', '-H', '-tn', 'state', 'established', 'sport', '=', ':' + str(PORTS[kind])]).strip(),
            'Stop and review an existing TCP consumer before server maintenance')
    if kind == 'mariadb':
        rows = execute(['mariadb', '--protocol=socket', '--user=root', '--batch', '--skip-column-names',
            '--execute', 'SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE ID <> CONNECTION_ID()']).strip()
        require(rows == '0', 'An existing MariaDB session is still active')


def health(kind, address, execute=command):
    if kind == 'mariadb':
        rows = execute(['mariadb', '--protocol=socket', '--user=root', '--batch', '--skip-column-names',
            '--execute', 'SELECT @@bind_address,@@port,@@datadir,@@socket,VERSION()']).strip().split('\t')
        require(len(rows) == 5 and rows[0] == address and rows[1] == '3306'
                and rows[2] == '/var/lib/mysql/' and rows[3] == '/run/mysqld/mysqld.sock',
                'Effective MariaDB bind/port/data/socket differs')
        accounts = execute(['mariadb', '--protocol=socket', '--user=root', '--batch', '--skip-column-names',
            '--execute', 'SELECT USER,HOST FROM mysql.global_priv ORDER BY USER,HOST; SELECT SCHEMA_NAME FROM information_schema.SCHEMATA ORDER BY SCHEMA_NAME;'])
        require(len(accounts.encode()) <= LIMIT, 'Bound nonsecret account/schema metadata')
        return {'version': rows[4], 'data_path': rows[2], 'socket': rows[3], 'account_schema_sha256': sha(accounts.encode())}
    values = {}
    for name, route in [('health', '/health'), ('setup', '/api/v2/setup')]:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open('http://' + address + ':8086' + route, timeout=5) as response:
            raw = response.read(16385)
        require(len(raw) <= 16384, 'Oversized health response')
        values[name] = json.loads(raw)
    require(values['health'].get('status') == 'pass' and values['setup'].get('allowed') is False,
            'InfluxDB is unhealthy or requires setup; never initialize it here')
    return {'version': values['health']['version'], 'setup_allowed': False}


def inspect(value, execute=command):
    value = identity(value); guard(value); kind = value['kind']
    conf = read(FILES[kind]); candidate(kind, conf['text'], '192.0.2.1')
    account = pwd.getpwnam('mysql' if kind == 'mariadb' else 'influxdb')
    require(conf['uid'] == account.pw_uid and conf['gid'] == account.pw_gid, 'Preserve the native data account configuration ownership')
    state = process(kind, execute); no_clients(kind, execute)
    listeners = sockets(kind, execute)
    require(listeners == (['0.0.0.0:3306'] if kind == 'mariadb' else ['*:8086']),
            'Review the effective original wildcard listener')
    return {'schema': SCHEMA, 'identity': value, 'config': conf, 'process': state,
            'listeners': listeners, 'health': health(kind, '0.0.0.0' if kind == 'mariadb' else '127.0.0.1', execute)}


def validate(value):
    require(isinstance(value, dict) and set(value) == {'schema', 'before', 'endpoint', 'old_address',
        'clients', 'inactive_client_vmids', 'files', 'allow_restart'} and value['schema'] == CHANGE,
        'Use the exact closed server maintenance request')
    before = value['before']; require(isinstance(before, dict) and before.get('schema') == SCHEMA, 'Bind original inspection')
    selected = identity(before['identity']); kind = selected['kind']; endpoint = value['endpoint']
    require(isinstance(endpoint, dict) and set(endpoint) == {'address', 'port'}
            and endpoint['port'] == PORTS[kind] and type(endpoint['port']) is int,
            'Bind fixed native engine endpoint')
    ipaddress.IPv4Address(endpoint['address']); ipaddress.IPv4Address(value['old_address'])
    require(value['old_address'] != endpoint['address'] and value['allow_restart'] is True,
            'Explicitly approve the exact new address and service restart')
    require(isinstance(value['clients'], list) and all(isinstance(c, dict) and 'vmid' in c for c in value['clients'])
            and isinstance(value['inactive_client_vmids'], list)
            and all(type(i) is int for i in value['inactive_client_vmids']), 'Bind explicit inactive clients')
    ids = [c['vmid'] for c in value['clients']]
    require(ids and all(type(i) is int for i in ids) and len(ids) == len(set(ids))
            and sorted(value['inactive_client_vmids']) == sorted(ids),
            'Every selected app remains inactive and owns its later activation/authentication')
    conf = before['config']; require(set(conf) == {'text', 'sha256', 'uid', 'gid', 'mode'}
        and conf['sha256'] == sha(conf['text'].encode()) and conf['mode'] == 0o600
        and type(conf['uid']) is int and type(conf['gid']) is int, 'Bind original configuration bytes/ownership')
    expected = candidate(kind, conf['text'], endpoint['address'])
    require(value['files'] == {FILE_KEYS[kind]: expected} and expected != conf['text'],
            'Only the exact listener substitution is permitted')
    return selected, kind, expected


def run(action, value, execute=command):
    if action == 'inspect':
        require(set(value) == {'identity'}, 'Use only an existing identity for inspection')
        return inspect(value['identity'], execute)
    selected, kind, text = validate(value); guard(selected)
    current = read(FILES[kind]); before = value['before']
    if action == 'preflight':
        require(inspect(selected, execute) == before, 'Server runtime changed since inspection')
    elif action == 'activate':
        require(current == before['config'], 'Original configuration changed before listener write')
        no_clients(kind, execute); process(kind, execute, active=False)
        path = FILES[kind]
        fd, temporary = tempfile.mkstemp(prefix='.homelab-network-', dir=path.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                os.fchown(stream.fileno(), current['uid'], current['gid']); os.fchmod(stream.fileno(), current['mode'])
                stream.write(text.encode()); stream.flush(); os.fsync(stream.fileno())
            require(read(path) == current, 'Configuration changed during preparation')
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(directory)
            finally: os.close(directory)
        finally:
            if os.path.exists(temporary): os.unlink(temporary)
        execute(['systemctl', 'restart', kind + '.service'], timeout=180)
    else:
        require(action == 'verify', 'Unsupported action')
    if action != 'preflight':
        actual = read(FILES[kind])
        require(actual == {**before['config'], 'text': text, 'sha256': sha(text.encode())}, 'Maintained configuration differs')
        process(kind, execute)
        address = value['endpoint']['address']
        require(sockets(kind, execute) == [address + ':' + str(PORTS[kind])], 'Retired/wildcard/management listener remains')
        require(health(kind, address, execute) == before['health'], 'Server version/data/socket/setup state changed')
    return {'status': 'passed', 'action': action, 'engine': kind, 'changed': action == 'activate'}


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('action', choices=('inspect', 'preflight', 'activate', 'verify'))
    args = parser.parse_args()
    try:
        raw = __import__('sys').stdin.buffer.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, 'Bound the runtime request')
        print(json.dumps(run(args.action, json.loads(raw))))
    except Exception as error:
        raise SystemExit('Server network held (' + type(error).__name__ + '); retain caller evidence, no replay') from None


if __name__ == '__main__': main()
