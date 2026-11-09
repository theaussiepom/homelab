"""Pure native database configuration from resolved component bindings.

No account provisioning, filesystem access, credentials, package installation or
service actions occur here. F's resolver supplies the explicitly selected HBA
allowances; a connection by itself never grants access. Existing monitoring and
managed-administrator hooks are applied after this base output by their owners.
"""
import ipaddress
import json
from pathlib import PurePosixPath
import re

from private_io import require


_DATA = {'postgresql': '/var/lib/postgresql', 'mariadb': '/var/lib/mysql',
         'influxdb': '/var/lib/influxdb'}
CONFIGURATION_ROOTS = {'postgresql': '/etc/postgresql', 'mariadb': '/etc/mysql',
                       'influxdb': '/etc/influxdb'}


def configuration_root(adapter):
    """Deployment and recovery consume the same native configuration owner."""
    require(adapter in CONFIGURATION_ROOTS, 'Select a native configuration owner')
    return CONFIGURATION_ROOTS[adapter]


class NativeNamespaceError(ValueError):
    """A closed native placement refusal that source compilation can locate."""


def namespace(rendered):
    """Refuse conflicting native owners using their actual rendered metadata.

    UID and GID are separate Unix namespaces. Package-managed accounts without
    declared numeric IDs remain unknown here; no target identity is inferred.
    This does not allocate accounts or make native multi-instance support.
    """
    def require(value,message):
        if not value:
            raise NativeNamespaceError(message)
    require(isinstance(rendered, dict), 'Resolve the native descriptor set')
    units, paths = set(), []
    numbers = {'uid': {}, 'gid': {}}
    principals = {'uid': {}, 'gid': {}}
    for app_id, value in rendered.items():
        require(isinstance(value, dict) and isinstance(value.get('identity'), dict)
                and isinstance(value.get('services'), list) and value['services'],
                'Resolve each native owned descriptor')
        identity = value['identity']
        for unit in value['services']:
            require(isinstance(unit, str) and unit and unit not in units,
                    'Native applications require distinct systemd units')
            units.add(unit)
        for field, principal in (('uid', 'user'), ('gid', 'group')):
            if field not in identity:
                continue
            number, name = identity[field], identity.get(principal)
            require(type(number) is int and number >= 0 and isinstance(name, str) and name,
                    'Resolve the declared native account identity')
            require(numbers[field].get(number, name) == name
                    and principals[field].get(name, number) == number,
                    'Native applications declare conflicting Unix account identities')
            numbers[field][number] = name
            principals[field][name] = number
        require(isinstance(identity.get('config_files'), list), 'Resolve native configuration destinations')
        claims = [('data', identity.get('home'))]
        for row in identity['config_files']:
            require(isinstance(row, dict), 'Resolve native configuration destinations')
            claims.append(('config', row.get('destination')))
        for kind, path in claims:
            require(isinstance(path, str) and path.startswith('/') and not path.startswith('//')
                    and path != '/' and PurePosixPath(path).as_posix() == path
                    and '..' not in path.split('/') and '\\' not in path
                    and not any(ord(char) < 32 or ord(char) == 127 for char in path),
                    'Resolve literal native owned paths')
            for previous, owner, previous_kind in paths:
                require(not (path == previous or
                    (owner != app_id or kind == previous_kind == 'config')
                    and (path.startswith(previous + '/') or previous.startswith(path + '/'))),
                    'Native applications require disjoint configuration and data ownership')
            paths.append((path, app_id, kind))


def _address(value):
    require(isinstance(value, str), 'Resolve a native database IPv4 address')
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError:
        raise ValueError('Resolve a native database IPv4 address') from None
    require(str(address) == value and not (address.is_unspecified or address.is_loopback
            or address.is_link_local or address.is_multicast or address.is_reserved),
            'Resolve an assigned native database IPv4 address')
    return value


def _data(app):
    require(set(app.get('storage_paths', {})) == {'data'},
            'Bind the explicit native database data directory')
    selected = app['storage_paths']['data']
    require(isinstance(selected, dict) and selected.get('target') == _DATA[app['adapter']]
            and selected.get('kind') == 'directory' and selected.get('read_only') is False,
            'Retain the native database writable data role')
    path = selected.get('source')
    require(isinstance(path, str) and len(path) <= 4096 and path.startswith('/') and not path.startswith('//') and path != '/'
            and PurePosixPath(path).as_posix() == path and '..' not in path.split('/')
            and not any(ord(character) < 32 or ord(character) == 127 for character in path)
            and '\\' not in path and '${' not in path,
            'Use the resolved native database data directory')
    require(app['adapter'] == 'influxdb' or path == _DATA[app['adapter']],
            'Native PostgreSQL and MariaDB data relocation is not implemented')
    return path


def _version(app):
    packages = app.get('software_selection', {}).get('packages')
    require(isinstance(packages, list) and all(isinstance(value, str) for value in packages),
            'Resolve the selected native database packages')
    adapter = app['adapter']
    prefix = {'postgresql': 'postgresql-', 'mariadb': 'mariadb-server=',
              'influxdb': 'influxdb2='}[adapter]
    if adapter == 'postgresql':
        servers = [value for value in packages if re.match(r'^postgresql-[0-9]+=', value)]
        pattern = r'postgresql-([1-9][0-9]*)=([1-9][0-9]*\.[0-9]+(?:\.[0-9]+)?)[-+~][A-Za-z0-9.+:~_-]+'
    else:
        servers = [value for value in packages if value.startswith(prefix)]
        pattern = re.escape(prefix) + r'(?:[0-9]+:)?([1-9][0-9]*\.[0-9]+\.[0-9]+)[-+~][A-Za-z0-9.+:~_-]+'
    require(len(servers) == 1, 'Select exactly one pinned native database server package')
    selected = re.fullmatch(pattern, servers[0])
    require(selected is not None, 'Select a supported pinned native database package version')
    if adapter == 'postgresql':
        major, version = selected.groups()
        require(version.split('.')[0] == major, 'Keep the PostgreSQL package and cluster major aligned')
        return version, major
    return selected.group(1), None


def _clients(clients):
    require(isinstance(clients, (list, tuple)) and len(clients) <= 128,
            'Resolve a finite explicit PostgreSQL client allowance list')
    result = []
    for row in clients:
        require(isinstance(row, dict) and set(row) == {'source_address', 'database', 'user', 'method'}
                and row['database'] == 'all' and row['user'] == 'all'
                and row['method'] == 'scram-sha-256',
                'Use only the explicitly selected base PostgreSQL client allowance')
        source = _address(row['source_address'])
        result.append(f'host all all {source}/32 scram-sha-256\n')
    return ''.join(result)


def web_frontend(app):
    """Own InfluxDB's optional web socket without moving its database listener.

    This is an app-owned local TCP forwarding socket, not a second database or
    a route between networks. Only fixed systemd unit names/commands are emitted.
    The ordinary InfluxDB profile has no web role and keeps its existing output.
    """
    require(app.get('adapter') == 'influxdb', 'Only InfluxDB owns this native web frontend')
    roles = app.get('role_addresses', {})
    selected = {'enabled': False, 'files': []}
    if 'web' not in roles:
        return selected
    source, target = _address(roles['web']), _address(roles['service'])
    require(source != target, 'Separate the InfluxDB web and database addresses')
    listeners = app.get('listeners', {})
    require(set(listeners) == {'web', 'backend'} and all(
        row.get('service') == 'influxdb' and row.get('namespace') == 'host'
        and row.get('bind') == 'interface' and row.get('protocol') == 'tcp'
        and row.get('port') == 8086 and 'publish' not in row
        and row.get('interface') == ('web' if name == 'web' else 'service')
        and row.get('actual_bind') == (source if name == 'web' else target)
        for name, row in listeners.items()), 'Bind the two exact InfluxDB listener roles')
    marker = '# Managed by HomeLab InfluxDB web frontend.\n'
    socket = marker + ('[Unit]\nDescription=InfluxDB application web frontend\n'
        'DefaultDependencies=no\nConflicts=shutdown.target\nBefore=shutdown.target\n'
        'Requires=homelab-network-ready.service influxdb.service\n'
        'After=homelab-network-ready.service influxdb.service\n\n'
        '[Socket]\nListenStream=' + source + ':8086\n\n'
        '[Install]\nWantedBy=multi-user.target\n')
    service = marker + ('[Unit]\nDescription=Forward InfluxDB web traffic to its local database listener\n'
        'Requires=influxdb.service\nAfter=influxdb.service\n\n'
        '[Service]\nExecStart=/usr/lib/systemd/systemd-socket-proxyd ' + target + ':8086\n'
        'DynamicUser=yes\nNoNewPrivileges=yes\n')
    return {'enabled': True, 'files': [
        {'name': 'homelab-influxdb-web.socket', 'content': socket},
        {'name': 'homelab-influxdb-web.service', 'content': service}]}


def render(app, *, clients=()):
    """Return base native texts, fixed units and existing Ansible metadata.

    ``clients`` contains only source-owned explicit PostgreSQL client_access
    selections resolved by F, in authored order. It is not every incoming app
    connection and never includes scoped monitoring or administrator prefixes.
    PostgreSQL/MariaDB relocation is intentionally unsupported. Their current
    package service layout is fixed; InfluxDB's existing explicit path settings
    can use its declared data source. This function does not initialize data.
    """
    require(isinstance(app, dict) and isinstance(app.get('adapter'), str) and app['adapter'] in _DATA,
            'Use a supported native database component')
    adapter = app['adapter']
    if adapter == 'influxdb':
        web_frontend(app)
    properties = app.get('properties', {})
    require(isinstance(properties, dict) and (not properties or
            adapter == 'postgresql' and set(properties) == {'client_access'}),
            'Use only supported native database component properties')
    require(adapter == 'postgresql' or clients == () or clients == [],
            'PostgreSQL client allowances belong only to PostgreSQL')
    require(set(app.get('role_addresses', {})) >= {'service'},
            'Resolve the native database service role')
    address = _address(app['role_addresses']['service'])
    data = _data(app)
    version, major = _version(app)
    if adapter == 'postgresql':
        files = {'homelab.conf': f"listen_addresses = '127.0.0.1,{address}'\n"
                 "password_encryption = 'scram-sha-256'\nshared_buffers = '256MB'\nmax_connections = 100\n",
                 'pg_hba.conf': 'local all postgres peer\nlocal all all peer\n'
                 'host all all 127.0.0.1/32 scram-sha-256\nhost all all ::1/128 scram-sha-256\n'
                 + _clients(clients)}
        directory = configuration_root(adapter) + '/' + major + '/main/'
        targets = [directory + 'conf.d/homelab.conf', directory + 'pg_hba.conf']
        identity = {'uid': 70, 'gid': 1000, 'user': 'postgres', 'group': 'postgres', 'home': data,
                    'version_command': ['/usr/lib/postgresql/' + major + '/bin/postgres', '--version']}
    elif adapter == 'mariadb':
        files = {'homelab.cnf': f'[mysqld]\nbind-address = {address}\nskip-name-resolve\n'
                 'max_connections = 100\ninnodb_buffer_pool_size = 256M\n'}
        targets = [configuration_root(adapter) + '/mariadb.conf.d/99-homelab.cnf']
        identity = {'account_mode': 'package', 'user': 'mysql', 'group': 'mysql', 'home': data,
                    'version_command': ['mariadb', '--version']}
    else:
        files = {'config.toml': 'bolt-path = ' + json.dumps(data + '/influxd.bolt', ensure_ascii=False)
                 + '\nengine-path = ' + json.dumps(data + '/engine', ensure_ascii=False)
                 + '\nhttp-bind-address = "' + address + ':8086"\nreporting-disabled = true\n'}
        targets = [configuration_root(adapter) + '/config.toml']
        identity = {'uid': 1000, 'gid': 1000, 'user': 'influxdb', 'group': 'influxdb', 'home': data,
                    'version_command': ['influxd', 'version']}
    identity['version_pattern'] = version
    identity['config_files'] = [{'source': '${inputs}/' + name, 'destination': target}
                                for name, target in zip(files, targets)]
    return {'files': files, 'services': [adapter], 'identity': identity}
