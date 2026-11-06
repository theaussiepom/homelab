"""Closed guest Agent 2 configuration derived from the blueprint inventory."""
import ipaddress
from pathlib import Path
import re

import monitoring
from private_io import require

AGENT_PACKAGE = {
    'version': '1:7.0.32-1+debian13',
    'url': 'https://repo.zabbix.com/zabbix/7.0/debian/pool/main/z/zabbix/zabbix-agent2_7.0.32-1%2Bdebian13_amd64.deb',
    'sha256': 'd846b7f6b2eae0d5457decf6f0814df8169361d3335aa900d93e0eb838ab36e7',
}
POSTGRESQL_PACKAGE = {
    'version': '1:7.0.32-1+debian13',
    'url': 'https://repo.zabbix.com/zabbix/7.0/debian/pool/main/z/zabbix-agent2-plugin-postgresql/zabbix-agent2-plugin-postgresql_7.0.32-1%2Bdebian13_amd64.deb',
    'sha256': '5d3d4ef1089c80cbefd52b4d8dc15aa9c4ab77b5678f8bf9952ca65f4c2983a2',
}


def profiles(cfg):
    value = ['linux']
    if 'docker' in cfg['deployment']['capabilities']:
        value.append('docker')
    kind = cfg['app']['kind']
    if kind in {'postgresql', 'mariadb', 'influxdb'}:
        value.append('mysql' if kind == 'mariadb' else kind)
    return value


def validate_legacy(cfg):
    selected = cfg['app']['monitoring']
    required = {'hostname', 'psk_identity', 'server_active', 'profiles', 'server_vmid', 'credential_file'}
    kind = cfg['app']['kind']
    if kind in {'postgresql', 'mariadb'}:
        required |= {'database_uri', 'database_password_file'}
    if kind == 'postgresql':
        required.add('storage_password_file')
    if kind == 'monitoring':
        required |= {'members', 'proxmox', 'server_file', 'postgresql_address', 'influxdb_address'}
    require(set(selected) == required and selected['profiles'] == profiles(cfg),
            'Use only the agent and workload settings derived from the root Zabbix property')
    hostname = cfg['site']['node'] + '-' + str(cfg['guest']['vmid'])
    require(selected['hostname'] == selected['psk_identity'] == hostname,
            'Bind monitoring to the declared Proxmox node and guest identity')
    endpoint = selected['server_active'].removesuffix(':10051')
    require(selected['server_active'] == endpoint + ':10051'
            and ipaddress.IPv4Address(endpoint).is_private,
            'Use one private active server on TCP10051')
    require(type(selected['server_vmid']) is int and selected['server_vmid'] >= 100,
            'Use the dedicated monitoring guest identity')
    for name in required & {'credential_file', 'database_password_file', 'storage_password_file', 'server_file'}:
        path = Path(selected[name])
        require(path.is_absolute() and '..' not in path.parts,
                'Use private immutable monitoring input files')
    if kind == 'monitoring':
        members = selected['members']
        require(isinstance(members, list) and len(members) <= 32,
                'Use a finite enabled monitoring inventory')
        identities = []
        for member in members:
            fields = {'guest', 'vmid', 'guest_hostname', 'hostname', 'psk_identity', 'profiles'}
            require(isinstance(member, dict) and isinstance(member.get('profiles'), list)
                    and set(member['profiles']) <= {'linux', 'docker', 'postgresql', 'mysql', 'influxdb'}
                    and member['profiles'] and member['profiles'][0] == 'linux'
                    and len(member['profiles']) == len(set(member['profiles'])),
                    'Use only the declared Linux and workload templates')
            require(set(member) == fields | ({'url'} if 'influxdb' in member['profiles'] else set())
                    and type(member['vmid']) is int and member['vmid'] >= 100
                    and member['hostname'] == member['psk_identity'] == cfg['site']['node'] + '-' + str(member['vmid'])
                    and all(isinstance(member[key], str) and re.fullmatch('[a-z][a-z0-9-]{0,62}', member[key])
                            for key in ('guest', 'guest_hostname')),
                    'Bind each monitored host to its declared guest identity')
            if 'influxdb' in member['profiles']:
                require(member['url'] == 'http://' + selected['influxdb_address'] + ':8086',
                        'Use the declared InfluxDB backend network')
            identities.append(member['hostname'])
        require(len(set(identities)) == len(members)
                and selected['server_vmid'] == cfg['guest']['vmid'],
                'Include the server and preserve distinct guest identities')
        require(selected['proxmox'] == {'hostname': cfg['site']['node'],
                    'endpoint': cfg['site']['api_endpoint'], 'ca_file': cfg['paths']['ca_file']}
                and all(ipaddress.IPv4Address(selected[key]).is_private
                        for key in ('postgresql_address', 'influxdb_address')),
                'Use the selected Proxmox trust and private database networks')
    return selected


COMPONENT_SCHEMA = 'homelab-component-guest-v1'
COMPONENT_PROFILES = {'linux', 'docker', 'postgresql', 'mysql', 'influxdb'}


def _component_path(value, filename):
    require(isinstance(value, str) and Path(value).is_absolute() and '..' not in Path(value).parts
            and Path(value).name == filename, 'Use the owned immutable monitoring input leaf')


def _component_profiles(value):
    require(isinstance(value, list) and value and value[0] == 'linux'
            and all(isinstance(item, str) and item in COMPONENT_PROFILES for item in value)
            and len(value) == len(set(value)), 'Use explicit closed monitoring workload profiles')
    return set(value)


def validate_component(cfg):
    """Validate compiled monitoring selections without inventing a guest kind."""
    selected = cfg['app']['monitoring']
    required = {'hostname', 'psk_identity', 'server_active', 'profiles', 'server_vmid',
                'server_hostname', 'credential_file'}
    optional = {'database_uri', 'database_password_file', 'storage_password_file', 'members',
                'proxmox', 'server_file', 'postgresql_address', 'influxdb_address'}
    require(isinstance(selected, dict) and required <= set(selected) <= required | optional,
            'Use only the compiled component monitoring settings')
    profiles = _component_profiles(selected['profiles'])
    applications = cfg['deployment']['applications']
    require(isinstance(applications, dict) and all(isinstance(row, dict)
            and isinstance(row.get('adapter'), str) for row in applications.values()),
            'Bind workload monitoring to selected owned applications')
    require('docker' not in profiles or 'docker' in cfg['deployment']['capabilities'],
            'Monitor Docker only when that capability is selected')
    native = {'postgresql': 'postgresql', 'mysql': 'mariadb', 'influxdb': 'influxdb'}
    for workload in profiles & set(native):
        require(sum(row['adapter'] == native[workload] for row in applications.values()) == 1,
                'Bind each requested native workload to one supported selected application')
    require(len(profiles & {'postgresql', 'mysql'}) <= 1,
            'Multiple database monitoring sessions require a separate supported capability')
    expected = cfg['site']['node'] + '-' + str(cfg['guest']['vmid'])
    require(selected['hostname'] == selected['psk_identity'] == expected,
            'Bind monitoring to the declared context and guest identity')
    active = selected['server_active']
    require(isinstance(active, str) and active.endswith(':10051'),
            'Use one private active server on TCP10051')
    address = active.removesuffix(':10051')
    try:
        parsed = ipaddress.IPv4Address(address)
    except (ValueError, TypeError):
        raise ValueError('Use one private active server on TCP10051') from None
    require(parsed.is_private and not (parsed.is_loopback or parsed.is_link_local
            or parsed.is_unspecified or parsed.is_multicast), 'Use one private active server on TCP10051')
    require(type(selected['server_vmid']) is int and selected['server_vmid'] >= 100
            and isinstance(selected['server_hostname'], str)
            and re.fullmatch('[a-z][a-z0-9-]{0,62}', selected['server_hostname']),
            'Bind the explicit monitoring server identity')
    _component_path(selected['credential_file'], 'monitoring-agent.json')
    database = bool(profiles & {'postgresql', 'mysql'})
    require(('database_uri' in selected) == ('database_password_file' in selected) == database,
            'Supply the database session only for its selected workload')
    if database:
        _component_path(selected['database_password_file'], 'monitoring-database-password')
        # configuration() retains the exact own-IP/loopback, protocol, port and
        # no-credentials/path/query/fragment checks before emitting this URI.
    if 'storage_password_file' in selected:
        require(sum(row['adapter'] == 'postgresql' for row in applications.values()) == 1,
                'Only the selected PostgreSQL storage app owns the shared monitoring password')
        _component_path(selected['storage_password_file'], 'monitoring-storage-password')
    server_fields = {'members', 'proxmox', 'server_file', 'postgresql_address'}
    root = bool(set(selected) & server_fields)
    if not root:
        require('influxdb_address' not in selected, 'Only the root server owns member endpoint metadata')
        return selected
    require(server_fields <= set(selected)
            and any(row['adapter'] == 'zabbix' for row in applications.values())
            and selected['server_vmid'] == cfg['guest']['vmid']
            and selected['server_hostname'] == cfg['guest']['hostname'],
            'Bind root monitoring metadata to its actual selected server guest')
    _component_path(selected['server_file'], 'monitoring-server.json')
    require(selected['proxmox'] == {'hostname': cfg['site']['node'],
        'endpoint': cfg['site']['api_endpoint'], 'ca_file': cfg['paths']['ca_file']},
        'Preserve the root server execution context and public trust')
    for key in ('postgresql_address', 'influxdb_address'):
        if key in selected:
            try:
                address = ipaddress.IPv4Address(selected[key])
            except (ValueError, TypeError):
                raise ValueError('Use only selected private monitoring endpoints') from None
            require(address.is_private and not (address.is_loopback or address.is_unspecified
                    or address.is_link_local or address.is_multicast), 'Use only selected private monitoring endpoints')
    members = selected['members']
    require(isinstance(members, list) and len(members) <= 32, 'Use the finite selected monitoring member inventory')
    identities = []
    for member in members:
        fields = {'guest', 'vmid', 'guest_hostname', 'hostname', 'psk_identity', 'profiles'}
        require(isinstance(member, dict) and type(member.get('vmid')) is int and member['vmid'] >= 100,
                'Bind a declared monitoring member guest')
        member_profiles = _component_profiles(member.get('profiles'))
        require(set(member) == fields | ({'url'} if 'influxdb' in member_profiles else set())
                and isinstance(member['guest'], str) and re.fullmatch('[a-z][a-z0-9_-]{0,62}', member['guest'])
                and isinstance(member['guest_hostname'], str) and re.fullmatch('[a-z][a-z0-9-]{0,62}', member['guest_hostname'])
                and member['hostname'] == member['psk_identity'] == cfg['site']['node']+'-'+str(member['vmid']),
                'Preserve each member identity and selected closed profiles')
        if 'influxdb' in member_profiles:
            require('influxdb_address' in selected and member['url'] == 'http://'+selected['influxdb_address']+':8086',
                    'Use only the explicit selected InfluxDB endpoint')
        identities.append(member['hostname'])
    require(len(identities) == len(set(identities)), 'Keep monitoring member identities unique')
    return selected


def validate(cfg):
    if cfg.get('schema') == COMPONENT_SCHEMA:
        return validate_component(cfg)
    return validate_legacy(cfg)


def configuration(cfg, password=None):
    selected = validate(cfg)
    text = monitoring.agent_config({k: selected[k] for k in ('hostname', 'server_active', 'psk_identity')}
                                   | {'psk_path': '/etc/zabbix/agent.psk'})
    if 'docker' in selected['profiles']:
        text += 'Plugins.Docker.Endpoint=unix:///var/run/docker.sock\n'
    for profile, plugin, port in [('postgresql', 'PostgreSQL', 5432), ('mysql', 'Mysql', 3306)]:
        if profile not in selected['profiles']:
            continue
        from urllib.parse import urlsplit
        url = urlsplit(selected['database_uri'])
        if cfg.get('schema') == COMPONENT_SCHEMA:
            import network_endpoints
            own = network_endpoints.addresses(cfg['guest']) | {'127.0.0.1'}
        else:
            own = {str(ipaddress.ip_interface(n['ipv4']).ip) for n in cfg['guest']['interfaces']
                   if n['ipv4'] not in {'manual', 'dhcp'}} | {'127.0.0.1'}
        require(url.scheme == 'tcp' and url.hostname in own and url.port == port
                and not (url.username or url.password or url.path or url.query or url.fragment),
                'Monitor a native database only from its owning guest')
        require(isinstance(password, str) and re.fullmatch('[0-9a-f]{64}', password),
                'Use the retained dedicated statistics credential')
        if profile == 'postgresql':
            text += 'Plugins.PostgreSQL.System.Path=/usr/sbin/zabbix-agent2-plugin/zabbix-agent2-plugin-postgresql\n'
        prefix = 'Plugins.' + plugin + '.Sessions.homelab.'
        text += prefix + 'Uri=' + selected['database_uri'] + '\n'
        text += prefix + 'User=zbx_monitor\n' + prefix + 'Password=' + password + '\n'
        if profile == 'postgresql':
            text += prefix + 'Database=postgres\n'
    return text
