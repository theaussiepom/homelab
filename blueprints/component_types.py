"""Small structural component validators, before references or global graphs."""
import ipaddress
from pathlib import PurePosixPath
import re

from component_adapters import adapter
from component_sources import closed, identifier, named, require
from component_errors import at, checked

CONTROL_PATHS = ('/bin', '/boot', '/dev', '/etc', '/lib', '/lib64', '/proc', '/root',
                 '/run', '/sbin', '/sys', '/usr', '/var/run', '/var/lib/homelab',
                 '/var/lib/homelab-inputs', '/var/lib/homelab-applications',
                 '/var/lib/homelab-bootstrap', '/var/lib/homelab-managed-credentials',
                 '/opt/homelab-app')


def text(value):
    require(isinstance(value, str) and 0 < len(value) <= 4096 and '\x00' not in value)
    return value


def integer(value, minimum=0, maximum=2**31-1):
    require(type(value) is int and minimum <= value <= maximum, 'component.integer')
    return value


def path(value, *, relative=False):
    text(value)
    parsed = PurePosixPath(value)
    require(not value.startswith('//') and not any(part in ('.', '..') for part in parsed.parts)
            and not any(char in value for char in '$:\\')
            and not any(ord(char) < 32 or ord(char) == 127 for char in value)
            and (not parsed.is_absolute() if relative else parsed.is_absolute())
            and parsed.as_posix() == value, 'component.path')
    return value


def ip(value):
    try:
        require(isinstance(value, str) and str(ipaddress.IPv4Address(value)) == value)
    except ipaddress.AddressValueError:
        require(False)
    return value


def strings(value, *, ids=False, unique=True):
    require(isinstance(value, list) and len(value) <= 1024)
    for item in value:
        require(identifier(item) if ids else isinstance(item, str) and bool(item) and len(item) <= 4096)
    require(not unique or len(set(value)) == len(value))
    return value


def endpoint(value):
    require(isinstance(value, dict))
    if 'external' in value:
        closed(value, ('external',))
    else:
        closed(value, ('app', 'endpoint'))
    require(all(identifier(item) for item in value.values()))
    return value


def resource(value, *, partial=False):
    keys = ('cpu_cores', 'memory_mib', 'root_gib', 'os_reserve_mib')
    closed(value, () if partial else keys, keys if partial else ())
    for key, item in value.items():
        integer(item, 0 if key == 'os_reserve_mib' else 256 if key == 'memory_mib' else 4 if key == 'root_gib' else 1)


def startup(value, *, partial=False):
    keys = ('started', 'start_on_boot', 'boot_order')
    closed(value, () if partial else keys, keys if partial else ())
    for key, item in value.items():
        require(type(item) is bool) if key != 'boot_order' else integer(item)


def security(value, *, partial=False):
    keys = ('unprivileged', 'protection', 'nesting', 'keyctl')
    closed(value, () if partial else keys, keys if partial else ())
    for key, item in value.items():
        require(type(item) is bool and (item if key in ('unprivileged', 'protection') else True))


def template(value):
    closed(value, ('resources', 'startup', 'security'), ('software', 'runtime', 'monitoring'))
    resource(value['resources'])
    startup(value['startup'])
    security(value['security'])
    for field in ('software', 'runtime'):
        strings(value.get(field, []), ids=True)
    if 'monitoring' in value:
        from component_monitoring import reference
        reference(value['monitoring'])


def context(value):
    closed(value, ('backend', 'node', 'api_endpoint', 'trust', 'credentials', 'paths',
                   'protected_guests', 'ssh_public_keys', 'dns_servers'), ('capabilities', 'timezone'))
    require(value['backend'] == 'proxmox-lxc')
    text(value['node'])
    endpoint(value['api_endpoint'])
    closed(value['trust'], ('ca_file', 'known_hosts'))
    closed(value['credentials'], ('api_token', 'ssh_private_key'))
    closed(value['paths'], ('state_root', 'backup_directory', 'backup_mount', 'backup_source'))
    for item in value['trust'].values():
        path(item)
    for key, item in value['paths'].items():
        text(item) if key == 'backup_source' else path(item)
    require(all(identifier(item) for item in value['credentials'].values()))
    require(isinstance(value['protected_guests'], list))
    for item in value['protected_guests']:
        integer(item, 1)
    require(len(value['protected_guests']) == len(set(value['protected_guests'])))
    strings(value['ssh_public_keys'])
    require(isinstance(value['dns_servers'], list) and bool(value['dns_servers']))
    for item in value['dns_servers']:
        endpoint(item)
    for row in named(value.get('capabilities', {})).values():
        closed(row, ('type', 'ssh_private_key', 'known_hosts'))
        require(row['type'] == 'serial-device' and identifier(row['ssh_private_key']))
        path(row['known_hosts'])
    if 'timezone' in value:
        timezone(value['timezone'])


def timezone(value):
    require(isinstance(value, str) and len(value) <= 128 and
            re.fullmatch(r'[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*', value))


def device(value):
    """A physical serial declaration; placement/capability references are separate."""
    closed(value,('type','context','path','capability'))
    require(value['type']=='serial' and identifier(value['context']) and identifier(value['capability']),
            'component.device')
    path(value['path'])
    require(value['path'].startswith('/dev/serial/by-id/'),'component.device')


def network(value):
    closed(value, ('context', 'cidr', 'bridge', 'vlan'), ('gateway',))
    require(identifier(value['context']))
    text(value['bridge'])
    try:
        require(isinstance(value['cidr'], str))
        selected = ipaddress.IPv4Network(value['cidr'], strict=True)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        require(False)
    require(str(selected) == value['cidr'])
    if value['vlan'] is not None:
        integer(value['vlan'], 1, 4094)
    if 'gateway' in value:
        ip(value['gateway'])
        address = ipaddress.IPv4Address(value['gateway'])
        require(address in selected and address not in (selected.network_address, selected.broadcast_address))


def interface(value):
    closed(value, ('network', 'slot', 'mac', 'address'), ('default_route', 'ipv6', 'ip_filter'))
    require(identifier(value['network']))
    integer(value['slot'], 0, 31)
    require(isinstance(value['mac'], str) and re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', value['mac']))
    require(type(value.get('default_route', False)) is bool)
    require('ipv6' not in value or value['ipv6'] == 'manual')
    address = value['address']
    require(isinstance(address, dict) and address.get('mode') in ('static', 'dhcp', 'manual'))
    field = {'static': 'value', 'dhcp': 'endpoint', 'manual': None}[address['mode']]
    closed(address, ('mode',) if field is None else ('mode', field))
    if field:
        ip(address[field])
    require(address['mode'] == 'static' or not value.get('default_route', False))
    require(type(value.get('ip_filter', False)) is bool
            and (not value.get('ip_filter', False) or address['mode'] == 'static'),
            'component.interface-ip-filter')


def policy_binding(value):
    if isinstance(value, str):
        require(identifier(value))
        return
    closed(value, ('policy',), ('interfaces', 'networks', 'endpoints', 'address_groups'))
    require(identifier(value['policy']))
    for field in ('interfaces', 'networks', 'endpoints', 'address_groups'):
        for item in named(value.get(field, {})).values():
            if field == 'endpoints':
                endpoint(item)
            elif field == 'interfaces' and isinstance(item, dict):
                closed(item, ('app', 'interface'))
                require(all(identifier(entry) for entry in item.values()))
            else:
                require(identifier(item))


def data_path(value):
    path(value)
    require(value != '/' and not any(value == prefix or value.startswith(prefix + '/')
            or prefix.startswith(value + '/') for prefix in CONTROL_PATHS), 'component.storage-path')
    return value


def volume(value):
    closed(value, ('storage', 'slot', 'path', 'size_gib'), ('backup',))
    if 'backup' in value:
        from component_backup import presence
        presence(value['backup'])
    require(identifier(value['storage']))
    checked(integer, value['slot'], 'slot', minimum=0, maximum=255)
    checked(data_path, value['path'], 'path')
    require(re.fullmatch(r'(/srv/[a-z0-9_-]+|/var/lib/(mysql|postgresql|influxdb))(/[a-z0-9_-]+)*',
                         value['path']) is not None, 'component.storage-backend-path')
    checked(integer, value['size_gib'], 'size_gib', minimum=1)


def root_path(value):
    closed(value, ('path',), ('host_bind',))
    checked(data_path, value['path'], 'path')
    if 'host_bind' in value:
        row = closed(value['host_bind'], ('source', 'slot', 'filesystem_source', 'filesystem', 'filesystem_root'))
        checked(data_path, row['source'], 'host_bind', 'source')
        require(all(re.fullmatch(r'/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', item)
                    for item in (value['path'], row['source']))
                and row['source'].startswith('/mnt/') and value['path'].startswith('/srv/'),
                'component.host-bind-path')
        checked(integer, row['slot'], 'host_bind', 'slot', minimum=0, maximum=255)
        require(row['filesystem'] in ('nfs', 'nfs4'), 'component.host-bind-filesystem')
        text(row['filesystem_source'])
        require(re.fullmatch(r'[A-Za-z0-9_.-]+:/(?:[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)?',
                             row['filesystem_source']), 'component.host-bind-source')
        checked(path, row['filesystem_root'], 'host_bind', 'filesystem_root')
        require(re.fullmatch(r'/(?:[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)?', row['filesystem_root']),
                'component.host-bind-path')


def storage_layout(volumes, roots):
    slots = [row['slot'] for row in volumes.values()] + [
        row['host_bind']['slot'] for row in roots.values() if 'host_bind' in row]
    require(len(set(slots)) == len(slots), 'component.storage-slot')
    paths = [PurePosixPath(row['path']) for row in [*volumes.values(), *roots.values()]]
    for index, selected in enumerate(paths):
        require(all(other != selected and other not in selected.parents and selected not in other.parents
                    for other in paths[index+1:]), 'component.storage-overlap')


def storage_role(value):
    closed(value, ('target', 'read_only', 'required', 'kind'), ('initialize',))
    path(value['target'])
    require(type(value['read_only']) is bool and type(value['required']) is bool
            and value['kind'] in ('file', 'directory'))
    if 'initialize' in value:
        selected = closed(value['initialize'], ('type', 'uid', 'gid', 'mode'))
        require(value['kind'] == 'directory' and value['read_only'] is False and
                selected['type'] == 'directory' and selected['mode'] == '0700',
                'component.storage-initialization')
        integer(selected['uid'], 0, 65535)
        integer(selected['gid'], 0, 65535)


def guest(value):
    closed(value, ('context', 'template', 'lifecycle', 'identity', 'template_file_id',
                   'root_storage', 'interfaces', 'control_interface'),
           ('display_name', 'resources', 'startup', 'security', 'ssh_public_keys', 'dns_servers',
            'volumes', 'root_paths', 'compose_projects', 'software', 'runtime', 'network_policy', 'timezone', 'readiness', 'source_policy_route', 'monitoring', 'backup'))
    if 'backup' in value:
        from component_backup_job import enrollment
        enrollment(value['backup'])
    require(all(identifier(value[key]) for key in ('context', 'template', 'root_storage', 'control_interface')))
    require(value['lifecycle'] in ('fresh', 'retained'))
    closed(value['identity'], ('vmid', 'hostname'))
    with at('identity', 'vmid'):
        integer(value['identity']['vmid'], 1)
    text(value['identity']['hostname'])
    require(re.fullmatch('[a-z][a-z0-9-]{0,62}', value['identity']['hostname']) is not None,
            'component.hostname')
    text(value['template_file_id'])
    if 'display_name' in value:
        text(value['display_name'])
    for key, check in (('resources', resource), ('startup', startup), ('security', security)):
        if key in value:
            check(value[key], partial=True)
    if 'ssh_public_keys' in value:
        strings(value['ssh_public_keys'])
    if 'dns_servers' in value:
        require(isinstance(value['dns_servers'], list) and bool(value['dns_servers']))
        for row in value['dns_servers']:
            endpoint(row)
    interfaces = named(value['interfaces'])
    require(bool(interfaces))
    for key, row in interfaces.items():
        checked(interface, row, 'interfaces', key)
    require(value['control_interface'] in interfaces and
            interfaces[value['control_interface']]['address'].get('mode') in ('static', 'dhcp'),
            'component.control-interface')
    if 'source_policy_route' in value:
        selected = closed(value['source_policy_route'], ('interface',))['interface']
        require(identifier(selected) and selected in interfaces and
                interfaces[selected]['address']['mode'] == 'static' and
                not interfaces[selected].get('default_route', False), 'component.source-policy-route')
    slots = [row['slot'] for row in interfaces.values()]
    require(sorted(slots) == list(range(len(slots))))
    # DHCP already obtains the receiver's ordinary route. Counting only the
    # explicit static flag would allow an unintended second effective route.
    require(sum(row['address']['mode'] == 'dhcp' or row.get('default_route', False)
                for row in interfaces.values()) == 1, 'component.default-route')
    volumes, roots = named(value.get('volumes', {})), named(value.get('root_paths', {}))
    for key, row in volumes.items():
        checked(volume, row, 'volumes', key)
    for key, row in roots.items():
        checked(root_path, row, 'root_paths', key)
    storage_layout(volumes, roots)
    project_files = []
    for key, row in named(value.get('compose_projects', {})).items():
        closed(row, ('name',), ('file',))
        text(row['name'])
        filename = row.get('file', 'compose-' + key + '.yml')
        require(isinstance(filename, str) and re.fullmatch('[a-z][a-z0-9_-]{0,62}\\.ya?ml', filename),
                'component.project-file')
        project_files.append(filename)
    require(len(set(project_files)) == len(project_files), 'component.project-file-conflict')
    for key in ('software', 'runtime'):
        strings(value.get(key, []), ids=True)
    require(isinstance(value.get('network_policy', []), list))
    for row in value.get('network_policy', []):
        policy_binding(row)
    if 'timezone' in value:
        timezone(value['timezone'])
    if 'monitoring' in value:
        from component_monitoring import reference
        reference(value['monitoring'])
    require(isinstance(value.get('readiness', []), list))
    for row in value.get('readiness', []):
        closed(row, ('stage', 'target'))
        require(row['stage'] == 'preparation' and isinstance(row['target'], dict) and 'app' in row['target'])
        endpoint(row['target'])


def role(value):
    require(isinstance(value, dict))
    if 'interface' in value:
        closed(value, ('interface',))
        require(identifier(value['interface']))
    elif value.get('scope') == 'app-network':
        closed(value, ('scope', 'network'))
        require(identifier(value['network']))
    else:
        closed(value, ('scope',))
        require(value['scope'] == 'guest-loopback')


def allocation(value):
    closed(value, (), ('memory_mib', 'cpu_limit', 'pids_limit'))
    require(bool(value), 'component.resource-allocation')
    for key, item in value.items():
        if key == 'cpu_limit':
            require(type(item) in (int, float) and 0 < item <= 256, 'component.resource-allocation')
        else:
            integer(item, 1)


def app(value):
    closed(value, ('profile', 'guest', 'lifecycle', 'interfaces'),
           ('display_name', 'identity', 'storage', 'properties', 'software', 'runtime',
            'authentication', 'devices', 'origin', 'secrets', 'resources'))
    require(identifier(value['profile']) and identifier(value['guest'])
            and value['lifecycle'] in ('fresh', 'retained'))
    if 'display_name' in value:
        text(value['display_name'])
    identity = closed(value.get('identity', {}), (), ('phase', 'runtime_id', 'project', 'services', 'networks',
                                                    'runtime_directory','custody_directory'))
    for field in ('phase', 'runtime_id', 'project'):
        require(field not in identity or identifier(identity[field]))
    for field in ('services', 'networks'):
        for item in named(identity.get(field, {})).values():
            text(item)
    if 'runtime_directory' in identity:
        from component_identity import directory
        directory(identity['runtime_directory'])
    if 'custody_directory' in identity:
        text(identity['custody_directory'])
    for row in named(value['interfaces']).values():
        role(row)
    for row in named(value.get('storage', {})).values():
        if isinstance(row, dict) and 'asset' in row:
            closed(row, ('asset',))
            require(identifier(row['asset']))
        else:
            field = 'root_path' if isinstance(row, dict) and 'root_path' in row else 'volume'
            closed(row, (field, 'subpath'))
            require(identifier(row[field]))
            require(row['subpath'] == '' or path(row['subpath'], relative=True))
    require(isinstance(value.get('properties', {}), dict))
    if 'resources' in value:
        selected = closed(value['resources'], ('containers',))['containers']
        require(bool(named(selected)), 'component.resource-allocation')
        for key, row in selected.items():
            checked(allocation, row, 'resources', 'containers', key)
    for field in ('software', 'runtime'):
        strings(value.get(field, []), ids=True)
    require('authentication' not in value or identifier(value['authentication']))
    for selected in named(value.get('secrets', {})).values():
        require(identifier(selected), 'component.secret-source')
    for item in named(value.get('devices', {})).values():
        require(identifier(item))


def health(value):
    closed(value, ('type', 'check'), ('source_interface',))
    require(value['type'] == 'adapter' and value['check'] == 'readiness')
    require('source_interface' not in value or identifier(value['source_interface']))


def profile(value):
    closed(value, ('adapter', 'display_name', 'interfaces'),
           ('listeners', 'endpoints', 'storage', 'software', 'runtime', 'authentication',
            'connections', 'health', 'monitoring', 'properties', 'devices', 'secrets', 'backup'))
    owner = adapter(value['adapter'])
    # Import locally: the source validators remain independently callable.
    from component_secrets import requirements
    requirements(value['adapter'], value.get('secrets', {}))
    text(value['display_name'])
    for row in named(value['interfaces']).values():
        closed(row, ('required', 'accepts'))
        require(type(row['required']) is bool)
        strings(row['accepts'])
        require(bool(row['accepts']) and set(row['accepts']) <= {'guest-interface', 'guest-loopback', 'app-network'})
    for row in named(value.get('listeners', {})).values():
        closed(row, ('service', 'namespace', 'interface', 'bind', 'protocol', 'port'), ('publish',))
        require(row['service'] in owner['services'] + owner['native']
                and row['namespace'] in ('host', 'app-network')
                and row['interface'] in value['interfaces']
                and row['bind'] in ('interface', 'wildcard', 'loopback')
                and row['protocol'] in ('tcp', 'udp'))
        integer(row['port'], 1, 65535)
        if 'publish' in row:
            publication = closed(row['publish'], ('scope', 'port'), ('interface',))
            require(publication['scope'] in ('guest-interface', 'guest-loopback'))
            integer(publication['port'], 1, 65535)
            require((publication.get('interface') in value['interfaces']) if publication['scope'] == 'guest-interface'
                    else 'interface' not in publication)
    for row in named(value.get('endpoints', {})).values():
        if isinstance(row, dict) and 'internal' in row:
            closed(row, ('internal',))
            require(value['adapter'] == 'traefik' and row['internal'] == 'dashboard')
            continue
        closed(row, ('listener', 'protocol', 'via'))
        require(row['listener'] in value.get('listeners', {}) and row['via'] in value['interfaces']
                and row['protocol'] in ('http', 'https', 'tcp', 'udp'))
    for key, row in named(value.get('storage', {})).items():
        checked(storage_role, row, 'storage', key)
    for field in ('software', 'runtime'):
        strings(value.get(field, []), ids=True)
    require(isinstance(value.get('properties', {}), dict))
    if 'monitoring' in value:
        from component_monitoring import reference
        reference(value['monitoring'])
    if 'backup' in value:
        from component_backup import application
        application(value['backup'], value.get('storage', {}), adapter=value['adapter'])
    from component_foundations import OWNED, validate
    if value['adapter'] in OWNED:
        validate(value['adapter'], value.get('properties', {}), partial=True)
    else:
        from component_properties import validate as app_properties
        app_properties(value['adapter'], value.get('properties', {}), partial=True)
    for row in named(value.get('connections', {})).values():
        closed(row, ('type', 'required'), ('readiness', 'accounts'))
        require(row['type'] in ('dns', 'mqtt', 'postgresql', 'mariadb', 'influxdb', 'http', 'https')
                and type(row['required']) is bool)
        strings(row.get('readiness', []))
        strings(row.get('accounts', []))
        require(set(row.get('readiness', [])) <= {'configure', 'start'}
                and set(row.get('accounts', [])) <= {'postgresql-admin', 'mariadb-admin', 'mqtt-client'})
    for row in named(value.get('devices', {})).values():
        closed(row, ('type', 'required'))
        require(row['type'] == 'serial' and type(row['required']) is bool)
    for row in named(value.get('health', {})).values():
        if isinstance(row, dict) and 'profile' in row:
            closed(row, ('profile',), ('source_interface',))
            require(identifier(row['profile']))
        else:
            health(row)
        require('source_interface' not in row or row['source_interface'] in value['interfaces'])
    require('authentication' not in value or identifier(value['authentication']))


def software(value):
    closed(value, (), ('packages', 'images', 'repositories'))
    strings(value.get('packages', []))
    require(all(re.fullmatch(r'[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?=[^\s=]+', item)
                for item in value.get('packages', [])))
    require(all(identifier(item) for item in named(value.get('images', {})).values()))
    require(isinstance(value.get('repositories', []), list))
    for row in value.get('repositories', []):
        closed(row, ('name', 'source', 'key_asset'))
        require(identifier(row['name']) and identifier(row['key_asset']))
        text(row['source'])


def runtime(value):
    closed(value, (), ('packages', 'requirements', 'containers', 'native', 'minimums'))
    strings(value.get('packages', []), ids=True)
    requirements = closed(value.get('requirements', {}), (), ('nesting', 'keyctl', 'os_reserve_mib'))
    require(all(type(item) is bool for key, item in requirements.items() if key != 'os_reserve_mib'))
    if 'os_reserve_mib' in requirements:
        integer(requirements['os_reserve_mib'], 1)
    if 'native' in value:
        closed(value['native'], ('memory_mib',))
        integer(value['native']['memory_mib'], 1)
    if 'minimums' in value:
        selected = closed(value['minimums'], ('containers',))['containers']
        for key, row in named(selected).items():
            checked(allocation, row, 'minimums', 'containers', key)
    for row in named(value.get('containers', {})).values():
        closed(row, (), ('memory_mib', 'pids_limit', 'cpu_limit', 'read_only', 'cap_drop',
                         'cap_add', 'no_new_privileges', 'user', 'tmpfs'))
        for key in ('memory_mib', 'pids_limit'):
            if key in row:
                integer(row[key], 1)
        if 'cpu_limit' in row:
            require(type(row['cpu_limit']) in (int, float) and 0 < row['cpu_limit'] <= 256)
        for key in ('read_only', 'no_new_privileges'):
            require(key not in row or type(row[key]) is bool)
        for key, allowed in (('cap_drop', {'ALL'}), ('cap_add', {'NET_ADMIN'})):
            if key in row:
                strings(row[key])
                require(set(row[key]) <= allowed)
        if 'user' in row:
            text(row['user'])
        if 'tmpfs' in row:
            strings(row['tmpfs'])
            require(all(re.fullmatch(r'/tmp:rw,nosuid,nodev,size=[1-9][0-9]*m', item) for item in row['tmpfs']))


def rule_address(value, *, ipv6=False):
    if isinstance(value, str):
        try:
            selected = ipaddress.ip_network(value, strict=False)
        except ValueError:
            require(False)
        require('%' not in value and (ipv6 or selected.version == 4))
    else:
        require(isinstance(value, dict) and len(value) == 1 and
                set(value) <= {'network', 'interface', 'endpoint', 'address_group'} and
                all(identifier(item) for item in value.values()))


def rule_port(value, *, icmp=False):
    """Literal transport ports, or one ICMP type carried by PVE's dport."""
    require(isinstance(value, str))
    if icmp:
        require(re.fullmatch(r'0|[1-9][0-9]{0,2}', value) and int(value) <= 255)
        return
    require(re.fullmatch(r'[1-9][0-9]{0,4}(?::[1-9][0-9]{0,4})?'
                         r'(?:,[1-9][0-9]{0,4}(?::[1-9][0-9]{0,4})?)*', value))
    require(all(1 <= bounds[0] <= bounds[-1] <= 65535
                for bounds in (list(map(int, item.split(':'))) for item in value.split(','))))


def rule_family(row):
    """Validate resolved selector families without adding grants or addresses."""
    families = {ipaddress.ip_network(row[field], strict=False).version
                for field in ('source', 'destination') if row.get(field) is not None}
    require(len(families) <= 1 and not (row['proto'] in ('icmp', 'igmp') and 6 in families)
            and not (row['proto'] == 'icmpv6' and 4 in families), 'component.policy-family')
    require(not (row['direction'] == 'in' and row.get('source') is not None
                 and ipaddress.ip_network(row['source'], strict=False).prefixlen == 0))


def network_policy(value):
    closed(value, ('rules',))
    require(isinstance(value['rules'], list) and len(value['rules']) <= 4096)
    for row in value['rules']:
        closed(row, ('direction', 'proto', 'comment'), ('port', 'source', 'destination', 'interface'))
        require(row['direction'] in ('in', 'out') and row['proto'] in ('tcp', 'udp', 'icmp', 'icmpv6', 'igmp'))
        text(row['comment'])
        require('interface' not in row or identifier(row['interface']))
        for field in ('source', 'destination'):
            if field in row:
                rule_address(row[field], ipv6=True)
        if 'port' in row:
            if row['port'] is None:
                continue
            if isinstance(row['port'], dict):
                closed(row['port'], ('endpoint',))
                require(row['proto'] in ('tcp', 'udp') and identifier(row['port']['endpoint']))
            else:
                require(row['proto'] != 'igmp')
                rule_port(row['port'], icmp=row['proto'] in ('icmp', 'icmpv6'))
