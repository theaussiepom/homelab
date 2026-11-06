"""Closed runtime PBS job contract, shared by deployment and the guest worker."""
from pathlib import PurePosixPath
import re
import ipaddress

from private_io import require


def exact(value, fields, optional=()):
    """Require a closed mapping with only its declared optional fields."""
    require(isinstance(value, dict) and set(fields) <= set(value) <= set(fields) | set(optional),
            'Preserve the closed operational backup contract')


def validate(value):
    """Check the finite destination, transport, credentials and capture contract."""
    exact(value, ('destination', 'schedule', 'limits', 'secrets', 'capture', 'staging', 'transport', 'group'))
    import backup_group
    backup_group.member(value['group'])
    limits(value['limits'])
    exact(value['transport'], ('device', 'address'))
    require(isinstance(value['transport']['device'], str) and re.fullmatch(r'eth[0-9]+', value['transport']['device'])
            and isinstance(value['transport']['address'], str)
            and str(ipaddress.IPv4Address(value['transport']['address'])) == value['transport']['address'],
            'Bind the intended backup transport interface')
    exact(value['staging'], ('path', 'size_bytes'))
    require(isinstance(value['staging']['path'], str) and re.fullmatch(
        r'/srv/[a-z0-9][a-z0-9_-]*(?:/[a-z0-9][a-z0-9_-]*)*', value['staging']['path'])
        and type(value['staging']['size_bytes']) is int and value['staging']['size_bytes'] >= 4*value['limits']['max_bytes'],
        'Bind a dedicated, bounded managed staging volume')
    dest = value['destination']
    exact(dest, ('server', 'port', 'datastore', 'namespace', 'fingerprint', 'auth_id', 'backup_id'))
    require(backup_group.identifier(dest['backup_id']) and dest['backup_id'] == value['group']['member'],
            'Preserve the stable backup group identity')
    require(isinstance(dest['server'], str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', dest['server'])
            and type(dest['port']) is int and 1 <= dest['port'] <= 65535,
            'Use the selected PBS endpoint')
    for field in ('datastore', 'namespace'):
        require(isinstance(dest[field], str) and len(dest[field]) <= 128 and re.fullmatch(
            r'[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*', dest[field]), 'Use literal PBS datastore and namespace names')
    require(len(dest['namespace'].split('/')) <= 6 and '/' not in dest['datastore'] and isinstance(dest['auth_id'], str) and re.fullmatch(
        r'[A-Za-z0-9_.-]+@pbs![A-Za-z0-9_.-]+', dest['auth_id']), 'Use the selected scoped PBS token identity')
    require(isinstance(dest['fingerprint'], str) and re.fullmatch(
        r'[0-9a-f]{2}(?::[0-9a-f]{2}){31}', dest['fingerprint']), 'Pin the PBS certificate fingerprint')
    schedule(value['schedule']); limits(value['limits'])
    exact(value['capture'], ('pause', 'database_lock', 'influx_tokens'))
    for field in ('pause', 'database_lock'):
        selected = value['capture'][field]
        require(isinstance(selected, list) and len(selected) <= 1024
                and all(isinstance(key, str) and re.fullmatch(r'[a-z][a-z0-9_-]{0,62}', key) for key in selected)
                and len(set(selected)) == len(selected), 'Bind finite named backup producers')
    exact(value['secrets'], ('password', 'encryption_key'), ('key_password',))
    require(isinstance(value['capture']['influx_tokens'], dict)
            and len(value['capture']['influx_tokens']) <= 1024, 'Bind native Influx token references')
    for source in [*value['secrets'].values(), *value['capture']['influx_tokens'].values()]:
        exact(source, ('type', 'path'))
        require(source['type'] == 'file' and isinstance(source['path'], str)
                and source['path'].startswith('/') and not source['path'].startswith('//')
                and PurePosixPath(source['path']).as_posix() == source['path']
                and not any(part in ('.', '..') for part in source['path'].split('/'))
                and not any(ord(char) < 32 for char in source['path']), 'Use canonical protected controller input references')
    return value


def owner(value):
    """Bind the stable guest node, VMID and hostname."""
    exact(value, ('node', 'vmid', 'hostname'))
    require(isinstance(value['node'], str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}', value['node'])
            and type(value['vmid']) is int and 100 <= value['vmid'] <= 999999999
            and isinstance(value['hostname'], str) and re.fullmatch(
                r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}', value['hostname']), 'Bind the exact backup guest identity')
    return value


def schedule(value):
    """Limit UTC scheduling to the supported calendar and bounded jitter."""
    exact(value, ('calendar', 'jitter_seconds'))
    require(isinstance(value['calendar'], str) and re.fullmatch(
        r'hourly|daily|[0-2][0-9]:[0-5][0-9]', value['calendar'])
        and (':' not in value['calendar'] or int(value['calendar'][:2]) < 24)
        and type(value['jitter_seconds']) is int and 0 <= value['jitter_seconds'] <= 3600,
        'Use the selected bounded backup schedule')


def limits(value):
    """Bound selected bytes, entries and the duration of each native phase."""
    exact(value, ('max_bytes', 'max_files', 'timeout_seconds'))
    for field, minimum, maximum in [('max_bytes', 1048576, 2**50), ('max_files', 1, 1000000),
                                   ('timeout_seconds', 60, 86400)]:
        require(type(value[field]) is int and minimum <= value[field] <= maximum,
                'Use bounded backup capacity and duration')
