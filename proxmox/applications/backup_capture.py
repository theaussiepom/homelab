"""Finite capture recipes and path normalization; never execute authored commands."""
from pathlib import PurePosixPath
import re

from private_io import require


def normalize(inventory):
    """Coalesce identical paths and retain explicit nested exclusions."""
    included, excluded = {}, set()

    def add(path, kind, capture):
        require(isinstance(path, str) and path.startswith('/') and path != '/'
                and not path.startswith('//') and str(PurePosixPath(path)) == path
                and not any(part in ('.', '..') for part in path.split('/'))
                and not any(ord(char) < 32 for char in path), 'Use canonical explicit capture paths')
        row = {'path': path, 'kind': kind, 'capture': capture}
        require(path not in included or included[path] == row,
                'One path cannot have conflicting recovery classifications')
        included[path] = row

    for row in inventory['configuration'].values():
        add(row['path'], row['kind'], 'files')
    for app in inventory['applications'].values():
        for row in app['configuration'].values():
            add(row['path'], row['kind'], 'files')
        for path in app['runtime_files']:
            add(path, 'file', 'files')
        for row in app['storage'].values():
            if row['include']:
                add(row['path'], row['kind'], row['capture'])
            else:
                excluded.add(row['path'])
    for path in included:
        require(not any(path == root or path.startswith(root + '/') for root in excluded),
                'An excluded directory cannot contain required recovery material')
    result = []
    for path, row in sorted(included.items(), key=lambda pair: (len(PurePosixPath(pair[0]).parts), pair[0])):
        parent = next((other for other in result if path.startswith(other['path'] + '/')), None)
        if parent:
            require(parent['kind'] == 'directory' and parent['capture'] == row['capture'],
                    'Overlapping paths must have the same consistency boundary')
        else:
            result.append(row)
    return {'include': result, 'exclude': sorted(excluded)}


def recipes(inventory):
    """Select only compiler-bound local services and owning native producers."""
    job = inventory['job']; result = {'pause': [], 'databases': []}
    apps = inventory['applications']
    require(isinstance(apps, dict) and all(isinstance(key, str) and re.fullmatch(
        r'[a-z][a-z0-9_-]{0,62}', key) for key in apps), 'Use compiler-owned application identifiers')
    require(set(job['capture']['pause']) <= set(apps), 'Bind quiescence to this guest')
    for app_id, app in apps.items():
        state = any(row.get('capture') == 'application-export' for row in app['storage'].values())
        producer = app.get('producer')
        if state:
            require(app_id in job['capture']['pause'] and producer is not None
                    and producer['type'] == 'compose',
                    'Changing app state needs an explicitly permitted supported quiesce')
        if app_id in job['capture']['pause']:
            require(producer is not None and producer['type'] == 'compose'
                    and set(producer) - {'overlay'} == {'type', 'project', 'file', 'services'}
                    and isinstance(producer['services'], list) and producer['services']
                    and len(set(producer['services'])) == len(producer['services'])
                    and all(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name)
                            for name in [producer['project'], *producer['services']])
                    and isinstance(producer['file'], str) and re.fullmatch(
                        r'/opt/homelab-app/[A-Za-z0-9_.-]+\.ya?ml', producer['file']),
                    'Use only owned Compose services for a backup pause')
            require('overlay' not in producer or producer['overlay'] == '/opt/homelab-app/component-'+app_id+'-environment.yml',
                    'Bind only this app owned private environment overlay')
            result['pause'].append({'app': app_id, **producer})
        if app['adapter'] in ('postgresql', 'mariadb', 'influxdb'):
            require(producer is not None and producer['type'] == app['adapter'],
                    'Native database exports belong to their owning guest')
            require(set(producer) == {'type', 'packages'} | (
                        {'endpoint'} if app['adapter'] == 'influxdb' else set())
                    and isinstance(producer['packages'], list)
                    and all(isinstance(item, str) for item in producer['packages']),
                    'Use a closed package-owned native database producer')
            if app['adapter'] == 'influxdb':
                require(isinstance(producer['endpoint'], str) and re.fullmatch(
                    r'http://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:8086', producer['endpoint']),
                    'Use the owning native Influx listener')
            if app['adapter'] == 'postgresql':
                postgresql_client(producer['packages'])
            if app['adapter'] == 'mariadb':
                require(app_id in job['capture']['database_lock'], 'Explicitly permit the database read lock')
            if app['adapter'] == 'influxdb':
                require(app_id in job['capture']['influx_tokens'], 'Bind the Influx operator-token reference')
            result['databases'].append({'app': app_id, **producer})
    return result


def compose(row, action):
    require(action in ('stop', 'start', 'ps', 'health'), 'Use a finite backup service action')
    args = ['docker', 'compose', '--project-name', row['project'], '-f', row['file']]
    if 'overlay' in row: args += ['-f', row['overlay']]
    return args + ({'stop': ['stop', '--timeout', '60'], 'start': ['start'],
                    'ps': ['ps', '--status', 'running', '--services'],
                    'health': ['ps', '--all', '--format', 'json']}[action]) + row['services']


def database(row, destination):
    """Use package-owned local authentication; never put passwords in argv."""
    adapter = row['type']
    if adapter == 'postgresql':
        return ['runuser', '-u', 'postgres', '--', postgresql_client(row['packages']), '--no-password'], 'cluster.sql'
    if adapter == 'mariadb':
        return ['mariadb-dump', '--protocol=socket', '--user=root', '--all-databases',
                '--lock-all-tables', '--routines', '--events', '--triggers', '--hex-blob'], 'cluster.sql'
    require(adapter == 'influxdb', 'Use an admitted native database producer')
    return ['influx', 'backup', '--host', row['endpoint'], str(destination/'native')], None


def postgresql_client(packages):
    """Resolve the installed major from the effective guest selection before pause."""
    versions = [item.split('=')[0].removeprefix('postgresql-client-')
                for item in packages if item.startswith('postgresql-client-')]
    require(len(versions) == 1 and re.fullmatch(r'[1-9][0-9]*', versions[0]),
            'Bind one installed PostgreSQL client major')
    return '/usr/lib/postgresql/' + versions[0] + '/bin/pg_dumpall'


def archive(selected, target):
    """GNU tar receives literal root-anchored exclusions, never glob patterns."""
    argv = ['tar', '--create', '--file', str(target), '--acls', '--xattrs', '--numeric-owner',
        '--sparse', '--one-file-system', '--directory', '/', '--anchored', '--no-wildcards']
    for excluded in selected['exclude']:
        argv += ['--exclude='+excluded.lstrip('/')]
    return argv + ['--', *[row['path'].lstrip('/') for row in selected['include']]]
