"""Validate the PBS preparation inventory; never copy live data or start jobs."""
import copy
import json
import re

from component_guest import path
from private_io import require

SCHEMA = 'homelab-pbs-coverage-v1'
PHASE = 'pbs-agent'


def configuration(cfg):
    value = cfg['app']['backup']
    require(isinstance(value, dict) and set(value) == {
        'schema', 'profile', 'owner', 'configuration', 'applications', 'managed_volumes'}
        and value['schema'] == SCHEMA and re.fullmatch('[a-z][a-z0-9_-]{0,62}', value['profile']),
        'Use the exact selected PBS preparation inventory')
    require(value['owner'] == {'node': cfg['site']['node'], 'vmid': cfg['guest']['vmid'],
                              'hostname': cfg['guest']['hostname']},
            'Bind PBS preparation to this guest identity')
    expected = {row['id']: row['adapter'] for row in cfg['deployment']['applications'].values()}
    require(isinstance(value['applications'], dict) and set(value['applications']) == set(expected),
            'Classify every selected application exactly once')
    for name, app in value['applications'].items():
        require(isinstance(app, dict) and set(app) == {
            'adapter', 'storage', 'configuration', 'runtime_files', 'databases'}
            and app['adapter'] == expected[name], 'Preserve PBS application ownership')
        require(isinstance(app['runtime_files'], list), 'Use the owned PBS runtime file inventory')
        for selected in app['runtime_files']:
            path(selected)
        require(isinstance(app['storage'], dict) and isinstance(app['databases'], list),
                'Preserve the closed PBS storage and database inventory')
        for row in app['storage'].values():
            require(isinstance(row, dict) and row.get('kind') in ('file', 'directory')
                    and type(row.get('include')) is bool,
                    'Preserve the PBS dataset classification')
            path(row['path'])
            if 'reason' in row:
                require(set(row) == {'path', 'kind', 'include', 'reason'} and row['include'] is False
                        and row['reason'] in ('transient', 'rebuildable'),
                        'Exclude only explicitly classified non-authoritative data')
            else:
                require(set(row) == {'path', 'kind', 'include', 'category', 'capture'}
                        and row['category'] in ('configuration', 'state', 'database')
                        and row['capture'] in ('files', 'application-export', 'database-export')
                        and (row['category'] == 'database') == (row['capture'] == 'database-export')
                        and row['include'] == (row['category'] != 'database')
                        and (row['category'] != 'state' or row['capture'] == 'application-export'),
                        'Require native database exports and coherent application capture')
        for row in app['databases']:
            require(isinstance(row, dict) and set(row) == {'connection', 'type', 'target'}
                    and row['type'] in ('postgresql', 'mariadb', 'influxdb')
                    and isinstance(row['target'], dict), 'Preserve related database recovery bindings')
    for rows in [value['configuration'], *[row['configuration'] for row in value['applications'].values()]]:
        require(isinstance(rows, dict), 'Use named PBS configuration paths')
        for row in rows.values():
            require(isinstance(row, dict) and set(row) == {'path', 'kind'}
                    and row['kind'] in ('file', 'directory') and row['path'] != '/',
                    'Use explicit PBS configuration paths')
            path(row['path'])
    volumes = {name: {'path': row['path'], 'include': row.get('backup', True)}
               for name, row in cfg['guest'].get('volumes', {}).items()}
    require(value['managed_volumes'] == volumes, 'Bind exact native managed-volume backup flags')
    packages = [item for item in cfg['app']['packages'] if item.startswith('proxmox-backup-client=')]
    require(len(packages) == 1 and re.fullmatch(r'proxmox-backup-client=[0-9][A-Za-z0-9.+:~\-]*', packages[0]),
            'Install one exact selected PBS client package')
    return {'inventory': json.dumps(copy.deepcopy(value), sort_keys=True, indent=2) + '\n',
            'package': packages[0]}
