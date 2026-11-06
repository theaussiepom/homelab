"""Presence-based PBS client preparation and source-derived recovery coverage.

This is source planning, not backup execution or recovery acceptance. Profiles
classify their own storage; guest bindings supply paths exactly once. Database
engine directories are never represented as selected file-backup inputs.
"""
import copy
from pathlib import PurePosixPath

from component_errors import at, checked
from component_sources import closed, identifier, named, require
import component_types as types

SCHEMA = 'homelab-pbs-coverage-v1'
PHASE = 'pbs-agent'
CATEGORIES = {'configuration', 'state', 'database'}
CAPTURES = {'files', 'application-export', 'database-export'}
EXCLUSIONS = {'transient', 'rebuildable'}
DATABASES = {'postgresql', 'mariadb', 'influxdb'}


def presence(value):
    require(value is None or isinstance(value, dict) and not value,
            'component.backup-presence')


def profile(value):
    closed(value, ('type', 'software', 'configuration'))
    require(value['type'] == 'pbs-client', 'component.backup-profile')
    types.strings(value['software'], ids=True)
    require(bool(value['software']), 'component.backup-profile')
    for row in named(value['configuration']).values():
        closed(row, ('path', 'kind'))
        types.path(row['path'])
        require(row['path'] != '/' and row['kind'] in ('file', 'directory'),
                'component.backup-path')


def dataset(value):
    closed(value, ('category', 'capture'))
    require(value['category'] in CATEGORIES and value['capture'] in CAPTURES,
            'component.backup-dataset')
    require((value['category'] == 'database') == (value['capture'] == 'database-export')
            and (value['category'] != 'state' or value['capture'] == 'application-export'),
            'component.backup-consistency')


def application(value, storage):
    """Every declared storage role has exactly one explicit disposition."""
    closed(value, ('include', 'exclude'), ('configuration',))
    includes, excludes = named(value['include']), named(value['exclude'])
    require(not set(includes) & set(excludes) and set(includes) | set(excludes) == set(storage),
            'component.backup-coverage')
    for role, row in includes.items():
        checked(dataset, row, 'include', role)
    require(all(row in EXCLUSIONS for row in excludes.values()),
            'component.backup-exclusion')
    for role, row in named(value.get('configuration', {})).items():
        with at('configuration', role):
            closed(row, ('path', 'kind'))
            types.path(row['path'])
            require(row['path'] != '/' and row['kind'] in ('file', 'directory'),
                    'component.backup-path')


def selected(resolver):
    if 'backup' not in resolver.site:
        return None
    value = resolver.site['backup']
    if value is None or value == {}:
        require(len(resolver.library['backup_profiles']) == 1, 'component.backup-profile-selection')
        name = next(iter(resolver.library['backup_profiles']))
    else:
        closed(value, ('profile',))
        name = value['profile']
    require(identifier(name) and name in resolver.library['backup_profiles'],
            'component.backup-profile-selection')
    return name


def software(resolver):
    name = selected(resolver)
    return [] if name is None else list(resolver.library['backup_profiles'][name]['software'])


def bind(resolver):
    name = selected(resolver)
    if name is None:
        return None
    client = resolver.library['backup_profiles'][name]
    for guest_id, guest in resolver.guests.items():
        context = resolver.site['contexts'][guest['context']]
        document = {'schema': SCHEMA, 'profile': name,
            'owner': {'node': context['node'], **guest['identity']},
            'configuration': copy.deepcopy(client['configuration']),
            'applications': {}, 'managed_volumes': {
                key: {'path': row['path'], 'include': 'backup' in row}
                for key, row in guest.get('volumes', {}).items()}}
        # Source closure covers configured guests, including disabled guests.
        # The deployment selector controls installation, never retirement.
        for app_id, app in resolver.apps.items():
            if app['guest'] != guest_id:
                continue
            with at('apps', app_id, 'backup'):
                definition = resolver.library['app_profiles'][app['profile']]
                require('backup' in definition, 'component.backup-coverage')
                rule = definition['backup']
                application(rule, definition.get('storage', {}))
                record = {'adapter': app['adapter'], 'storage': {},
                    'configuration': copy.deepcopy(rule.get('configuration', {})),
                    'runtime_files': [str(PurePosixPath(app['runtime_files']['directory']) / leaf)
                        for leaf in app.get('runtime_files', {}).get('files', [])]
                        + [row['destination'] for row in app.get('sidecar_files', {}).values()],
                    'databases': []}
                if 'project' in app['identity']:
                    project = guest['compose_projects'][app['identity']['project']]
                    record['runtime_files'].append('/opt/homelab-app/' + project['file'])
                if app['adapter'] in ('node_red', 'bitwarden') and app.get('secret_bindings'):
                    record['runtime_files'].append('/opt/homelab-app/component-' + app_id + '-environment.yml')
                for role, binding in app.get('storage', {}).items():
                    require('asset' not in binding, 'component.backup-binding')
                    kind = 'root_paths' if 'root_path' in binding else 'volumes'
                    key = binding.get('root_path', binding.get('volume'))
                    root = guest[kind][key]
                    path = str(PurePosixPath(root['path']) / binding['subpath'])
                    row = {'path': path, 'kind': definition['storage'][role]['kind']}
                    if role in rule['include']:
                        row.update(copy.deepcopy(rule['include'][role]))
                        row['include'] = row['category'] != 'database'
                        if kind == 'volumes':
                            require('backup' in root, 'component.backup-authoritative-volume')
                    else:
                        row.update(include=False, reason=rule['exclude'][role])
                    record['storage'][role] = row
                for connection, row in app['resolved_connections'].items():
                    if row['type'] in DATABASES:
                        record['databases'].append({'connection': connection, 'type': row['type'],
                            'target': copy.deepcopy(row['target'])})
                document['applications'][app_id] = record
        guest['backup'] = document
    return {'profile': name, 'mode': 'client-preparation'}
