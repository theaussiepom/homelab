"""Presence-based PBS client preparation and source-derived recovery coverage.

This is source planning, not backup execution or recovery acceptance. Profiles
classify their own storage; guest bindings supply paths exactly once. Database
engine directories are never represented as selected file-backup inputs.
"""
import copy
import re
from pathlib import PurePosixPath

from component_errors import at, checked
from component_sources import closed, identifier, named, require
import component_types as types
import component_backup_job
import component_backup_key
import component_backup_management
import monitoring_paths
import component_native

SCHEMA = 'homelab-pbs-coverage-v1'
PHASE = 'pbs-agent'
CATEGORIES = {'configuration', 'state', 'database'}
CAPTURES = {'files', 'application-export', 'database-export'}
EXCLUSIONS = {'transient', 'rebuildable'}
DATABASES = {'postgresql', 'mariadb', 'influxdb'}
MONITORING_CONFIGURATION = monitoring_paths.RECOVERY


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
        closed(value, (), ('profile', 'job', 'recovery_public_key', 'management', 'defaults'))
        require(('job' in value) == ('recovery_public_key' in value) == ('management' in value),
                'component.backup-recovery-key')
        if 'recovery_public_key' in value:
            component_backup_key.source(value['recovery_public_key'])
        require('profile' in value or len(resolver.library['backup_profiles']) == 1,
                'component.backup-profile-selection')
        name = value.get('profile', next(iter(resolver.library['backup_profiles']), None))
        if 'job' in value:
            component_backup_job.job(value['job'])
            component_backup_management.source(value['management'])
    require(identifier(name) and name in resolver.library['backup_profiles'],
            'component.backup-profile-selection')
    return name


def software(resolver, guest):
    require('backup' not in guest or 'backup' in resolver.site, 'component.backup-root-required')
    name = selected(resolver)
    return [] if name is None or 'backup' not in guest else list(resolver.library['backup_profiles'][name]['software'])


def bind(resolver):
    name = selected(resolver)
    if name is None:
        require(not any('backup' in row for row in resolver.guests.values()),
                'component.backup-root-required')
        return None
    client = resolver.library['backup_profiles'][name]
    bindings = component_backup_job.clients(resolver)
    for guest_id, guest in resolver.guests.items():
        if 'backup' not in guest:
            continue
        packages = [item for item in guest['software_selection']['packages']
                    if item.startswith('proxmox-backup-client=')]
        require(len(packages) == 1 and re.fullmatch(
            r'proxmox-backup-client=[0-9][A-Za-z0-9.+:~\-]*', packages[0]),
            'component.backup-client-package')
        context = resolver.site['contexts'][guest['context']]
        document = {'schema': SCHEMA, 'profile': name,
            'owner': {'node': context['node'], **guest['identity']},
            'configuration': copy.deepcopy(client['configuration']),
            'applications': {}, 'managed_volumes': {
                key: {'path': row['path'], 'include': 'backup' in row}
                for key, row in guest.get('volumes', {}).items()}}
        if 'monitoring' in guest:
            for key, row in MONITORING_CONFIGURATION.items():
                require(key not in document['configuration'] or document['configuration'][key] == row,
                        'component.backup-configuration-owner')
                document['configuration'][key] = copy.deepcopy(row)
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
                    record['producer'] = {'type': 'compose', 'project': project['name'],
                        'file': '/opt/homelab-app/' + project['file'],
                        'services': list(app['identity']['services'].values())}
                elif app['adapter'] in DATABASES:
                    require('native' not in record['configuration'] or record['configuration']['native'] == {
                        'path': component_native.configuration_root(app['adapter']), 'kind': 'directory'},
                        'component.backup-configuration-owner')
                    record['configuration']['native'] = {
                        'path': component_native.configuration_root(app['adapter']), 'kind': 'directory'}
                    record['producer'] = {'type': app['adapter'],
                        'packages': guest['software_selection']['packages']}
                    if app['adapter'] == 'influxdb':
                        record['producer']['endpoint'] = 'http://' + app['role_addresses']['service_interface'] + ':8086'
                if app['adapter'] == 'postgresql' and 'application_database' in app['settings']:
                    record['configuration']['application_database'] = {
                        'path': '/var/lib/homelab-databases/' + app['settings']['application_database']['name'] + '.json',
                        'kind': 'file'}
                if app['adapter'] in ('node_red', 'bitwarden', 'renovate') and app.get('secret_bindings'):
                    overlay = '/opt/homelab-app/component-' + app_id + '-environment.yml'
                    record['runtime_files'].append(overlay)
                    record['producer']['overlay'] = overlay
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
    result = {'profile': name, 'mode': 'client-preparation'}
    if isinstance(resolver.site['backup'], dict) and 'job' in resolver.site['backup']:
        result.update(management=component_backup_management.bind(resolver, resolver.site['backup']['management']))
        result.update(mode='scheduled-recovery', group=component_backup_job.bind(
            resolver, resolver.site['backup']['job'], bindings))
    return result
