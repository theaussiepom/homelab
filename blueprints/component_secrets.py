"""Named adapter secret requirements; resolution never opens a secret source."""
import copy
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'proxmox/applications'))

from component_errors import at
from component_sources import closed, identifier, named, require
import component_types as types
from component_input_secrets import ROLES as INPUT_ROLES, SLOTS

# These are application capabilities, not environment-variable overrides.
# Existing ordinary input custody owns materialization and runtime filenames.
ROLES = {key: value for key, value in INPUT_ROLES.items() if key not in ('cloudbeaver', 'mqtt_explorer')}


def action_inputs(resolver, app_id):
    """Select finite scalar slots; never wrap or transform a secret value."""
    require(app_id in resolver.apps, 'component.reference')
    app = resolver.apps[app_id]
    selected = copy.deepcopy(app.get('secret_bindings', {}))
    if app['adapter'] == 'cloudbeaver':
        auth = app.get('authentication_resolved', {})
        if 'client_secret' in auth:
            selected['client_secret'] = resolver.site['secret_sources'][auth['client_secret']]
    if app['adapter'] == 'mqtt_explorer':
        credential = app.get('settings', {}).get('broker', {}).get('credential')
        if credential is not None:
            selected['broker_password'] = resolver.site['secret_sources'][credential['secret']]
    result = {}
    for role, value in selected.items():
        require(role in SLOTS.get(app['adapter'], {}), 'component.secret-role')
        source({key: row for key, row in value.items() if key != 'source_id'})
        if value['type'] != 'environment':
            continue
        name = SLOTS[app['adapter']][role]
        result[name] = {'environment': value['name'],
                        'workflow_secret': value.get('workflow_secret', value['name'])}
    return result


def source(value):
    require(isinstance(value, dict), 'component.secret-source')
    field = {'file': 'path', 'environment': 'name', 'generated': 'credential_id'}.get(value.get('type'))
    require(field is not None, 'component.secret-source')
    closed(value, ('type', field), ('workflow_secret',) if field == 'name' else ())
    if field == 'path':
        types.path(value[field])
    elif field == 'name':
        require(isinstance(value[field], str) and
                re.fullmatch('[A-Z][A-Z0-9_]{0,127}', value[field]) is not None,
                'component.secret-source')
        if 'workflow_secret' in value:
            require(isinstance(value['workflow_secret'], str) and
                    re.fullmatch('[A-Z][A-Z0-9_]{0,127}', value['workflow_secret']) is not None,
                    'component.secret-source')
    else:
        require(isinstance(value[field], str) and
                re.fullmatch('[a-z][a-z0-9-]{2,62}', value[field]) is not None,
                'component.secret-source')


def requirements(adapter, value):
    for role, row in named(value).items():
        with at(role):
            require(role in ROLES.get(adapter, set()), 'component.secret-role')
            closed(row, ('required',))
            require(type(row['required']) is bool, 'component.secret-role')


def bind(resolver):
    for app_id, app in resolver.apps.items():
        with at('apps', app_id, 'secrets'):
            profile = resolver.library['app_profiles'][app['profile']]
            declared = profile.get('secrets', {})
            requirements(app['adapter'], declared)
            bindings = app.get('secrets', {})
            require(set(bindings) <= set(declared), 'component.secret-role')
            require(all(not row['required'] or role in bindings for role, row in declared.items()),
                    'component.secret-required')
            selected = {}
            for role, source_id in bindings.items():
                require(identifier(source_id) and source_id in resolver.site['secret_sources'],
                        'component.reference')
                value = resolver.site['secret_sources'][source_id]
                require(value['type'] in ('file', 'environment'), 'component.secret-source')
                selected[role] = dict(copy.deepcopy(value), source_id=source_id)
            app['secret_bindings'] = selected
