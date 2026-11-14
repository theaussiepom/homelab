"""Explicit Mend CE and PostgreSQL-owner bindings; no credentials or target I/O."""
import copy
import re

from component_errors import at
from component_sources import closed, identifier, require


def database(value):
    closed(value, ('name', 'user'))
    require(all(isinstance(row, str) and re.fullmatch('[a-z][a-z0-9_]{0,62}', row)
                and row not in {'postgres', 'template0', 'template1', 'public', 'all', 'none', 'replication'}
                and not row.startswith('pg_') for row in value.values()), 'component.database')


def validate(value, *, partial=False):
    fields = ('database', 'repositories')
    closed(value, () if partial else fields, fields if partial else ())
    if 'database' in value:
        database(value['database'])
    if 'repositories' in value:
        repos = value['repositories']
        require(isinstance(repos, list) and 1 <= len(repos) <= 10
                and all(isinstance(repo, str) and re.fullmatch(
                    '[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', repo)
                    for repo in repos)
                and len({repo.lower() for repo in repos}) == len(repos), 'component.renovate-repositories')


def bind(resolver):
    owned = set()
    for name, producer in resolver.apps.items():
        selected = producer['properties'].get('application_database') if producer['adapter'] == 'postgresql' else None
        if selected is None:
            continue
        with at('apps', name, 'properties', 'application_database'):
            closed(selected, ('app',))
            key = selected['app']
            require(identifier(key) and key in resolver.apps and key not in owned, 'component.database-binding')
            app = resolver.apps[key]
            require(app['adapter'] == 'renovate', 'component.database-binding')
            validate(app['properties'])
            link = app['resolved_connections'].get('database', {})
            require(link.get('type') == 'postgresql' and link.get('target', {}).get('app') == name
                    and link['target']['port'] == 5432 and link.get('readiness') == 'start'
                    and resolver.guests[producer['guest']]['context'] == resolver.guests[app['guest']]['context'],
                    'component.database-binding')
            require('database_password' in app['secret_bindings'], 'component.secret-required')
            credential = copy.deepcopy(app['secret_bindings']['database_password'])
            require('application_database_password' not in producer['secret_bindings'], 'component.secret-conflict')
            producer['secret_bindings']['application_database_password'] = credential
            value = copy.deepcopy(app['properties']['database'])
            producer['settings']['application_database'] = dict(value, consumer=key,
                source_vmid=resolver.guests[app['guest']]['identity']['vmid'])
            clients = producer['settings']['client_access']
            require(all(row['source_address'] != link['source_address'] for row in clients), 'component.database-access')
            clients.append({'source_address': link['source_address'], 'database': value['name'],
                            'user': value['user'], 'method': 'scram-sha-256'})
            app['settings'] = dict(copy.deepcopy(app['properties']), database=dict(value,
                host=link['target']['address'], port=link['target']['port']))
            owned.add(key)
    require(owned == {key for key, app in resolver.apps.items() if app['adapter'] == 'renovate'},
            'component.database-binding')
