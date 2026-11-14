"""Mend CE source contracts with explicit fake component collaborators."""
import copy
from types import SimpleNamespace
import unittest

import component_renovate as m
import component_foundations
from component_errors import ComponentError


def properties():
    return {'database': {'name': 'updates', 'user': 'updates'},
            'repositories': ['example-owner/example-repo']}


def resolver():
    return SimpleNamespace(apps={
        'database': {'adapter': 'postgresql', 'guest': 'database',
            'properties': {'application_database': {'app': 'updates'}},
            'settings': {'client_access': []}, 'secret_bindings': {}},
        'updates': {'adapter': 'renovate', 'guest': 'worker', 'properties': properties(),
            'secret_bindings': {'database_password': {'type': 'environment', 'name': 'DB_PASSWORD'}},
            'resolved_connections': {'database': {'type': 'postgresql',
                'target': {'app': 'database', 'address': '198.18.31.10', 'port': 5432},
                'source_address': '198.18.31.18', 'readiness': 'start'}}}},
        guests={'database': {'context': 'lab', 'identity': {'vmid': 810}},
                'worker': {'context': 'lab', 'identity': {'vmid': 818}}})


class RenovateProperties(unittest.TestCase):
    def test_complete_partial_and_foundation_dispatch(self):
        m.validate(properties())
        m.validate({}, partial=True)
        component_foundations.validate('renovate', properties())
        component_foundations.validate('postgresql', {'application_database': {'app': 'updates'}})
        for value in ({'app': '../outside'}, {'app': 'updates', 'sql': 'anything'}):
            with self.assertRaises(ComponentError):
                component_foundations.validate('postgresql', {'application_database': value})

    def test_closed_database_names_and_exact_repository_allowlist(self):
        for field in ('name', 'user'):
            for value in (None, True, '', 'pg_admin', 'postgres', 'template0', 'template1',
                          'public', 'all', 'none', 'replication', 'UPPER', 'x;DROP', 'x' * 64):
                selected = properties(); selected['database'][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ComponentError):
                    m.validate(selected)
        for repos in (None, 'owner/repo', [], ['owner/*'], ['a/b', 'A/B'], ['a/b\n'],
                      ['a/' + 'x' * 101], ['a/b'] * 11, [1]):
            selected = properties(); selected['repositories'] = repos
            with self.subTest(repos=repos), self.assertRaises(ComponentError):
                m.validate(selected)
        for value in ({}, {'database': {}}, dict(properties(), environment={}),
                      dict(properties(), database={'name': 'updates', 'user': 'updates', 'sql': ''})):
            with self.assertRaises(ComponentError):
                m.validate(value)


class DatabaseBinding(unittest.TestCase):
    def test_one_credential_source_and_scoped_hba_without_new_network_or_admin(self):
        r = resolver(); original = copy.deepcopy(r.apps)
        m.bind(r)
        db, app = r.apps['database'], r.apps['updates']
        self.assertEqual(db['settings']['application_database'], {
            'name': 'updates', 'user': 'updates', 'consumer': 'updates', 'source_vmid': 818})
        self.assertEqual(db['settings']['client_access'], [{'source_address': '198.18.31.18',
            'database': 'updates', 'user': 'updates', 'method': 'scram-sha-256'}])
        self.assertEqual(db['secret_bindings']['application_database_password'],
                         app['secret_bindings']['database_password'])
        self.assertEqual(app['settings']['database'], {'name': 'updates', 'user': 'updates',
                         'host': '198.18.31.10', 'port': 5432})
        self.assertEqual(app['properties'], original['updates']['properties'])
        self.assertNotIn('database_administrators', db)
        m.bind(SimpleNamespace(apps={'plain': {'adapter': 'postgresql', 'properties': {}}}))

    def test_wrong_owner_connection_readiness_scope_or_secret_refuses(self):
        changes = [
            lambda r: r.apps['database']['properties'].clear(),
            lambda r: r.apps['database']['properties']['application_database'].update(app='missing'),
            lambda r: r.apps['updates'].update(adapter='authentik'),
            lambda r: r.apps['updates']['resolved_connections'].clear(),
            lambda r: r.apps['updates']['resolved_connections']['database'].update(type='mariadb'),
            lambda r: r.apps['updates']['resolved_connections']['database'].update(readiness='none'),
            lambda r: r.apps['updates']['resolved_connections']['database']['target'].update(app='other'),
            lambda r: r.apps['updates']['resolved_connections']['database']['target'].update(port=1),
            lambda r: r.guests['worker'].update(context='other'),
            lambda r: r.apps['updates']['secret_bindings'].clear(),
            lambda r: r.apps['database']['secret_bindings'].update(application_database_password={}),
            lambda r: r.apps['database']['settings']['client_access'].append({'source_address': '198.18.31.18'}),
            lambda r: r.apps.update(other=copy.deepcopy(r.apps['database'])),
        ]
        for change in changes:
            with self.subTest(case=changes.index(change)), self.assertRaises(ComponentError):
                r = resolver(); change(r); m.bind(r)
