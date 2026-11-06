"""Capture planners are pure: no service, database or archive is contacted."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backup_capture as capture
from test_backup_agent import fixture


def operational():
    value = fixture()['app']['backup']
    value['job'] = {'capture': {'pause': ['app'], 'database_lock': [], 'influx_tokens': {}}}
    value['applications']['app']['producer'] = {'type': 'compose', 'project': 'example',
        'file': '/opt/homelab-app/compose.yml', 'services': ['service']}
    return value


class CaptureTests(unittest.TestCase):
    def test_paths_are_derived_coalesced_and_explicit_exclusions_survive(self):
        value = operational(); app = value['applications']['app']
        app['runtime_files'].append('/opt/homelab-app/app.json')
        result = capture.normalize(value)
        self.assertEqual(sum(row['path'] == '/opt/homelab-app/app.json' for row in result['include']), 1)
        self.assertIn('/srv/example/logs', result['exclude'])
        self.assertIn('/srv/example/database', result['exclude'])
        self.assertFalse(any(row['path'] == '/srv/example/database' for row in result['include']))
        app['configuration']['nested'] = {'path': '/etc/ssh/known_hosts', 'kind': 'file'}
        self.assertFalse(any(row['path'].endswith('known_hosts') for row in capture.normalize(value)['include']))

    def test_duplicate_and_nested_conflicting_classifications_refuse(self):
        changes = [lambda a: a['storage']['config'].update(path='/etc/ssh', kind='file'),
                   lambda a: a['storage']['state'].update(path='/etc/ssh/state'),
                   lambda a: a['runtime_files'].append('/srv/example/logs/required'),
                   lambda a: a['runtime_files'].append('/srv/example/database'),
                   lambda a: a['runtime_files'].append('/etc/../outside'),
                   lambda a: a['runtime_files'].append('/'),
                   lambda a: a['runtime_files'].append('/bad\npath')]
        for change in changes:
            value = operational(); change(value['applications']['app'])
            with self.subTest(case=changes.index(change)), self.assertRaises(ValueError): capture.normalize(value)

    def test_only_explicit_owned_running_services_can_be_selected_for_pause(self):
        value = operational(); before = copy.deepcopy(value)
        result = capture.recipes(value)
        self.assertEqual(result['pause'][0]['services'], ['service'])
        self.assertEqual(value, before)
        for action in ('ps', 'stop', 'start', 'health'):
            argv = capture.compose(result['pause'][0], action)
            self.assertEqual(argv[:3], ['docker', 'compose', '--project-name'])
            self.assertEqual(argv[-1], 'service')
            if action == 'health':
                self.assertIn('--format', argv)
                self.assertIn('json', argv)
        with self.assertRaises(ValueError): capture.compose(result['pause'][0], 'down')
        changes = [lambda v: v['job']['capture'].update(pause=[]),
            lambda v: v['job']['capture'].update(pause=['foreign']),
            lambda v: v['applications']['app'].pop('producer'),
            lambda v: v['applications']['app']['producer'].update(services=[]),
            lambda v: v['applications']['app']['producer'].update(services=['service', 'service']),
            lambda v: v['applications']['app']['producer'].update(services=['--unsafe']),
            lambda v: v['applications']['app']['producer'].update(file='/etc/foreign')]
        for change in changes:
            value = operational(); change(value)
            with self.subTest(case=changes.index(change)), self.assertRaises(ValueError): capture.recipes(value)

    def test_native_database_commands_keep_engines_separate_and_passwords_out_of_argv(self):
        for kind in ('postgresql', 'mariadb', 'influxdb'):
            value = operational(); app = value['applications']['app']
            app.update(adapter=kind, producer={'type': kind, 'packages': ['postgresql-client-16=16.10-1'],
                                              'endpoint': 'http://192.0.2.60:8086'})
            if kind != 'influxdb': app['producer'].pop('endpoint')
            app['storage'].pop('state'); value['job']['capture']['pause'] = []
            value['job']['capture'].update(database_lock=['app'], influx_tokens={'app': 'private-reference'})
            recipe = capture.recipes(value)['databases'][0]
            argv, output = capture.database(recipe, Path('/private/stage'))
            self.assertNotIn('private-reference', ' '.join(argv))
            self.assertEqual(output, None if kind == 'influxdb' else 'cluster.sql')
        value['job']['capture']['influx_tokens'].clear()
        with self.assertRaises(ValueError): capture.recipes(value)
        value['applications']['app'].update(adapter='mariadb', producer={'type': 'mariadb', 'packages': []})
        value['job']['capture']['database_lock'] = []
        with self.assertRaises(ValueError): capture.recipes(value)
        value['applications']['app']['producer']['type'] = 'foreign'
        with self.assertRaises(ValueError): capture.recipes(value)
        pg = operational()
        pg['applications']['app'].update(adapter='postgresql', storage={}, producer={'type':'postgresql','packages':[]})
        pg['job']['capture']['pause'] = []
        with self.assertRaisesRegex(ValueError,'installed PostgreSQL'): capture.recipes(pg)
        for packages in ([], ['postgresql-client-bad=1'], ['postgresql-client-16=1', 'postgresql-client-17=1']):
            with self.subTest(packages=packages), self.assertRaises(ValueError):
                capture.database({'type': 'postgresql', 'packages': packages}, Path('/stage'))
        with self.assertRaises(ValueError): capture.database({'type': 'shell'}, Path('/stage'))


if __name__ == '__main__': unittest.main()
