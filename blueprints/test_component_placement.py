"""Guest execution composition units fake validated app/component contracts."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from component_plan import Resolver
from component_errors import ComponentError


def fixture():
    native = {'id': 'database', 'guest': 'host', 'adapter': 'mariadb', 'profile': 'db',
              'properties': {}, 'runtime': []}
    container = {'id': 'recursive', 'guest': 'host', 'adapter': 'unbound', 'profile': 'dns',
                 'properties': {}, 'runtime': []}
    return SimpleNamespace(
        library={'software': {'native': {'packages': ['mariadb-server=1:12.3.3+maria~deb13']},
                               'dns': {'images': {'unbound': 'dns'}}},
                 'runtime_profiles': {'native': {'native': {'memory_mib': 768}},
                    'dns': {'containers': {'unbound': {'memory_mib': 256, 'cpu_limit': 1, 'pids_limit': 128}}}},
                 'app_profiles': {'db': {'runtime': ['native'], 'software': ['native']},
                                  'dns': {'runtime': ['dns'], 'software': ['dns']}}},
        guests={'host': {'runtime': [], 'software': [], 'security': {},
                         'resources': {'os_reserve_mib': 256, 'memory_mib': 1280}}},
        apps={'database': native, 'recursive': container})


class PlacementTests(unittest.TestCase):
    def test_runtime_os_requirement_is_shared_headroom_not_per_app_free_space(self):
        resolver = fixture()
        resolver.library['runtime_profiles']['dns']['requirements'] = {'os_reserve_mib': 512}
        with self.assertRaisesRegex(ComponentError, 'memory-budget'):
            Resolver.execution_values(resolver, {'dns': {'image': 'synthetic'}})
        resolver.guests['host']['resources']['memory_mib'] = 1536
        Resolver.execution_values(resolver, {'dns': {'image': 'synthetic'}})
        self.assertEqual(resolver.guests['host']['effective_os_reserve_mib'], 512)
        resolver.guests['host']['resources']['memory_mib'] -= 1
        with self.assertRaisesRegex(ComponentError, 'memory-budget'):
            Resolver.execution_values(resolver, {'dns': {'image': 'synthetic'}})

    def test_native_and_container_reservations_compose_without_zero_cost(self):
        resolver = fixture()
        Resolver.execution_values(resolver, {'dns': {'image': 'synthetic'}})
        self.assertEqual(resolver.apps['database']['native_requirements'], {'memory_mib': 768})
        self.assertEqual(resolver.guests['host']['software_selection']['packages'],
                         ['mariadb-server=1:12.3.3+maria~deb13'])
        resolver.guests['host']['resources']['memory_mib'] -= 1
        with self.assertRaisesRegex(ComponentError, 'memory-budget'):
            Resolver.execution_values(resolver, {'dns': {'image': 'synthetic'}})
        resolver.apps.pop('recursive')
        resolver.guests['host']['resources']['memory_mib'] = 1023
        with self.assertRaisesRegex(ComponentError, 'memory-budget'):
            Resolver.execution_values(resolver, {})

    def test_missing_native_or_wrong_scope_reservations_refuse(self):
        mutations = [
            lambda r: r.library['runtime_profiles']['native'].pop('native'),
            lambda r: r.library['runtime_profiles']['dns'].update(native={'memory_mib': 64}),
            lambda r: r.guests['host']['runtime'].append('native'),
            lambda r: r.library['runtime_profiles'].update(other={'native': {'memory_mib': 767}}),
        ]
        for index, mutate in enumerate(mutations):
            resolver = fixture()
            mutate(resolver)
            if index == 3:
                resolver.apps['database']['runtime'] = ['other']
            with self.subTest(case=index), self.assertRaises(ComponentError):
                Resolver.execution_values(resolver, {'dns': {'image': 'synthetic'}})

    def test_app_image_roles_are_not_guest_global_namespaces(self):
        resolver = fixture()
        resolver.apps.pop('database')
        second = copy.deepcopy(resolver.apps['recursive'])
        second.update(id='recursive_b', profile='dns_b')
        resolver.apps['recursive_b'] = second
        resolver.library['app_profiles']['dns_b'] = {'runtime': ['dns'], 'software': ['dns_b']}
        resolver.library['software']['dns_b'] = {'images': {'unbound': 'other'}}
        Resolver.execution_values(resolver, {'dns': {'image': 'first'}, 'other': {'image': 'second'}})
        self.assertEqual(resolver.apps['recursive']['software_selection']['images']['unbound']['image'], 'first')
        self.assertEqual(resolver.apps['recursive_b']['software_selection']['images']['unbound']['image'], 'second')
        self.assertNotIn('images', resolver.guests['host']['software_selection'])


if __name__ == '__main__':
    unittest.main()
