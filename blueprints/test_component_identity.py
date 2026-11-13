"""Runtime identity component tests use conforming app metadata fakes."""
import copy
from types import SimpleNamespace
import unittest

import component_identity as identity
from component_errors import ComponentError


def app(name, lifecycle='fresh'):
    return {'id': name, 'guest': 'guest', 'adapter': 'authentik', 'lifecycle': lifecycle,
            'identity': {}, 'secret_bindings': {'secret_key': {}, 'postgresql_password': {}}}


class RuntimeIdentityTests(unittest.TestCase):
    def test_fixed_sidecars_refuse_same_guest_instances_and_allow_separate_guests(self):
        for adapter in ('pihole','zigbee2mqtt'):
            first=dict(app('first'),adapter=adapter)
            second=dict(app('second'),adapter=adapter)
            resolver=SimpleNamespace(apps={'first':first,'second':second})
            with self.subTest(adapter=adapter),self.assertRaisesRegex(ComponentError,'sidecar-file-conflict'):
                identity.bind(resolver)
            second['guest']='another_guest'
            identity.bind(resolver)
            self.assertEqual(first['sidecar_files'],identity.SIDECAR_FILES[adapter])
            self.assertEqual(second['sidecar_files'],identity.SIDECAR_FILES[adapter])

    def test_custody_roots_are_explicit_for_retained_and_independent_for_fresh_apps(self):
        def proxy(name,lifecycle='fresh',directory=None):
            selected=app(name,lifecycle);selected['adapter']='cloudbeaver';selected['settings']={}
            if lifecycle=='retained':selected['identity']['runtime_directory']=identity.ROOT
            if directory is not None:selected['identity']['custody_directory']=directory
            return selected
        root=identity.CUSTODY_ROOTS['cloudbeaver']
        resolver=SimpleNamespace(apps={'first':proxy('first'),'second':proxy('second')})
        identity.bind(resolver)
        self.assertEqual(resolver.apps['first']['identity']['custody_directory'],root+'/first')
        self.assertEqual(resolver.apps['second']['identity']['custody_directory'],root+'/second')
        resolver=SimpleNamespace(apps={'old':proxy('old','retained',root),'new':proxy('new')})
        identity.bind(resolver) # Each helper touches only its fixed direct leaves.
        self.assertEqual(resolver.apps['new']['identity']['custody_directory'],root+'/new')
        resolver.apps['new']['identity']['custody_directory']=root
        with self.assertRaisesRegex(ComponentError,'custody-directory-conflict'):identity.bind(resolver)
        for path in ('/etc',root+'/../foreign',root+'/${ENV}',root+'/bad\\path',
                     '/var/lib/homelab-mqtt-explorer',None):
            selected=proxy('old','retained')
            if path is not None:selected['identity']['custody_directory']=path
            with self.subTest(path=path),self.assertRaisesRegex(ComponentError,'custody-directory'):
                identity.bind(SimpleNamespace(apps={'old':selected}))

    def test_fresh_defaults_repeat_stably_and_labels_do_not_own_paths(self):
        resolver = SimpleNamespace(apps={'alpha': app('alpha'), 'beta': app('beta')})
        identity.bind(resolver)
        original = copy.deepcopy(resolver.apps)
        self.assertEqual(resolver.apps['alpha']['identity']['runtime_directory'], identity.ROOT + '/alpha')
        self.assertNotEqual(resolver.apps['alpha']['runtime_files']['directory'],
                            resolver.apps['beta']['runtime_files']['directory'])
        resolver.apps['alpha']['display_name'] = 'A different display label'
        identity.bind(resolver)
        self.assertEqual(resolver.apps['alpha']['runtime_files'], original['alpha']['runtime_files'])

    def test_retained_shared_directory_is_explicit_and_leaf_ownership_is_exclusive(self):
        resolver = SimpleNamespace(apps={'alpha': app('alpha', 'retained')})
        with self.assertRaisesRegex(ComponentError, 'runtime-directory-required'):
            identity.bind(resolver)
        resolver.apps['alpha']['identity']['runtime_directory'] = identity.ROOT
        identity.bind(resolver)
        self.assertEqual(resolver.apps['alpha']['runtime_files']['directory'], identity.ROOT)
        resolver.apps['beta'] = app('beta', 'retained')
        resolver.apps['beta']['identity']['runtime_directory'] = identity.ROOT
        with self.assertRaisesRegex(ComponentError, 'runtime-file-conflict'):
            identity.bind(resolver)
        resolver.apps['beta']['guest'] = 'another_guest'
        identity.bind(resolver)

    def test_path_component_refusals_do_not_echo_values(self):
        for value in ('/opt', '/opt/homelab-app', '/opt/homelab-app/runtime/',
                      '/opt/homelab-app/runtime/../private', '/opt/homelab-app/runtime/a//b',
                      '/opt/homelab-app/runtime/a.b', '/opt/homelab-app/runtime-other',
                      'relative', None, '/PRIVATE_SENTINEL'):
            with self.subTest(case=value), self.assertRaises(ComponentError) as caught:
                identity.directory(value)
            self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))

    def test_directory_visibility_refuses_peer_inputs_even_with_distinct_filenames(self):
        first = {'app': 'alpha', 'guest': 'guest', 'directory': identity.ROOT,
                 'files': ['alpha-secret'], 'directory_mounts': []}
        second = {'app': 'beta', 'guest': 'guest', 'directory': identity.ROOT,
                  'files': ['beta-secret'], 'directory_mounts': []}
        identity.claims([first, second])
        first['directory_mounts'] = [identity.ROOT]
        with self.assertRaisesRegex(ComponentError, 'runtime-visibility'):
            identity.claims([first, second])
        second['directory'] = identity.ROOT + '/beta'
        with self.assertRaisesRegex(ComponentError, 'runtime-visibility'):
            identity.claims([first, second])
        first['directory'] = identity.ROOT + '/alpha'
        first['directory_mounts'] = [identity.ROOT + '/alpha']
        identity.claims([first, second])
        second['app'] = 'alpha'
        first['directory_mounts'] = [identity.ROOT]
        identity.claims([first, second])

    def test_unsupported_identity_and_invalid_leaf_refuse(self):
        resolver = SimpleNamespace(apps={'alpha': dict(app('alpha'), adapter='unbound')})
        identity.bind(resolver)
        resolver.apps['alpha']['identity']['runtime_directory'] = identity.ROOT
        with self.assertRaisesRegex(ComponentError, 'runtime-directory-unused'):
            identity.bind(resolver)
        for leaf in ('../secret', '/absolute', '.', '..'):
            with self.subTest(leaf=leaf), self.assertRaisesRegex(ComponentError, 'runtime-file'):
                identity.claims([{'app': 'alpha', 'guest': 'guest', 'directory': identity.ROOT,
                                  'files': [leaf]}])


if __name__ == '__main__':
    unittest.main()
