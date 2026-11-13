"""Storage component unit contracts; no app/guest/compiler execution here."""
import unittest
from component_errors import ComponentError
import component_types as types


class StorageComponentTests(unittest.TestCase):
    def test_volume_success_preserves_ownerless_provider_fields(self):
        value = {'storage': 'pool', 'slot': 0, 'path': '/srv/app', 'size_gib': 4}
        types.volume(value)
        self.assertEqual(set(value), {'storage', 'slot', 'path', 'size_gib'})
        types.root_path({'path': '/srv/root-owned-data'})

    def test_control_paths_and_ancestors_cannot_become_app_mounts(self):
        for path in ('/', '/etc', '/etc/ssh', '/proc', '/var', '/var/lib', '/run/docker.sock',
                     '/usr', '/usr/local', '/srv/app/../control', 'relative', '/srv/app/'):
            with self.subTest(path=path), self.assertRaises(ComponentError):
                types.volume({'storage': 'pool', 'slot': 0, 'path': path, 'size_gib': 4})
        for prefix in ('/etc','/opt/homelab-app','/var/lib/homelab-managed-credentials'):
            for path in (prefix,'/'+prefix,'/'+prefix+'/child'):
                with self.subTest(path=path),self.assertRaises(ComponentError):types.root_path({'path':path})
        types.root_path({'path':'/srv/example/apps'})
        self.assertEqual(types.path('definitions/profile.yaml',relative=True),'definitions/profile.yaml')

    def test_volume_types_ranges_unknown_fields_and_invented_owners_refuse(self):
        base = {'storage': 'pool', 'slot': 0, 'path': '/srv/app', 'size_gib': 4}
        for field, value in (('slot', True), ('slot', -1), ('size_gib', False), ('size_gib', 0),
                             ('storage', '../pool'), ('owner', '1000:1000'), ('retained', True)):
            with self.subTest(field=field, value=value), self.assertRaises(ComponentError):
                types.volume(dict(base, **{field: value}))

    def test_storage_batch_refuses_equal_nested_and_rootfs_provider_shadowing(self):
        first = {'storage': 'pool', 'slot': 0, 'path': '/srv/app', 'size_gib': 4}
        second = dict(first, slot=1, path='/srv/other')
        types.storage_layout({'first': first, 'second': second}, {})
        for path in ('/srv/app', '/srv/app/nested', '/srv'):
            with self.subTest(path=path), self.assertRaises(ComponentError):
                types.storage_layout({'first': first, 'second': dict(second, path=path)}, {})
        with self.assertRaises(ComponentError):
            types.storage_layout({'first': first}, {'root': {'path': '/srv/app/nested'}})
        with self.assertRaises(ComponentError):
            types.storage_layout({'first': first, 'second': dict(second, slot=0)}, {})

    def test_root_paths_and_subpaths_reject_compose_interpolation_and_control_syntax(self):
        for value in ('${COMPONENT_LITERAL_ROOT}', '$UNSET', 'literal$$value', 'part:other',
                      'part\\other', 'part\nother', 'part\tother', 'part\x7fother'):
            with self.subTest(value=value):
                with self.assertRaises(ComponentError):
                    types.root_path({'path': '/srv/example/' + value})
                with self.assertRaises(ComponentError):
                    types.path(value, relative=True)
        self.assertEqual(types.path('normal/subdir', relative=True), 'normal/subdir')

    def test_fresh_directory_initializer_is_profile_owned_and_closed(self):
        base={'target':'/config','read_only':False,'required':True,'kind':'directory',
              'initialize':{'type':'directory','uid':0,'gid':0,'mode':'0700'}}
        types.storage_role(base)
        types.storage_role(dict(base,initialize=dict(base['initialize'],uid=1000,gid=1000)))
        for key,value in (('uid',True),('gid',-1),('uid',65536),('type','command'),
                          ('mode','0777'),('command','PRIVATE_SENTINEL')):
            selected=dict(base,initialize=dict(base['initialize'],**{key:value}))
            with self.subTest(key=key),self.assertRaises(ComponentError):types.storage_role(selected)
        for key,value in (('kind','file'),('read_only',True)):
            with self.subTest(key=key),self.assertRaises(ComponentError):types.storage_role(dict(base,**{key:value}))


if __name__ == '__main__':
    unittest.main()
