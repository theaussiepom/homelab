"""Runtime alias units test endpoint metadata without revalidating applications."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import component_runtime as runtime


def app(*values):
    return {'resolved_connections': {str(index): {'hostname': host, 'target': {'address': address}}
                                     for index, (host, address) in enumerate(values)}}


class AliasTests(unittest.TestCase):
    def test_literal_aliases_preserve_bytes_and_casefold_conflicts_are_refused(self):
        self.assertEqual(runtime._aliases(app(('mariadb.db_hass', '198.18.31.21'))),
                         {'mariadb.db_hass': '198.18.31.21'})
        selected = app(('db.local', '198.18.31.21'), ('DB.local', '198.18.31.21'))
        self.assertEqual(runtime._aliases(selected), {'db.local': '198.18.31.21', 'DB.local': '198.18.31.21'})
        selected['resolved_connections']['1']['target']['address'] = '198.18.31.22'
        with self.assertRaisesRegex(ValueError, 'aliases conflict'):
            runtime._aliases(selected)
        self.assertEqual(runtime._aliases({'resolved_connections': {'unused': {'target': {}}}}), {})

    def test_alias_targets_and_hostnames_cannot_add_separators_or_extra_hosts(self):
        for host, address in [('db:3306', '198.18.31.21'), ('db/path', '198.18.31.21'),
                ('${ALIAS}', '198.18.31.21'), ('db\nname', '198.18.31.21'),
                ('db.local', '198.18.31.21/32'), ('db.local', 'host.invalid'),
                ('db..local', '198.18.31.21'), ('db-.local', '198.18.31.21')]:
            with self.subTest(host=host), self.assertRaises(ValueError):
                runtime._aliases(app((host, address)))

    def test_short_and_long_bind_serialization_refuses_interpolation(self):
        for source in ('/srv/app/${ROOT}', '/srv/app/$ROOT', '/srv/app/literal$$',
                       '/srv/app/with\nnewline', '/srv/app/with\\slash'):
            for mount in (source + ':/config:ro', {'type': 'bind', 'source': source,
                                                  'target': '/config', 'read_only': True}):
                with self.subTest(mount=type(mount).__name__), self.assertRaises(ValueError):
                    runtime._validate_mounts({'volumes': [mount]})
        runtime._validate_mounts({'volumes': ['/srv/app:/config:ro',
            {'type': 'bind', 'source': '/srv/app/settings', 'target': '/settings', 'read_only': True}]})


if __name__ == '__main__':
    unittest.main()
