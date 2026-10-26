"""pgAdmin source contracts; these do not prove a real OAuth or DB login."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from test_render import render, image
from test_deploy import deploy, fixture as site_fixture


def fixture():
    service = image()
    service['environment'] = {
        'PGADMIN_DEFAULT_EMAIL': 'admin@example.invalid',
        'PGADMIN_DEFAULT_PASSWORD': 'synthetic-only-$bootstrap',
        'PGADMIN_CONFIG_AUTHENTICATION_SOURCES': "['oauth2']",
        'PGADMIN_CONFIG_OAUTH2_CONFIG': repr([{
            'OAUTH2_NAME': 'authentik', 'OAUTH2_DISPLAY_NAME': 'Existing SSO',
            'OAUTH2_CLIENT_ID': 'synthetic-client',
            'OAUTH2_CLIENT_SECRET': 'synthetic-$client-secret',
            'OAUTH2_SERVER_METADATA_URL': 'https://auth.example.invalid/application/o/pgadmin/.well-known/openid-configuration',
            'OAUTH2_SCOPE': 'openid email profile',
        }]),
        'PGADMIN_CONFIG_PROXY_X_HOST_COUNT': '1',
        'PGADMIN_CONFIG_PROXY_X_PROTO_COUNT': '1',
    }
    return {'kind': 'db-tools', 'guest_memory_mib': 1024,
            'pgadmin_bind_address': '198.18.30.32', 'services': {'pgadmin': service}}


class PgAdminTests(unittest.TestCase):
    def test_db_tools_contains_only_pgadmin_and_uses_the_restored_data(self):
        result = render.compose(fixture())
        self.assertEqual(result['name'], 'homelab-db-tools')
        self.assertEqual(set(result['services']), {'pgadmin'})
        service = result['services']['pgadmin']
        self.assertEqual(service['volumes'], [{'type': 'bind', 'source': '/srv/homelab/data/pgadmin',
            'target': '/var/lib/pgadmin', 'bind': {'create_host_path': False}}])
        self.assertNotIn('network_mode', service)
        self.assertEqual(service['ports'], ['198.18.30.32:80:80'])
        self.assertNotIn('labels', service)
        self.assertNotIn('depends_on', service)

    def test_preserves_the_existing_provider_and_proxy_settings_literally(self):
        cfg = fixture()
        before = copy.deepcopy(cfg)
        env = render.compose(cfg)['services']['pgadmin']['environment']
        self.assertEqual(cfg, before)
        for key, value in before['services']['pgadmin']['environment'].items():
            self.assertEqual(env[key], value.replace('$', '$$'))
        self.assertEqual(ast.literal_eval(env['PGADMIN_CONFIG_AUTHENTICATION_SOURCES']), ['oauth2'])

    def test_refuses_missing_or_additional_authentication_sources(self):
        for value in (None, "['internal']", "['oauth2', 'internal']", 'oauth2', '__import__("os")', []):
            with self.subTest(value=value):
                cfg = fixture(); env = cfg['services']['pgadmin']['environment']
                if value is None: env.pop('PGADMIN_CONFIG_AUTHENTICATION_SOURCES')
                else: env['PGADMIN_CONFIG_AUTHENTICATION_SOURCES'] = value
                with self.assertRaisesRegex(ValueError, 'OAuth2'):
                    render.compose(cfg)

    def test_provider_must_be_a_nonempty_literal_list_of_mappings(self):
        for value in (None, '', '[]', '{}', "['authentik']", '[{}]', '[1/0]'):
            with self.subTest(value=value):
                cfg = fixture(); env = cfg['services']['pgadmin']['environment']
                if value is None: env.pop('PGADMIN_CONFIG_OAUTH2_CONFIG')
                else: env['PGADMIN_CONFIG_OAUTH2_CONFIG'] = value
                with self.assertRaisesRegex(ValueError, 'OAuth2'):
                    render.compose(cfg)

    def test_existing_local_image_still_requires_a_verified_archive(self):
        cfg = fixture(); service = cfg['services']['pgadmin']
        service['image'] = 'sha256:' + '2' * 64
        with self.assertRaises(ValueError): render.compose(cfg)
        service.update(archive='/private/pgadmin.tar', archive_sha256='3' * 64)
        self.assertEqual(render.compose(cfg)['services']['pgadmin']['pull_policy'], 'never')

    def test_pgadmin_only_publishes_port_80_on_a_specific_backend_ipv4(self):
        for value in (None, '0.0.0.0', '127.0.0.1', '::', 'db.example.invalid', '198.18.30.32:8080'):
            with self.subTest(value=value):
                cfg = fixture(); cfg['pgadmin_bind_address'] = value
                with self.assertRaises(ValueError): render.compose(cfg)

    def test_authentication_and_listener_overrides_are_not_silently_accepted(self):
        for key, value in [('PGADMIN_LISTEN_PORT', '8080'), ('PGADMIN_ENABLE_TLS', '1'),
                           ('PGADMIN_CUSTOM_CONFIG_DISTRO_FILE', '/var/lib/pgadmin/config.py')]:
            with self.subTest(key=key):
                cfg = fixture(); cfg['services']['pgadmin']['environment'][key] = value
                with self.assertRaises(ValueError): render.compose(cfg)
        cfg = fixture()
        cfg['services']['pgadmin']['extra_mounts'] = [
            {'source': '/srv/homelab/data/config.py', 'target': '/pgadmin4/config_local.py'}]
        with self.assertRaises(ValueError): render.compose(cfg)

    def test_synthetic_example_is_renderable(self):
        path = Path(__file__).resolve().parents[1] / 'examples/db-tools.stack.example.json'
        result = render.compose(json.loads(path.read_text()))
        self.assertEqual(set(result['services']), {'pgadmin'})

    def test_preflight_binds_pgadmin_to_an_interface_on_the_selected_guest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); cfg = site_fixture(root)
            cfg['guest']['interfaces'].append({'ipv4': '198.18.30.32/24', 'mac': '02:00:00:00:61:32'})
            stack = root / 'stack.json'
            cfg['app'].update(kind='db-tools', stack_config=str(stack))
            for address in ('198.18.30.32', '198.18.30.99'):
                value = fixture(); value['pgadmin_bind_address'] = address
                stack.write_text(json.dumps(value))
                if address.endswith('.32'):
                    self.assertEqual(deploy.validate(cfg), 6101)
                else:
                    with self.assertRaisesRegex(ValueError, 'assigned to this guest'):
                        deploy.validate(cfg)

    def test_private_source_selector_reuses_the_db_tools_input_and_plan_guard(self):
        path = Path(__file__).resolve().parents[1] / 'templates/application_source.py'
        spec = importlib.util.spec_from_file_location('pgadmin_source', path)
        source = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(source)
        lock = {'repository': 'theaussiepom/homelab', 'revision': '1' * 40}
        selected = source.resolve(lock, 'db-tools', 'deploy', '2' * 64)
        self.assertEqual(selected['input_path'], '/var/lib/homelab-inputs/db-tools.json')
        with self.assertRaises(ValueError): source.resolve(lock, 'db-tools', 'deploy')


if __name__ == '__main__':
    unittest.main()
