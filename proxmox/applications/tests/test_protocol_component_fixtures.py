"""Mocked constructor units and real source-only protocol service comparisons."""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
F = Path(os.environ.get('HOMELAB_FRAMEWORK', HERE.parents[2])).resolve()
sys.path[:0] = [str(HERE), str(F/'proxmox/applications'), str(F/'blueprints')]
import protocol_component_fixtures as fixtures
import monitoring

BASELINE = json.loads((HERE/'protocol-compose-baseline.json').read_text())
CE_IMAGE = 'dbeaver/cloudbeaver:26.2.3@sha256:a537c60a7ca98d8d791c11c01172c1354e8dedfe222d04a54795ceeb32f12bbc'
GATEWAY_IMAGE = 'quay.io/oauth2-proxy/oauth2-proxy:v7.15.5@sha256:0d989b27d90d5e527fb2b045d864c4001c3104bdd763b3211b7e9ba2110380ea'


def selected():
    return {'oauth_name': 'Synthetic issuer', 'oauth_client_id': 'fixture-client',
            'oidc_issuer': 'https://sso.example.invalid/oidc/', 'user_claim': 'preferred_username'}


def value():
    return {'public_url': 'https://cloud.fixture.test:9443',
            'auth_headers': {'user': 'X-User', 'team': 'X-Team'}}


def cloud(authentication=None, settings=None):
    return fixtures.cloudbeaver_app(selected() if authentication is None else authentication,
        value() if settings is None else settings, image=CE_IMAGE, gateway_image=GATEWAY_IMAGE)


def protected_shape(path):
    """Hash every fixture instruction except the bounded construction replaced here.

    The exceptions below are only top-level statements in the three constructor
    functions. Protocol, Docker, cleanup, args and image declarations are retained.
    """
    tree = ast.parse(path.read_text())
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if path.name == 'cloudbeaver_gateway_fixture.py':
            if node.name == 'start_community':
                remaining = []
                for row in node.body:
                    text = ast.unparse(row)
                    if (isinstance(row, (ast.Import, ast.ImportFrom))
                            and any(name in text for name in ('render', 'test_cloudbeaver', 'protocol_component_fixtures'))):
                        continue
                    if isinstance(row, ast.Assign) and any(isinstance(target, ast.Name)
                            and target.id in ('cfg', 'app', 'rows', 'compose') for target in row.targets):
                        continue
                    if text.startswith(("cfg['foundation'] =", "cfg['services']", "cfg['cloudbeaver'].update")):
                        continue
                    remaining.append(row)
                node.body = remaining
                class OldNames(ast.NodeTransformer):
                    def visit_Subscript(self, item):
                        if (isinstance(item.value, ast.Name) and item.value.id == 'app'
                                and isinstance(item.slice, ast.Constant) and item.slice.value == 'settings'):
                            item.slice.value = 'cloudbeaver'
                        return self.generic_visit(item)
                    def visit_Name(self, item):
                        if item.id == 'app': item.id = 'cfg'
                        return item
                OldNames().visit(node)
            if node.name == 'combined_checks':
                class OldSettings(ast.NodeTransformer):
                    def visit_Subscript(self, item):
                        if (isinstance(item.value, ast.Name) and item.value.id == 'cfg'
                                and isinstance(item.slice, ast.Constant) and item.slice.value == 'settings'):
                            item.slice.value = 'cloudbeaver'
                        return self.generic_visit(item)
                OldSettings().visit(node)
        if path.name in ('bitwarden_runtime_fixture.py', 'monitoring_fixture.py') and node.name == 'main':
            class RemoveConstruction(ast.NodeTransformer):
                def visit_ImportFrom(self, row):
                    return None if row.module == 'test_monitoring' else row
                def visit_Assign(self, row):
                    if any(isinstance(target, ast.Name) and target.id in ('cfg', 'app') for target in row.targets):
                        return None
                    if (any(isinstance(target, ast.Name) and target.id == 'document' for target in row.targets)
                            and isinstance(row.value, ast.Call) and isinstance(row.value.func, ast.Attribute)
                            and row.value.func.attr in ('compose', 'document')):
                        return None
                    if ast.unparse(row).startswith("cfg['monitoring']['postgresql_host'] ="):
                        return None
                    return self.generic_visit(row)
                def visit_Expr(self, row):
                    text = ast.unparse(row)
                    if text.startswith(("(root / 'password').write_text(", "(root / 'password').chmod(", "(root / 'ca').write_text(")):
                        return None
                    return self.generic_visit(row)
            RemoveConstruction().visit(node)
    tree.body = [node for node in tree.body if not (isinstance(node, ast.Import)
                 and any(name.name in ('render', 'protocol_component_fixtures') for name in node.names))]
    # Python 3.13 omits empty lists by default; retain the recorded tree shape.
    options = {'show_empty': True} if sys.version_info >= (3, 13) else {}
    return hashlib.sha256(ast.dump(tree, include_attributes=False, **options).encode()).hexdigest()


class NoNative(unittest.TestCase):
    def setUp(self):
        for target in ('subprocess.Popen', 'socket.create_connection', 'socket.socket.connect'):
            patcher = mock.patch(target, side_effect=AssertionError('Source-only fixture controls'))
            patcher.start(); self.addCleanup(patcher.stop)


class ConstructorUnits(NoNative):
    def test_actual_composition_contract_and_original_budget(self):
        app = cloud(); sentinel = {'services': {'selected': {}}}
        with mock.patch.object(fixtures.component_runtime, 'compositions', return_value={app['project_name']: sentinel}) as call:
            self.assertIs(fixtures.document(app), sentinel)
        call.assert_called_once_with({'schema': fixtures.component_runtime.SCHEMA,
            'guest': {'timezone': 'Etc/UTC', 'memory_mib': 2048, 'os_reserve_mib': 256},
            'applications': {app['id']: app}})

    def test_cloud_dynamic_metadata_and_images_are_not_frozen_or_mutated(self):
        auth = selected(); auth.update(oauth_client_id='alternate-client', user_claim='email')
        auth['oidc_endpoints'] = {key: 'https://sso.example.invalid/'+path for key, path in (
            ('authorization_url', 'authorize'), ('token_url', 'token'),
            ('userinfo_url', 'userinfo'), ('jwks_url', 'jwks'))}
        auth['oidc_endpoints']['signing_algorithms'] = ['RS256']
        data = value(); data.update(heap_mib=768, server_name='Alternate', bind_address='198.18.99.12',
                                   auth_headers={'user': 'X-Alternate-User', 'team': 'X-Alternate-Team'},
                                   connections={'one': {'name': 'One', 'driver': 'postgresql', 'database': 'one',
                                                       'sslmode': 'require', 'host': '198.18.99.13', 'port': 5432}})
        before = copy.deepcopy((auth, data))
        app = fixtures.cloudbeaver_app(auth, data, image='test/ce@sha256:'+'2'*64,
                                      gateway_image='test/gateway@sha256:'+'3'*64)
        self.assertEqual(app['settings'], dict(data, recovery_admin='local-recovery',
            retained_pgadmin_image='dpage/pgadmin4@sha256:'+'a'*64))
        self.assertEqual(app['authentication_resolved'], dict(auth, version=1))
        self.assertEqual(app['listeners']['web']['publication_address'], data['bind_address'])
        self.assertEqual(app['software_selection']['images']['cloudbeaver']['image'], 'test/ce@sha256:'+'2'*64)
        self.assertEqual(app['software_selection']['images']['auth_gateway']['image'], 'test/gateway@sha256:'+'3'*64)
        self.assertEqual((auth, data), before)

    def test_cloud_supplied_secret_goes_only_to_current_pure_file_builder(self):
        app = cloud(); secret = b'synthetic-only-secret-material'*2
        with mock.patch.object(fixtures.component_proxy_files, 'files', return_value=['selected']) as call:
            self.assertEqual(fixtures.cloudbeaver_files(app, secret), ['selected'])
        call.assert_called_once_with(app, secrets={'client_secret': secret}, records={}, public_ca=None)

    def test_observed_bitwarden_image_and_fixed_original_database_are_explicit(self):
        app = fixtures.bitwarden_app('sha256:'+'4'*64, image='ghcr.io/bitwarden/lite:latest')
        self.assertEqual(app['settings']['settings']['image_id'], 'sha256:'+'4'*64)
        self.assertEqual(app['settings']['settings']['database_name'], 'bitwarden_fixture')
        self.assertEqual(app['settings']['settings']['database_server'], '198.18.32.24')
        self.assertEqual(app['containers']['bitwarden'], {'memory_mib': 1536, 'cpu_limit': 1, 'pids_limit': 256})

    def test_monitoring_database_and_both_selected_images_flow_to_owned_descriptor(self):
        images = {'zabbix_server': 'selected-server', 'zabbix_web': 'selected-web'}
        app = fixtures.zabbix_app(database_host='selected-database', images=images)
        self.assertEqual(app['settings']['database'], {'host': 'selected-database', 'name': 'zabbix', 'user': 'zabbix'})
        self.assertEqual(app['software_selection']['images'], {key: {'image': item} for key, item in images.items()})
        self.assertEqual(app['settings']['database_credential'], {'type': 'monitoring-owned', 'server': app['id']})


class ActualRendererControls(NoNative):
    def test_cloudbeaver_services_exactly_match_frozen_original_render(self):
        self.assertEqual(fixtures.document(cloud()), BASELINE['documents']['cloudbeaver'])

    def test_bitwarden_services_exactly_match_frozen_original_render(self):
        app = fixtures.bitwarden_app('sha256:'+'1'*64, image='ghcr.io/bitwarden/lite:latest')
        self.assertEqual(fixtures.document(app), BASELINE['documents']['bitwarden'])

    def test_monitoring_services_exactly_match_frozen_original_render(self):
        app = fixtures.zabbix_app(database_host='postgres', images=monitoring.VERSIONS)
        self.assertEqual(fixtures.document(app), BASELINE['documents']['zabbix'])

    def test_cloudbeaver_runtime_file_bytes_match_original_pure_builder(self):
        rows = fixtures.cloudbeaver_files(cloud(), b'fixture-secret-entropy-not-production'*2)
        self.assertEqual({row['path']: hashlib.sha256(row['content'].encode()).hexdigest() for row in rows},
                         BASELINE['cloudbeaver_file_hashes'])
        self.assertTrue(all(row['mode'] == '0400' and row['uid'] == row['gid'] for row in rows))

    def test_discovery_and_explicit_oidc_inputs_reach_generated_files(self):
        for explicit in (False, True):
            auth = selected(); auth.update(oauth_name='Alternate login', oauth_client_id='alternate-client', user_claim='email')
            if explicit:
                auth['oidc_endpoints'] = {key: 'https://sso.example.invalid/'+path for key, path in (
                    ('authorization_url', 'authorize'), ('token_url', 'token'),
                    ('userinfo_url', 'userinfo'), ('jwks_url', 'jwks'))}
                auth['oidc_endpoints']['signing_algorithms'] = ['RS256']
            data = value(); data.update(public_url='https://alternate.example.invalid:9444', heap_mib=768,
                                       server_name='Alternate name', auth_headers={'user': 'X-Custom-User', 'team': 'X-Custom-Team'})
            with self.subTest(explicit=explicit):
                app = cloud(auth, data)
                rows = {row['path']: row['content'] for row in fixtures.cloudbeaver_files(app, b'fixture-secret-entropy-not-production'*2)}
                provider = json.loads(rows['oauth2-alpha.json'])['providers'][0]
                self.assertEqual(provider['clientID'], 'alternate-client')
                self.assertEqual(provider['oidcConfig']['issuerURL'], auth['oidc_issuer'])
                self.assertEqual(provider['oidcConfig'].get('skipDiscovery', False), explicit)
                if explicit: self.assertEqual(provider['oidcConfig']['jwksURL'], auth['oidc_endpoints']['jwks_url'])
                self.assertIn('alternate.example.invalid:9444', rows['oauth2.cfg'])
                public = json.loads(rows['cloudbeaver-public.json'])
                self.assertEqual(public['auth_headers'], data['auth_headers'])
                self.assertEqual(public['server_name'], data['server_name'])
                self.assertIn('-Xmx768m', fixtures.document(app)['services']['cloudbeaver']['environment']['JAVA_OPTS'])

    def test_current_renderer_refusals_are_not_hidden_by_constructor(self):
        bad = cloud(); bad['settings']['heap_mib'] = 1536
        with self.assertRaises(ValueError): fixtures.document(bad)
        bad = fixtures.bitwarden_app('not-observed', image='ghcr.io/bitwarden/lite:latest')
        with self.assertRaises(ValueError): fixtures.document(bad)
        bad = fixtures.zabbix_app(database_host='postgres', images=dict(monitoring.VERSIONS, zabbix_web='foreign'))
        with self.assertRaises(ValueError): fixtures.document(bad)


class FixtureCallSiteControls(NoNative):
    def test_protocol_assertions_args_images_docker_limits_and_cleanup_are_unchanged(self):
        for name, expected in BASELINE['protected_fixture_shapes'].items():
            with self.subTest(fixture=name): self.assertEqual(protected_shape(HERE/name), expected)

    def test_cloud_callsite_passes_actual_selected_value_images_and_secret(self):
        tree = ast.parse((HERE/'cloudbeaver_gateway_fixture.py').read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'start_community')
        rows = [node for node in function.body if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id in ('app', 'rows', 'compose') for target in node.targets)]
        scope = {'component_fixtures': mock.Mock(), 'selected': object(), 'value': object(),
                 'CE_IMAGE': 'selected-ce', 'IMAGE': 'selected-gateway',
                 'provider': type('Provider', (), {'client_secret': 'synthetic-secret'})}
        scope['component_fixtures'].document.return_value = {'services': {'cloudbeaver': {}}}
        exec(compile(ast.fix_missing_locations(ast.Module(body=rows, type_ignores=[])), '<actual-cloud-constructor>', 'exec'), scope)
        scope['component_fixtures'].cloudbeaver_app.assert_called_once_with(scope['selected'], scope['value'],
            image='selected-ce', gateway_image='selected-gateway')
        scope['component_fixtures'].cloudbeaver_files.assert_called_once_with(scope['app'], b'synthetic-secret')
        scope['component_fixtures'].document.assert_called_once_with(scope['app'])

    def test_bitwarden_and_monitoring_callsites_use_current_component_constructors(self):
        for name, builder in [('bitwarden_runtime_fixture.py', 'bitwarden_app'), ('monitoring_fixture.py', 'zabbix_app')]:
            tree = ast.parse((HERE/name).read_text())
            rows = [node for node in ast.walk(next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                                               and node.name == 'main'))
                    if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
                       and target.id in ('app', 'document') for target in node.targets)
                    and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute)
                    and isinstance(node.value.func.value, ast.Name) and node.value.func.value.id == 'component_fixtures']
            rows.sort(key=lambda row: row.lineno)
            scope = {'component_fixtures': mock.Mock(), 'IMAGE': 'selected-image',
                     'image_id': 'selected-observation', 'monitoring': monitoring}
            exec(compile(ast.fix_missing_locations(ast.Module(body=rows, type_ignores=[])), '<actual-fixture-constructor>', 'exec'), scope)
            factory = getattr(scope['component_fixtures'], builder)
            if builder == 'bitwarden_app': factory.assert_called_once_with('selected-observation', image='selected-image')
            else: factory.assert_called_once_with(database_host='postgres', images=monitoring.VERSIONS)
            scope['component_fixtures'].document.assert_called_once_with(scope['app'])


if __name__ == '__main__':
    unittest.main()
