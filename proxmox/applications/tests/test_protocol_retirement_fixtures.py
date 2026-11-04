"""Offline construction retirement controls; no protocol/native execution."""
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import yaml

HERE = Path(__file__).resolve().parent
F = Path(os.environ.get('HOMELAB_FRAMEWORK', HERE.parents[2])).resolve()
sys.path[:0] = [str(HERE), str(F/'proxmox/applications'), str(F/'blueprints')]
import protocol_component_fixtures as fixtures

BASELINE = json.loads((HERE/'protocol-retirement-baseline.json').read_text())


def literal(file, name):
    return next(ast.literal_eval(node.value) for node in ast.parse((HERE/file).read_text()).body
                if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == name
                                                       for target in node.targets))


def identity():
    return fixtures.authentik_app(image=literal('identity_fixture.py', 'AUTH'),
                                  redis_image=literal('identity_fixture.py', 'REDIS'))


def protected_shape(path):
    """Classify only constructor statements; preserve every protocol instruction."""
    tree = ast.parse(path.read_text())
    class ConstructorOnly(ast.NodeTransformer):
        def visit_Import(self, row):
            return None if any(item.name in ('render', 'protocol_component_fixtures') for item in row.names) else row
        def visit_ImportFrom(self, row):
            return None if row.module in ('test_render', 'test_foundation') else row
        def visit_Assign(self, row):
            if any(isinstance(target, ast.Name) and target.id in ('cfg', 'app', 'config', 'runtime_files', 'health')
                   for target in row.targets): return None
            if (any(isinstance(target, ast.Name) and target.id == 'document' for target in row.targets)
                    and isinstance(row.value, ast.Call)): return None
            text = ast.unparse(row)
            if text == "document['services']['redis']['command'] = ['redis-server', '--appendonly', 'yes']": return None
            return self.generic_visit(row)
        def visit_For(self, row):
            if len(row.body) == 1 and ast.unparse(row.body[0]).startswith("cfg['services'][name].update("):
                return None
            return self.generic_visit(row)
        def visit_Expr(self, row):
            text = ast.unparse(row)
            if text.startswith(("cfg['foundation'].update(", "cfg['services']['redis'].update(", 'sys.path.insert(')):
                return None
            return self.generic_visit(row)
    ConstructorOnly().visit(tree)
    # Python 3.13 omits empty lists by default; retain the recorded tree shape.
    options = {'show_empty': True} if sys.version_info >= (3, 13) else {}
    return hashlib.sha256(ast.dump(tree, include_attributes=False, **options).encode()).hexdigest()


class Offline(unittest.TestCase):
    def setUp(self):
        for target in ('subprocess.Popen', 'socket.create_connection', 'socket.socket.connect'):
            patcher = mock.patch(target, side_effect=AssertionError('Offline fixture construction only'))
            patcher.start(); self.addCleanup(patcher.stop)


class ConstructorUnits(Offline):
    def test_identity_explicit_images_resources_database_smtp_and_roles(self):
        app = identity()
        self.assertEqual(app['settings']['database'], {'host': 'postgres', 'name': 'authentik', 'user': 'authentik'})
        self.assertEqual(set(app['secret_bindings']), {'secret_key', 'postgresql_password', 'smtp_password'})
        self.assertEqual(app['properties']['smtp'], {'host': 'smtp.example.invalid', 'from': 'sso@example.invalid', 'use_tls': True})
        self.assertEqual([app['containers'][name]['memory_mib'] for name in ('server','worker','redis')], [768,768,128])
        self.assertEqual(app['software_selection']['images']['server']['image'], literal('identity_fixture.py','AUTH'))
        self.assertEqual(app['software_selection']['images']['redis']['image'], literal('identity_fixture.py','REDIS'))

    def test_identity_pure_input_boundary_supplies_only_the_original_synthetic_roles(self):
        app = identity()
        with mock.patch.object(fixtures.component_foundation_files,'files',return_value=[{'content':b'original'}]) as call:
            self.assertEqual(fixtures.authentik_files(app), [{'content':'original'}])
        call.assert_called_once_with(app, secrets={name: ('synthetic-$'+name).encode() for name in app['input_sources']})

    def test_dns_constructor_passes_explicit_two_apps_original_budget_and_records(self):
        records = {'broker.mqtt':'198.18.40.21'}; before = copy.deepcopy(records)
        with mock.patch.object(fixtures.component_runtime,'compositions', return_value={'homelab-dns':{'services':{}}}) as call:
            fixtures.dns_document(image=literal('dns_records_fixture.py','IMAGE'), records=records)
        cfg = call.call_args.args[0]
        self.assertEqual(cfg['guest'], {'timezone':'Etc/UTC','memory_mib':1024,'os_reserve_mib':256})
        self.assertEqual(set(cfg['applications']), {'pihole','unbound'})
        self.assertEqual(cfg['applications']['pihole']['settings']['dns_records'], records)
        self.assertEqual(records,before)
        self.assertEqual({row['memory_mib'] for app in cfg['applications'].values() for row in app['containers'].values()}, {256})

    def test_zigbee_constructor_does_not_open_the_serial_device(self):
        with mock.patch('builtins.open',side_effect=AssertionError('No device or config read')):
            app = fixtures.zigbee_app(image=literal('zigbee_health_fixture.py','IMAGE'))
        self.assertEqual(app['settings']['serial_device'], '/dev/serial/by-id/usb-fixture')
        self.assertEqual(app['settings']['frontend_port'],8099)
        self.assertEqual(app['software_selection']['images']['zigbee2mqtt']['image'], literal('zigbee_health_fixture.py','IMAGE'))


class ActualConstructionIntegration(Offline):
    def test_identity_only_adapter_difference_is_the_preserved_fixture_redis_command(self):
        document = fixtures.document(identity(),memory_mib=4096)
        self.assertEqual(document['services']['redis']['command'], ['--save','60','1','--loglevel','warning'])
        self.assertNotEqual(document, BASELINE['identity'])
        document['services']['redis']['command']=['redis-server','--appendonly','yes']
        self.assertEqual(document,BASELINE['identity'])

    def test_identity_all_three_file_rows_preserve_content_and_ownership(self):
        self.assertEqual(fixtures.authentik_files(identity()), BASELINE['identity_files'])

    def test_dns_full_document_and_unstarted_peer_are_exact(self):
        actual = fixtures.dns_document(image=literal('dns_records_fixture.py','IMAGE'), records={'broker.mqtt':'198.18.40.21'})
        self.assertEqual(actual,BASELINE['dns'])

    def test_zigbee_full_selected_service_and_original_health_argv_are_exact(self):
        actual=fixtures.document(fixtures.zigbee_app(image=literal('zigbee_health_fixture.py','IMAGE')))['services']['zigbee2mqtt']
        self.assertEqual(actual,BASELINE['zigbee_service_with_selected_image'])
        self.assertEqual(actual['healthcheck'],BASELINE['zigbee_health'])

    def test_structural_layout_preserves_all_application_families_and_replaces_pgadmin(self):
        cfg=fixtures.structural_runtime();docs=fixtures.component_runtime.compositions(cfg)
        self.assertEqual({app['adapter'] for app in cfg['applications'].values()},
            {'homeassistant','node_red','mqtt','pihole','unbound','authentik','traefik','zigbee2mqtt','cloudbeaver'})
        self.assertEqual(len(docs),6)
        self.assertEqual(sum(len(doc['services']) for doc in docs.values()),12)
        self.assertEqual(set(docs['homelab-automation']['services']),{'homeassistant','node_red','mqtt'})
        self.assertEqual(set(docs['homelab-db-tools']['services']),{'cloudbeaver','auth_gateway'})
        self.assertFalse(any('pgadmin' in document['services'] for document in docs.values()))
        self.assertEqual(len({app['project_name'] for app in cfg['applications'].values()}),6)

    def test_two_projects_can_own_the_same_service_key_without_merging(self):
        app=fixtures.dns_apps(image=literal('dns_records_fixture.py','IMAGE'),records={})['unbound']
        peer=copy.deepcopy(app)
        app.update(id='resolver-a',project_name='resolver-a');peer.update(id='resolver-b',project_name='resolver-b')
        peer['storage_paths']['config']['source']='/srv/homelab/data/resolver-b'
        cfg={'schema':fixtures.component_runtime.SCHEMA,
             'guest':{'timezone':'Etc/UTC','memory_mib':1024,'os_reserve_mib':256},
             'applications':{'resolver-a':app,'resolver-b':peer}}
        docs=fixtures.component_runtime.compositions(cfg)
        self.assertEqual(set(docs),{'resolver-a','resolver-b'})
        self.assertTrue(all(set(doc['services'])=={'unbound'} for doc in docs.values()))

    def test_real_renderer_refuses_collision_budget_invalid_image_and_missing_upstream(self):
        cfg=fixtures.structural_runtime();duplicate=copy.deepcopy(cfg['applications']['unbound'])
        duplicate['id']='duplicate';cfg['applications']['duplicate']=duplicate
        with self.assertRaises(ValueError):fixtures.component_runtime.compositions(cfg)
        cfg=fixtures.structural_runtime();cfg['guest']['memory_mib']=256
        with self.assertRaises(ValueError):fixtures.component_runtime.compositions(cfg)
        app=identity();app['software_selection']['images']['server']['image']='not-pinned'
        with self.assertRaises(ValueError):fixtures.document(app,memory_mib=4096)
        app=fixtures.dns_apps(image=literal('dns_records_fixture.py','IMAGE'),records={})['pihole'];app['resolved_connections']={}
        with self.assertRaises(ValueError):fixtures.document(app)


class FixtureWiringControls(Offline):
    def test_three_protocol_bodies_images_args_limits_and_cleanup_are_unchanged(self):
        for name, expected in BASELINE['protected_shapes'].items():
            with self.subTest(fixture=name):self.assertEqual(protected_shape(HERE/name),expected)

    def test_identity_actual_constructor_and_fixture_only_command_are_selected(self):
        tree=ast.parse((HERE/'identity_fixture.py').read_text())
        main=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='main')
        rows=[node for node in ast.walk(main) if isinstance(node,ast.Assign) and (
            any(isinstance(target,ast.Name) and target.id in ('app','document','runtime_files') for target in node.targets)
            or ast.unparse(node).startswith("document['services']['redis']['command'] ="))]
        rows.sort(key=lambda node:node.lineno)
        mocked=mock.Mock(); mocked.document.return_value={'services':{'redis':{}}}
        scope={'component_fixtures':mocked,'AUTH':'selected-auth','REDIS':'selected-redis'}
        exec(compile(ast.fix_missing_locations(ast.Module(body=rows,type_ignores=[])),'<actual-identity-construction>','exec'),scope)
        mocked.authentik_app.assert_called_once_with(image='selected-auth',redis_image='selected-redis')
        mocked.document.assert_called_once_with(scope['app'],memory_mib=4096)
        mocked.authentik_files.assert_called_once_with(scope['app'])
        self.assertEqual(scope['document']['services']['redis']['command'],['redis-server','--appendonly','yes'])

    def test_compose_cli_emits_only_actual_owned_project_documents(self):
        spec=importlib.util.spec_from_file_location('retained_structural_cli', HERE/'compose_fixture.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            module.main(directory)
            files=sorted(Path(directory).iterdir())
            self.assertEqual(len(files),6)
            self.assertEqual({file.name for file in files},{project+'.json' for project in fixtures.structural_documents()})
            self.assertEqual({file.stem:json.loads(file.read_text()) for file in files},fixtures.structural_documents())

    def test_ci_checks_emitted_projects_and_only_supported_retained_profiles(self):
        path=HERE/'ci.yml'
        if not path.exists():path=F/'.github/workflows/ci.yml'
        text=path.read_text()
        jobs=yaml.safe_load(text)['jobs']
        structural=[step['run'] for step in jobs['applications']['steps']
                    if 'proxmox/applications/tests/compose_fixture.py' in step.get('run','')]
        self.assertEqual(len(structural),1)
        self.assertIn('for composition in "$RUNNER_TEMP/app-compose/"*.json; do',structural[0])
        self.assertIn('docker compose -f "$composition" config --quiet',structural[0])
        retained='\n'.join(step.get('run','') for step in jobs['retained-runtimes']['steps'])
        image=literal('pegaprox_runtime_fixture.py','IMAGE')
        self.assertRegex(image,r'^ghcr\.io/pegaprox/pegaprox@sha256:[0-9a-f]{64}$')
        self.assertIn('docker pull --platform linux/amd64 '+image,retained)
        self.assertIn('python3 proxmox/applications/tests/pegaprox_runtime_fixture.py',retained)
        self.assertNotIn('dpage/pgadmin4',retained)
        self.assertNotIn('pgadmin_runtime_fixture.py',text)


if __name__=='__main__':unittest.main()
