"""Fixed CE runtime behavior, secret refusal and PostgreSQL lifecycle wiring."""
import copy
import json
from pathlib import Path
import unittest
import sys
sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parents[3]/'blueprints')]

import yaml
import renovate
import component_runtime as runtime
import component_checks
import component_prepare
import component_native


def values():
    return {'accept_terms': b'y', 'license_key': b'synthetic-license', 'github_app_id': b'1234',
            'github_app_key': b'base64://c3ludGhldGlj', 'database_password': b'synthetic-db-value'}


def app():
    return {'adapter': 'renovate', 'lifecycle': 'fresh', 'listeners': {},
        'identity': {'services': {'renovate': 'updates'}},
        'settings': {'database': {'name': 'updates', 'user': 'updates', 'host': '198.18.31.10', 'port': 5432},
                     'repositories': ['example/repo']},
        'health': {'ready': {'type': 'adapter', 'check': 'readiness'}},
        'containers': {'renovate': {'memory_mib': 2048, 'cpu_limit': 2, 'pids_limit': 512,
            'user': '12021:12021', 'cap_drop': ['ALL'], 'no_new_privileges': True, 'read_only': True}},
        'software_selection': {'images': {'renovate': {
            'image': 'ghcr.io/mend/renovate-ce:15.11.0@sha256:' + 'a' * 64}}},
        'storage_paths': {key: {'source': '/srv/renovate/' + key, 'target': target, 'read_only': False}
            for key, target in [('scratch', '/tmp'), ('cache', '/opt/containerbase')]}}


class RenovateRuntime(unittest.TestCase):
    def test_ce_server_runtime_with_no_public_ports_or_implicit_terms(self):
        selected = app(); original = copy.deepcopy(selected)
        service = runtime._renovate(selected, {'timezone': 'Etc/UTC'})['renovate']
        env = service['environment']
        self.assertEqual(selected, original)
        self.assertNotIn('ports', service)
        self.assertEqual(env['MEND_RNV_DATA_HANDLER_TYPE'], 'postgresql')
        self.assertEqual(env['PGHOST'], '198.18.31.10')
        self.assertNotIn('PGPASSWORD', env)
        self.assertNotIn('MEND_RNV_ACCEPT_TOS', env)
        self.assertEqual(json.loads(env['RENOVATE_CONFIG'])['force'],
                         {'automerge': False, 'platformAutomerge': False})
        self.assertEqual(service['security_opt'], ['no-new-privileges:true'])
        checks = component_checks.checks(selected, {}, compose_file='/opt/homelab-app/compose-updates.yml')
        self.assertEqual(checks[0]['argv'][:7], ['docker', 'compose', '-f',
            '/opt/homelab-app/compose-updates.yml', 'exec', '-T', 'updates'])
        self.assertEqual(checks[0]['argv'][-1], 'http://127.0.0.1:8080/health')

    def test_unsupported_listener_image_privileges_and_missing_storage_refuse(self):
        changes = [lambda a: a.update(lifecycle='import'),
            lambda a: a['listeners'].update(public={}),
            lambda a: a['containers']['renovate'].update(user='0'),
            lambda a: a['containers']['renovate'].update(cap_drop=[]),
            lambda a: a['containers']['renovate'].update(no_new_privileges=False),
            lambda a: a['containers']['renovate'].update(read_only=False),
            lambda a: a['containers']['renovate'].update(cap_add=['SYS_ADMIN']),
            lambda a: a['software_selection']['images']['renovate'].update(image='renovate/renovate:44@sha256:'+'a'*64),
            lambda a: a['storage_paths'].pop('scratch')]
        for change in changes:
            with self.subTest(case=changes.index(change)), self.assertRaises(ValueError):
                selected = app(); change(selected); runtime._renovate(selected, {'timezone': 'Etc/UTC'})

    def test_exact_scalar_roles_acceptance_and_private_overlay(self):
        env = renovate.secrets(values())
        self.assertEqual(env['MEND_RNV_GITHUB_APP_ID'], '1234')
        env['PGPASSWORD'] = 'synthetic-$-value'
        overlay = json.loads(component_prepare.overlay(app(), env))
        self.assertEqual(overlay['services']['updates']['environment']['PGPASSWORD'], 'synthetic-$$-value')
        for role, raw in [('accept_terms', b'n'), ('github_app_id', b'0'),
                          ('github_app_key', b'unencoded-pem'), ('license_key', b'\xff'),
                          ('license_key', b''), ('license_key', b'x'*65537),
                          ('database_password', b'line\nbreak'), ('database_password', 'not-bytes')]:
            with self.subTest(role=role, kind=type(raw).__name__), self.assertRaises(ValueError):
                renovate.secrets(dict(values(), **{role: raw}))
        for value in (None, {}, dict(values(), extra=b'x')):
            with self.assertRaises(ValueError): renovate.secrets(value)

    def test_native_hba_retains_existing_rules_and_scopes_new_database(self):
        row = {'source_address': '198.18.31.18', 'database': 'updates', 'user': 'updates', 'method': 'scram-sha-256'}
        self.assertEqual(component_native._clients([row]), 'host updates updates 198.18.31.18/32 scram-sha-256\n')
        for change in ({'database': 'all'}, {'user': 'pg_read_all_data'}, {'database': 'template0'},
                       {'user': 'postgres'}, {'user': 'x;drop'}, {'user': None}):
            with self.assertRaises(ValueError): component_native._clients([dict(row, **change)])

    def test_existing_database_names_and_producer_bindings_cannot_be_replaced(self):
        old = app(); renovate.preserve_storage(old, copy.deepcopy(old))
        for field in ('name','user','host','port'):
            changed = copy.deepcopy(old); changed['settings']['database'][field] = 'different'
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'Preserve the owned'):
                renovate.preserve_storage(old, changed)
        with self.assertRaises(ValueError): renovate.preserve_storage(old, dict(old, adapter='unbound'))
        before = {'adapter':'postgresql', 'settings':{}}
        owner = {'name':'updates','user':'updates','consumer':'renovate','source_vmid':818}
        after = {'adapter':'postgresql','settings':{'application_database':owner}}
        renovate.preserve_storage(before, after)
        renovate.preserve_storage(after, copy.deepcopy(after))
        for changed in (before, dict(after, adapter='unbound'),
                {'adapter':'postgresql','settings':{'application_database':dict(owner, name='replacement')}},
                {'adapter':'postgresql','settings':{'application_database':dict(owner, user='replacement')}},
                {'adapter':'postgresql','settings':{'application_database':dict(owner, consumer='other')}},
                {'adapter':'postgresql','settings':{'application_database':dict(owner, source_vmid=999)}}):
            with self.assertRaisesRegex(ValueError, 'Preserve the owned'):
                renovate.preserve_storage(after, changed)
        renovate.preserve_storage({'adapter':'unbound'}, {'adapter':'unbound'})

    def test_create_once_storage_tasks_reject_foreign_state_and_never_rotate_or_drop(self):
        root = Path(component_prepare.__file__).parent
        raw = (root/'ansible/tasks/application-database.yml').read_text()
        tasks = yaml.safe_load(raw)
        by_name = {row['name']: row for row in tasks}
        self.assertIn("'1:1' if application_database_receipt.stat.exists else '0:0'",
                      str(by_name['Refuse foreign or partially created application storage']))
        for name in ('Create the restricted application role once', 'Create the empty application database once',
                     'Set only the initial password using client-side SCRAM encryption',
                     'Restrict access to the new application database'):
            self.assertEqual(by_name[name]['when'], 'not application_database_receipt.stat.exists')
        self.assertIn('NOT r.rolsuper', raw)
        self.assertIn('pg_auth_members', raw)
        self.assertIn('aclexplode', raw)
        self.assertNotIn('DROP ', raw)
        self.assertNotIn('ALTER ROLE', raw)
        self.assertFalse(by_name['Record completed application database ownership']['ansible.builtin.copy']['force'])
        self.assertTrue(by_name['Verify authentication without resetting an existing credential']['no_log'])


from test_component_caller_paths import CallerCase
from unittest.mock import patch
from private_io import encoded, write_new
import component_ansible


class RenovatePreparation(CallerCase):
    def inputs(self, selected, data):
        for role, raw in data.items():
            path = self.root / (str(self.serial)+'-'+role)
            write_new(path, raw)
            selected['input_sources'][role] = {'type':'file','path':str(path)}
        self.save()

    def test_real_payload_keeps_only_worker_inputs_and_reuses_the_sealed_bytes(self):
        selected = app()
        for row in selected['storage_paths'].values(): row['kind'] = 'directory'
        cfg, selected = self.case('renovate', selected)
        self.inputs(selected, values())
        with patch.object(component_prepare.component_continuity, 'verify'):
            payload = component_prepare.prepare(cfg, 'selected', {}, attempt=self.attempt)
            before = {p.name:p.read_bytes() for p in payload.directory.iterdir()}
            repeated = component_prepare.prepare(cfg, 'selected', {}, attempt=self.attempt)
        self.assertEqual(before, {p.name:p.read_bytes() for p in repeated.directory.iterdir()})
        self.assertEqual(json.loads(before['environment.yml'])['services']['updates']['environment'], renovate.secrets(values()))
        actual = component_ansible.variables(cfg, 'selected', payload=payload)
        self.assertEqual(actual['component_environment_source'], str(payload.directory/'environment.yml'))
        self.assertNotIn('component_application_database', actual)

    def test_postgresql_receives_only_the_same_password_and_no_worker_credentials(self):
        cfg, selected = self.case('postgresql', {'settings':{'application_database':{
            'name':'updates','user':'updates','consumer':'renovate','source_vmid':818}}})
        self.inputs(selected, {'application_database_password': values()['database_password']})
        write_new(self.directory/'component-native.json', encoded({'selected':{
            'identity':{'user':'postgres'},'services':['postgresql']}}))
        with patch.object(component_prepare.component_continuity, 'verify'):
            payload = component_prepare.prepare(cfg, 'selected', {}, attempt=self.attempt)
        self.assertEqual((payload.directory/'application-database-password').read_bytes(), values()['database_password'])
        self.assertFalse((payload.directory/'environment.yml').exists())
        actual = component_ansible.variables(cfg, 'selected', payload=payload)
        self.assertEqual(actual['component_application_database']['password_file'], str(payload.directory/'application-database-password'))
        self.assertEqual(actual['component_application_database']['consumer'], 'renovate')
        cfg, selected = self.case('postgresql', {'settings':{'application_database':{'name':'updates'}}})
        with patch.object(component_prepare.component_continuity, 'verify'), self.assertRaisesRegex(ValueError, 'Supply the selected'):
            component_prepare.prepare(cfg, 'selected', {}, attempt=self.attempt)
        cfg, selected = self.case('postgresql', {'settings':{'application_database':{'name':'updates'}}})
        self.inputs(selected, {'application_database_password': b'line\nbreak'})
        with patch.object(component_prepare.component_continuity, 'verify'), self.assertRaisesRegex(ValueError, 'scalar'):
            component_prepare.prepare(cfg, 'selected', {}, attempt=self.attempt)
