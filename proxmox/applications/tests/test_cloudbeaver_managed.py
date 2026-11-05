"""Native filesystem custody, with only numeric ownership and Docker boundaries mocked."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

CODE = Path(os.environ.get('CLOUDBEAVER_RUNTIME', Path(__file__).resolve().parents[1] / 'cloudbeaver-runtime.py'))
spec = importlib.util.spec_from_file_location('cloudbeaver_managed_fixture', CODE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ManagedFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.workspace = self.root / 'workspace'
        self.custody = self.root / 'custody'
        self.directory = self.workspace / 'GlobalConfiguration/.dbeaver'
        self.directory.mkdir(parents=True)
        self.custody.mkdir(mode=0o700)
        self.runtime = self.root / 'runtime.json'
        self.native = self.directory / 'data-sources-homelab-administrators.json'
        self.receipt = self.custody / 'managed-connections.json'
        self.hold = self.custody / 'MANAGED-CONNECTIONS-HOLD.json'
        self.permissions = self.directory / 'data-sources-permissions.json'
        self.owners = {}
        self.real_lstat, self.real_stat, self.real_fstat, self.real_open = Path.lstat, os.stat, os.fstat, os.open
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for key, value in [('WORKSPACE', self.workspace), ('CUSTODY', self.custody), ('MANAGED', self.runtime)]:
            self.stack.enter_context(patch.object(m, key, value))
        self.stack.enter_context(patch.object(m,'RUNTIME',self.root))
        self.stack.enter_context(patch.object(Path, 'lstat', lambda path: self.metadata(self.real_lstat(path))))
        self.stack.enter_context(patch.object(m.os, 'stat', lambda *a, **kw: self.metadata(self.real_stat(*a, **kw))))
        self.stack.enter_context(patch.object(m.os, 'fstat', lambda fd: self.metadata(self.real_fstat(fd))))
        self.stack.enter_context(patch.object(m.os, 'open', self.open_file))
        self.stack.enter_context(patch.object(m.os, 'chown', lambda path, uid, gid: self.set_owner(path, uid, gid)))
        self.stack.enter_context(patch.object(m.os, 'fchown', lambda fd, uid, gid: self.set_owner_fd(fd, uid, gid)))
        self.stack.enter_context(patch.object(m.os, 'geteuid', lambda: 0))
        def no_server(args, **kwargs):
            if args[0] == 'ps': return ''
            raise AssertionError('No native Docker in custody fixtures')
        self.docker = self.stack.enter_context(patch.object(m, 'docker', Mock(side_effect=no_server)))
        for path in [self.workspace, self.directory.parent, self.directory]:
            path.chmod(0o700)
            self.set_owner(path, 8978, 8978)
        self.owner = {'node': 'fixture', 'vmid': 12002, 'hostname': 'database-ui'}
        self.write(self.custody / 'workspace.json', self.owner, 0)
        self.grants = {'metadata': ['user'], 'custom': ['existing-team']}
        self.write(self.permissions, self.grants, 8978, 0o640)
        self.metadata_path = self.directory / 'data-sources.json'
        self.custom_path = self.directory / 'data-sources-custom.json'
        self.write(self.metadata_path, {'connections': {'metadata': {'name': 'Existing metadata'}}}, 8978)
        self.write(self.custom_path, {'connections': {'custom': {'name': 'Existing custom'}}}, 8978)
        self.original_metadata = self.metadata_path.read_bytes()
        self.original_custom = self.custom_path.read_bytes()
        self.passwords = {name: secrets.token_hex(24) for name in ('postgresql-admin', 'mariadb-admin')}
        self.context_config = {'workspace':str(self.workspace), 'project':'homelab-db-tools'}
        self.config = {**self.context_config, 'cloudbeaver_image': 'fixture@sha256:'+'1'*64, 'managed_connections': {name: {
            'owner': dict(self.owner, engine=engine, source_address=source), 'driver': engine,
            'host': host, 'username': 'fixture_admin',
        } for name, engine, source, host in [
            ('postgresql-admin', 'postgresql', '198.18.31.32', '198.18.31.23'),
            ('mariadb-admin', 'mariadb', '198.18.32.32', '198.18.32.24'),
        ]}}
        self.jar=self.root/'mariadb-java-client-3.5.11.jar'
        self.jar.write_bytes(b'bounded synthetic driver fixture');self.jar.chmod(0o400);self.set_owner(self.jar,8978,8978)
        self.config['mariadb_jdbc']={'version':'3.5.11','sha256':hashlib.sha256(self.jar.read_bytes()).hexdigest(),
            'image_filename':'mariadb-java-client-3.5.10.jar','source':str(self.jar),
            'target':'/opt/cloudbeaver/drivers/mariadb/mariadb-java-client-3.5.10.jar',
            'url':'https://repo.maven.apache.org/maven2/org/mariadb/jdbc/mariadb-java-client/3.5.11/mariadb-java-client-3.5.11.jar'}
        self.document = {'folders': {}, 'connections': {name: {
            'configuration': {'auth-properties': {'userName': 'fixture_admin', 'userPassword': self.passwords[name]}},
            'save-password': True,
        } for name in self.config['managed_connections']}}
        self.write(self.runtime, self.document, 0)
        self.config['managed_sha256'] = hashlib.sha256(self.runtime.read_bytes()).hexdigest()

    def metadata(self, row):
        fields = [name for name in dir(row) if name.startswith('st_')]
        value = {name: getattr(row, name) for name in fields}
        value['st_uid'], value['st_gid'] = self.owners.get((row.st_dev, row.st_ino), (0, 0))
        return SimpleNamespace(**value)

    def set_owner(self, path, uid, gid):
        row = self.real_lstat(path)
        self.owners[(row.st_dev, row.st_ino)] = (uid, gid)

    def set_owner_fd(self, fd, uid, gid):
        row = self.real_fstat(fd)
        self.owners[(row.st_dev, row.st_ino)] = (uid, gid)

    def open_file(self, path, flags, *args, **kwargs):
        fd = self.real_open(path, flags, *args, **kwargs)
        if flags & os.O_CREAT and flags & os.O_EXCL:
            # A newly created inode belongs to the simulated root process,
            # even if Linux recycled an inode previously owned by the app.
            self.set_owner_fd(fd, 0, 0)
        return fd

    def write(self, path, value, uid, mode=0o600):
        path.write_text(json.dumps(value, sort_keys=True) + '\n')
        path.chmod(mode)
        self.set_owner(path, uid, uid)

    def unchanged_other_data(self):
        self.assertEqual(self.metadata_path.read_bytes(), self.original_metadata)
        self.assertEqual(self.custom_path.read_bytes(), self.original_custom)

    def test_first_seed_preserves_metadata_custom_grants_and_private_modes(self):
        before = self.runtime.read_bytes()
        self.assertEqual(m.managed(self.config), {'managed_connections': 'verified', 'private_native_file': True})
        self.assertEqual(self.native.read_bytes(), before)
        self.assertEqual(stat.S_IMODE(self.native.lstat().st_mode), 0o600)
        self.assertEqual((self.native.lstat().st_uid, self.native.lstat().st_gid), (8978, 8978))
        grants = json.loads(self.permissions.read_bytes())
        self.assertEqual(grants, dict(self.grants, **{key: ['user'] for key in self.config['managed_connections']}))
        self.assertEqual(stat.S_IMODE(self.permissions.lstat().st_mode), 0o640)
        self.assertFalse(self.hold.exists())
        self.assertEqual(json.loads(self.receipt.read_bytes())['sha256'], self.config['managed_sha256'])
        self.unchanged_other_data()
        self.assertEqual(len(self.docker.call_args_list), 1)
        self.assertEqual(self.docker.call_args.args[0][0], 'ps')

    def test_new_private_receipt_does_not_inherit_recycled_inode_ownership(self):
        real_open = self.real_open
        def recycled(path, flags, *args, **kwargs):
            fd = real_open(path, flags, *args, **kwargs)
            if flags & os.O_CREAT and flags & os.O_EXCL:
                self.set_owner_fd(fd, 8978, 8978)
            return fd
        self.real_open = recycled
        path = self.custody / 'new-receipt.json'
        m.create(path, {'owned': True})
        self.assertEqual(m.private(path), {'owned': True})
        self.assertEqual(path.lstat().st_uid, 0)

    def server(self):
        return {'Id': 'a'*64, 'Config': {'Image': self.config['cloudbeaver_image'], 'Labels': {
            'com.docker.compose.project': 'homelab-db-tools', 'com.docker.compose.service': 'cloudbeaver'}},
            'Mounts': [{'Type': 'bind', 'Source': str(self.workspace), 'Destination': '/opt/cloudbeaver/workspace', 'RW': True}],
            'State': {'Running': True}}

    def test_first_seed_stops_only_owned_server_and_preserves_its_final_flush(self):
        row = self.server();calls = []
        def boundary(args, **kwargs):
            calls.append(args)
            if args[0] == 'ps': return row['Id']
            if args[0] == 'inspect': return json.dumps([row])
            self.assertEqual(args, ['stop', '--time', '30', row['Id']])
            self.assertTrue(self.hold.is_file())
            self.assertFalse(self.native.exists())
            self.write(self.permissions, dict(self.grants, flushed=['retained-team']), 8978, 0o640)
            row['State']['Running'] = False
            return row['Id']
        with patch.object(m, 'docker', side_effect=boundary): m.managed(self.config)
        self.assertEqual([value[0] for value in calls], ['ps','inspect','stop','inspect'])
        self.assertEqual(json.loads(self.permissions.read_bytes())['flushed'], ['retained-team'])
        with patch.object(m, 'docker', side_effect=AssertionError('Repeat must not stop')):
            m.managed(self.config, seed=False)
        self.unchanged_other_data()

    def test_foreign_or_shadowed_server_stays_held_and_is_not_stopped(self):
        for mutate in (lambda r:r['Config'].update(Image='foreign'),
                       lambda r:r['Config']['Labels'].update({'com.docker.compose.project':'foreign'}),
                       lambda r:r['Mounts'].append(dict(r['Mounts'][0],Destination='/opt/cloudbeaver/workspace/GlobalConfiguration'))):
            row=self.server();mutate(row)
            with patch.object(m, 'docker', side_effect=[row['Id'],json.dumps([row])]) as boundary:
                with self.assertRaises(ValueError):m.managed(self.config)
            self.assertEqual(boundary.call_count, 2)
            self.assertTrue(self.hold.exists());self.assertFalse(self.native.exists())
            self.hold.unlink()

    def test_stopped_server_is_not_stopped_again_and_failed_stop_refuses_seed(self):
        row=self.server();row['State']['Running']=False
        with patch.object(m,'docker',side_effect=[row['Id'],json.dumps([row])]) as boundary:
            m.managed_writer(self.config)
        self.assertEqual(boundary.call_count,2)
        row['State']['Running']=True
        with patch.object(m,'docker',side_effect=[row['Id'],json.dumps([row]),'',json.dumps([row])]):
            with self.assertRaises(ValueError):m.managed(self.config)
        self.assertTrue(self.hold.exists());self.assertFalse(self.native.exists())

    def test_post_flush_connection_collision_refuses_instead_of_overwriting(self):
        def flush(config):
            self.write(self.custom_path, {'connections':{'postgresql-admin':{'name':'Flushed existing connection'}}},8978)
        with patch.object(m,'managed_writer',side_effect=flush):
            with self.assertRaises(ValueError):m.managed(self.config)
        self.assertTrue(self.hold.exists());self.assertFalse(self.native.exists())

    def test_repeat_verifies_without_rewrite_and_allows_unrelated_extra_permissions(self):
        m.managed(self.config)
        grants = json.loads(self.permissions.read_bytes());grants['later-custom'] = ['another-team']
        self.write(self.permissions, grants, 8978, 0o640)
        before = {path: (self.real_lstat(path).st_ino, path.read_bytes()) for path in (self.native, self.receipt, self.permissions)}
        with patch.object(m, 'create', side_effect=AssertionError('Idempotent verification cannot write')):
            self.assertEqual(m.managed(self.config, seed=False)['managed_connections'], 'verified')
        self.assertEqual(before, {path: (self.real_lstat(path).st_ino, path.read_bytes()) for path in before})
        self.unchanged_other_data()

    def test_absent_selection_reads_no_private_input_and_owns_nothing(self):
        with patch.object(m, 'managed_bytes', side_effect=AssertionError('No selected credential')):
            self.assertEqual(m.managed(self.context_config), {'managed_connections': 'absent'})
        self.assertFalse(self.native.exists())
        self.assertFalse(self.receipt.exists())

    def test_absent_selection_refuses_existing_native_ownership(self):
        self.write(self.native, self.document, 8978)
        with self.assertRaises(ValueError):m.managed(self.context_config)

    def test_existing_unknown_native_file_cannot_be_adopted(self):
        self.write(self.native, self.document, 8978)
        with self.assertRaises(ValueError):m.managed(self.config)
        self.assertFalse(self.hold.exists())
        self.assertFalse(self.receipt.exists())
        self.unchanged_other_data()

    def test_collision_in_other_connection_file_refuses_before_hold(self):
        self.write(self.custom_path, {'connections': {'postgresql-admin': {'name': 'Foreign'}}}, 8978)
        before = self.custom_path.read_bytes()
        with self.assertRaises(ValueError):m.managed(self.config)
        self.assertFalse(self.native.exists())
        self.assertFalse(self.hold.exists())
        self.assertEqual(self.custom_path.read_bytes(), before)

    def test_existing_grant_collision_refuses_before_seed(self):
        self.write(self.permissions, dict(self.grants, **{'postgresql-admin': ['foreign-team']}), 8978)
        with self.assertRaises(ValueError):m.managed(self.config)
        self.assertFalse(self.native.exists())
        self.assertFalse(self.hold.exists())

    def test_existing_hold_is_preserved_without_replay(self):
        self.write(self.hold, {'status': 'uncertain'}, 0)
        before = self.hold.read_bytes()
        with self.assertRaises(ValueError):m.managed(self.config)
        self.assertEqual(self.hold.read_bytes(), before)
        self.assertFalse(self.native.exists())

    def test_partial_seed_keeps_hold_and_next_attempt_refuses(self):
        real = m.create
        def failure(path, value, **kwargs):
            if path == self.native:raise OSError('Fixture failure after durable hold')
            return real(path, value, **kwargs)
        permissions = self.permissions.read_bytes()
        with patch.object(m, 'create', side_effect=failure):
            with self.assertRaises(OSError):m.managed(self.config)
        self.assertTrue(self.hold.exists())
        self.assertFalse(self.receipt.exists())
        with self.assertRaises(ValueError):m.managed(self.config)
        self.assertEqual(self.permissions.read_bytes(), permissions)
        self.unchanged_other_data()

    def test_seed_false_cannot_create_a_new_managed_file(self):
        with self.assertRaises(ValueError):m.managed(self.config, seed=False)
        self.assertFalse(self.hold.exists())
        self.assertFalse(self.native.exists())

    def test_input_digest_and_ownership_changes_refuse(self):
        changed = dict(self.config, managed_sha256='0' * 64)
        with self.assertRaises(ValueError):m.managed(changed)
        self.set_owner(self.runtime, 8978, 8978)
        with self.assertRaises(ValueError):m.managed(self.config)
        self.assertFalse(self.hold.exists())

    def test_input_connection_set_and_folder_changes_refuse(self):
        for document in [dict(self.document, folders={'unknown': {}}), {'folders': {}, 'connections': {}}]:
            self.write(self.runtime, document, 0)
            changed = dict(self.config, managed_sha256=hashlib.sha256(self.runtime.read_bytes()).hexdigest())
            with self.assertRaises(ValueError):m.managed(changed)
        self.assertFalse(self.hold.exists())

    def test_receipt_native_content_and_owned_grant_drift_refuse(self):
        m.managed(self.config)
        original = self.native.read_bytes()
        self.native.write_bytes(original + b' ')
        with self.assertRaises(ValueError):m.managed(self.config, seed=False)
        self.native.write_bytes(original)
        grants = json.loads(self.permissions.read_bytes());grants['postgresql-admin'] = ['foreign-team']
        self.write(self.permissions, grants, 8978)
        with self.assertRaises(ValueError):m.managed(self.config, seed=False)
        self.assertFalse(self.hold.exists())

    def test_foreign_receipt_owner_refuses_without_mutating_evidence(self):
        m.managed(self.config)
        value = json.loads(self.receipt.read_bytes());value['owners']['postgresql-admin']['vmid'] = 999
        self.write(self.receipt, value, 0)
        raw = self.receipt.read_bytes()
        with self.assertRaises(ValueError):m.managed(self.config, seed=False)
        self.assertEqual(self.receipt.read_bytes(), raw)

    def test_symlink_workspace_ancestor_refuses(self):
        moved = self.workspace / 'moved';self.directory.rename(moved)
        self.directory.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(ValueError):m.managed(self.config)
        self.assertFalse(self.hold.exists())

    def test_managed_bytes_uses_real_no_follow_modes_and_hardlink_guard(self):
        self.assertEqual(m.managed_bytes(self.runtime, 0, (0o600,)), self.runtime.read_bytes())
        self.runtime.chmod(0o644)
        with self.assertRaises(ValueError):m.managed_bytes(self.runtime, 0, (0o600,))
        self.runtime.chmod(0o600)
        link = self.root / 'symlink';link.symlink_to(self.runtime)
        with self.assertRaises(OSError):m.managed_bytes(link, 0, (0o600,))
        hard = self.root / 'hard';os.link(self.runtime, hard)
        with self.assertRaises(ValueError):m.managed_bytes(self.runtime, 0, (0o600,))

    def test_managed_bytes_rejects_fifo_oversize_and_real_write_during_read(self):
        fifo = self.root / 'fifo';os.mkfifo(fifo, 0o600)
        with self.assertRaises(ValueError):m.managed_bytes(fifo, 0, (0o600,))
        with self.runtime.open('wb') as stream:stream.truncate(1024 * 1024 + 1)
        with self.assertRaises(ValueError):m.managed_bytes(self.runtime, 0, (0o600,))
        self.write(self.runtime, self.document, 0)
        original = m.os.fstat;changed = False
        identity = self.real_lstat(self.runtime)
        def mutate(fd):
            nonlocal changed
            row = original(fd)
            if not changed and (row.st_dev,row.st_ino) == (identity.st_dev,identity.st_ino):
                changed = True
                self.runtime.write_bytes(self.runtime.read_bytes() + b' ')
            return row
        with patch.object(m.os, 'fstat', side_effect=mutate):
            with self.assertRaises(ValueError):m.managed_bytes(self.runtime, 0, (0o600,))
        self.assertTrue(changed, 'The selected payload was mutated during its anchored read')

    def test_database_health_omitted_selection_never_reads_password_or_docker(self):
        with patch.object(m, 'managed_bytes', side_effect=AssertionError('No managed password selected')):
            self.assertEqual(m.database_health(self.context_config), 'individual_credentials_required')
        self.docker.assert_not_called()

    def test_driver_health_requires_exact_readonly_hash_and_no_folder_or_nested_shadow(self):
        artifact=self.config['mariadb_jdbc']
        server={'Mounts':[{'Type':'bind','Source':artifact['source'],'Destination':artifact['target'],'RW':False}]}
        m.driver_health(self.config,server)
        m.driver_health(self.context_config, {'Mounts':[]})
        for mutate in (lambda c,s:c['mariadb_jdbc'].update(sha256='0'*64),
            lambda c,s:c['mariadb_jdbc'].update(version='3.5.10'),
            lambda c,s:c['mariadb_jdbc'].update(source='/foreign.jar'),
            lambda c,s:c['mariadb_jdbc'].update(url='https://foreign.example.invalid/driver.jar'),
            lambda c,s:s['Mounts'][0].update(RW=True),
            lambda c,s:s['Mounts'].append(dict(s['Mounts'][0],Destination='/opt/cloudbeaver/drivers/mariadb'))):
            config,container=copy.deepcopy(self.config),copy.deepcopy(server);mutate(config,container)
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):m.driver_health(config,container)
        config=copy.deepcopy(self.config);config.pop('mariadb_jdbc')
        with self.assertRaises(ValueError):m.driver_health(config,server)
        self.jar.chmod(0o600)
        with self.assertRaises(ValueError):m.driver_health(self.config,server)

    def test_database_health_sends_each_password_only_on_stdin_with_exact_tls_proof(self):
        calls = []
        def docker(args, *, input, timeout):
            calls.append((args, input, timeout))
            self.assertNotIn(input.strip(), repr(args))
            return json.dumps({'database_administrator': 'verified', 'encrypted': True, 'source_match': True})
        with patch.object(m, 'docker', side_effect=docker), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.database_health(self.config), 'managed_tls_administrator_verified')
        self.assertEqual(out.getvalue(), '')
        self.assertEqual(len(calls), 2)
        for key, (args, stdin, timeout) in zip(self.config['managed_connections'], calls):
            value = self.config['managed_connections'][key]
            self.assertEqual(stdin, self.passwords[key] + '\n')
            self.assertEqual(timeout, 20)
            selected=[value['driver'], value['host'], value['owner']['source_address'], value['username']]
            if value['driver']=='mariadb':
                self.assertEqual(args[-7:-3],selected)
                self.assertEqual(args[-3:],[self.config['mariadb_jdbc'][key] for key in ('version','sha256','image_filename')])
            else:self.assertEqual(args[-4:],selected)
            self.assertTrue(all(password not in repr(args) for password in self.passwords.values()))

    def test_database_health_refuses_failed_tls_source_or_extra_output_without_password_leak(self):
        for response in [{'database_administrator': 'verified', 'encrypted': False, 'source_match': True},
                         {'database_administrator': 'verified', 'encrypted': True, 'source_match': False},
                         {'database_administrator': 'verified', 'encrypted': True, 'source_match': True, 'private': self.passwords['postgresql-admin']}]:
            with self.subTest(keys=sorted(response)), patch.object(m, 'docker', return_value=json.dumps(response)):
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    with self.assertRaises(ValueError) as error:m.database_health(self.config)
                self.assertEqual(out.getvalue(), '')
                self.assertTrue(all(password not in str(error.exception) for password in self.passwords.values()))


if __name__ == '__main__':
    unittest.main()
