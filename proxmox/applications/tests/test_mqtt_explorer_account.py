"""Real retained files with mocked numeric owners and native Docker boundaries."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


CODE = Path(__file__).resolve().parents[1]/'mqtt-explorer-account.py'


class AccountTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('mqtt_explorer_account_test', CODE)
        self.m = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.m)
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.m.CONFIG = self.root/'config'; self.m.CONFIG.mkdir()
        self.m.CUSTODY = self.root/'custody'; self.m.CUSTODY.mkdir(mode=0o700)
        self.m.DATA = self.root/'data'; self.m.DATA.mkdir(mode=0o700)
        self.owner = {'node': 'fixture-node', 'vmid': 901, 'hostname': 'fixture-broker'}
        self.write(self.m.CUSTODY/'workspace.json', self.owner)
        self.username = 'fixture_gui'; self.password = 'c'*64
        self.selected = {'name': 'Fixture broker', 'hostname': 'broker.example.invalid', 'port': 1883,
            'username': self.username, 'credential_id': 'fixture-account', 'password_file': '/mosquitto/config/passwd_file',
            'access': 'read-write-all'}
        self.value = {'connection': self.selected, 'credential': {'schema': 'homelab-application-account-v1',
            'owner': dict(self.owner, purpose='mqtt-explorer', username=self.username), 'password': self.password},
            'image': 'example.invalid/mosquitto@sha256:'+'a'*64}
        self.config = self.m.CONFIG/'mosquitto.conf'
        self.config.write_text('listener 1883\nallow_anonymous false\npassword_file /mosquitto/config/passwd_file\npersistence true\n')
        self.path = self.m.CONFIG/'passwd_file'; self.path.write_bytes(b'existing:$7$101$YWJj$ZGVm\n'); self.path.chmod(0o755)
        self.before = self.path.read_bytes()
        self.owners = {}
        self.real_lstat, self.real_fstat, self.real_open = Path.lstat, os.fstat, os.open
        self.own(self.m.DATA, 1001, 1001); self.own(self.path, 1883, 1883)
        def opened(path, flags, mode=0o777, **kwargs):
            fd = self.real_open(path, flags, mode, **kwargs)
            self.owners.setdefault(self.key(self.real_fstat(fd)), (0, 0))
            return fd
        self.add_patch(Path, 'lstat', lambda path, *a, **kw: self.overlay(self.real_lstat(path, *a, **kw)))
        self.add_patch(os, 'fstat', lambda fd: self.overlay(self.real_fstat(fd)))
        self.add_patch(os, 'open', opened)
        self.add_patch(os, 'chown', lambda path, uid, gid: self.own(path, uid, gid))
        self.add_patch(os, 'fchown', lambda fd, uid, gid: self.owners.__setitem__(self.key(self.real_fstat(fd)), (uid, gid)))
        self.add_patch(os, 'geteuid', lambda: 0)
        # Darwin's Python lacks these Linux APIs. Linux runs use real xattrs;
        # the portable fixture models only this unavailable kernel boundary.
        if not hasattr(os, 'listxattr'):
            attrs = {}
            self.add_patch(os, 'listxattr', lambda path: list(attrs.get(self.key(self.real_lstat(path)), {})), create=True)
            self.add_patch(os, 'getxattr', lambda path, name: attrs[self.key(self.real_lstat(path))][name], create=True)
            self.add_patch(os, 'setxattr', lambda path, name, value: attrs.setdefault(self.key(self.real_lstat(path)), {}).__setitem__(name, value), create=True)
        self.cid = 'b'*64; self.docker_calls = []; self.hash_hook = None
        self.row = {'Id': self.cid, 'State': {'Running': True}, 'Config': {'Image': self.value['image'],
            'Labels': {'com.docker.compose.project': 'homelab-mqtt', 'com.docker.compose.service': 'mqtt'},
            'Cmd': ['/usr/sbin/mosquitto', '-c', '/mosquitto/config/mosquitto.conf']}, 'Mounts': [{
                'Type': 'bind', 'RW': True, 'Source': str(self.m.CONFIG), 'Destination': '/mosquitto/config'}]}
        self.add_patch(self.m, 'docker', self.docker)
        self.auth = []
        self.add_patch(self.m, 'authenticate', lambda user, password: self.auth.append((user, password)))

    def add_patch(self, obj, name, value, create=False):
        p = patch.object(obj, name, value, create=create); p.start(); self.addCleanup(p.stop)

    @staticmethod
    def key(info):
        return info.st_dev, info.st_ino

    def own(self, path, uid, gid):
        self.owners[self.key(self.real_lstat(path))] = uid, gid

    def overlay(self, info):
        uid, gid = self.owners.get(self.key(info), (0, 0))
        return SimpleNamespace(**{name: uid if name == 'st_uid' else gid if name == 'st_gid' else getattr(info, name)
            for name in dir(info) if name.startswith('st_')})

    @staticmethod
    def write(path, document):
        path.write_text(json.dumps(document)); path.chmod(0o600)

    def docker(self, args, input=None):
        self.docker_calls.append((args, input))
        if args[0] == 'ps':
            return '' if 'label=com.docker.compose.service=mqtt_explorer' in args else self.cid
        if args[0] == 'inspect':return json.dumps([self.row])
        if args[0] == 'run':
            self.assertNotIn(self.password, ' '.join(args)); self.assertEqual(input, self.password+'\n'+self.password+'\n')
            if self.hash_hook:self.hash_hook()
            return self.username+':$7$101$YWJj$ZGVm\n'
        self.assertEqual(args, ['kill', '--signal', 'HUP', self.cid]); return self.cid

    def test_first_account_preserves_real_bytes_mode_xattrs_and_never_restarts_broker(self):
        os.setxattr(self.path, 'user.homelab-fixture', b'preserve')
        self.assertEqual(self.m.account(self.value), {'account': 'verified', 'broker_container_preserved': True})
        self.assertTrue(self.path.read_bytes().startswith(self.before))
        self.assertEqual(self.path.read_bytes().count(self.username.encode()+b':'), 1)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o755)
        self.assertEqual((self.path.lstat().st_uid, self.path.lstat().st_gid), (1883, 1883))
        self.assertEqual(os.getxattr(self.path, 'user.homelab-fixture'), b'preserve')
        self.assertFalse(list(self.m.CUSTODY.glob('*HOLD*')))
        before = self.path.read_bytes(); calls = len(self.docker_calls)
        self.m.account(self.value)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertTrue(all(args[0] not in ('run', 'kill', 'stop', 'restart') for args, _ in self.docker_calls[calls:]))

    def test_same_bytes_metadata_or_directory_drift_refuses_before_replacement(self):
        for drift in ('mode', 'inode', 'xattr', 'directory'):
            with self.subTest(drift=drift):
                # Independent fixture per refused operation preserves its real hold.
                child = AccountTests('runTest'); child.setUp()
                try:
                    def change():
                        if drift == 'mode':child.path.chmod(0o700)
                        elif drift == 'inode':
                            replacement = child.path.with_name('replacement'); replacement.write_bytes(child.before)
                            os.replace(replacement, child.path)
                        elif drift == 'xattr':os.setxattr(child.path, 'user.homelab-fixture', b'changed')
                        else:
                            child.m.CONFIG.rename(child.root/'old-config'); child.m.CONFIG.mkdir()
                            (child.m.CONFIG/'passwd_file').write_bytes(child.before)
                            child.config.write_text('allow_anonymous false\npassword_file /mosquitto/config/passwd_file\n')
                    child.hash_hook = change
                    with self.assertRaises(ValueError):child.m.account(child.value)
                    self.assertEqual(child.path.read_bytes(), child.before)
                    self.assertTrue(list(child.m.CUSTODY.glob('*HOLD*')))
                finally:child.doCleanups()

    def test_foreign_account_hold_or_receipt_cannot_be_adopted_or_reset(self):
        self.path.write_bytes(self.before+self.username.encode()+b':foreign\n')
        with self.assertRaises(ValueError):self.m.account(self.value)
        self.path.write_bytes(self.before)
        hold = self.m.CUSTODY/'fixture-account-ACCOUNT-HOLD.json'; self.write(hold, {'interrupted': True})
        with self.assertRaises(ValueError):self.m.account(self.value)
        self.assertEqual(self.path.read_bytes(), self.before)

    def test_config_and_shadowed_mounts_fail_before_any_account_write(self):
        original = self.config.read_text()
        for directive in ('acl_file /tmp/acl', 'include_dir /tmp/else', 'plugin /tmp/plugin', 'plugin_opt_value on',
                          'auth_plugin /tmp/plugin', 'auth_opt_value on', 'per_listener_settings true',
                          'allow_anonymous true', 'password_file /mosquitto/config/other'):
            self.config.write_text(original+directive+'\n')
            with self.subTest(directive=directive), self.assertRaises(ValueError):self.m.account(self.value)
            self.assertEqual(self.path.read_bytes(), self.before)
        self.config.write_text(original)
        self.row['Mounts'].append({'Destination': '/mosquitto/config/passwd_file', 'Type': 'bind', 'RW': True})
        with self.assertRaises(ValueError):self.m.account(self.value)
        self.assertFalse(list(self.m.CUSTODY.glob('*HOLD*')))

    def test_profile_adds_only_own_id_and_preserves_custom_settings_without_autoconnect(self):
        retained = {'ConnectionManager_connections': {'custom': {'id': 'custom', 'keep': [1, 2]}}, 'other': {'keep': True}}
        path = self.m.DATA/'settings.json'; self.write(path, retained); self.own(path, 1001, 1001)
        self.m.profile(self.value)
        actual = json.loads(path.read_text()); self.assertEqual(actual['other'], retained['other'])
        self.assertEqual(actual['ConnectionManager_connections']['custom'], retained['ConnectionManager_connections']['custom'])
        own = actual['ConnectionManager_connections']['managed-fixture-account']
        self.assertEqual(own['username'], self.username); self.assertEqual(own['password'], self.password)
        self.assertNotIn('clientId', own); self.assertNotIn('autoConnect', own)
        before = path.read_bytes(); self.m.profile(self.value); self.assertEqual(path.read_bytes(), before)
        own['host'] = 'foreign.example.invalid'; self.write(path, actual)
        with self.assertRaises(ValueError):self.m.profile(self.value)


    def gui(self, running=True):
        return {'Id': 'd'*64, 'State': {'Running': running}, 'Config': {'User': '1001:1001', 'Labels': {
            'com.docker.compose.project': 'homelab-mqtt', 'com.docker.compose.service': 'mqtt_explorer'}},
            'Mounts': [{'Type': 'bind', 'Source': str(self.m.DATA), 'Destination': '/app/data', 'RW': True}]}

    def test_profile_first_empty_workspace_and_stopped_GUI_do_not_touch_broker(self):
        row=self.gui(False)
        def boundary(args,input=None):
            self.assertNotIn('mqtt', args)
            if args[0]=='ps':return row['Id']
            if args[0]=='inspect':return json.dumps([row])
            raise AssertionError(args)
        with patch.object(self.m,'docker',side_effect=boundary):self.m.profile(self.value)
        doc=json.loads((self.m.DATA/'settings.json').read_bytes())
        self.assertEqual(set(doc['ConnectionManager_connections']),{'managed-fixture-account'})

    def test_profile_stops_GUI_before_merging_its_last_flushed_settings(self):
        row=self.gui();path=self.m.DATA/'settings.json'
        self.write(path,{'before':'preserved'});self.own(path,1001,1001)
        calls=[]
        def boundary(args,input=None):
            calls.append(args)
            if args[0]=='ps':return row['Id']
            if args[0]=='inspect':return json.dumps([row])
            self.assertEqual(args,['stop','--time','30',row['Id']])
            self.write(path,{'before':'preserved','flushed':'preserved','ConnectionManager_connections':{'custom':{'id':'custom'}}})
            self.own(path,1001,1001);row['State']['Running']=False
            return row['Id']
        with patch.object(self.m,'docker',side_effect=boundary):self.m.profile(self.value)
        doc=json.loads(path.read_bytes());self.assertEqual(doc['flushed'],'preserved')
        self.assertEqual(doc['ConnectionManager_connections']['custom'],{'id':'custom'})
        self.assertEqual([args[0]for args in calls],['ps','inspect','stop','inspect'])

    def test_profile_interrupted_GUI_stop_retains_durable_hold(self):
        row=self.gui()
        def boundary(args,input=None):
            if args[0]=='ps':return row['Id']
            if args[0]=='inspect':return json.dumps([row])
            raise OSError('Synthetic interrupted GUI stop')
        with patch.object(self.m,'docker',side_effect=boundary):
            with self.assertRaises(OSError):self.m.profile(self.value)
        self.assertTrue((self.m.CUSTODY/'fixture-account-PROFILE-HOLD.json').is_file())

    def test_profile_rejects_nested_workspace_shadow_before_stopping_GUI(self):
        row=self.gui();row['Mounts'].append(dict(row['Mounts'][0],Destination='/app/data/profiles'))
        def boundary(args,input=None):
            if args[0]=='ps':return row['Id']
            if args[0]=='inspect':return json.dumps([row])
            raise AssertionError('A shadowed GUI must not be stopped')
        with patch.object(self.m,'docker',side_effect=boundary):
            with self.assertRaises(ValueError):self.m.profile(self.value)


if __name__ == '__main__':
    unittest.main()
