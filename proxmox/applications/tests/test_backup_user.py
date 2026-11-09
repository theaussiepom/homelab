"""The standard user manager must be hardened before any backup side effect."""
import copy
import json
import os
from pathlib import Path
import runpy
import stat
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backup_user as subject


class UserTests(unittest.TestCase):
    """Exercise ownership, kernel evidence, bus binding and closed systemctl responses."""
    def setUp(self):
        self.actor = {'uid': 1000, 'name': 'homelab-runner', 'home': '/home/homelab-runner',
            'runtime': '/run/user/1000', 'unit_directory': '/home/homelab-runner/.config/systemd/user',
            'environment': {'XDG_RUNTIME_DIR': '/run/user/1000',
                'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/1000/bus'}}
        self.state = dict(LoadState='loaded', ActiveState='active', MainPID='123',
                          NoNewPrivileges='yes', NeedDaemonReload='no')

    def test_metadata_foreign_links_permissions_and_kinds_refuse(self):
        for directory, mode in ((True, stat.S_IFDIR|0o700), (False, stat.S_IFREG|0o600)):
            info = NS(st_mode=mode, st_uid=1000, st_nlink=1)
            with patch.object(Path, 'lstat', return_value=info):
                self.assertIs(subject.metadata('/fixed', {1000}, directory=directory), info)
            negatives = [('st_uid', 1001), ('st_mode', mode|0o022), ('st_mode', stat.S_IFLNK|0o777)]
            if not directory: negatives.append(('st_nlink', 2))
            for key, value in negatives:
                bad = copy.copy(info); setattr(bad, key, value)
                with patch.object(Path, 'lstat', return_value=bad), self.assertRaises(ValueError):
                    subject.metadata('/fixed', {1000}, directory=directory)
            with patch.object(Path, 'lstat', return_value=info), self.assertRaises(ValueError):
                subject.metadata('/fixed', {1000}, directory=directory, modes={0o444})

    def test_stable_regular_read_is_bounded_and_never_follows_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'file'; path.write_bytes(b'private metadata'); path.chmod(0o600)
            self.assertEqual(subject.read(path, {os.getuid()}, {0o600}), b'private metadata')
            with self.assertRaises(ValueError): subject.read(path, {os.getuid()}, {0o600}, 2)
            alias = path.parent/'alias'; alias.symlink_to(path)
            with self.assertRaises(OSError): subject.read(alias, {os.getuid()}, {0o600})
            before = path.stat()
            with patch.object(subject, 'identity', side_effect=[('fd',), ('path',)]), self.assertRaises(ValueError):
                subject.read(path, {os.getuid()}, {0o600})
            with patch.object(subject, 'identity', side_effect=[1, 1, 2, 1]), self.assertRaises(ValueError):
                subject.read(path, {os.getuid()}, {0o600})
            with patch.object(subject, 'identity', side_effect=[1, 1, 1, 2]), self.assertRaises(ValueError):
                subject.read(path, {os.getuid()}, {0o600})
            self.assertEqual(path.stat().st_ino, before.st_ino)

    def test_account_uses_passwd_not_caller_home_or_xdg(self):
        row = NS(pw_uid=1000, pw_name='homelab-runner', pw_dir='/home/homelab-runner')
        with patch.object(subject.pwd, 'getpwuid', return_value=row), patch.object(subject, 'ancestors'), \
                patch.object(subject, 'metadata'), patch.object(Path, 'stat', return_value=NS(st_mode=0o40700)), \
                patch.dict(os.environ, {'HOME': '/foreign', 'XDG_RUNTIME_DIR': '/foreign'}):
            self.assertEqual(subject.account(1000), self.actor)
            for key, value in [('pw_uid', 999), ('pw_name', 'bad\nname')]:
                bad = copy.copy(row); setattr(bad, key, value)
                with patch.object(subject.pwd, 'getpwuid', return_value=bad), self.assertRaises(ValueError): subject.account(1000)
            with patch.object(Path, 'stat', return_value=NS(st_mode=0o40000)), self.assertRaises(ValueError): subject.account(1000)
        for uid in (0, -1, True, '1000'):
            with self.assertRaises(ValueError): subject.account(uid)

    def test_ancestors_refuse_alias_and_foreign_writable_parents(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); (root/'real').mkdir(); (root/'alias').symlink_to(root/'real')
            with patch.object(subject, 'metadata') as check:
                subject.ancestors(root/'real'/'absent', os.getuid()); self.assertTrue(check.called)
            for path in ('relative', root/'alias'):
                with self.assertRaises(ValueError): subject.ancestors(path, os.getuid())
            with patch.object(subject, 'metadata', side_effect=ValueError('foreign')), self.assertRaises(ValueError):
                subject.ancestors(root, os.getuid())

    def test_show_requires_closed_scalar_response_and_fixed_scope_environment(self):
        process = NS(stdout='LoadState=not-found\n', stderr='', returncode=1)
        with patch.object(subject.subprocess, 'run', return_value=process) as run:
            self.assertEqual(subject.show('fixed.timer', ['LoadState']), {'LoadState': 'not-found'})
            self.assertEqual(run.call_args.args[0][:3], ['/usr/bin/systemctl', '--system', 'show'])
            subject.show('fixed.timer', ['LoadState'], scope='user', environment=self.actor['environment'])
            self.assertEqual(run.call_args.kwargs['env']['XDG_RUNTIME_DIR'], '/run/user/1000')
            for stdout, stderr, code in [('LoadState=loaded\n', '', 1), ('LoadState=loaded\n', 'warning', 0),
                    ('Foreign=value\n', '', 0), ('LoadState=loaded\nLoadState=loaded\n', '', 0),
                    ('sentinel', '', 0), ('x'*16385, '', 0)]:
                with patch.object(subject.subprocess, 'run', return_value=NS(stdout=stdout, stderr=stderr, returncode=code)), self.assertRaises(ValueError):
                    subject.show('fixed.timer', ['LoadState'])
        with self.assertRaises(ValueError): subject.show('fixed', [], scope='foreign')

    def kernel_text(self):
        return b'Name:\tsystemd\nUid:\t1000 1000 1000 1000\nNoNewPrivs:\t1\nCapEff:\t0000\nCapPrm:\t0000\nCapAmb:\t0000\n'

    def test_kernel_requires_real_actor_nnp_and_zero_capabilities(self):
        raw = self.kernel_text()
        with patch.object(subject, 'read', return_value=raw): self.assertTrue(subject.kernel(123, 1000))
        for old, new in [(b'NoNewPrivs:\t1', b'NoNewPrivs:\t0'), (b'CapEff:\t0000', b'CapEff:\t0001'),
                         (b'CapPrm:\t0000', b'CapPrm:\t0001'), (b'CapAmb:\t0000', b'CapAmb:\t0001')]:
            with patch.object(subject, 'read', return_value=raw.replace(old, new)): self.assertFalse(subject.kernel(123, 1000))
        for value in [raw.replace(b'1000 1000 1000 1000', b'0 0 0 0'), raw.replace(b'CapAmb:\t0000\n', b''),
                raw+ b'CapEff:\t0\n', raw.replace(b'NoNewPrivs:\t1', b'NoNewPrivs:\tyes'),
                raw.replace(b'CapEff:\t0000', b'CapEff:\tx'), raw.replace(b'CapEff:\t0000', b'CapEff:\t0 0')]:
            with patch.object(subject, 'read', return_value=value), self.assertRaises(ValueError): subject.kernel(123, 1000)
        for pid in (0, True, -1):
            with self.assertRaises(ValueError): subject.kernel(pid, 1000)

    def test_inspection_never_starts_or_repairs_an_existing_manager(self):
        with patch.object(subject, 'account', return_value=self.actor), patch.object(subject, 'ancestors'), \
                patch.object(subject, 'read', return_value=subject.POLICY), \
                patch.object(subject, 'show', return_value=self.state) as show, patch.object(subject, 'kernel', return_value=True):
            value = subject.inspect(1000)
            self.assertTrue(value['kernel_hardened']); self.assertTrue(value['policy_matches'])
            self.assertEqual(show.call_count, 2)
            with patch.object(subject, 'read', side_effect=FileNotFoundError), patch.object(subject, 'show', return_value={**self.state, 'ActiveState': 'inactive', 'MainPID': '0'}):
                value = subject.inspect(1000); self.assertFalse(value['active']); self.assertFalse(value['policy_present'])
            for key, changed in [('LoadState', 'not-found'), ('ActiveState', 'activating'), ('MainPID', 'sentinel'),
                                 ('NoNewPrivileges', ''), ('NeedDaemonReload', '')]:
                with patch.object(subject, 'show', return_value={**self.state, key: changed}), self.assertRaises(ValueError): subject.inspect(1000)
            with patch.object(subject, 'show', side_effect=[self.state, {**self.state, 'MainPID': '124'}]), self.assertRaises(ValueError):
                subject.inspect(1000)

    def ready_value(self):
        return {**self.actor, 'active': True, 'policy_present': True, 'policy_matches': True,
                'kernel_hardened': True, 'configured_hardened': True, 'reload_needed': False}

    def test_ready_binds_root_policy_linger_runtime_and_socket(self):
        value = self.ready_value()
        with patch.object(subject, 'inspect', return_value=value), patch.object(subject, 'ancestors'), \
                patch.object(subject, 'read', return_value=b''), patch.object(subject, 'metadata'), \
                patch.object(Path, 'lstat', return_value=NS(st_mode=stat.S_IFSOCK|0o600, st_uid=1000, st_nlink=1)):
            self.assertEqual(subject.ready(1000), value)
            for key in ('active', 'policy_present', 'policy_matches', 'kernel_hardened', 'configured_hardened', 'reload_needed'):
                with patch.object(subject, 'inspect', return_value={**value, key: not value[key]}), self.assertRaises(ValueError): subject.ready(1000)
            with patch.object(subject, 'read', return_value=b'foreign'), self.assertRaises(ValueError): subject.ready(1000)
            for change in [dict(st_mode=stat.S_IFREG|0o600, st_uid=1000, st_nlink=1),
                           dict(st_mode=stat.S_IFSOCK, st_uid=1001, st_nlink=1), dict(st_mode=stat.S_IFSOCK, st_uid=1000, st_nlink=2)]:
                with patch.object(Path, 'lstat', return_value=NS(**change)), self.assertRaises(ValueError): subject.ready(1000)

    def test_execution_and_system_namesake_admission_are_read_only(self):
        with patch.object(os, 'getuid', return_value=1000), patch.object(os, 'geteuid', return_value=1000), \
                patch.object(subject, 'kernel', return_value=True):
            self.assertEqual(subject.execution(), 1000)
            with patch.object(subject, 'kernel', return_value=False), self.assertRaises(ValueError): subject.execution()
            with patch.object(os, 'geteuid', return_value=0), self.assertRaises(ValueError): subject.execution()
        with patch.object(os, 'getuid', return_value=0), self.assertRaises(ValueError): subject.execution()
        def observation(unit, keys, **kwargs):
            return ({'LoadState': 'not-found', 'FragmentPath': '', 'DropInPaths': ''}
                    if kwargs.get('scope') == 'user' else {'LoadState': 'not-found'})
        with patch.object(subject, 'execution', return_value=1000), patch.object(subject, 'ready', return_value=self.actor), \
                patch.object(subject, 'show', side_effect=observation) as show:
            self.assertEqual(subject.verify('homelab-backup-A_1.test'), self.actor); self.assertEqual(show.call_count, 4)
            with patch.object(subject, 'show', return_value={'LoadState': 'loaded'}), self.assertRaises(ValueError): subject.verify('homelab-backup-valid')
            for name in ('other', 'homelab-backup-bad\n', 'homelab-backup-'):
                with self.assertRaises(ValueError): subject.verify(name)
            def loaded(unit, keys, **kwargs):
                return ({'LoadState': 'loaded', 'FragmentPath': self.actor['unit_directory']+'/'+unit, 'DropInPaths': ''}
                        if kwargs.get('scope') == 'user' else {'LoadState': 'not-found'})
            with patch.object(subject, 'show', side_effect=loaded), patch.object(subject, 'ancestors'), patch.object(subject, 'metadata') as metadata:
                subject.verify('homelab-backup-owned'); self.assertEqual(metadata.call_count, 2)
            for path, dropin in [('/foreign/unit', ''), (self.actor['unit_directory']+'/homelab-backup-owned.service','/override')]:
                values=[{'LoadState':'not-found'},{'LoadState':'loaded','FragmentPath':path,'DropInPaths':dropin}]
                with patch.object(subject, 'show', side_effect=values), self.assertRaises(ValueError): subject.verify('homelab-backup-owned')

    def test_closed_observation_cli_never_starts_anything(self):
        with patch.object(subject, 'inspect', return_value=self.actor), patch.object(subject, 'ready', return_value=self.actor), \
                patch.object(os, 'geteuid', return_value=0), patch('builtins.print') as output:
            for action in ('inspect', 'ready'):
                with patch.object(sys, 'argv', ['helper', action, '1000']): subject.main()
                self.assertEqual(json.loads(output.call_args.args[0]), self.actor)
            for args in (['helper'], ['helper', 'start', '1000'], ['helper', 'ready', '0']):
                with patch.object(sys, 'argv', args), self.assertRaises(ValueError): subject.main()
            with patch.object(sys, 'argv', ['helper', 'ready', '1000']), patch.object(os, 'geteuid', return_value=1001), self.assertRaises(ValueError): subject.main()
        with patch.object(sys, 'argv', ['helper']), self.assertRaises(ValueError): runpy.run_path(subject.__file__, run_name='__main__')
