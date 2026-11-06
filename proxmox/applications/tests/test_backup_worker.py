"""Actual private generations with fake native services/PBS, never production paths."""
import copy
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backup_worker as worker
from private_io import encoded, write_new
from test_backup_capture import operational


class FakeEngine:
    def __init__(self, failure=None):
        self.failure = failure; self.calls = []; self.upload = None; self.stamp = None

    def begin_phase(self):
        pass

    def run(self, argv, *, output=None, environment=None, restore=False):
        self.calls.append((argv, environment, restore))
        action = ('route' if argv[0] == 'ip' else 'preflight' if argv[:3] == ['proxmox-backup-client', 'snapshot', 'list'] and self.upload is None
            else 'snapshot' if argv[:3] == ['proxmox-backup-client', 'snapshot', 'list']
            else 'upload' if argv[:2] == ['proxmox-backup-client', 'backup']
            else 'restore' if argv[:2] == ['proxmox-backup-client', 'restore']
            else 'health' if 'ps' in argv and '--format' in argv else 'ps' if '--services' in argv else 'start' if restore
            else 'stop' if 'stop' in argv else 'tar' if argv[0] == 'tar' else 'database')
        if self.failure == action: raise RuntimeError('synthetic '+action+' failure')
        if action == 'route': output.write_text(json.dumps([{'dev': 'eth1', 'prefsrc': '192.0.2.10'}]))
        elif action == 'health':
            output.write_text(json.dumps([{'Service':'service','State':'running','Health':'unhealthy' if self.failure=='unhealthy' else 'healthy'}]))
        elif action == 'ps': output.write_text('service\n' if self.failure != 'not_running' else '')
        elif action == 'upload':
            self.upload = Path(next(value.removeprefix('recovery.pxar:') for value in argv if value.startswith('recovery.pxar:')))
            self.stamp = int(argv[argv.index('--backup-time')+1])
        elif action in ('preflight', 'snapshot'):
            output.write_text(json.dumps([] if action == 'preflight' else [{
                'backup-id': 'example-node-610', 'backup-type': 'host',
                'backup-time': self.stamp if self.failure != 'wrong_snapshot' else self.stamp-1}]))
        elif action == 'restore':
            shutil.copytree(self.upload, Path(argv[4]))
            if self.failure == 'corrupt_readback': (Path(argv[4])/'inventory.json').write_text('corrupt')
        elif action == 'tar':
            Path(argv[argv.index('--file')+1]).write_bytes(b'synthetic archived file bytes')
        elif action == 'database':
            if output is not None: output.write_bytes(b'' if self.failure == 'empty_database' else b'native database fixture')
            else:
                target = Path(argv[-1]); target.mkdir(); (target/'native.bin').write_bytes(b'native Influx fixture')


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.previous_mask = os.umask(0o077); self.addCleanup(os.umask, self.previous_mask)
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name).resolve()
        self.root = self.tmp/'state'; self.config = self.tmp/'config'
        self.root.mkdir(mode=0o700); self.config.mkdir(mode=0o700)
        for name in ('pbs-password', 'pbs-key', 'pbs-key-password', 'influx-app'):
            write_new(self.config/name, b'synthetic-private-input\n')
        value = operational()
        value['configuration'] = {}
        app = value['applications']['app']; app['configuration'] = {}; app['runtime_files'] = []
        app['storage'] = {'state': {'path': str(self.tmp/'data'), 'kind': 'directory', 'include': True,
            'category': 'state', 'capture': 'application-export'}}
        (self.tmp/'data').mkdir(); (self.tmp/'data'/'private.txt').write_text('synthetic private material')
        value['job'].update(destination={'server': '192.0.2.50', 'port': 8007, 'datastore': 'recovery',
            'namespace': 'guests', 'fingerprint': ':'.join(['ab']*32), 'auth_id': 'one@pbs!backup'},
            schedule={'calendar': 'daily', 'jitter_seconds': 60},
            staging={'path': '/srv/backup-stage', 'size_bytes': 1024**3},
            transport={'device': 'eth1', 'address': '192.0.2.10'},
            limits={'max_bytes': 1024*1024, 'max_files': 100, 'timeout_seconds': 60},
            secrets={'password': {'type': 'file', 'path': '/controller/password'},
                     'encryption_key': {'type': 'file', 'path': '/controller/key'}})
        value['job']['destination']['backup_id'] = 'example-node-610'
        value['job']['group'] = {'name': 'example', 'member': 'example-node-610'}
        self.value = value

    def run_worker(self, engine=None, value=None, generation='a'*32):
        return worker.run(self.value if value is None else value, root=self.root, config=self.config,
                          engine=FakeEngine() if engine is None else engine, generation=generation)

    def test_upload_requires_immutable_complete_encrypted_readback_and_keeps_history(self):
        engine = FakeEngine(); result = self.run_worker(engine)
        self.assertEqual(result['status'], 'uploaded'); self.assertFalse(result['restore_verified'])
        receipt = json.loads((self.root/('a'*32)/'complete.json').read_text())
        self.assertTrue(receipt['archive_readback_verified']); self.assertFalse(receipt['cross_guest_transaction'])
        self.assertFalse((self.root/'PENDING').exists())
        self.assertEqual(engine.calls[0][0][:3], ['ip', '-j', 'route'])
        self.assertTrue(any(restored for _, _, restored in engine.calls))
        for argv, _, _ in engine.calls: self.assertNotIn('synthetic-private-input', ' '.join(argv))
        self.run_worker(generation='b'*32)
        self.assertTrue((self.root/('a'*32)/'complete.json').is_file())
        self.assertTrue((self.root/('b'*32)/'complete.json').is_file())

    def test_every_controlled_failure_preserves_evidence_and_restarts_only_prior_running_services(self):
        for failure in ('preflight', 'not_running', 'stop', 'tar', 'start', 'upload',
                        'snapshot', 'wrong_snapshot', 'restore', 'corrupt_readback', 'unhealthy'):
            with self.subTest(failure=failure):
                self.root = self.tmp/failure; self.root.mkdir(mode=0o700)
                engine = FakeEngine(failure)
                with self.assertRaises((ValueError, RuntimeError)): self.run_worker(engine)
                self.assertEqual((self.root/'PENDING').exists(), failure not in ('preflight', 'not_running'))
                self.assertTrue((self.root/('a'*32)/'failed.json').exists())
                self.assertFalse((self.root/('a'*32)/'complete.json').exists())
                if failure not in ('preflight', 'not_running'):
                    self.assertTrue(any(restored for _, _, restored in engine.calls))
                count = len(engine.calls)
                with self.assertRaises((ValueError, FileExistsError)): self.run_worker(engine)
                self.assertEqual(len(engine.calls), count)

    def test_native_database_exports_are_not_raw_engine_directory_copies(self):
        for adapter in ('postgresql', 'mariadb', 'influxdb'):
            with self.subTest(adapter=adapter):
                self.root = self.tmp/adapter; self.root.mkdir(mode=0o700)
                value = copy.deepcopy(self.value); app = value['applications']['app']
                app.update(adapter=adapter, storage={}, producer={'type': adapter,
                    'packages': ['postgresql-client-16=16.10-1']})
                if adapter == 'influxdb': app['producer']['endpoint'] = 'http://192.0.2.60:8086'
                value['job']['capture'].update(pause=[], database_lock=['app'],
                    influx_tokens={'app': {'type': 'file', 'path': '/controller/token'}})
                value['job']['secrets']['key_password'] = {'type': 'file', 'path': '/controller/key-password'}
                self.run_worker(FakeEngine(), value)
                receipt = json.loads((self.root/('a'*32)/'complete.json').read_text())
                self.assertEqual(receipt['completed_databases'], ['app'])
        self.root = self.tmp/'empty'; self.root.mkdir(mode=0o700)
        value['applications']['app'].update(adapter='mariadb', producer={'type': 'mariadb', 'packages': []})
        with self.assertRaises(ValueError): self.run_worker(FakeEngine('empty_database'), value)

    def test_coordinated_run_embeds_exact_member_manifest_after_resume(self):
        import backup_group
        from test_backup_group import scope, destination
        stages = []
        def barrier(stage, metadata):
            stages.append(stage)
            if stage == 'captured': self.capture_sha = metadata['data_manifest_sha256']
            if stage == 'resumed':
                return backup_group.recovery_set(scope(), 'a'*32, 1,
                    {'example-node-610': self.capture_sha}, destination())
        result = worker.run(self.value, root=self.root, config=self.config, engine=FakeEngine(), generation='a'*32,
            backup_time=1, barrier=barrier, group_config=scope())
        self.assertEqual(stages, ['prepared', 'paused', 'captured', 'resumed', 'uploaded'])
        self.assertEqual(result['status'], 'uploaded')
        receipt = json.loads((self.root/('a'*32)/'complete.json').read_text())
        self.assertTrue(receipt['coordinated_window'])

    def test_declared_transient_paths_remain_excluded_from_native_archive(self):
        value = copy.deepcopy(self.value)
        excluded = str(self.tmp/'data'/'logs')
        value['applications']['app']['storage']['logs'] = {
            'path':excluded,'kind':'directory','include':False,'reason':'transient'}
        Path(excluded).mkdir(); (Path(excluded)/'transient.txt').write_text('not a recovery input')
        engine = FakeEngine(); self.run_worker(engine,value)
        command = next(argv for argv,_,_ in engine.calls if argv[0]=='tar')
        self.assertIn('--exclude='+excluded.lstrip('/'), command)

    def test_private_inputs_invalid_generations_and_insufficient_capacity_refuse(self):
        for generation in ('../escape', 'x'*32, 'a'*31):
            with self.subTest(generation=generation), self.assertRaises(ValueError):
                self.run_worker(generation=generation)
        with patch.object(worker.shutil, 'disk_usage', return_value=type('Disk', (), {'free': 1})()):
            with self.assertRaises(ValueError): self.run_worker()
        self.assertFalse((self.root/'PENDING').exists())
        (self.config/'pbs-password').chmod(0o644)
        with self.assertRaises(ValueError): self.run_worker()
        self.assertFalse((self.root/'PENDING').exists())


if __name__ == '__main__': unittest.main()
