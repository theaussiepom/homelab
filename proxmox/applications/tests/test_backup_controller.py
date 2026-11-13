"""Controller coordination with real local pipes and mocked custody/native peers."""
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import backup_controller as controller
import backup_group
from custody_records import no_markers
from private_io import encoded, write_new
from test_backup_group import scope
import test_backup_worker as worker_fixture

PEER = r'''
import json,sys,time
begin=json.loads(sys.stdin.readline()); member=sys.argv[1]; fail=sys.argv[2]
for stage,action in [('prepared','pause'),('paused','capture'),('captured','resume'),('resumed','upload'),('uploaded','finish')]:
    if fail==stage: raise SystemExit(1)
    value={'stage':stage,'generation':begin['generation'],'member':member}
    if stage in ('captured','uploaded'): value['data_manifest_sha256']='a'*64
    raw=json.dumps(value)+'\n'
    sys.stdout.write(raw[:8]);sys.stdout.flush();time.sleep(.002)
    sys.stdout.write(raw[8:]);sys.stdout.flush()
    command=json.loads(sys.stdin.readline());assert command['action']==action
    if action=='upload': assert member in command['group']['members']
'''


class ControllerTests(unittest.TestCase):
    def setUp(self):
        activation=patch('backup_readiness.verify');activation.start();self.addCleanup(activation.stop)
        self.mask = os.umask(0o077); self.addCleanup(os.umask, self.mask)
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup); self.tmp = Path(temp.name).resolve()
        self.state = self.tmp/'state'; self.state.mkdir(mode=0o700)
        self.fixture = worker_fixture.WorkerTests(); self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.group = scope(); row = self.group['members'].pop('example-node-610')
        row['state_root'] = str(self.state)
        self.group['members'] = {'one': dict(row), 'two': {**row, 'vmid': 611, 'hostname': 'second'}}
        self.cfg = {}
        for name, row in self.group['members'].items():
            work = self.state/str(row['vmid']); work.mkdir(mode=0o700)
            for leaf in ('workflow.lock', 'deployment.lock'): write_new(work/leaf, b'')
            inventory = copy.deepcopy(self.fixture.value)
            inventory['job']['group']['member'] = name; inventory['job']['destination']['backup_id'] = name
            self.cfg[name] = {'app': {'backup': inventory, 'address': '192.0.2.20'},
                'paths': {'known_hosts': '/private/known-hosts', 'private_key': '/private/key'}}
        write_new(self.state/'database-network.lock', b'')
        self.value = {'schema': 'homelab-pbs-schedule-v1', 'group': self.group,
            'schedule': {'calendar': 'hourly', 'jitter_seconds': 0},
            'limits': self.fixture.value['job']['limits']}
        self.path = self.tmp/'schedule.json'; write_new(self.path, encoded(self.value))

    def admission(self, name, row):
        no_markers(self.state/str(row['vmid']))
        return self.cfg[name], 'a'*64

    def execute(self, failure=''):
        def launch(argv, **kw):
            name = argv[-2]
            return subprocess.Popen([sys.executable, '-c', PEER, name, failure if name == 'two' else ''], **kw)
        with patch.object(controller, 'command', side_effect=lambda cfg: ['peer', cfg['app']['backup']['job']['group']['member'], 'serve']), \
                patch.object(controller, 'controls', return_value={}):
            return controller.run(self.path, launch=launch, admission=self.admission)

    def test_all_peers_barrier_and_exact_success_close_only_own_holds(self):
        result = self.execute(); self.assertEqual(result['status'], 'passed')
        operation = self.state/'backup-groups'/result['generation']
        manifest = json.loads((operation/'recovery-set.json').read_text())
        self.assertEqual(set(manifest['members']), {'one', 'two'})
        self.assertTrue((operation/'complete.json').exists())
        self.assertEqual(len(list(operation.glob('*.closed.json'))), 2)
        self.assertFalse(list(self.state.glob('*/BACKUP-HOLD.json')))

    def test_preflight_failure_has_no_window_but_partial_capture_preserves_all_holds(self):
        with self.assertRaises(ValueError): self.execute('prepared')
        self.assertFalse(list(self.state.glob('*/BACKUP-HOLD.json')))
        with self.assertRaises(ValueError): self.execute('captured')
        self.assertEqual(len(list(self.state.glob('*/BACKUP-HOLD.json'))), 2)
        with self.assertRaises(ValueError): self.execute()
        receipts = [json.loads(p.read_text()) for p in (self.state/'backup-groups').glob('*/failed.json')]
        self.assertEqual({r['window_opened'] for r in receipts}, {False, True})

    def test_lock_contention_prevents_any_peer_launch(self):
        import fcntl
        with (self.state/'610'/'workflow.lock').open('rb') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(controller, 'command') as command, self.assertRaises(BlockingIOError): self.execute()
            command.assert_not_called()

    def test_units_preserve_utc_pinned_source_actor_and_no_catchup(self):
        result = controller.units(self.value, '/state/framework/'+'b'*64+'/proxmox/applications', 1000, '/home/runner')
        self.assertIn('UTC', result['timer']); self.assertIn('Persistent=false', result['timer'])
        self.assertIn('--group', result['service']); self.assertNotIn('--site', result['service'])
        self.value['schedule']['calendar'] = '02:30'
        self.assertIn('02:30:00 UTC', controller.units(self.value, '/state/framework/'+'b'*64+'/proxmox/applications', 1000, '/home/runner')['timer'])
        controller.continuity(self.value, self.value)
        added = copy.deepcopy(self.value); added['group']['members']['three'] = {**added['group']['members']['two'], 'vmid': 612}
        controller.continuity(self.value, added)
        for change in [lambda v: v['group']['members'].pop('two'), lambda v: v['group'].update(name='new')]:
            value = copy.deepcopy(self.value); change(value)
            with self.assertRaises(ValueError): controller.continuity(self.value, value)
        for path in ('relative', '/bad%path', '/newline\n'):
            with self.assertRaises(ValueError): controller.units(self.value, path, 1000, '/home/runner')
        with self.assertRaises(ValueError): controller.schedule({**self.value, 'schema': 'foreign'})
        command = controller.command(self.cfg['one'])
        self.assertIn('StrictHostKeyChecking=yes', command); self.assertIn('ConnectTimeout=10', command)

    def test_pipe_deadlines_disconnects_oversize_and_wrong_owners_refuse(self):
        code = 'import sys,time;sys.stdout.write(sys.argv[1]);sys.stdout.flush();time.sleep(.1)'
        for payload in ('', '{}', '{}\n', '{"stage":"prepared","generation":"'+'a'*32+'","member":"foreign"}\n'):
            peer = subprocess.Popen([sys.executable, '-c', code, payload], stdin=subprocess.PIPE, stdout=subprocess.PIPE, start_new_session=True, bufsize=0)
            try:
                exchange = controller.Exchange({'one': peer}, 'a'*32, time.monotonic()+.05)
                with self.assertRaises(ValueError): exchange.transfer(stage='prepared')
            finally: controller.reap({'one': peer}, success=False, deadline=time.monotonic()+1)
        peer = subprocess.Popen([sys.executable, '-c', 'import sys;sys.stdout.write("x"*1100000);sys.stdout.flush()'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, start_new_session=True, bufsize=0)
        try:
            with self.assertRaises(ValueError): controller.Exchange({'one': peer}, 'a'*32, time.monotonic()+2).transfer(stage='prepared')
        finally: controller.reap({'one': peer}, success=False, deadline=time.monotonic()+1)
