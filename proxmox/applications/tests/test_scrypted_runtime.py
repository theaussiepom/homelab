"""Scrypted's cold-start storage guard never creates a local recording fallback."""
import copy
import contextlib
import io
import json
import os
from pathlib import Path
import runpy
import tempfile
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'blueprints'))
import component_runtime
import component_app_hooks
import component_checks
import scrypted_runtime


class RecordingMountAdmission(unittest.TestCase):
    def test_script_entrypoint_refuses_an_absent_recording_directory_without_creation(self):
        path=self.nvr/'absent';output=io.StringIO()
        argv=['guard','--mount-only','--recordings',str(path),
              '--source','nas.example.invalid:/recordings','--filesystem','nfs4','--root','/camera']
        with patch.object(sys,'argv',argv),contextlib.redirect_stdout(output),self.assertRaises(SystemExit)as result:
            runpy.run_path(str(Path(scrypted_runtime.__file__)),run_name='__main__')
        self.assertEqual(result.exception.code,1)
        self.assertEqual(json.loads(output.getvalue())['reason'],'scrypted_storage_admission_failed')
        self.assertFalse(path.exists())

    def test_cli_mount_only_and_state_checks_keep_diagnostics_redacted(self):
        common=['guard','--recordings','/srv/recordings','--source','nas.example.invalid:/recordings',
                '--filesystem','nfs4','--root','/camera']
        result={'status':'passed','writes_performed':False}
        for extra, helper in ((['--mount-only'],'validate_mount'),(['--data','/srv/state'],'validate')):
            output=io.StringIO()
            with patch.object(sys,'argv',common+extra),patch.object(scrypted_runtime,helper,return_value=result),contextlib.redirect_stdout(output):
                self.assertEqual(scrypted_runtime.main(),0)
            self.assertEqual(json.loads(output.getvalue()),result)
        for extra in ([],['--mount-only','--data','/srv/state']):
            output=io.StringIO()
            with patch.object(sys,'argv',common+extra),contextlib.redirect_stdout(output):
                self.assertEqual(scrypted_runtime.main(),1)
            self.assertEqual(json.loads(output.getvalue())['reason'],'scrypted_storage_admission_failed')
        output=io.StringIO()
        with patch.object(sys,'argv',common+['--mount-only']),patch.object(scrypted_runtime,'validate_mount',side_effect=ValueError('PRIVATE_SENTINEL')),contextlib.redirect_stdout(output):
            self.assertEqual(scrypted_runtime.main(),1)
        self.assertNotIn('PRIVATE_SENTINEL',output.getvalue())

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name).resolve()
        self.data = root / 'data'
        self.nvr = root / 'recordings'
        (self.data / 'scrypted.db').mkdir(parents=True)
        self.nvr.mkdir()
        self.mount = {'source': '198.18.20.2:/recordings', 'fstype': 'nfs4',
                      'fsroot': '/camera', 'target': str(self.nvr), 'options': 'rw,relatime'}

    def check(self, mount=None):
        reply = {'filesystems': [self.mount if mount is None else mount]}
        with patch.object(scrypted_runtime.subprocess, 'run',
                          return_value=SimpleNamespace(stdout=json.dumps(reply).encode())):
            return scrypted_runtime.validate(str(self.data), str(self.nvr),
                                             self.mount['source'], 'nfs4', '/camera')

    def test_exact_mounted_writable_source_passes_without_changing_state(self):
        before = {(p.name, p.stat().st_ino, p.stat().st_mtime_ns) for p in self.data.iterdir()}
        self.assertEqual(self.check()['writes_performed'], False)
        self.assertEqual(before, {(p.name, p.stat().st_ino, p.stat().st_mtime_ns)
                                  for p in self.data.iterdir()})
        self.assertEqual(list(self.nvr.iterdir()), [])

    def test_wrong_mount_wrong_subdirectory_ancestor_mount_or_read_only_is_refused(self):
        for field, value in (('source', '198.18.20.3:/recordings'), ('fstype', 'ext4'),
                             ('fsroot', '/another-camera'), ('target', self.temp.name),
                             ('options', 'ro,relatime')):
            mount = {**self.mount, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(mount)

    def test_absent_recordings_never_creates_a_local_directory(self):
        self.nvr.rmdir()
        with self.assertRaises(FileNotFoundError):
            self.check()
        self.assertFalse(self.nvr.exists())

    def test_symlink_state_or_recordings_and_empty_state_are_refused(self):
        (self.data / 'scrypted.db').rmdir()
        with self.assertRaises(FileNotFoundError):
            self.check()
        (self.data / 'scrypted.db').mkdir()
        self.nvr.rmdir()
        self.nvr.symlink_to(self.data, target_is_directory=True)
        with self.assertRaises(OSError):
            self.check()

    def test_read_only_kernel_view_or_no_write_access_is_refused(self):
        with patch.object(scrypted_runtime.os, 'fstatvfs', return_value=SimpleNamespace(f_flag=os.ST_RDONLY)), self.assertRaises(ValueError):
            self.check()
        with patch.object(scrypted_runtime.os, 'access', return_value=False), self.assertRaises(ValueError):
            self.check()


class RenderPreservation(unittest.TestCase):
    def test_latest_image_policy_is_exclusive_to_the_scrypted_adapter(self):
        selected={'image':'ghcr.io/koush/scrypted:latest'}
        self.assertEqual(component_runtime._image(selected,'scrypted'),(selected['image'],'always'))
        with self.assertRaises(ValueError):component_runtime._image(selected,'homeassistant')

    def test_owned_storage_hook_and_both_listener_contracts_precede_core_readiness(self):
        app=self.app();app['settings']={'recording_mount':{
            'source':'nas.example.invalid:/recordings','filesystem':'nfs4','root':'/camera'}}
        app['role_addresses']={'web_interface':'198.18.25.10'}
        app['listeners']={name:{'service':'scrypted','namespace':'host','protocol':'tcp','port':port}
            for name,port in (('web_listener',80),('secure_listener',443))}
        hook=component_app_hooks.descriptors(app,compose_file='/opt/homelab-app/compose.yml')
        self.assertEqual([row['source']for row in hook['helpers']],['scrypted_runtime.py','scrypted-datastore.js'])
        self.assertEqual(hook['scrypted_state']['argv'][-6:],['--source','nas.example.invalid:/recordings',
            '--filesystem','nfs4','--root','/camera'])
        rows=component_checks._scrypted(app,None)
        self.assertEqual(rows[-1]['argv'][-1],'http://198.18.25.10:80/')
        for mutate in (lambda a:a['listeners'].pop('secure_listener'),
                       lambda a:a['listeners']['secure_listener'].update(port=10443),
                       lambda a:a['listeners'].update(extra={'service':'scrypted'})):
            bad=copy.deepcopy(app);mutate(bad)
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):component_checks._scrypted(bad,None)
        app['storage_paths'].pop('recordings')
        with self.assertRaises(ValueError):component_app_hooks.descriptors(app,compose_file='/opt/homelab-app/compose.yml')

    def app(self):
        return {'adapter': 'scrypted', 'identity': {'runtime_id':'scrypted'}, 'storage_paths': {
            'data': {'source': '/srv/example/config', 'target': '/server/volume',
                     'read_only': False, 'kind': 'directory'},
            'recordings': {'source': '/srv/example/recordings', 'target': '/nvr',
                           'read_only': False, 'kind': 'directory'}},
            'containers': {'scrypted': {'memory_mib': 4096, 'cpu_limit': 4,
                                         'pids_limit': 512, 'user': '0:0'}}}

    def render(self, app):
        with patch.object(component_runtime, '_service', return_value={
                'image': 'ghcr.io/koush/scrypted:latest', 'mem_limit': '4096m',
                'environment': {}}):
            return component_runtime._scrypted(app, {})['scrypted']

    def test_container_paths_identity_and_no_restart_are_preserved(self):
        app = self.app(); before = copy.deepcopy(app)
        service = self.render(app)
        self.assertEqual(app, before)
        self.assertEqual((service['user'], service['restart'], service['network_mode']), ('0:0', 'no', 'host'))
        self.assertEqual(service['memswap_limit'], '4096m')
        self.assertEqual((service['hostname'],service['container_name']),('scrypted','scrypted'))
        self.assertEqual(service['environment']['SCRYPTED_INSECURE_PORT'],'80')
        self.assertEqual(service['environment']['SCRYPTED_SECURE_PORT'],'443')
        self.assertEqual({m['target'] for m in service['volumes']},
                         {'/server/volume', '/nvr', '/opt/homelab-app/scrypted-datastore.js'})
        self.assertTrue(all(m['bind']['create_host_path'] is False for m in service['volumes']))
        self.assertTrue(service['volumes'][-1]['read_only'])
        self.assertNotIn('entrypoint', service)
        self.assertTrue(service['command'][-1].startswith('node /opt/homelab-app/scrypted-datastore.js verify;'))
        self.assertNotIn('devices', service)
        self.assertNotIn('privileged', service)

    def test_changed_identity_paths_privileges_or_overlapping_state_are_refused(self):
        cases = []
        app = self.app(); app['containers']['scrypted']['user'] = '1000:1000'; cases.append(app)
        app = self.app(); app['devices'] = {'gpu': 'example'}; cases.append(app)
        app = self.app(); app['containers']['scrypted']['cap_add'] = ['NET_ADMIN']; cases.append(app)
        for source in ('/', '/srv/example/config', '/srv/example/config/recordings'):
            app = self.app(); app['storage_paths']['recordings']['source'] = source; cases.append(app)
        for app in cases:
            with self.subTest(app=app), self.assertRaises(ValueError):
                self.render(app)
