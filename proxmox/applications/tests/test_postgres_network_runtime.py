"""Real disposable file effects with recording PG/systemctl stubs; no native PG."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import postgres_network_runtime as runtime
from test_database_network_server import contract, postgres


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        for name,value in [('CLUSTERS',self.root/'etc/postgresql'),('DATA',self.root/'data'),
                           ('IDENTITY',self.root/'identity.json'),('UID_MAP',self.root/'uid_map'),
                           ('PVE',self.root/'pve'),('ROOT_UID',os.getuid())]:
            p = patch.object(runtime,name,value); p.start(); self.addCleanup(p.stop)
        for p in [patch.object(runtime.os,'geteuid',return_value=0),
                  patch.object(runtime.pwd,'getpwnam',return_value=types.SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid())),
                  patch.object(runtime.time,'sleep')]:
            p.start(); self.addCleanup(p.stop)
        self.identity = {'vmid':208,'hostname':'postgresql','address':'10.88.25.23','mac':'02:25:00:00:00:23'}
        self.cluster = {'major':16,'name':'main'}; self.paths = runtime.cluster_paths(self.cluster)
        for name,text in postgres().items(): self.put(self.paths[name],text)
        self.put(self.paths['config'],"# existing Debian cluster\ninclude_dir = 'conf.d'\n")
        self.put(self.paths['auto'],'# no automatic overrides\n')
        self.put(runtime.IDENTITY,json.dumps({'vmid':208,'hostname':'postgresql','address':'10.88.25.23','kind':'postgresql'}))
        self.put(runtime.UID_MAP,'0 100000 65536\n')
        self.data = self.paths['auto'].parent/'preserve-database'
        self.put(self.data,'existing database bytes and credentials must survive\n')
        self.data_before = self.snapshot(self.data)
        self.calls = []; self.restarts = 0; self.running = True
        self.pid = 123; self.started = '1000'; self.start_time = '2026-10-28 01:00:00+00'
        self.listening = '127.0.0.1,10.88.30.23'
        self.binary_version = 'postgres (PostgreSQL) 16.10 (Fixture)'
        self.server_version = '16.10'; self.server_version_num = '160010'
        self.config_invalid = False; self.hba_invalid = False; self.restart_fails = False; self.keep_old_listener = False

    def put(self,path,text):
        path.parent.mkdir(parents=True,exist_ok=True); path.write_text(text); path.chmod(0o600)

    def snapshot(self,path):
        info = path.stat()
        return path.read_bytes(),info.st_ino,info.st_mtime_ns,info.st_uid,info.st_gid,info.st_mode

    def native_hba(self):
        def row(kind,db,user,address,mask,auth):
            return dict(type=kind,database=[db],user_name=[user],address=address,netmask=mask,
                        auth_method=auth,options=None,file_name=str(self.paths['pg_hba.conf']),error=None)
        rows = [row('local','all','postgres',None,None,'peer'),row('local','all','all',None,None,'peer'),
                row('host','all','all','127.0.0.1','255.255.255.255','scram-sha-256'),
                row('host','all','all','::1','ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff','scram-sha-256')]
        if '10.88.31.32/32' in self.paths['pg_hba.conf'].read_text():
            rows += [row('host','all','all','10.88.31.32','255.255.255.255','scram-sha-256'),
                     row('host','all','all','10.88.31.20','255.255.255.255','scram-sha-256')]
        else:
            rows += [row('host','all','all','10.88.30.0','255.255.255.0','scram-sha-256')]
        if self.hba_invalid: rows[-1]['error'] = 'SYNTHETIC_PRIVATE_PARSE_ERROR'
        return rows

    def execute(self,argv,timeout=20):
        self.calls.append((list(argv),timeout))
        if argv[0] == 'systemctl':
            self.assertEqual(argv[2],runtime.unit_name(self.cluster))
            if argv[1] == 'restart':
                self.restarts += 1
                if self.restart_fails: raise subprocess.CalledProcessError(1,argv,stderr=b'PRIVATE_ERROR')
                self.running = True; self.pid = 456; self.started = '2000'; self.start_time = '2026-10-28 02:00:00+00'
                if not self.keep_old_listener: self.listening = '127.0.0.1,10.88.31.23'
                return b''
            self.assertEqual(argv[1],'show')
            return ('MainPID='+str(self.pid if self.running else 0)+'\nActiveEnterTimestampMonotonic='+self.started+
                    '\nActiveState='+('active' if self.running else 'failed')+'\n').encode()
        if argv[0] == 'ss':
            return ''.join('LISTEN 0 128 '+ip+':5432 0.0.0.0:*\n' for ip in self.listening.split(',')).encode()
        if argv[-1] == '--version': return (self.binary_version+'\n').encode()
        if '-C' in argv:
            if self.config_invalid: raise subprocess.CalledProcessError(1,argv,stderr=b'PRIVATE_CONFIG_ERROR')
            return b'127.0.0.1,10.88.31.23\n'
        self.assertEqual(argv[-1],runtime.SQL)
        if not self.running: raise subprocess.CalledProcessError(2,argv)
        return json.dumps(dict(version=self.server_version,version_num=self.server_version_num,config_file=str(self.paths['config']),
            hba_file=str(self.paths['pg_hba.conf']),data_directory=str(self.paths['auto'].parent),port='5432',
            listen_addresses=self.listening,start_time=self.start_time,file_errors=[],hba=self.native_hba())).encode()

    def inspected(self):
        return runtime.inspect(self.identity,self.cluster,self.execute)

    def packet(self):
        return runtime.prepare(contract(),self.inspected(),[211,202],'10.88.30.23')

    def assert_data_unchanged(self):
        self.assertEqual(self.snapshot(self.data),self.data_before)

    def test_inspection_is_read_only_and_contains_exact_cluster_and_file_bindings(self):
        before = {path:self.snapshot(path) for path in self.paths.values()}
        real_open = os.open
        with patch.object(runtime.os,'open',wraps=real_open) as opened:
            result = self.inspected()
        self.assertEqual(result['unit'],'postgresql@16-main.service')
        self.assertEqual(result['settings']['listen_addresses'],'127.0.0.1,10.88.30.23')
        self.assertEqual(result['files']['homelab.conf']['text'],postgres()['homelab.conf'])
        self.assertTrue(all(not (call.args[1] & (os.O_RDWR|os.O_WRONLY|os.O_TRUNC|os.O_CREAT)) for call in opened.call_args_list))
        self.assertEqual({path:self.snapshot(path) for path in self.paths.values()},before)
        self.assert_data_unchanged(); self.assertEqual(self.restarts,0)

    def test_prepare_uses_shared_exact_renderer_and_selects_two_current_clients_only(self):
        packet = self.packet()
        self.assertEqual([c['vmid'] for c in packet['clients']],[202,211])
        self.assertEqual(packet['candidate']['homelab.conf']['text'],postgres()['homelab.conf'].replace('10.88.30.23','10.88.31.23'))
        self.assertNotIn('10.88.31.27',packet['candidate']['pg_hba.conf']['text'])
        self.assertEqual(packet['activation'],{'action':'restart','unit':'postgresql@16-main.service'})

    def test_preflight_refuses_original_process_or_config_drift_without_writes(self):
        packet = self.packet(); self.pid = 999
        before = {p:self.snapshot(p) for p in self.paths.values()}
        with self.assertRaisesRegex(ValueError,'healthy'): runtime.preflight(packet,self.execute)
        self.assertEqual({p:self.snapshot(p) for p in self.paths.values()},before)
        self.assertEqual(self.restarts,0)

    def test_preflight_passes_unchanged_healthy_snapshot_and_request_schema_is_closed(self):
        packet = self.packet(); before = {p:self.snapshot(p) for p in self.paths.values()}
        self.assertEqual(runtime.run('preflight',packet,self.execute)['phase'],'preflight')
        request = {'schema':runtime.SCHEMA,'identity':self.identity,'cluster':self.cluster}
        self.assertEqual(runtime.run('inspect',request,self.execute),packet['before'])
        with self.assertRaises(ValueError): runtime.run('inspect',dict(request,extra=True),self.execute)
        self.assertEqual({p:self.snapshot(p) for p in self.paths.values()},before); self.assertEqual(self.restarts,0)

    def test_actual_cluster_paths_and_version_must_match_derived_identity(self):
        settings = self.inspected()['settings']
        for key,value in [('config_file','/etc/postgresql/other/postgresql.conf'),
                          ('hba_file','/elsewhere/pg_hba.conf'),('data_directory','/other-data'),
                          ('version_num','170001')]:
            changed = dict(settings,**{key:value})
            with self.subTest(field=key), patch.object(runtime,'query',return_value=changed):
                with self.assertRaisesRegex(ValueError,'cluster paths'): self.inspected()
        self.assertEqual(self.restarts,0); self.assert_data_unchanged()

    def test_activation_preserves_data_owners_modes_and_inodes_and_restarts_only_one_cluster(self):
        packet = self.packet(); before = {p:self.snapshot(p) for p in self.paths.values()}
        result = runtime.activate(packet,self.execute)
        self.assertTrue(result['changed']); self.assertEqual(result['hba_validation_before_restart'],'postgresql-parser')
        self.assertEqual(self.restarts,1)
        mutations = [argv for argv,_ in self.calls if argv[:2] == ['systemctl','restart']]
        self.assertEqual(mutations,[['systemctl','restart','postgresql@16-main.service']])
        for name in ('homelab.conf','pg_hba.conf'):
            self.assertEqual(self.paths[name].read_text(),packet['candidate'][name]['text'])
            self.assertEqual(self.snapshot(self.paths[name])[1:2]+self.snapshot(self.paths[name])[3:],
                             before[self.paths[name]][1:2]+before[self.paths[name]][3:])
        for name in ('config','auto'): self.assertEqual(self.snapshot(self.paths[name]),before[self.paths[name]])
        self.assert_data_unchanged()

    def test_provider_cycle_may_leave_cluster_down_and_changed_pid_before_activation(self):
        packet = self.packet(); self.running = False; self.pid = 999; self.started = '1500'
        result = runtime.activate(packet,self.execute)
        self.assertEqual(result['hba_validation_before_restart'],'strict-supported-policy')
        self.assertEqual(self.restarts,1); self.assert_data_unchanged()

    def test_future_verification_is_read_only_and_never_restarts(self):
        packet = self.packet(); runtime.activate(packet,self.execute)
        before = {p:self.snapshot(p) for p in self.paths.values()}; self.calls.clear()
        real_open = os.open
        with patch.object(runtime.os,'open',wraps=real_open) as opened:
            result = runtime.verify(packet,self.execute)
        self.assertFalse(result['changed']); self.assertEqual(self.restarts,1)
        self.assertFalse(any(argv[:2] == ['systemctl','restart'] for argv,_ in self.calls))
        self.assertTrue(all(not (call.args[1] & (os.O_RDWR|os.O_WRONLY|os.O_TRUNC|os.O_CREAT)) for call in opened.call_args_list))
        self.assertEqual({p:self.snapshot(p) for p in self.paths.values()},before); self.assert_data_unchanged()

    def test_later_minor_update_verifies_but_pre_change_binary_drift_still_refuses(self):
        packet = self.packet(); runtime.activate(packet,self.execute)
        self.binary_version = 'postgres (PostgreSQL) 16.11 (Fixture)'
        self.server_version = '16.11'; self.server_version_num = '160011'
        self.assertEqual(runtime.verify(packet,self.execute)['status'],'passed')
        self.assertEqual(self.restarts,1)
        with self.assertRaises(ValueError): runtime.preflight(packet,self.execute)
        with self.assertRaises(ValueError): runtime.activate(packet,self.execute)
        self.assertEqual(self.restarts,1)

    def test_later_major_update_or_cluster_path_drift_still_refuses(self):
        packet = self.packet(); runtime.activate(packet,self.execute)
        self.server_version = '17.1'; self.server_version_num = '170001'
        with self.assertRaises(ValueError): runtime.verify(packet,self.execute)
        self.server_version = '16.10'; self.server_version_num = '160010'
        settings = self.inspected()['settings']; settings['data_directory'] = '/other-data'
        with patch.object(runtime,'query',return_value=settings):
            with self.assertRaises(ValueError): runtime.verify(packet,self.execute)
        self.assertEqual(self.restarts,1)

    def test_changed_bound_candidate_or_extra_configuration_change_fails_before_writes(self):
        for mutate in (lambda p:p['candidate']['homelab.conf'].update(sha256='0'*64),
                       lambda p:p['candidate']['pg_hba.conf'].update(text='host all all 0.0.0.0/0 trust\n'),
                       lambda p:p['activation'].update(unit='postgresql.service'),
                       lambda p:p.update(extra='unreviewed')):
            packet = self.packet(); mutate(packet); self.calls.clear()
            before = {p:self.snapshot(p) for p in self.paths.values()}
            with self.assertRaises(ValueError): runtime.activate(packet,self.execute)
            self.assertEqual(self.calls,[]); self.assertEqual(self.restarts,0)
            self.assertEqual({p:self.snapshot(p) for p in self.paths.values()},before)

    def test_configuration_drift_after_provider_cycle_stops_before_staging(self):
        packet = self.packet(); self.running = False
        self.put(self.paths['homelab.conf'],self.paths['homelab.conf'].read_text()+'# drift\n')
        before = {p:self.snapshot(p) for p in self.paths.values()}
        with self.assertRaisesRegex(ValueError,'configuration changed'): runtime.activate(packet,self.execute)
        self.assertEqual({p:self.snapshot(p) for p in self.paths.values()},before); self.assertEqual(self.restarts,0)

    def test_config_or_native_hba_validation_failure_preserves_candidate_without_restart(self):
        for failure in ('config','hba'):
            with self.subTest(failure=failure):
                original = postgres()
                for name,text in original.items(): self.put(self.paths[name],text)
                packet = self.packet()
                self.config_invalid = failure == 'config'; self.hba_invalid = failure == 'hba'
                with self.assertRaises((ValueError,subprocess.CalledProcessError)): runtime.activate(packet,self.execute)
                self.assertEqual(self.restarts,0)
                self.assertEqual(self.paths['homelab.conf'].read_text(),packet['candidate']['homelab.conf']['text'])
                self.assert_data_unchanged(); self.config_invalid = self.hba_invalid = False

    def test_failed_restart_is_not_repeated_or_rolled_back(self):
        packet = self.packet(); self.restart_fails = True
        with self.assertRaises(subprocess.CalledProcessError): runtime.activate(packet,self.execute)
        self.assertEqual(self.restarts,1)
        self.assertEqual(self.paths['pg_hba.conf'].read_text(),packet['candidate']['pg_hba.conf']['text'])
        self.assert_data_unchanged()

    def test_retired_listener_after_restart_fails_without_another_restart(self):
        packet = self.packet(); self.keep_old_listener = True
        with self.assertRaisesRegex(ValueError,'listeners'): runtime.activate(packet,self.execute)
        self.assertEqual(self.restarts,1); self.assert_data_unchanged()

    def test_extra_actual_socket_is_refused_even_when_show_listener_is_correct(self):
        packet = self.packet(); runtime.activate(packet,self.execute)
        original = self.execute
        def extra_socket(argv,timeout=20):
            result = original(argv,timeout)
            return result+b'LISTEN 0 128 10.88.30.23:5432 0.0.0.0:*\n' if argv[0] == 'ss' else result
        with self.assertRaisesRegex(ValueError,'listeners'): runtime.verify(packet,extra_socket)
        self.assertEqual(self.restarts,1); self.assert_data_unchanged()

    def test_extra_remote_hba_and_includes_require_review(self):
        # Bind a synthetic inspected text without claiming PostgreSQL accepted it.
        before = self.inspected()
        text = before['files']['pg_hba.conf']['text']+'host all all 10.89.0.0/16 scram-sha-256\n'
        before['files']['pg_hba.conf'].update(text=text,sha256=runtime.sha(text.encode()))
        with self.assertRaisesRegex(ValueError,'extra remote HBA'): runtime.prepare(contract(),before,[211,202],'10.88.30.23')
        for text in ('include additional.conf\n','host all all 10.88.30.0/24 md5\n'):
            with self.assertRaises(ValueError): runtime.hba_rows(text,self.paths['pg_hba.conf'])

    def test_symlinks_extra_includes_auto_overrides_and_wrong_guest_are_read_only_refusals(self):
        self.put(self.paths['auto'],"listen_addresses = '*'\n")
        with self.assertRaisesRegex(ValueError,'automatic'): self.inspected()
        self.put(self.paths['auto'],'# no automatic overrides\n')
        self.put(self.paths['config'],"include_dir = 'conf.d'\ninclude = '/etc/other.conf'\n")
        with self.assertRaisesRegex(ValueError,'include graph'): self.inspected()
        self.put(self.paths['config'],"include_dir = 'conf.d'\n")
        target = self.paths['homelab.conf'].with_name('saved'); self.paths['homelab.conf'].rename(target)
        self.paths['homelab.conf'].symlink_to(target)
        with self.assertRaisesRegex(ValueError,'symlink'): self.inspected()
        self.paths['homelab.conf'].unlink(); target.rename(self.paths['homelab.conf'])
        self.put(runtime.UID_MAP,'0 0 4294967295\n')
        with self.assertRaisesRegex(ValueError,'privileged'): self.inspected()
        self.put(runtime.UID_MAP,'0 100000 65536\n')
        wrong = dict(self.identity,vmid=209)
        with self.assertRaisesRegex(ValueError,'identity differs'): runtime.inspect(wrong,self.cluster,self.execute)
        self.assertEqual(self.restarts,0); self.assert_data_unchanged()

    def test_partial_file_failure_is_preserved_without_restart_or_rollback(self):
        packet = self.packet()
        with patch.object(runtime.os,'fsync',side_effect=OSError('synthetic write failure')):
            with self.assertRaises(OSError): runtime.activate(packet,self.execute)
        self.assertEqual(self.paths['homelab.conf'].read_text(),packet['candidate']['homelab.conf']['text'])
        self.assertEqual(self.paths['pg_hba.conf'].read_text(),packet['before']['files']['pg_hba.conf']['text'])
        self.assertEqual(self.restarts,0); self.assert_data_unchanged()

    def test_command_does_not_inherit_credential_or_pg_option_environment(self):
        with patch.object(runtime.subprocess,'run',return_value=types.SimpleNamespace(stdout=b'OK')) as call:
            self.assertEqual(runtime.command(['systemctl','show','postgresql@16-main.service']),b'OK')
        self.assertEqual(set(call.call_args.kwargs['env']),{'PATH','LANG','LC_ALL','HOME','PGCONNECT_TIMEOUT'})

    def test_cli_failure_has_no_private_input_or_traceback_in_output(self):
        helper = Path(runtime.__file__)
        result = subprocess.run([sys.executable,str(helper),'activate'],input=b'{"secret":"DO_NOT_PRINT"}',
                                stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(result.stdout,b'')
        self.assertNotIn(b'DO_NOT_PRINT',result.stderr); self.assertNotIn(b'Traceback',result.stderr)


if __name__ == '__main__': unittest.main()
