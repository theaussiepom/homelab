"""Portable server runtime and durable-order tests; native calls are mocked."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import database_server_network_runtime as runtime
import database_network_cutover as cutover
import database_network_server as renderer
from test_database_network_cutover import packet as pg_packet, Driver
from test_database_network_server import contract
from test_database_server_cutover import SOURCES


def request(kind):
    net = contract()['networks'][kind]; text = next(iter(SOURCES[kind].values()))
    address = net['server']['address']; end = address.split('.')[-1]
    return {'schema': runtime.CHANGE, 'before': {'schema': runtime.SCHEMA,
        'identity': {'kind': kind, 'vmid': net['server']['vmid'], 'hostname': kind,
                     'address': '10.88.25.' + end, 'mac': '02:25:00:00:02:06'},
        'config': {'text': text, 'sha256': runtime.sha(text.encode()), 'uid': 100, 'gid': 100, 'mode': 0o600},
        'process': {'MainPID': '123', 'ActiveState': 'active', 'ActiveEnterTimestampMonotonic': '1'},
        'health': {'version': 'retained'}, 'listeners': ['original']},
        'endpoint': {'address': address, 'port': runtime.PORTS[kind]},
        'old_address': '10.88.30.' + end, 'clients': copy.deepcopy(net['clients']),
        'inactive_client_vmids': [c['vmid'] for c in net['clients']],
        'files': {runtime.FILE_KEYS[kind]: runtime.candidate(kind, text, address)}, 'allow_restart': True}


def single(kind):
    value = pg_packet(); member = value['members']['postgresql']
    member['vmid'] = contract()['networks'][kind]['server']['vmid']
    member['network_packet']['vmid'] = member['vmid']; member['runtime_packet'] = request(kind)
    return dict(value, schema='homelab-database-server-cutover-v1', operation=kind + '-example', members={kind: member})


class RuntimeTests(unittest.TestCase):
    def test_command_preserves_short_default_and_forwards_restart_timeout(self):
        with patch.object(runtime.subprocess, 'run') as run:
            run.return_value.stdout = b'ok'
            self.assertEqual(runtime.command(['inspect']), 'ok')
            self.assertEqual(run.call_args.kwargs['timeout'], 30)
            self.assertEqual(runtime.command(['restart'], timeout=180), 'ok')
            self.assertEqual(run.call_args.kwargs['timeout'], 180)

    def test_portable_candidate_exactly_matches_the_pure_renderer(self):
        for kind in SOURCES:
            value = request(kind); original = copy.deepcopy(value)
            selected, engine, text = runtime.validate(value)
            candidate = renderer.render(contract(), kind, SOURCES[kind], phase='cutover',
                client_vmids=value['inactive_client_vmids'])
            self.assertEqual(candidate['files'], value['files'])
            self.assertEqual(text, next(iter(candidate['files'].values())))
            self.assertEqual(value, original)

    def test_extra_config_write_wrong_endpoint_changed_identity_or_active_app_refuses(self):
        for kind in SOURCES:
            changes = []
            v = request(kind); v['files'][runtime.FILE_KEYS[kind]] += '# arbitrary write'; changes.append(v)
            v = request(kind); v['endpoint']['port'] = 5432; changes.append(v)
            v = request(kind); v['allow_restart'] = False; changes.append(v)
            v = request(kind); v['inactive_client_vmids'] = []; changes.append(v)
            v = request(kind); v['before']['config']['sha256'] = 'f' * 64; changes.append(v)
            for value in changes:
                with self.subTest(kind=kind, value=value), self.assertRaises(ValueError): runtime.validate(value)

    def test_listener_activation_refuses_new_client_before_any_write_or_restart(self):
        for kind in SOURCES:
            value = request(kind)
            with patch.object(runtime, 'guard'), patch.object(runtime, 'read', return_value=value['before']['config']), \
                    patch.object(runtime, 'no_clients', side_effect=ValueError('new writer')), \
                    patch.object(runtime.tempfile, 'mkstemp') as create:
                with self.assertRaises(ValueError): runtime.run('activate', value, lambda argv: self.fail('native command'))
                create.assert_not_called()

    def test_listener_parser_uses_the_actual_tcp_only_ss_columns(self):
        self.assertEqual(runtime.sockets('mariadb', lambda argv: 'LISTEN 0 70 0.0.0.0:3306 0.0.0.0:*\n'), ['0.0.0.0:3306'])
        self.assertEqual(runtime.sockets('influxdb', lambda argv: 'LISTEN 0 4096 *:8086 *:*\n'), ['*:8086'])

    def test_verify_never_changes_configuration_or_restarts_service(self):
        for kind in SOURCES:
            value = request(kind); text = next(iter(value['files'].values()))
            config = dict(value['before']['config'], text=text, sha256=runtime.sha(text.encode()))
            with patch.object(runtime, 'guard'), patch.object(runtime, 'read', return_value=config), \
                    patch.object(runtime, 'process'), patch.object(runtime, 'sockets', return_value=[value['endpoint']['address'] + ':' + str(runtime.PORTS[kind])]), \
                    patch.object(runtime, 'health', return_value=value['before']['health']), \
                    patch.object(runtime.os, 'replace') as replace:
                result = runtime.run('verify', value, lambda argv: self.fail('restart'))
                self.assertFalse(result['changed']); replace.assert_not_called()

    def test_unexpected_management_or_wildcard_listener_never_verifies(self):
        value = request('mariadb'); text = next(iter(value['files'].values()))
        config = dict(value['before']['config'], text=text, sha256=runtime.sha(text.encode()))
        with patch.object(runtime, 'guard'), patch.object(runtime, 'read', return_value=config), \
                patch.object(runtime, 'process'), patch.object(runtime, 'sockets', return_value=['0.0.0.0:3306']):
            with self.assertRaises(ValueError): runtime.run('verify', value)

    def test_activation_changes_only_listener_preserves_file_metadata_and_restarts_once(self):
        for kind in SOURCES:
            with tempfile.TemporaryDirectory() as temp:
                value = request(kind); path = Path(temp).resolve() / runtime.FILES[kind].name
                path.write_text(value['before']['config']['text']); path.chmod(0o600)
                value['before']['config'] = runtime.read(path)
                commands = []
                with patch.dict(runtime.FILES, {kind: path}), patch.object(runtime, 'guard'), \
                        patch.object(runtime, 'no_clients'), patch.object(runtime, 'process'), \
                        patch.object(runtime, 'sockets', return_value=[value['endpoint']['address'] + ':' + str(runtime.PORTS[kind])]), \
                        patch.object(runtime, 'health', return_value=value['before']['health']):
                    result = runtime.run('activate', value, lambda argv, **kwargs: commands.append((argv, kwargs)))
                    self.assertTrue(result['changed'])
                    self.assertEqual(path.read_text(), next(iter(value['files'].values())))
                    self.assertEqual(path.stat().st_uid, os.getuid())
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(commands, [(['systemctl', 'restart', kind + '.service'], {'timeout': 180})])
                    with self.assertRaises(ValueError): runtime.run('activate', value, lambda argv: self.fail('replay'))

    def test_restart_failure_retains_new_file_and_does_not_automatically_undo_it(self):
        value = request('mariadb')
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp).resolve() / '99-homelab.cnf'; path.write_text(value['before']['config']['text']); path.chmod(0o600)
            value['before']['config'] = runtime.read(path)
            with patch.dict(runtime.FILES, {'mariadb': path}), patch.object(runtime, 'guard'), \
                    patch.object(runtime, 'no_clients'), patch.object(runtime, 'process'):
                def fail(argv, **kwargs): raise RuntimeError('synthetic restart failure')
                with self.assertRaises(RuntimeError): runtime.run('activate', value, fail)
                self.assertEqual(path.read_text(), next(iter(value['files'].values())))
                with self.assertRaises(ValueError): runtime.run('activate', value, fail)


class CoordinationTests(unittest.TestCase):
    def test_source_validation_binds_runtime_vmid_before_any_native_phase(self):
        for kind in SOURCES:
            value = single(kind)
            member = value['members'][kind]
            member['runtime_packet']['before']['identity']['vmid'] = member['vmid'] + 1
            with tempfile.TemporaryDirectory() as temp:
                state = Path(temp); state.chmod(0o700); driver = Driver()
                with self.assertRaises(ValueError): cutover.run(value, state, driver)
                self.assertEqual(driver.calls, [])
                self.assertEqual(list(state.iterdir()), [])

    def test_single_server_uses_existing_custody_and_sequence_without_activating_apps(self):
        for kind in SOURCES:
            with tempfile.TemporaryDirectory() as temp:
                state = Path(temp); state.chmod(0o700); driver = Driver(); value = single(kind)
                cutover.run(value, state, driver)
                cutover.validate_catalogue(value, contract())
                self.assertEqual(driver.calls, [(step, kind) for step in ('preflight', 'startup', 'network', 'activate', 'verify')])
                driver.calls.clear(); cutover.run(value, state, driver)
                self.assertEqual(driver.calls, [('verify', kind)])

    def test_server_failure_holds_and_a_fresh_operation_cannot_replay(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp); state.chmod(0o700); value = single('mariadb'); driver = Driver(('activate', 'mariadb'))
            with self.assertRaises(RuntimeError): cutover.run(value, state, driver)
            calls = list(driver.calls); driver.fail = None
            with self.assertRaises(ValueError): cutover.run(dict(value, operation='mariadb-next'), state, driver)
            self.assertEqual(driver.calls, calls)


if __name__ == '__main__': unittest.main()
