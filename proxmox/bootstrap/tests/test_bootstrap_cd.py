"""Exercise the host API transaction, conflicting changes, and failed-operation hold."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bootstrap_cd as cd
import host_cd_access as access


def config():
    return {'schema': 'homelab-bootstrap-cd-v1', 'endpoint': 'https://198.18.25.10:8006/',
            'node': 'pve', 'deploy': {'vmid': 900, 'mac': '02:00:00:00:09:00'}, 'bridge': 'vmbr30',
            'applications': [{'vmid': 208, 'hostname': 'postgresql'}],
            'existing_grants': [{'path': '/vms/900', 'role': 'PVEVMAdmin', 'propagate': 0}],
            'backup_source': '198.18.20.2:/backups/deploy'}


class FakeAPI:
    def __init__(self):
        self.network = [{'iface': 'vmbr0', 'type': 'bridge', 'bridge_ports': 'mgmt0',
                         'autostart': 1, 'active': 1, 'method': 'manual', 'method6': 'manual'}]
        self.acls = [{'path': '/vms/900', 'roleid': 'PVEVMAdmin', 'propagate': 0,
                      'type': 'token', 'ugid': 'root@pam!homelab-deploy-900'}]
        self.meta = {'privsep': 1, 'expire': 0}
        self.pending = ''
        self.writes = []
        self.fail_reload = False
        self.extra_pending = False
        self.guests = [{'vmid': 900, 'node': 'pve', 'name': 'deploy', 'type': 'lxc', 'status': 'running'}]

    def call(self, path, method='GET', values=None):
        if method != 'GET':
            self.writes.append((path, method, values))
            if method == 'POST':
                self.network.append({**values, 'active': 0, 'method': 'manual', 'method6': 'manual'})
                self.pending = 'isolated bridge addition'
                if self.extra_pending:
                    self.network[0]['bridge_ports'] = 'different0'
            elif method == 'PUT' and path.endswith('/network'):
                if self.fail_reload:
                    raise ValueError('Synthetic interrupted reload')
                self.network[-1]['active'] = 1
                self.pending = ''
                return {'data': 'UPID:pve:synthetic'}
            elif path == '/access/acl':
                self.acls.append({'path': values['path'], 'roleid': values['roles'],
                                  'propagate': values['propagate'], 'ugid': values['tokens'], 'type': 'token'})
            else:
                raise AssertionError((path, method))
            return {'data': None}
        if path == '/nodes': data = [{'node': 'pve'}]
        elif path == '/cluster/resources?type=vm': data = self.guests
        elif path.endswith('/lxc/900/config'):
            data = {'hostname': 'deploy', 'unprivileged': 1, 'protection': 1,
                    'net0': 'bridge=vmbr0,hwaddr=02:00:00:00:09:00,tag=25'}
        elif path.endswith('/token/homelab-deploy-900'): data = self.meta
        elif path == '/access/acl': data = self.acls
        elif path.endswith('/network'): return copy.deepcopy({'data': self.network, 'changes': self.pending})
        elif '/tasks/' in path: data = {'status': 'stopped', 'exitstatus': 'OK'}
        elif path.startswith('/access/permissions?'):
            data = {r['path']: {'VM.Allocate' if r['roleid'] == 'PVEVMAdmin' else 'SDN.Use': 0} for r in self.acls}
        else: raise AssertionError(path)
        return copy.deepcopy({'data': data})


class BootstrapCDTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'state'; self.root.mkdir()
        self.nas = Path(self.tmp.name) / 'nas'; self.nas.mkdir()
        self.c = config()
        self.api = FakeAPI()

    def run_cd(self):
        mounted = {'filesystems': [{'target': str(self.nas), 'source': self.c['backup_source'], 'fstype': 'nfs4'}]}
        with patch.object(cd.subprocess, 'check_output', return_value=json.dumps(mounted).encode()):
            return cd.run(self.c, self.api, self.root, self.nas)

    def test_create_verify_and_idempotent_rerun_preserve_existing_network_and_token(self):
        old = copy.deepcopy(self.api.network[0])
        first = self.run_cd()
        self.assertTrue(first['bridge_created'])
        self.assertEqual(first['new_acl_rows'], 2)
        writes = len(self.api.writes)
        repeated = self.run_cd()
        self.assertFalse(repeated['bridge_created'])
        self.assertEqual(repeated['new_acl_rows'], 0)
        self.assertEqual(len(self.api.writes), writes)
        self.assertEqual(self.api.network[0], old)
        self.assertEqual(self.api.meta, {'privsep': 1, 'expire': 0})
        self.assertFalse((self.root / 'CONFIGURING').exists())
        for source in self.root.glob('cd-*/result.json'):
            self.assertEqual(source.read_bytes(), (self.nas / source.parent.name / 'result.json').read_bytes())

    def test_bridge_creation_uses_only_the_installed_pve_api_parameters(self):
        self.run_cd()
        request = next(values for _, method, values in self.api.writes if method == 'POST')
        # Proxmox 9.2's network create schema has no bridge_stp/bridge_fd parameters.
        self.assertEqual(set(request), {'iface', 'type', 'autostart', 'bridge_ports', 'comments'})

    def test_existing_pending_networks_and_occupied_ids_refuse_before_any_write(self):
        for change in ('pending', 'occupied', 'acl'):
            with self.subTest(change=change):
                self.api = FakeAPI()
                if change == 'pending': self.api.pending = 'unrelated physical port edit'
                if change == 'occupied': self.api.guests.append({'vmid': 208, 'name': 'unrelated', 'node': 'pve'})
                if change == 'acl': self.api.acls[0]['propagate'] = 1
                with self.assertRaises(ValueError): self.run_cd()
                self.assertEqual(self.api.writes, [])

    def test_concurrent_physical_change_refuses_reload_and_keeps_hold(self):
        self.api.extra_pending = True
        with self.assertRaisesRegex(ValueError, 'delta'): self.run_cd()
        self.assertEqual([w[1] for w in self.api.writes], ['POST'])
        self.assertTrue((self.root / 'BOOTSTRAP-CD-HOLD.json').exists())
        self.assertTrue((self.root / 'CONFIGURING').exists())

    def test_interrupted_reload_never_replays_on_next_run(self):
        self.api.fail_reload = True
        with self.assertRaises(ValueError): self.run_cd()
        writes = copy.deepcopy(self.api.writes)
        with self.assertRaisesRegex(ValueError, 'hold'): self.run_cd()
        self.assertEqual(self.api.writes, writes)

    def test_a_directory_is_not_a_backup_mount(self):
        with patch.object(cd.subprocess, 'check_output', return_value=b'{"filesystems":[]}'):
            with self.assertRaisesRegex(ValueError, 'actual mounted'): cd.run(self.c, self.api, self.root, self.nas)
        self.assertEqual(self.api.writes, [])

    def test_routed_or_physical_existing_bridge_is_refused(self):
        for field, value in [('bridge_ports', 'eth0'), ('address', '10.77.30.1'), ('gateway6', 'fe80::1'),
                             ('bridge_vlan_aware', 1), ('active', 0)]:
            self.api = FakeAPI()
            row = {'iface': 'vmbr30', 'type': 'bridge', 'autostart': 1, 'active': 1,
                   'method': 'manual', 'method6': 'manual'}
            row[field] = value
            self.api.network.append(row)
            with self.subTest(field=field), self.assertRaises(ValueError): self.run_cd()
            self.assertEqual(self.api.writes, [])

    def test_reject_protected_ids_and_unexpected_fields(self):
        for mutate in [lambda c: c.update(reboot=True), lambda c: c.update(bridge='vmbr1'),
                       lambda c: c['applications'][0].update(vmid=900),
                       lambda c: c['applications'][0].update(vmid=4920),
                       lambda c: c.update(endpoint='http://198.18.25.10:8006/')]:
            c = config(); mutate(c)
            with self.assertRaises(ValueError): cd.validate(c)

    def test_https_has_no_redirect_or_proxy_and_uses_separate_credential(self):
        with self.assertRaises(ValueError): cd.API(config()['endpoint'], 'application-token', Path('/missing'))
        with self.assertRaises(ValueError): cd.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://elsewhere')


class CredentialTests(unittest.TestCase):
    def provision(self, execute, emit):
        with patch.object(access.socket, 'gethostname', return_value='pve'), \
                patch.object(access.os.path, 'ismount', return_value=True), \
                patch.object(access.Path, 'resolve', return_value=Path('/etc/pve/nodes/pve')):
            return access.provision('pve', execute=execute, emit=emit)

    def test_partial_secret_is_saved_before_acl_failure_and_existing_identity_is_not_rotated(self):
        emitted, calls = [], []
        def execute(args):
            calls.append(args)
            if args[1:4] == ['user', 'token', 'add']: return {'value': 'synthetic-only'}
            if args[1:3] == ['acl', 'modify']: raise ValueError('Synthetic ACL failure')
            return []
        with self.assertRaises(ValueError): self.provision(execute, emitted.append)
        self.assertEqual(emitted[0]['status'], 'credential_created_acl_pending')
        self.assertIn('synthetic-only', emitted[0]['token'])
        calls.clear()
        def existing(args):
            calls.append(args)
            return [{'tokenid': access.TOKEN}]
        with self.assertRaisesRegex(ValueError, 'already exists'):
            self.provision(existing, emitted.append)
        self.assertEqual(calls, [['pveum', 'user', 'token', 'list', 'root@pam', '--output-format', 'json']])


class DiagnosticTests(unittest.TestCase):
    def test_cli_prints_fixed_refusals_but_hides_unexpected_value_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.json'
            c = config(); c['schema'] = 'invalid'; path.write_text(json.dumps(c))
            with patch.object(sys, 'argv', ['bootstrap_cd', '--config', str(path)]), \
                    self.assertRaisesRegex(SystemExit, 'Unsupported bootstrap CD schema'):
                cd.main()
            c = config(); c['endpoint'] = 'https://198.18.25.10:private-input/'; path.write_text(json.dumps(c))
            with patch.object(sys, 'argv', ['bootstrap_cd', '--config', str(path)]), self.assertRaises(SystemExit) as error:
                cd.main()
            self.assertNotIn('private-input', str(error.exception))
            self.assertEqual(str(error.exception), 'Bootstrap CD stopped. Inspect its private plan/hold; do not automatically rerun.')


if __name__ == '__main__':
    unittest.main()
