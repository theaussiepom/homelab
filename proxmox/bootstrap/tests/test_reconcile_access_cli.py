"""Permission-only bootstrap preserves scope and proves repeated native no-op."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import host_access
import reconcile_access as cli
from test_reconcile_access import ReconcileTests


class AccessCommandTests(unittest.TestCase):
    def setUp(self):
        """Use the existing real reconciler fixture and an isolated receipt store."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.work = self.root / 'access'
        self.path = self.root / 'request.json'
        self.case = ReconcileTests()
        self.case.setUp()
        original = self.case.request
        fields = ['node', 'vmid', 'storage_id', 'template_storage', 'bridge', 'guest_mac', 'applications']
        self.request = {k: original[k] for k in fields}
        self.request['vlan'] = original.get('vlan')
        self.request['expected'] = {k: original['expected'][k]
                                    for k in ['status', 'token_id', 'expires_at', 'grants']}
        self.save_request()

    def save_request(self):
        """Keep desired allocations separate from the command's evolving receipt."""
        self.path.write_text(json.dumps(self.request))

    def remote(self, host, request, source, apply):
        """Exercise the actual remote program against independently held ACL rows."""
        def run(value, execute=None, apply=False):
            with patch.object(host_access.socket, 'gethostname', return_value='pve'), \
                    patch.object(host_access, 'node_ready', return_value=True), \
                    patch.object(host_access.time, 'time', return_value=1000):
                return host_access.reconcile(value, execute or self.case.execute, apply)
        scope = {'payload': {'request': request, 'source_sha256': source, 'apply': apply},
                 'ns': {'reconcile': run, 'command': self.case.execute},
                 'hashlib': cli.hashlib, 'json': json}
        with contextlib.redirect_stdout(io.StringIO()) as output:
            exec(cli.REMOTE, scope)
        return json.loads(output.getvalue())

    def invoke(self, apply=''):
        """Keep the permission operation independent from NAS/runner configuration."""
        with patch.object(cli, 'remote', side_effect=self.remote):
            return cli.reconcile(self.work, self.path, 'pve', apply)

    def test_plan_apply_and_repeat_preserve_credentials_and_prove_zero_writes(self):
        """Persisting the successful receipt makes unchanged repeats true no-ops."""
        before = copy.deepcopy(self.case.host.acls)
        plan = self.invoke()
        self.assertEqual(self.case.host.acls, before)
        result = self.invoke(plan['plan_sha256'])
        self.assertTrue(result['access']['changed'])
        self.assertEqual(result['acl_modifications'], 2)
        self.assertFalse((self.work / 'ACCESS-HOLD.json').exists())
        saved = json.loads((self.work / 'access.json').read_text())
        self.assertNotIn('PROXMOX_VE_API_TOKEN', saved['access'])
        self.assertEqual(saved['access']['expires_at'], self.request['expected']['expires_at'])
        self.case.host.calls.clear()
        again = self.invoke()
        self.assertFalse(again['access']['changed'])
        repeated = self.invoke(again['plan_sha256'])
        self.assertFalse(repeated['access']['changed'])
        self.assertEqual(repeated['acl_modifications'], 0)
        self.assertFalse(any(c[:3] == ['pveum', 'acl', 'modify'] for c in self.case.host.calls))
        self.assertFalse(any('add' in c or 'delete' in c or 'modify' in c for c in self.case.host.calls))

    def test_drift_and_occupied_new_id_refuse_without_adopting_resources(self):
        """A declared new ID cannot silently acquire access to somebody else's guest."""
        self.case.rows.append({'vmid': 6101, 'node': 'pve', 'name': 'somebody-else'})
        with self.assertRaisesRegex(RuntimeError, 'already exists'):
            self.invoke()
        self.assertFalse((self.work / 'ACCESS-HOLD.json').exists())
        self.assertFalse(any(c[:3] == ['pveum', 'acl', 'modify'] for c in self.case.host.calls))

    def test_changed_input_or_source_cannot_apply_an_old_plan(self):
        """Apply is bound to the reviewed source and complete desired request."""
        plan = self.invoke()
        self.request['guest_mac'] = '02:00:00:00:09:01'
        self.save_request()
        with patch.object(cli, 'remote', side_effect=AssertionError('native call forbidden')):
            with self.assertRaisesRegex(cli.Refused, 'exact reviewed plan'):
                cli.reconcile(self.work, self.path, 'pve', plan['plan_sha256'])
        self.assertFalse((self.work / 'ACCESS-HOLD.json').exists())

    def test_unknown_apply_remains_held_and_receipt_does_not_advance(self):
        """A timeout never authorises a blind apply retry or receipt adoption."""
        plan = self.invoke()
        with patch.object(cli, 'remote', side_effect=subprocess.TimeoutExpired(['ssh'], 210)):
            with self.assertRaises(subprocess.TimeoutExpired):
                cli.reconcile(self.work, self.path, 'pve', plan['plan_sha256'])
        self.assertTrue((self.work / 'ACCESS-HOLD.json').exists())
        self.assertFalse((self.work / 'access.json').exists())
        attempt = json.loads((self.work / 'ACCESS-HOLD.json').read_text())['attempt']
        self.assertEqual(json.loads((self.work / attempt / 'failure.json').read_text())['error_type'], 'TimeoutExpired')
        with self.assertRaisesRegex(cli.Refused, 'held'):
            self.invoke()

    def test_failed_readback_preserves_response_without_advancing_receipt(self):
        """A status, identity or lifetime mismatch cannot become a successful baseline."""
        for change in ['status', 'token_id', 'expires_at']:
            with self.subTest(change=change):
                self.work = self.root / change
                plan = self.invoke()
                result = {'status': 'ready', 'access': copy.deepcopy(self.request['expected'])}
                if change == 'status':
                    result['status'] = 'unknown'
                else:
                    result['access'][change] = 'wrong'
                with patch.object(cli, 'remote', return_value=result):
                    with self.assertRaises(cli.Refused):
                        cli.reconcile(self.work, self.path, 'pve', plan['plan_sha256'])
                self.assertFalse((self.work / 'access.json').exists())
                attempt = json.loads((self.work / 'ACCESS-HOLD.json').read_text())['attempt']
                self.assertEqual(json.loads((self.work / attempt / 'result.json').read_text()), result)

    def test_plan_failures_do_not_create_an_apply_hold(self):
        """Read-only transport errors leave no false claim of an attempted apply."""
        with patch.object(cli, 'remote', side_effect=cli.Refused('transport failed')):
            with self.assertRaises(cli.Refused):
                cli.reconcile(self.work, self.path, 'pve')
        self.assertFalse((self.work / 'ACCESS-HOLD.json').exists())

    def test_wrong_hash_is_refused_before_the_apply_attempt(self):
        """Unchanged inputs still require the exact printed plan hash."""
        self.invoke()
        with self.assertRaises(cli.Refused):
            self.invoke('wrong-hash')
        self.assertFalse((self.work / 'ACCESS-HOLD.json').exists())

    def test_complete_public_example_uses_the_existing_grant_contract(self):
        """The published example is a complete, closed permission request."""
        example = Path(cli.__file__).with_name('access-request.example.json')
        request, identity = cli.request_for(example, self.work)
        grants = host_access.declared_grants(request)
        self.assertEqual(identity['node'], 'pve-example')
        self.assertEqual(grants['/vms/6102'], {'PVEVMAdmin'})

    def test_unknown_fields_and_secret_receipts_are_rejected_before_remote(self):
        """The permission-only request cannot carry an extra operation or token value."""
        for target in [self.request, self.request['expected']]:
            target['PROXMOX_VE_API_TOKEN'] = 'synthetic-never-copy'
            self.save_request()
            with patch.object(cli, 'remote', side_effect=AssertionError('native call forbidden')):
                with self.assertRaises(cli.Refused):
                    cli.reconcile(self.work, self.path, 'pve')
            del target['PROXMOX_VE_API_TOKEN']

    def test_receipt_identity_and_lifetime_must_match_on_repeat(self):
        """A successful workspace cannot be reused for a different deployment token."""
        plan = self.invoke()
        self.invoke(plan['plan_sha256'])
        saved = json.loads((self.work / 'access.json').read_text())
        for key, replacement in [('token_id', 'root@pam!other'), ('expires_at', 999999)]:
            wrong = copy.deepcopy(saved)
            wrong['access'][key] = replacement
            cli.write(self.work / 'access.json', wrong)
            with self.assertRaises(cli.Refused):
                self.invoke()

    def test_concurrent_or_symlink_workspaces_do_not_run_remote(self):
        """Only one operator owns the receipt and its pending apply."""
        link = self.root / 'link'
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(cli.Refused):
            with cli.locked(link):
                self.fail('symlink workspace accepted')
        with cli.locked(self.work):
            with self.assertRaises(BlockingIOError):
                self.invoke()

    def test_live_plan_change_is_rejected_by_remote_before_acl_modification(self):
        """A reviewed hash cannot be replaced by a caller-supplied live guess."""
        with self.assertRaisesRegex(RuntimeError, 'changed after'):
            self.remote('pve', self.request, 'source', 'wrong-reviewed-hash')
        self.assertFalse(any(c[:3] == ['pveum', 'acl', 'modify'] for c in self.case.host.calls))

    def test_transport_is_pinned_and_has_no_token_secret(self):
        """Use the existing operator key and explicit host-key verification."""
        key, hosts = self.root / 'key', self.root / 'hosts'
        key.touch(); hosts.touch()
        env = {'HOMELAB_SSH_KEY': str(key), 'HOMELAB_KNOWN_HOSTS': str(hosts)}
        process = subprocess.CompletedProcess([], 0, '{"status":"ready"}', '')
        with patch.dict(os.environ, env), patch.object(cli.subprocess, 'run', return_value=process) as run:
            self.assertEqual(cli.remote('pve', self.request, 'source', '')['status'], 'ready')
            args = run.call_args.args[0]
            self.assertIn('StrictHostKeyChecking=yes', args)
            self.assertIn('UpdateHostKeys=no', args)
            self.assertIn('ClearAllForwardings=yes', args)
            self.assertIn('root@pve', args)
            self.assertNotIn('synthetic-never-copy', run.call_args.kwargs['input'])
            with self.assertRaises(cli.Refused):
                cli.remote('-unselected', self.request, 'source', '')
        with patch.dict(os.environ, env), patch.object(cli.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', '')):
            with self.assertRaises(cli.Refused):
                cli.remote('pve', self.request, 'source', '')

    def test_cli_routes_named_inputs_and_sanitizes_failure(self):
        """The shell entry point delegates only this operation and emits no secret."""
        args = ['reconcile-access', '--work', str(self.work), '--request', str(self.path), '--host', 'pve']
        with patch.object(sys, 'argv', args), patch.object(cli, 'reconcile', return_value={'status': 'ready'}) as run, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(), 0)
            run.assert_called_once_with(self.work.absolute(), self.path, 'pve', '')
        with patch.object(sys, 'argv', args), patch.object(cli, 'reconcile', side_effect=ValueError('private-detail')), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(), 2)
        self.assertNotIn('private-detail', output.getvalue())
        with patch.object(sys, 'argv', args), patch.object(cli, 'remote', side_effect=cli.Refused('private-detail')), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as stopped:
                runpy.run_path(cli.__file__, run_name='__main__')
        self.assertEqual(stopped.exception.code, 2)
