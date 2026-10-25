"""Scripted API-token setup uses only the selected bootstrap resources."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import host_access


class HostAccessTests(unittest.TestCase):
    def setUp(self):
        self.request = dict(node='pve', vmid=900, storage_id='local-lvm',
                            template_storage='local', download_template=False,
                            bridge='vmbr0', expires_in=21600)
        self.calls = []
        self.emitted = []
        self.fail_acl = False
        self.existing_vm = False
        self.existing_token = False
        self.minted = False
        self.acls = []
        self.bad_metadata = False

    def execute(self, args):
        self.calls.append(args)
        if args[:2] == ['pvesh', 'get']:
            return [{'vmid': 900}] if self.existing_vm else []
        if args[:4] == ['pveum', 'user', 'token', 'list']:
            return [{'tokenid': 'homelab-deploy-900', 'expire': 1 if self.bad_metadata else 22600,
                     'privsep': 1}] if self.existing_token or self.minted else []
        if args[:3] == ['pveum', 'acl', 'list']:
            return list(self.acls)
        if args[:3] == ['pveum', 'role', 'list']:
            return [{'roleid': name} for name in ['PVEVMAdmin', 'PVEDatastoreUser', 'PVEDatastoreAdmin', 'PVEAuditor', 'PVESDNUser']]
        if args[:4] == ['pveum', 'user', 'token', 'add']:
            self.minted = True
            return {'value': 'synthetic-secret'}
        if args[:3] == ['pveum', 'acl', 'modify']:
            if self.fail_acl:
                raise RuntimeError('synthetic ACL failure')
            for role in args[args.index('--roles') + 1].split(','):
                self.acls.append({'type': 'token', 'ugid': args[args.index('--tokens') + 1],
                                  'path': args[3], 'roleid': role, 'propagate': 0})
            return None
        if args[:4] == ['pveum', 'user', 'token', 'permissions']:
            permissions = {'/vms/900': dict.fromkeys(['VM.Allocate', 'VM.Audit', 'VM.PowerMgmt',
                    'VM.Config.CPU', 'VM.Config.Memory', 'VM.Config.Disk', 'VM.Config.Network', 'VM.Config.Options'], 0),
                    '/storage/local-lvm': dict.fromkeys(['Datastore.AllocateSpace', 'Datastore.Audit', 'Datastore.AllocateTemplate'], 0),
                    '/storage/local': {'Datastore.Audit': 0},
                    '/nodes/pve': {'Sys.Audit': 0}, '/sdn/zones/localnetwork/vmbr0': {'SDN.Use': 0}}
            if self.request['download_template']:
                permissions['/storage/' + self.request['template_storage']]['Datastore.AllocateTemplate'] = 0
            return permissions
        raise AssertionError(args)

    def grant(self):
        with patch.object(host_access.socket, 'gethostname', return_value='pve'), \
                patch.object(host_access, 'node_ready', return_value=True), \
                patch.object(host_access.time, 'time', return_value=1000):
            return host_access.grant(self.request, self.execute, self.emitted.append,
                                     ca_pem='synthetic-public-ca')

    def test_one_separated_token_and_only_exact_nonpropagating_acl_paths(self):
        result = self.grant()
        self.assertEqual(result['status'], 'ready')
        minted = [c for c in self.calls if c[:4] == ['pveum', 'user', 'token', 'add']]
        self.assertEqual(len(minted), 1)
        self.assertIn('--privsep', minted[0])
        self.assertEqual(minted[0][minted[0].index('--expire') + 1], '22600')
        acls = [c for c in self.calls if c[:3] == ['pveum', 'acl', 'modify']]
        self.assertEqual({c[3] for c in acls}, {'/vms/900', '/storage/local-lvm',
                         '/storage/local', '/nodes/pve', '/sdn/zones/localnetwork/vmbr0'})
        for command in acls:
            self.assertEqual(command[command.index('--propagate') + 1], '0')
            self.assertEqual(command[command.index('--tokens') + 1], 'root@pam!homelab-deploy-900')
            self.assertNotIn('--users', command)
        self.assertEqual(self.emitted[0]['status'], 'token_created_grants_pending')
        self.assertIn('synthetic-secret', self.emitted[0]['PROXMOX_VE_API_TOKEN'])

    def test_template_download_gets_its_storage_role_without_losing_guest_storage_access(self):
        self.request.update(download_template=True)
        self.grant()
        acl = next(c for c in self.calls if c[:4] == ['pveum', 'acl', 'modify', '/storage/local'])
        self.assertIn('PVEDatastoreAdmin', acl[acl.index('--roles') + 1])

    def test_preexisting_acl_rows_are_refused_before_mint(self):
        self.acls = [{'type': 'token', 'ugid': 'root@pam!homelab-deploy-900',
                      'path': '/', 'roleid': 'Administrator', 'propagate': 1}]
        with self.assertRaisesRegex(RuntimeError, 'ACL'):
            self.grant()
        self.assertFalse(self.minted)

    def test_expiry_readback_mismatch_is_not_claimed_ready(self):
        self.bad_metadata = True
        with self.assertRaisesRegex(RuntimeError, 'expiry'):
            self.grant()

    def test_missing_pmxcfs_readiness_prevents_even_the_collision_lookup(self):
        with patch.object(host_access.socket, 'gethostname', return_value='pve'), \
                patch.object(host_access, 'node_ready', return_value=False):
            with self.assertRaisesRegex(RuntimeError, 'ready'):
                host_access.grant(self.request, self.execute, self.emitted.append,
                                  ca_pem='synthetic-public-ca')
        self.assertEqual(self.calls, [])

    def test_existing_guest_or_token_is_not_replaced(self):
        for field in ('existing_vm', 'existing_token'):
            self.calls.clear()
            setattr(self, field, True)
            with self.assertRaises(RuntimeError):
                self.grant()
            self.assertFalse(any(c[:4] == ['pveum', 'user', 'token', 'add'] for c in self.calls))
            setattr(self, field, False)

    def test_partial_acl_failure_keeps_minted_secret_receipt_without_retry_or_cleanup(self):
        self.fail_acl = True
        with self.assertRaises(RuntimeError):
            self.grant()
        self.assertEqual(len(self.emitted), 1)
        self.assertEqual(sum(c[:4] == ['pveum', 'user', 'token', 'add'] for c in self.calls), 1)
        self.assertFalse(any('delete' in c for c in self.calls))

    def test_no_broad_paths_or_protected_ids(self):
        for key, value in [('vmid', 4914), ('bridge', '../other'), ('storage_id', '/'),
                           ('expires_in', -1), ('node', 'other-pve')]:
            request = dict(self.request)
            self.request[key] = value
            with self.assertRaises((RuntimeError, ValueError)):
                self.grant()
            self.request = request


if __name__ == '__main__':
    unittest.main()
