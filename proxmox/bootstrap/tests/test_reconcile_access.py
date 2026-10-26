"""A completed bootstrap can add declared scopes without replacing credentials."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import host_access
import test_host_access as original


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        """Start with the exact successfully issued bootstrap token."""
        self.host = original.HostAccessTests()
        self.host.setUp()
        self.saved = self.host.grant()
        self.host.calls.clear()
        self.rows = [{'vmid': 900, 'node': 'pve', 'name': 'deploy'}]
        self.expiry = self.saved['expires_at']
        self.request = dict(self.host.request, expected=self.saved,
                            guest_mac='02:00:00:00:09:00', applications=[
            {'vmid': 6101, 'storage_id': 'local-lvm', 'template_storage': 'local',
             'interfaces': [{'bridge': 'vmbr0', 'vlan': 25}]}])

    def execute(self, args):
        """Model live permissions from ACL rows rather than from desired inputs."""
        if args[:4] == ['pveum', 'user', 'token', 'modify']:
            self.host.calls.append(args)
            self.expiry = int(args[-1]); return None
        if args[:4] == ['pveum', 'user', 'token', 'list']:
            self.host.calls.append(args)
            return [{'tokenid': 'homelab-deploy-900', 'expire': self.expiry, 'privsep': 1}]
        if args[:2] == ['pvesh', 'get']:
            self.host.calls.append(args)
            if args[2] == '/cluster/resources':
                return self.rows
            return {'hostname': 'deploy', 'unprivileged': 1,
                    'net0': 'name=eth0,hwaddr=02:00:00:00:09:00,bridge=vmbr0'}
        if args[:4] == ['pveum', 'user', 'token', 'permissions']:
            self.host.calls.append(args)
            roles = {'PVEVMAdmin': ['VM.Allocate', 'VM.Audit', 'VM.PowerMgmt',
                     'VM.Config.CPU', 'VM.Config.Memory', 'VM.Config.Disk',
                     'VM.Config.Network', 'VM.Config.Options'],
                     'PVEDatastoreUser': ['Datastore.AllocateSpace', 'Datastore.Audit'],
                     'PVEAuditor': ['Datastore.Audit', 'Sys.Audit'],
                     'PVESDNUser': ['SDN.Use']}
            result = {}
            for row in self.host.acls:
                result.setdefault(row['path'], {}).update(dict.fromkeys(roles[row['roleid']], 0))
            return result
        return self.host.execute(args)

    def reconcile(self, apply=False):
        """Run through the same selected host and node guards as initial setup."""
        with patch.object(host_access.socket, 'gethostname', return_value='pve'), \
                patch.object(host_access, 'node_ready', return_value=True), \
                patch.object(host_access.time, 'time', return_value=1000):
            return host_access.reconcile(self.request, self.execute, apply=apply)

    def test_plan_is_read_only_and_second_apply_is_a_noop(self):
        """Only missing declared rows are added; token identity/lifetime survive."""
        before = copy.deepcopy(self.host.acls)
        plan = self.reconcile()
        self.assertEqual(self.host.acls, before)
        self.assertEqual({x['path'] for x in plan['missing']},
                         {'/vms/6101', '/sdn/zones/localnetwork/vmbr0/25'})
        result = self.reconcile(apply=True)
        self.assertTrue(result['changed'])
        self.assertEqual(result['token_id'], self.saved['token_id'])
        self.assertEqual(result['expires_at'], self.saved['expires_at'])
        self.request['expected'] = dict(self.saved, grants=result['grants'])
        self.host.calls.clear()
        self.assertFalse(self.reconcile(apply=True)['changed'])
        self.assertFalse(any(c[:3] == ['pveum', 'acl', 'modify'] for c in self.host.calls))
        self.assertFalse(any('add' in c or 'delete' in c for c in self.host.calls))

    def test_new_application_id_collision_does_not_gain_access(self):
        """An existing unrelated guest must not be silently adopted."""
        self.rows.append({'vmid': 6101, 'node': 'pve', 'name': 'somebody-else'})
        with self.assertRaisesRegex(RuntimeError, 'already exists'):
            self.reconcile(apply=True)
        self.assertFalse(any(c[:3] == ['pveum', 'acl', 'modify'] for c in self.host.calls))

    def test_drift_and_protected_ids_fail_before_acl_changes(self):
        """Rerun support does not normalize a widened grant or a changed guest."""
        self.host.acls.append({'type': 'token', 'ugid': self.saved['token_id'],
                               'path': '/', 'roleid': 'PVEAuditor', 'propagate': 0})
        with self.assertRaisesRegex(RuntimeError, 'differ'):
            self.reconcile(apply=True)
        self.host.acls.pop()
        self.request['applications'][0]['vmid'] = 4914
        with self.assertRaisesRegex(RuntimeError, 'protected'):
            self.reconcile(apply=True)
        self.assertFalse(any(c[:3] == ['pveum', 'acl', 'modify'] for c in self.host.calls))

    def test_expired_token_requires_an_explicit_new_expiry_and_readback(self):
        self.expiry = self.request['expected']['expires_at'] = 999
        with self.assertRaisesRegex(RuntimeError, 'expired'):
            self.reconcile(apply=True)
        self.request['expires_at'] = 25000
        self.assertTrue(self.reconcile()['expiry_change'])
        self.assertEqual(self.expiry, 999)
        result = self.reconcile(apply=True)
        self.assertEqual(result['expires_at'], 25000)
        self.assertEqual(self.expiry, 25000)
        self.assertFalse(any('add' in c or 'delete' in c for c in self.host.calls))


if __name__ == '__main__':
    unittest.main()
