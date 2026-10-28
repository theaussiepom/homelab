"""Coordinator custody and original guest bindings surround one route overlay."""
import json
from pathlib import Path, PurePosixPath
import unittest
from unittest.mock import patch

import foundation_cd as fc
import ingress_browser_maintenance as maintenance
from test_component_browser import browser, update_packet
import test_foundation_maintenance as fixtures


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        fixtures.ImageMaintenanceTests.setUp(self)
        self.original = b'{"http":{}}'
        self.selected = update_packet(self.original, 702)
        self.selected.update(plan_sha256=self.plan['plan_sha256'], state_sha256=fc.digest((self.work/'terraform.tfstate').read_bytes()),
            foundation_complete_sha256=fc.digest((self.work/'foundation-complete.json').read_bytes()))
        evidence = self.work/'admission'; evidence.mkdir(mode=0o700)
        for name in ('network_evidence', 'policy_evidence'):
            if name == 'network_evidence':
                value = {'schema': 'homelab-database-network-overlay-v1', 'status': 'network_overlay_verified',
                         'vmid': 702, 'state_sha256': self.selected['state_sha256']}
            else:
                value = dict(schema='homelab-influx-browser-policy-evidence-v1', vmid=702,
                    route_sha256=fc.digest(fc.encoded(self.selected['route'])), provider_host_confirmed=True,
                    outpost_membership_confirmed=True, access_policy_confirmed=True, issuer_alignment_confirmed=True,
                    direct_peer_allowlist_approved=True)
            p = evidence/(name+'.json'); fc.write_new(p, fc.encoded(value))
            self.selected[name] = {'path': str(p), 'sha256': fc.digest(p.read_bytes())}
        p = patch.object(browser, 'EVIDENCE_ROOT', PurePosixPath(self.state)); p.start(); self.addCleanup(p.stop)
        self.deployment.quiet.side_effect = self.ansible

    def ansible(self, argv, *args):
        value = json.loads(Path(argv[-1][1:]).read_bytes())
        if not value['browser_verify_only']:
            fc.write_new(Path(value['browser_archive']), self.original)

    def run_update(self):
        return maintenance.run(self.deployment, fc, self.cfg, self.site, self.root/'helper', self.selected, self.state)

    def test_preserves_original_installation_and_repeated_cd_verifies_overlay_only(self):
        original = {p: p.read_bytes() for p in self.work.iterdir() if p.is_file()}
        self.assertTrue(self.run_update()['changed'])
        self.assertFalse(self.run_update()['changed'])
        self.deployment.execute.assert_not_called()
        for path, data in original.items(): self.assertEqual(path.read_bytes(), data)
        self.assertEqual((self.nas/'influx-browser-shared-before.json').read_bytes(), self.original)
        self.assertFalse((self.work/'CONTINUATION-HOLD.json').exists())

    def test_missing_or_changed_network_evidence_refuses_before_claim(self):
        Path(self.selected['network_evidence']['path']).write_bytes(b'drift')
        with self.assertRaises(ValueError): self.run_update()
        self.deployment.quiet.assert_not_called()
        self.assertFalse((self.work/'influx-browser-route').exists())

    def test_target_failure_is_held_and_source_revision_change_cannot_replay(self):
        self.deployment.quiet.side_effect = RuntimeError('synthetic failure')
        with self.assertRaises(RuntimeError): self.run_update()
        self.assertTrue((self.work/'CONTINUATION-HOLD.json').exists())
        self.selected['revision'] = 'f'*40
        with self.assertRaises(ValueError): self.run_update()
        self.deployment.quiet.assert_called_once()

    def test_wrong_original_completion_is_refused(self):
        p = self.work/'foundation-complete.json'; v = json.loads(p.read_bytes()); v['status'] = 'failed'
        p.write_bytes(fc.encoded(v)); self.selected['foundation_complete_sha256'] = fc.digest(p.read_bytes())
        with self.assertRaises(ValueError): self.run_update()
        self.deployment.quiet.assert_not_called()

    def test_review_hash_cannot_substitute_incomplete_or_unrelated_policy(self):
        path = Path(self.selected['policy_evidence']['path'])
        original = json.loads(path.read_bytes())
        for key, wrong in [('issuer_alignment_confirmed', False), ('vmid', 703), ('route_sha256', '0'*64)]:
            path.write_bytes(fc.encoded({**original, key: wrong}))
            self.selected['policy_evidence']['sha256'] = fc.digest(path.read_bytes())
            with self.subTest(key=key), self.assertRaises(ValueError): self.run_update()
        self.deployment.quiet.assert_not_called()
        self.assertFalse((self.work/'influx-browser-route').exists())


if __name__ == '__main__': unittest.main()
