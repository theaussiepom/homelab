"""Run ordinary creation through the real creation-log SSH identity checker."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_guest_identity as fixture
import test_ordinary_cd as lifecycle

ordinary = lifecycle.ordinary


class CreationIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.identity = fixture.IdentityTests()
        self.cfg = self.identity.setup_fixture(self.root)
        self.cfg['paths']['ca_file'] = str(self.root / 'fixture-ca.crt')
        (self.root / 'api').chmod(0o600)
        self.cfg['ssh_public_keys'] = ['synthetic-public-key']
        self.cfg['app']['address'] = '198.18.100.42'
        self.site = self.root / 'site.json'
        self.site.write_text('{}')
        self.work = self.root / 'work'
        self.operation = self.work / 'ordinary-777-1'
        self.operation.mkdir(parents=True)
        self.source = self.root / 'source'
        (self.source / 'tofu').mkdir(parents=True)
        (self.source / 'tofu/main.tf').write_text('# synthetic fixture\n')
        self.expected = {'vmid': 6101, 'source_sha256': 'a' * 64}
        self.plan = {'resource_changes': [
            {'address': address, 'type': address.split('.')[2], 'change': {
                'actions': ['create'], 'before': None,
                'after': {key: 6101, 'node_name': 'practice-pve'}}}
            for address, key in ordinary.check_plan.__globals__['RESOURCES'].items()]}
        self.fail_apply = False
        for target, options in [
            (ordinary.deploy, {'SOURCE': self.source}),
            (ordinary, {'binding': lambda *_: self.expected}),
            (ordinary.deploy, {'backup': lambda *_: None}),
            (ordinary.deploy.discovery, {'labels': lambda *_: {}}),
            (ordinary.deploy, {'api_get': lambda _, path: self.identity.fetch(path)}),
            (ordinary.deploy, {'quiet': self.command}),
        ]:
            patcher = patch.multiple(target, **options)
            patcher.start()
            self.addCleanup(patcher.stop)

    def command(self, argv, environment, log):
        if 'plan' in argv:
            (self.operation / 'guest.tfplan').write_bytes(b'original-reviewed-binary-plan')
        if 'apply' in argv:
            # The durable proof must exist before the native operation begins.
            window = json.loads((self.work / 'apply-window.json').read_text())
            plan = json.loads((self.work / 'plan.json').read_text())
            self.assertEqual(window['plan_sha256'], plan['plan_sha256'])
            self.assertNotIn('finished_at_ns', window)
            if self.fail_apply:
                raise subprocess.CalledProcessError(1, argv)
            (self.work / 'terraform.tfstate').write_text('new authoritative state')

    def run_creation(self):
        with patch.object(ordinary.subprocess, 'check_output', return_value=json.dumps(self.plan).encode()), \
             patch.object(fixture.identity.subprocess, 'run', side_effect=self.identity.command), \
             patch('time.time_ns', side_effect=[1_700_000_000_000_000_000, 1_700_000_010_000_000_000]):
            return ordinary.infrastructure(self.cfg, self.site, self.work, self.operation, self.expected)

    def test_new_creation_has_durable_window_and_real_task_verified_key(self):
        result = self.run_creation()
        self.assertTrue(result['created'])
        self.assertEqual(json.loads((self.work / 'host-key-evidence.json').read_text())['source'],
                         'synthetic-creation')
        self.assertIn(fixture.public_key(), (self.root / 'hosts').read_text())
        self.assertEqual(json.loads((self.work / 'apply-window.json').read_text())['finished_at_ns'],
                         1_700_000_010_000_000_000)

    def test_failed_apply_never_claims_finished_creation_or_pins_a_key(self):
        self.fail_apply = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_creation()
        self.assertNotIn('finished_at_ns', json.loads((self.work / 'apply-window.json').read_text()))
        self.assertEqual((self.root / 'hosts').read_text(), '')
        self.assertFalse((self.work / 'host-key-evidence.json').exists())

    def test_existing_reconciliation_preserves_original_creation_records(self):
        (self.work / 'terraform.tfstate').write_text('existing authoritative state')
        for name in ('plan.json', 'apply-window.json'):
            (self.work / name).write_text('original installation proof')
        for row in self.plan['resource_changes']:
            row['change'].update(actions=['no-op'], before=dict(row['change']['after']))
        with patch.object(ordinary.deploy.guest_identity, 'pin') as pin:
            result = self.run_creation()
        self.assertFalse(result['created'])
        pin.assert_not_called()
        for name in ('plan.json', 'apply-window.json'):
            self.assertEqual((self.work / name).read_text(), 'original installation proof')


if __name__ == '__main__':
    unittest.main()
