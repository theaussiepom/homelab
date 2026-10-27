"""A management preview must not grant access or become a deployment."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import deploy
import pegaprox


class PegaProxTests(unittest.TestCase):
    def setUp(self):
        self.cfg = json.loads((ROOT / 'examples/pegaprox.preparation.example.json').read_text())

    def test_preview_limits_listeners_and_keeps_key_outside_config(self):
        service = pegaprox.compose_preview(self.cfg)['services']['pegaprox']
        self.assertEqual(service['ports'], ['198.18.25.34:5000:5000/tcp'])
        self.assertEqual(service['cap_drop'], ['ALL'])
        self.assertNotIn('network_mode', service)
        self.assertTrue(service['read_only'])
        self.assertEqual(service['restart'], 'no')
        self.assertEqual(service['pull_policy'], 'missing')
        key = next(v for v in service['volumes'] if v['target'] == '/run/secrets/pegaprox-db-key')
        self.assertTrue(key['read_only'])
        self.assertFalse(key['bind']['create_host_path'])
        self.assertEqual(service['environment']['PEGAPROX_KEY_FILE'], key['target'])
        self.assertNotIn('PEGAPROX_DB_KEY', service['environment'])
        self.assertEqual(len(service['volumes']), 3)

    def test_preview_refuses_activation_unpinned_images_and_extra_inputs(self):
        for key, value in [('enabled', True), ('deployable', True),
                           ('image', 'ghcr.io/pegaprox/pegaprox:latest'),
                           ('image', 'example.invalid/other@sha256:' + 'a' * 64),
                           ('password', 'synthetic'), ('network_mode', 'host')]:
            cfg = copy.deepcopy(self.cfg); cfg[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                pegaprox.compose_preview(cfg)

    def test_no_wildcard_public_multicast_or_loopback_listener(self):
        for address in ['0.0.0.0', '127.0.0.1', '169.254.1.2', '224.0.0.1',
                        '255.255.255.255', '8.8.8.8', '::', '10.0.0.1:5000']:
            cfg = copy.deepcopy(self.cfg); cfg['bind_address'] = address
            with self.subTest(address=address), self.assertRaises(ValueError):
                pegaprox.compose_preview(cfg)

    def test_resource_budget_reserves_guest_memory(self):
        for key, value in [('guest_memory_mib', 1024), ('container_memory_mib', 2048),
                           ('cpus', True), ('cpus', float('nan')), ('pids_limit', 0)]:
            cfg = copy.deepcopy(self.cfg); cfg[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                pegaprox.compose_preview(cfg)

    def test_existing_deployer_refuses_before_target_or_private_file_reads(self):
        with patch.object(deploy, 'api_get', side_effect=AssertionError('no target contact')), \
                patch.object(Path, 'read_text', side_effect=AssertionError('no private reads')):
            with self.assertRaisesRegex(deploy.InputNeeded, 'PegaProx.*preparation'):
                deploy.validate({'app': {'kind': 'pegaprox'}})
