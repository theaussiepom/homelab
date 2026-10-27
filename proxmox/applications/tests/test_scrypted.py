"""Preparation must never become a decoder experiment or application deployment."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import deploy
import render
import scrypted


class ScryptedPreparationTests(unittest.TestCase):
    def setUp(self):
        self.cfg = json.loads((ROOT / 'examples/scrypted.preparation.example.json').read_text())

    def test_review_preserves_identity_paths_and_has_no_runnable_stack(self):
        original = copy.deepcopy(self.cfg)
        result = scrypted.review(self.cfg)
        self.assertEqual(self.cfg, original)
        self.assertIs(result['deployable'], False)
        self.assertEqual(result['selected_image'], self.cfg['selected_image'])
        self.assertEqual(result['preserve'], self.cfg['preserve'])
        self.assertEqual(result['limits']['container']['pids'], 512)
        self.assertNotIn('services', result)
        self.assertIn('decoder_gpu', result['holds'])
        self.assertIn('nvr_source_guard', result['holds'])

    def test_booleans_and_claimed_approval_cannot_enable_execution(self):
        for field, value in [('enabled', True), ('enabled', 'false'),
                             ('decoder_decision', 'software'), ('decoder_decision', 'intel'),
                             ('decoder_decision', 'automatic'), ('decoder_decision', 'approved')]:
            cfg = copy.deepcopy(self.cfg)
            cfg[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                scrypted.review(cfg)

    def test_unbounded_or_invalid_limits_are_refused(self):
        for scope, field, value in [('container', 'memory_mib', 0), ('container', 'memory_mib', 5120),
                ('container', 'cpus', 7), ('container', 'pids', -1), ('container', 'pids', 1.5),
                ('container', 'pids', True), ('container', 'cpus', float('inf')),
                ('container', 'cpus', float('nan')), ('guest', 'memory_mib', 0),
                ('logs', 'max_files', 0), ('logs', 'max_size_mib', 0)]:
            cfg = copy.deepcopy(self.cfg)
            cfg['limits'][scope][field] = value
            with self.subTest(scope=scope, field=field, value=value), self.assertRaises(ValueError):
                scrypted.review(cfg)

    def test_mutable_image_and_changed_path_semantics_are_refused(self):
        for key, value in [('selected_image', 'ghcr.io/koush/scrypted:latest'),
                           ('unknown_runtime_option', {'devices': ['/dev/dri']})]:
            cfg = copy.deepcopy(self.cfg)
            cfg[key] = value
            with self.assertRaises(ValueError): scrypted.review(cfg)
        for key, value in [('server_volume_target', '/data'), ('nvr_target', '/recordings'),
                           ('numeric_user', '1000:1000'), ('configuration', ['new-defaults'])]:
            cfg = copy.deepcopy(self.cfg)
            cfg['preserve'][key] = value
            with self.assertRaises(ValueError): scrypted.review(cfg)

    def test_existing_installer_refuses_before_reading_target_or_private_files(self):
        for approval in [False, True]:
            with self.assertRaisesRegex(deploy.InputNeeded, 'Scrypted.*decoder'):
                deploy.validate({'app': {'kind': 'scrypted', 'enabled': approval}})
        with self.assertRaises(ValueError): render.compose({'kind': 'scrypted'})

    def test_no_runnable_compose_even_when_missing_inputs_are_filled(self):
        cfg = copy.deepcopy(self.cfg)
        cfg['inputs'] = {key: 'invented-receipt' for key in cfg['inputs']}
        self.assertIs(scrypted.review(cfg)['deployable'], False)


if __name__ == '__main__': unittest.main()
