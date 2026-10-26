"""Credential setup restricts GitHub access and will not repeat a partial attempt."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cd_access as cd


class CDEnvironmentTests(unittest.TestCase):
    def test_new_environment_allows_only_the_main_branch(self):
        calls = []
        def github(repo, path, method='GET', payload=None):
            calls.append((path, method, payload))
            if path == '': return {'private': True, 'permissions': {'admin': True}}
            if path.startswith('/environments?'): return {'total_count': 0, 'environments': []}
            if path.endswith('/deployment-branch-policies') and method == 'GET':
                return {'total_count': 1, 'branch_policies': [{'name': 'main', 'type': 'branch'}]}
            return {'deployment_branch_policy': {'protected_branches': False, 'custom_branch_policies': True}}
        with patch.object(cd, 'github', side_effect=github): cd.environment('example/private')
        mutations = [c for c in calls if c[1] != 'GET']
        self.assertEqual(len(mutations), 2)
        self.assertEqual(mutations[1][2], {'name': 'main', 'type': 'branch'})

    def test_existing_unrestricted_environment_is_not_weakened_or_used(self):
        calls = []
        def github(repo, path, method='GET', payload=None):
            calls.append((path, method))
            if path == '': return {'private': True, 'permissions': {'admin': True}}
            if path.startswith('/environments?'):
                return {'total_count': 1, 'environments': [{'name': cd.ENVIRONMENT}]}
            return {'deployment_branch_policy': None}
        with patch.object(cd, 'github', side_effect=github), self.assertRaisesRegex(ValueError, 'restrictions'):
            cd.environment('example/private')
        self.assertTrue(all(c[1] == 'GET' for c in calls))

    def test_partial_workstation_attempt_refuses_before_any_remote_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); bundle = root / 'bundle'; bundle.mkdir()
            (bundle / 'tofu').mkdir()
            (bundle / 'settings.json').write_text(json.dumps({'repository': 'example/private'}))
            (bundle / 'tofu/site.auto.tfvars.json').write_text(json.dumps({
                'site': {'api_endpoint': 'https://198.18.25.10:8006/'}}))
            out = root / 'attempt'; out.mkdir()
            with patch.object(cd.subprocess, 'run') as remote, self.assertRaisesRegex(ValueError, 'incomplete'):
                cd.setup(bundle, out)
            remote.assert_not_called()
