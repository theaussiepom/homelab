"""Credential setup restricts GitHub access and will not repeat a partial attempt."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

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

    def test_missing_environment_on_read_only_check_cannot_be_recreated(self):
        calls = []
        def github(repo, path, method='GET', payload=None):
            calls.append((path, method))
            if path == '': return {'private': True, 'permissions': {'admin': True}}
            return {'total_count': 0, 'environments': []}
        with patch.object(cd, 'github', side_effect=github), self.assertRaisesRegex(ValueError, 'missing'):
            cd.environment('example/private', create=False)
        self.assertTrue(all(method == 'GET' for _, method in calls))

    def test_completed_setup_refuses_a_missing_github_secret_without_any_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); bundle = root / 'bundle'; bundle.mkdir(); (bundle / 'tofu').mkdir()
            endpoint = 'https://198.18.25.10:8006/'
            (bundle / 'settings.json').write_text(json.dumps({'repository': 'example/private'}))
            (bundle / 'tofu/site.auto.tfvars.json').write_text(json.dumps({'site': {'api_endpoint': endpoint}}))
            out = root / 'completed'; out.mkdir()
            (out / 'token').write_text('synthetic-only')
            (out / 'result.json').write_text(json.dumps({'status': 'ready', 'repository': 'example/private', 'endpoint': endpoint}))
            api = Mock(); api.call.return_value = {'data': {'expire': 0, 'privsep': 1}}
            with patch.object(cd, 'API', return_value=api), patch.object(cd, 'environment') as env, \
                    patch.object(cd, 'github', return_value={'name': 'wrong-secret'}) as github, \
                    patch.object(cd.subprocess, 'run') as mutation, self.assertRaisesRegex(ValueError, 'secret'):
                cd.setup(bundle, out)
            env.assert_called_once_with('example/private', create=False)
            github.assert_called_once_with('example/private', '/environments/homelab-bootstrap/secrets/PROXMOX_BOOTSTRAP_TOKEN')
            mutation.assert_not_called()
