"""Exercise the workstation launcher without GitHub, Docker or a live runner."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


BASE = Path(__file__).resolve().parents[1]


class RunnerAuthenticationTests(unittest.TestCase):
    def launch(self, mode='success', action='runner', repository='example-owner/private-site', saved_access=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = root / 'bundle'
            bundle.mkdir()
            (bundle / 'settings.json').write_text(json.dumps({'repository': repository}))
            if saved_access:
                (bundle / 'access.json').write_text(json.dumps({'status': 'ready', 'expires_at': 0,
                    'PROXMOX_VE_API_TOKEN': 'synthetic-private-api-value'}))
                (bundle / 'pve-ca.pem').write_text('synthetic public CA')
            bin_dir = root / 'bin'
            bin_dir.mkdir()
            fixture = '''import json, os, sys
from pathlib import Path
args = sys.argv[1:]
kind = Path(sys.argv[0]).name
record = {'command': kind, 'arguments': args}
if kind == 'docker':
    record['fresh_registration_token'] = os.environ.get('HOMELAB_RUNNER_REGISTRATION_TOKEN') == 'synthetic-registration-token'
    record['saved_api_token_loaded'] = os.environ.get('PROXMOX_VE_API_TOKEN') == 'synthetic-private-api-value'
with open(os.environ['AUTH_FIXTURE_CALLS'], 'a') as stream:
    stream.write(json.dumps(record) + '\\n')
mode = os.environ['AUTH_FIXTURE_MODE']
if kind == 'docker':
    print('Synthetic Docker invocation only; no runner registered.')
    raise SystemExit(7 if mode == 'docker-failure' else 0)
assert args[0] == 'api'
if '--method' not in args:
    if mode == 'unauthenticated':
        raise SystemExit(1)
    print('false' if mode == 'public-or-no-admin' else 'true')
else:
    assert args[:3] == ['api', '--hostname', 'github.com']
    assert args[args.index('--method') + 1] == 'POST'
    assert 'repos/example-owner/private-site/actions/runners/registration-token' in args
    assert not os.environ.get('GH_DEBUG'), 'API debugging must not expose the token response'
    if mode == 'token-failure':
        raise SystemExit(1)
    print('' if mode == 'empty-token' else 'synthetic-registration-token')
'''
            for name in ('gh', 'docker'):
                command = bin_dir / name
                command.write_text('#!' + sys.executable + '\n' + fixture)
                command.chmod(0o700)
            calls_path = root / 'calls.jsonl'
            env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ['PATH'],
                       AUTH_FIXTURE_CALLS=str(calls_path), AUTH_FIXTURE_MODE=mode,
                       GH_DEBUG='api', HOMELAB_RUNNER_REGISTRATION_TOKEN='stale-synthetic-token')
            for name in ('PROXMOX_VE_API_TOKEN', 'PROXMOX_VE_USERNAME', 'PROXMOX_VE_PASSWORD', 'HOMELAB_PVE_CA'):
                env.pop(name, None)
            result = subprocess.run([str(BASE / 'bootstrap'), action, str(bundle)],
                                    env=env, capture_output=True, text=True, timeout=10)
            calls = [json.loads(line) for line in calls_path.read_text().splitlines()] if calls_path.exists() else []
            self.assertNotIn('synthetic-registration-token', result.stdout + result.stderr)
            self.assertNotIn('synthetic-private-api-value', result.stdout + result.stderr)
            return result, calls

    def test_existing_auth_obtains_fresh_token_without_exposing_it_in_arguments(self):
        result, calls = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call['command'] for call in calls], ['gh', 'gh', 'docker'])
        docker = calls[-1]
        self.assertTrue(docker['fresh_registration_token'])
        self.assertIn('HOMELAB_RUNNER_REGISTRATION_TOKEN', docker['arguments'])
        self.assertFalse(any('synthetic-token' in arg or 'synthetic-registration-token' in arg
                             for call in calls for arg in call['arguments']))
        self.assertNotIn('GH_TOKEN', docker['arguments'])
        self.assertNotIn('GITHUB_TOKEN', docker['arguments'])

    def test_missing_auth_stops_before_token_or_docker(self):
        result, calls = self.launch('unauthenticated')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([call['command'] for call in calls], ['gh'])

    def test_public_repository_or_missing_admin_stops_before_token_or_docker(self):
        result, calls = self.launch('public-or-no-admin')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([call['command'] for call in calls], ['gh'])

    def test_token_failure_or_empty_response_stops_before_docker_without_retry(self):
        for mode in ('token-failure', 'empty-token'):
            with self.subTest(mode=mode):
                result, calls = self.launch(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual([call['command'] for call in calls], ['gh', 'gh'])

    def test_runner_failure_does_not_request_another_token_or_retry(self):
        result, calls = self.launch('docker-failure')
        self.assertEqual(result.returncode, 7)
        self.assertEqual([call['command'] for call in calls], ['gh', 'gh', 'docker'])

    def test_guest_plan_does_not_need_github_authentication(self):
        result, calls = self.launch('unauthenticated', action='plan')
        self.assertEqual(result.returncode, 0)
        self.assertEqual([call['command'] for call in calls], ['docker'])

    def test_saved_access_is_loaded_without_secret_arguments_or_manual_exports(self):
        result, calls = self.launch(action='plan', saved_access=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(calls[-1]['saved_api_token_loaded'])
        self.assertFalse(any('synthetic-private-api-value' in arg for arg in calls[-1]['arguments']))
        self.assertTrue(any('/keys/pve-ca.pem:ro' in arg for arg in calls[-1]['arguments']))

    def test_access_uses_existing_ssh_without_github_authentication(self):
        result, calls = self.launch('unauthenticated', action='access')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call['command'] for call in calls], ['docker'])
        self.assertIn('/src/proxmox/bootstrap/access.py', calls[-1]['arguments'])

    def test_invalid_repository_stops_before_contacting_github(self):
        result, calls = self.launch(repository='example-owner/private-site/../other-repo')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])


if __name__ == '__main__':
    unittest.main()
