"""Private capture and failure handling for the scripted SSH token setup."""
import json
import hashlib
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
import access


class AccessClientTests(unittest.TestCase):
    def run_case(self, mode, cached=False):
        """Exercise one synthetic access attempt and return its retained evidence."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / 'work'
            (work / 'tofu').mkdir(parents=True)
            (work / 'tofu/site.auto.tfvars.json').write_text(json.dumps({
                'site': {'node': 'pve', 'api_endpoint': 'https://pve.example.invalid:8006/'},
                'deploy': {'vmid': 900, 'storage_id': 'local-lvm', 'bridge': 'vmbr0',
                           'template_file_id': 'local:vztmpl/debian.tar.zst'}, 'template': None}))
            keys = root / 'keys'
            keys.mkdir()
            for name in ('bootstrap-key', 'known_hosts'):
                (keys / name).write_text('synthetic fixture')
            secret = 'root@pam!homelab-deploy-900=synthetic-private-value'
            response = {'status': 'ready', 'token_id': 'root@pam!homelab-deploy-900',
                        'expires_at': 0, 'PROXMOX_VE_API_TOKEN': secret,
                        'ca_pem': 'synthetic public CA', 'grants': []}
            if cached:
                (work / 'template.archive').write_bytes(b'cached archive')
                template = {'node': 'pve', 'file_id': 'local:vztmpl/debian.tar.zst',
                            'size_bytes': 14, 'sha256': hashlib.sha256(b'cached archive').hexdigest()}
                (work / 'template.json').write_text(json.dumps(template))

            def invoke(args, **kwargs):
                """Return a simulated command response for the current access scenario."""
                self.assertEqual(args[0], 'ssh')
                self.assertIn('StrictHostKeyChecking=yes', args)
                self.assertIn('root@pve.example.invalid', args)
                self.assertNotIn(secret, ' '.join(args))
                if kwargs.get('stdin') is not None:
                    self.assertEqual(kwargs['stdin'].read(), b'cached archive')
                    kwargs['stdout'].write(json.dumps({'status': 'stored', **template}) + '\n')
                    return subprocess.CompletedProcess(args, 0)
                kwargs['stdout'].write(json.dumps(response) + '\n')
                if mode == 'timeout':
                    raise subprocess.TimeoutExpired(args, 180)
                if mode == 'partial':
                    kwargs['stdout'].write(json.dumps({'status': 'held'}) + '\n')
                return subprocess.CompletedProcess(args, 0 if mode == 'success' else 1)

            def paths(value):
                """Supply synthetic key locations without reading operator credentials."""
                return keys if str(value) == '/keys' else Path(value)

            with patch.object(access, 'Path', side_effect=paths), patch.object(access.subprocess, 'run', side_effect=invoke) as ssh:
                if mode == 'success':
                    summary = access.setup(work, 21600)
                    self.assertNotIn(secret, json.dumps(summary))
                    self.assertEqual(json.loads((work / 'access.json').read_text())['PROXMOX_VE_API_TOKEN'], secret)
                    self.assertEqual((work / 'pve-ca.pem').read_text(), 'synthetic public CA')
                    self.assertFalse(access.setup(work, 21600)['changed'])
                else:
                    with self.assertRaises(ValueError):
                        access.setup(work, 21600)
                    self.assertFalse((work / 'access.json').exists())
                    self.assertEqual(json.loads((work / 'access-result.json').read_text())['status'],
                                     'UNKNOWN' if mode == 'timeout' else 'held')
                    with self.assertRaises(ValueError):
                        access.setup(work, 21600)
                self.assertEqual(ssh.call_count, 2 if cached else 1)
            self.assertIn(secret, (work / 'access.stdout').read_text())
            for name in ('access.stdout', 'access.stderr', 'access-attempt.json'):
                self.assertEqual(stat.S_IMODE((work / name).stat().st_mode), 0o600)

    def test_success_saves_secret_privately_and_reuses_it_without_reminting(self):
        """Verify success saves secret privately and reuses it without reminting."""
        self.run_case('success')

    def test_partial_failure_retains_credential_evidence_without_retry(self):
        """Verify partial failure retains credential evidence without retry."""
        self.run_case('partial')

    def test_timeout_retains_partial_stdout_and_does_not_claim_remote_completion(self):
        """Verify timeout retains partial stdout and does not claim remote completion."""
        self.run_case('timeout')

    def test_cached_template_is_sent_over_pinned_ssh_before_token_creation(self):
        """Verify cached template is sent over pinned SSH before token creation."""
        self.run_case('success', cached=True)


if __name__ == '__main__':
    unittest.main()
