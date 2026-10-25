"""The workstation preserves the selected VLAN across the SSH credential request."""
import json
from pathlib import Path
import shlex
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import access


class AccessRequestTests(unittest.TestCase):
    def test_selected_vlan_reaches_the_host_credential_request(self):
        """A tagged catalog must not accidentally request only untagged bridge access."""
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / 'tofu').mkdir()
            (work / 'tofu/site.auto.tfvars.json').write_text(json.dumps({
                'site': {'api_endpoint': 'https://198.18.25.10:8006/', 'node': 'pve'},
                'deploy': {'vmid': 900, 'storage_id': 'local-zfs', 'bridge': 'vmbr0',
                           'vlan': 25, 'template_file_id': 'local:vztmpl/debian.tar.zst'}}))
            captured = []

            def fake_ssh(args, **kwargs):
                """Capture the remote request and return a synthetic private receipt."""
                captured.append(json.loads(shlex.split(args[-1])[-1]))
                kwargs['stdout'].write(json.dumps({'status': 'ready', 'ca_pem': 'synthetic',
                    'token_id': 'root@pam!homelab-deploy-900', 'expires_at': 22600,
                    'grants': []}) + '\n')
                return SimpleNamespace(returncode=0)

            original_is_file = Path.is_file
            with patch.object(Path, 'is_file', lambda p: True if p.parent == Path('/keys') else original_is_file(p)), \
                    patch.object(access.subprocess, 'run', side_effect=fake_ssh):
                access.setup(work, 21600)
            self.assertEqual(len(captured), 1)
            self.assertEqual(captured[0]['vlan'], 25)
            self.assertEqual(captured[0]['bridge'], 'vmbr0')
