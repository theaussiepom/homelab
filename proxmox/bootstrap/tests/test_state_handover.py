"""State copying, single-writer handover and private backup without a VM."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
import native
import runner
import workstation
from bootstrap import Refused


class StateHandoverTests(unittest.TestCase):
    def workspace(self, root):
        """Create a private local state fixture with a known lineage and serial."""
        work = root / 'work'
        tofu = work / 'tofu'
        tofu.mkdir(parents=True)
        (tofu / 'main.tf').write_text('terraform { backend "local" {} }\n')
        (tofu / 'terraform.tfstate').write_text(json.dumps({
            'version': 4, 'lineage': 'synthetic-lineage', 'serial': 2, 'resources': []}))
        return work

    def test_runner_install_uses_linux_locale_despite_mac_session_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); work = self.workspace(root)
            (work / 'tofu/site.auto.tfvars.json').write_text(json.dumps({
                'site': {'node': 'fixture-pve', 'api_endpoint': 'https://192.0.2.10:8006/'},
                'deploy': {'vmid': 900, 'ipv4': '192.0.2.90/24'}}))
            (work / 'settings.json').write_text(json.dumps({'repository': 'fixture/private', 'runner_name': 'fixture-runner'}))
            (work / 'inventory.json').write_text(json.dumps({'all': {'hosts': {'deploy': {}}}}))
            keys = root / 'keys'; keys.mkdir()
            for name in ('bootstrap-key', 'known_hosts', 'pve-ca.pem'): (keys / name).write_text('synthetic only')
            installs = []
            def invoke(arguments, **kwargs):
                if arguments[0] == 'ssh':
                    return subprocess.CompletedProcess(arguments, 0, 'ssh-ed25519 AAAAsynthetic\n192.0.2.90\n', '')
                self.assertEqual(arguments[0], 'ansible-playbook')
                installs.append(kwargs['env'])
                return subprocess.CompletedProcess(arguments, 0)
            with patch.dict(os.environ, {'PROXMOX_VE_API_TOKEN': 'synthetic-token',
                    'LC_ALL': 'unsupported-fixture', 'LANG': 'unsupported-fixture',
                    'LC_CTYPE': 'UTF-8', 'FIXTURE_PRESERVED': 'present'}, clear=True), \
                    patch.object(native, 'run_locked'), patch.object(runner, 'allow_host_api'), \
                    patch.object(runner, 'Path', side_effect=lambda value: keys if value == '/keys' else Path(value)), \
                    patch.object(runner.subprocess, 'run', side_effect=invoke):
                runner.install(work)
                self.assertEqual(os.environ['LC_ALL'], 'unsupported-fixture')
            self.assertEqual(len(installs), 1)
            self.assertEqual(installs[0]['LC_ALL'], 'C.UTF-8')
            self.assertEqual(installs[0]['LANG'], 'C.UTF-8')
            self.assertEqual(installs[0]['FIXTURE_PRESERVED'], 'present')
            self.assertTrue((work / 'runner-result.json').is_file())

    def test_handover_copies_exact_state_and_freezes_workstation(self):
        """Verify handover copies exact state and freezes workstation."""
        with tempfile.TemporaryDirectory() as tmp:
            work = self.workspace(Path(tmp))
            (work / 'tofu/review.tfplan').write_text('private saved plan, excluded')
            cache = work / 'tofu/.terraform'
            cache.mkdir()
            (cache / 'terraform.tfstate').write_text('backend cache, excluded')
            with native.workspace_lock(work):
                destination, receipt = runner.stage_handover(work)
            self.assertEqual((destination / 'tofu/terraform.tfstate').read_bytes(),
                             (work / 'tofu/terraform.tfstate').read_bytes())
            self.assertEqual(receipt['lineage'], 'synthetic-lineage')
            self.assertEqual(receipt['serial'], 2)
            self.assertFalse((destination / 'tofu/review.tfplan').exists())
            self.assertFalse((destination / 'tofu/.terraform').exists())
            self.assertEqual((destination / 'tofu/terraform.tfstate').stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(Refused, 'handover has started'):
                native.run('plan', work)
            with native.workspace_lock(destination):
                pass

    def test_failed_copy_keeps_workstation_frozen_and_never_retries(self):
        """Verify failed copy keeps workstation frozen and never retries."""
        with tempfile.TemporaryDirectory() as tmp:
            work = self.workspace(Path(tmp))
            with native.workspace_lock(work), patch.object(native, 'copy_workspace', side_effect=OSError('fixture failure')):
                with self.assertRaises(OSError):
                    runner.stage_handover(work)
            self.assertTrue((work / 'HANDOVER.json').exists())
            with self.assertRaisesRegex(Refused, 'handover has started'):
                native.run('apply', work)

    def test_missing_state_is_not_replaced_by_an_empty_state(self):
        """Verify missing state is not replaced by an empty state."""
        with tempfile.TemporaryDirectory() as tmp:
            work = self.workspace(Path(tmp))
            (work / 'tofu/terraform.tfstate').unlink()
            with self.assertRaisesRegex(Refused, 'existing local state'):
                runner.stage_handover(work)
            self.assertFalse((work / 'HANDOVER.json').exists())

    def test_workspace_lock_refuses_another_process(self):
        """Verify workspace lock refuses another process."""
        with tempfile.TemporaryDirectory() as tmp:
            work = self.workspace(Path(tmp))
            code = '''import sys
sys.path.insert(0, sys.argv[1])
import native
from pathlib import Path
try:
    with native.workspace_lock(Path(sys.argv[2])):
        raise SystemExit(9)
except native.Refused:
    raise SystemExit(0)
'''
            with native.workspace_lock(work):
                process = subprocess.run([sys.executable, '-c', code, str(BASE), str(work)],
                                         env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'),
                                         capture_output=True, text=True, timeout=5)
            self.assertEqual(process.returncode, 0, process.stderr)

    def test_backup_after_handover_is_private_and_does_not_unfreeze_source(self):
        """Verify backup after handover is private and does not unfreeze source."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = self.workspace(root)
            with native.workspace_lock(work):
                runner.stage_handover(work)
            destination = root / 'nas-backup'
            receipt = native.backup(work, destination)
            self.assertEqual(receipt['state_sha256'], native.sha(work / 'tofu/terraform.tfstate'))
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
            self.assertTrue((work / 'HANDOVER.json').exists())
            with self.assertRaises(FileExistsError):
                native.backup(work, destination)

    def test_workstation_does_not_launch_docker_during_another_operation(self):
        """Verify workstation does not launch docker during another operation."""
        with tempfile.TemporaryDirectory() as tmp:
            work = self.workspace(Path(tmp))
            with native.workspace_lock(work, name='.workstation.lock'):
                with patch.object(workstation.subprocess, 'run') as command:
                    with self.assertRaisesRegex(Refused, 'Another bootstrap operation'):
                        workstation.run(work, ['docker', 'run', 'synthetic-only'])
                    command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
