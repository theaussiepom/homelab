"""Check target matching, required NAS custody, and exact saved-plan application."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import deploy


def fixture(root):
    return {'guest': {'vmid': 6101, 'hostname': 'practice-automation', 'memory_mib': 4096,
                      'interfaces': [{'ipv4': '198.18.100.20/24', 'mac': '02:00:00:00:61:01'}]},
            'site': {'node': 'practice-pve', 'api_endpoint': 'https://pve.example.invalid:8006/'},
            'app': {'vmid': 6101, 'hostname': 'practice-automation', 'memory_mib': 4096,
                    'address': '198.18.100.20', 'mac': '02:00:00:00:61:01', 'new_target': True},
            'paths': {'state_root': str(root / 'state'), 'backup_mount': str(root / 'nas'),
                      'backup_source': 'nas.example.invalid:/backups',
                      'backup_directory': str(root / 'nas' / 'backups'), 'api_token': str(root / 'api'),
                      'ca_file': str(root / 'ca'), 'private_key': str(root / 'ssh'), 'known_hosts': str(root / 'hosts')}}


class DeployTests(unittest.TestCase):
    def test_tofu_and_ansible_cannot_select_different_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = fixture(Path(tmp)); self.assertEqual(deploy.validate(cfg), 6101)
            for key, value in [('vmid', 6102), ('address', '198.18.100.21'), ('mac', '02:00:00:00:61:02'), ('memory_mib', 1024)]:
                bad = copy.deepcopy(cfg); bad['app'][key] = value
                with self.assertRaises(ValueError): deploy.validate(bad)

    def test_bootstrap_and_retained_targets_are_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            for vmid in (True, 99, 900, 4914, 4915, 4920):
                cfg = fixture(Path(tmp)); cfg['guest']['vmid'] = vmid
                with self.assertRaises(ValueError): deploy.validate(cfg)

    def test_backup_requires_a_real_nas_mount_without_local_fallback(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(deploy.os.path, 'ismount', return_value=False):
            cfg = fixture(Path(tmp))
            with self.assertRaises(ValueError): deploy.backup(cfg, Path(tmp) / 'state', 'before')
            self.assertFalse((Path(tmp) / 'nas').exists())

    def test_backup_readback_matches_the_active_state_bytes(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(deploy.os.path, 'ismount', return_value=True), patch.object(deploy.subprocess, 'check_output', return_value='nfs4 nas.example.invalid:/backups\n'):
            root = Path(tmp); cfg = fixture(root); state = root / 'current.tfstate'
            state.write_text('{"lineage":"synthetic","serial":1}')
            deploy.backup(cfg, state, 'before')
            stored = list((root / 'nas').rglob('*.tfstate'))
            self.assertEqual(len(stored), 1); self.assertEqual(stored[0].read_bytes(), state.read_bytes())

    def test_existing_hold_prevents_any_native_command(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(deploy, 'quiet') as run:
            root = Path(tmp); cfg = fixture(root); site = root / 'site.json'
            site.write_text(json.dumps(cfg)); work = root / 'state' / '6101'; work.mkdir(parents=True)
            (work / 'HOLD.json').write_text('{}')
            with self.assertRaises(ValueError): deploy.execute('apply', site, '0' * 64)
            run.assert_not_called()

    def test_unreviewed_apply_does_not_call_tofu(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(deploy, 'quiet') as run, patch.object(deploy, 'backup'), patch.object(deploy, 'input_hashes', return_value={}):
            root = Path(tmp); cfg = fixture(root); site = root / 'site.json'; site.write_text(json.dumps(cfg)); (root / 'api').write_text('synthetic')
            work = root / 'state' / '6101'; work.mkdir(parents=True)
            deploy.write(work / 'plan.json', {'site_sha256': deploy.sha(site), 'source_sha256': deploy.source_hash(), 'plan_sha256': '1' * 64, 'input_hashes': {}})
            with self.assertRaises(ValueError): deploy.execute('apply', site, '2' * 64)
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
