"""Check target matching, required NAS custody, and exact saved-plan application."""
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import subprocess
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
    def test_guest_plan_binds_nested_monitoring_credentials_and_plugin_packages(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); cfg = fixture(root)
            for name in ('ca', 'credential', 'password', 'plugin'):
                (root / name).write_text('original-' + name)
            cfg['app']['zabbix_agent'] = {'credential_file': str(root / 'credential'),
                'postgresql_package_file': str(root / 'plugin'),
                'workloads': {'postgresql': {'password_file': str(root / 'password')}}}
            original = deploy.input_hashes(cfg)
            for name in ('credential', 'password', 'plugin'):
                path = root / name; path.write_text('changed-' + name)
                self.assertNotEqual(original[str(path)], deploy.input_hashes(cfg)[str(path)])
            cfg['app']['zabbix_agent']['credential_file'] = 'relative'
            with self.assertRaises(deploy.InputNeeded): deploy.input_hashes(cfg)

    def test_network_gate_waits_for_backend_even_when_management_exists(self):
        cfg={'guest':{'interfaces':[{'ipv4':'dhcp'},{'ipv4':'10.88.30.23/24'},{'ipv4':'manual'}]}}
        self.assertEqual(deploy.required_network_interfaces(cfg),['eth0','eth1'])
        cfg['guest']['interfaces']=[{'ipv4':'manual'}]
        with self.assertRaises(ValueError): deploy.required_network_interfaces(cfg)

    def test_saved_plan_binds_shared_guest_startup_behaviour(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'applications'; source.mkdir()
            common = root / 'common'; common.mkdir()
            (source / 'deploy.py').write_text('synthetic application caller')
            gate = common / 'network-ready.yml'; gate.write_text('original network dependency')
            with patch.object(deploy, 'SOURCE', source):
                original = deploy.source_hash()
                gate.write_text('different network dependency')
                self.assertNotEqual(deploy.source_hash(), original)

    def test_package_account_exception_is_explicit_and_only_for_new_empty_mariadb(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = fixture(Path(tmp))
            cfg['app'].update(kind='mariadb', database={'account_mode': 'package', 'user': 'mysql', 'group': 'mysql'})
            self.assertEqual(deploy.validate(cfg), 6101)
            for key, value in [('uid', 999), ('gid', 999), ('user', 'root'), ('group', 'root'), ('account_mode', 'other')]:
                bad = copy.deepcopy(cfg); bad['app']['database'][key] = value
                with self.subTest(key=key), self.assertRaises(deploy.InputNeeded):
                    deploy.validate(bad)
            for kind in ('postgresql', 'influxdb'):
                bad = copy.deepcopy(cfg); bad['app']['kind'] = kind
                with self.subTest(kind=kind), self.assertRaises(deploy.InputNeeded):
                    deploy.validate(bad)

    def test_plan_records_fresh_creation_from_the_actual_tofu_change(self):
        from test_plan import fixture as plan_fixture
        for action in ('create', 'update', 'no-op'):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); cfg = fixture(root)
                cfg['guest']['vmid'] = cfg['app']['vmid'] = 6100
                cfg['site']['node'] = 'pve-lab'
                cfg['ssh_public_keys'] = json.loads((ROOT / 'examples/site.example.json').read_text())['ssh_public_keys']
                site = root / 'site.json'; site.write_text(json.dumps(cfg))
                (root / 'api').write_text('synthetic')
                (root / 'ca').write_text('synthetic CA')
                value = plan_fixture()
                for row in value['resource_changes']:
                    row['change']['actions'] = [action]
                    if action != 'create':
                        row['change']['before'] = copy.deepcopy(row['change']['after'])
                def quiet(command, *args):
                    for argument in command:
                        if argument.startswith('-out='):
                            Path(argument.removeprefix('-out=')).write_bytes(b'synthetic saved plan')
                with patch.object(deploy, 'backup'), patch.object(deploy, 'quiet', side_effect=quiet), \
                        patch.object(deploy.subprocess, 'check_output', return_value=json.dumps(value).encode()):
                    receipt = deploy.execute('plan', site)
                self.assertEqual(receipt['creates_guest'], action == 'create')

    def test_dhcp_resolves_only_the_selected_mac_over_verified_api_tls(self):
        """Never guess a guest address or weaken TLS for DHCP deployments."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); cfg = fixture(root)
            cfg['guest']['interfaces'][0]['ipv4'] = cfg['app']['address'] = 'dhcp'
            (root / 'api').write_text('synthetic-token')
            self.assertEqual(deploy.validate(cfg), 6101)
            rows = [{'hwaddr': cfg['app']['mac'], 'inet': '198.18.100.42/24'},
                    {'hwaddr': '02:00:00:00:99:99', 'inet': '198.18.100.43/24'}]
            with patch.object(deploy.ssl, 'create_default_context') as tls, \
                    patch.object(deploy, 'build_opener') as opener:
                opener.return_value.open.return_value = io.BytesIO(json.dumps({'data': rows}).encode())
                self.assertEqual(deploy.application_address(cfg), '198.18.100.42')
                tls.assert_called_once_with(cafile=str(root / 'ca'))
                self.assertIn('/nodes/practice-pve/lxc/6101/interfaces', opener.return_value.open.call_args.args[0].full_url)
            rows[0]['hwaddr'] = '02:00:00:00:99:98'
            with patch.object(deploy.ssl, 'create_default_context'), \
                    patch.object(deploy, 'build_opener') as opener:
                opener.return_value.open.return_value = io.BytesIO(json.dumps({'data': rows}).encode())
                with self.assertRaises(deploy.InputNeeded): deploy.application_address(cfg)

    def test_token_bearing_api_request_never_follows_redirects(self):
        request = deploy.Request('https://pve.example.invalid:8006/api2/json', headers={'Authorization': 'synthetic-secret'})
        for url in ('http://other.invalid/', 'https://other.invalid/', 'https://pve.example.invalid:8006/elsewhere'):
            with self.subTest(url=url), self.assertRaises(deploy.InputNeeded):
                deploy.RefuseRedirects().redirect_request(request, None, 302, 'Found', {}, url)

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

    def test_interrupted_apply_remains_held_before_a_native_command_can_escape(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(deploy, 'quiet', side_effect=KeyboardInterrupt), patch.object(deploy, 'backup'), patch.object(deploy, 'input_hashes', return_value={}):
            root = Path(tmp); cfg = fixture(root); site = root / 'site.json'; site.write_text(json.dumps(cfg)); (root / 'api').write_text('synthetic')
            work = root / 'state' / '6101'; work.mkdir(parents=True)
            plan = work / 'guest.tfplan'; plan.write_bytes(b'synthetic-plan')
            deploy.write(work / 'plan.json', {'site_sha256': deploy.sha(site), 'source_sha256': deploy.source_hash(), 'plan_sha256': deploy.sha(plan), 'input_hashes': {}})
            with self.assertRaises(KeyboardInterrupt): deploy.execute('apply', site, deploy.sha(plan))
            self.assertTrue((work / 'HOLD.json').exists())
            with self.assertRaises(ValueError): deploy.execute('apply', site, deploy.sha(plan))

    def test_unapplied_stage_repeated_apply_and_staging_started_guest_are_preflight_failures(self):
        for scenario in ('unapplied-stage', 'repeated-apply', 'started-stage'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp, patch.object(deploy, 'quiet') as run, patch.object(deploy, 'backup'), patch.object(deploy, 'input_hashes', return_value={}):
                root = Path(tmp); cfg = fixture(root); site = root / 'site.json'; site.write_text(json.dumps(cfg)); (root / 'api').write_text('synthetic')
                work = root / 'state' / '6101'; work.mkdir(parents=True)
                plan = work / 'guest.tfplan'; plan.write_bytes(b'synthetic-plan')
                receipt = {'site_sha256': deploy.sha(site), 'source_sha256': deploy.source_hash(), 'plan_sha256': deploy.sha(plan), 'input_hashes': {}}
                deploy.write(work / 'plan.json', receipt)
                if scenario != 'unapplied-stage': deploy.write(work / 'applied.json', receipt)
                if scenario == 'started-stage': deploy.write(work / 'started.json', receipt)
                action = 'apply' if scenario == 'repeated-apply' else 'stage'
                with self.assertRaises(ValueError): deploy.execute(action, site, deploy.sha(plan))
                self.assertFalse((work / 'HOLD.json').exists()); run.assert_not_called()

    def test_guest_trust_is_bound_after_creation_and_cannot_silently_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); cfg = fixture(root)
            (root / 'hosts').touch()
            line = '198.18.100.20 ssh-ed25519 AAAAsynthetic\n'
            with patch.object(deploy.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '# Host found: line 1\n' + line, '')):
                deploy.guest_trust(cfg, root)
            with patch.object(deploy.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '# Host found: line 7\n' + line, '')):
                deploy.guest_trust(cfg, root)
            with patch.object(deploy.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, line.replace('AAAAsynthetic', 'AAAAdifferent'), '')):
                with self.assertRaises(ValueError): deploy.guest_trust(cfg, root)

    def test_missing_known_hosts_or_guest_entry_has_a_safe_actionable_instruction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); cfg = fixture(root)
            with self.assertRaisesRegex(deploy.InputNeeded, 'Verify the new guest SSH host key'):
                deploy.guest_trust(cfg, root)
            (root / 'hosts').touch()
            # Use real ssh-keygen to cover its no-match exit status 1.
            with self.assertRaisesRegex(deploy.InputNeeded, 'Verify the new guest SSH host key'):
                deploy.guest_trust(cfg, root)


if __name__ == '__main__':
    unittest.main()
