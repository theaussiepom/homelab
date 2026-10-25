import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('bootstrap', BASE / 'bootstrap.py')
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class BootstrapTests(unittest.TestCase):
    def test_executor_user_can_run_openssh_without_network(self):
        """Verify executor user can run openSSH without network."""
        result = subprocess.run(['ssh', '-F', '/dev/null', '-G', 'root@198.18.0.1'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('hostname 198.18.0.1', result.stdout)

    def test_prepare_builds_for_the_operator_uid_and_gid(self):
        """Verify prepare builds for the operator uid and gid."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            site, settings = root / 'site.json', root / 'settings.json'
            bootstrap.write(site, self.catalog)
            bootstrap.write(settings, self.settings)
            with patch.object(bootstrap, 'ROOT', root), patch.object(bootstrap, 'snapshot'), \
                    patch.object(bootstrap.subprocess, 'run') as run:
                report = bootstrap.container_prepare(site, settings, root / 'first-run')
            build = run.call_args_list[0].args[0]
            self.assertEqual(build[:2], ['docker', 'build'])
            self.assertIn(f'HOST_UID={os.getuid()}', build)
            self.assertIn(f'HOST_GID={os.getgid()}', build)
            self.assertEqual(run.call_args_list[0].kwargs.get('timeout'), 1800)
            self.assertEqual(run.call_args_list[1].kwargs.get('timeout'), 300)
            self.assertEqual(report['prepared_bundle'], str(root / 'first-run/bundle'))

    def test_prepare_timeout_preserves_the_unknown_docker_outcome(self):
        """Explain that stopping a timed-out CLI does not close its Docker work."""
        error = io.StringIO()
        with patch.object(sys, 'argv', ['bootstrap', 'container-prepare',
                '--catalog', '/synthetic/site.json', '--settings', '/synthetic/settings.json',
                '--out', '/synthetic/new-output']), \
                patch.object(bootstrap, 'container_prepare',
                             side_effect=subprocess.TimeoutExpired(['docker', 'run'], 300)), \
                patch.object(sys, 'stderr', error):
            self.assertEqual(bootstrap.main(), 3)
        self.assertIn('may still be running', error.getvalue())
        self.assertIn('before another attempt', error.getvalue())

    def setUp(self):
        """Create isolated synthetic inputs for this test case."""
        self.catalog = bootstrap.read(bootstrap.ROOT / 'examples/site/catalog/site.json')
        self.settings = bootstrap.read(BASE / 'settings.example.json')
        self.catalog['site']['ssh_public_keys'] = ['ssh-ed25519 synthetic-public-fixture']

    def test_deploy_only(self):
        """Verify deploy only."""
        self.assertEqual(bootstrap.select(self.catalog)['key'], 'deploy')
        self.assertGreater(len(self.catalog['guests']), 1)

    def test_no_missing_deploy(self):
        """Verify no missing deploy."""
        self.catalog['guests'] = [g for g in self.catalog['guests'] if g['key'] != 'deploy']
        with self.assertRaises(ValueError): bootstrap.select(self.catalog)

    def test_preserve_guest_protection(self):
        """Verify preserve guest protection."""
        catalog = copy.deepcopy(self.catalog)
        next(g for g in catalog['guests'] if g['key'] == 'deploy')['protection'] = False
        with self.assertRaises(ValueError): bootstrap.select(catalog)

    def test_no_extra_nic(self):
        """Verify no extra NIC."""
        catalog = copy.deepcopy(self.catalog)
        guest = next(g for g in catalog['guests'] if g['key'] == 'deploy')
        guest['interfaces'].append(copy.deepcopy(guest['interfaces'][0]))
        with self.assertRaises(ValueError): bootstrap.select(catalog)

    def test_no_credentials_in_settings(self):
        """Verify no credentials in settings."""
        self.settings['token'] = 'synthetic'
        with self.assertRaises(ValueError): bootstrap.settings_check(self.settings)

    def test_api_template_download_is_not_an_mvp_preparation_option(self):
        """Keep template transfer on the qualified cached-file SSH path."""
        self.settings['template'] = {'url': 'https://example.invalid/debian.tar.zst',
            'file_name': 'debian.tar.zst', 'sha256': 'a' * 64, 'datastore_id': 'local'}
        with self.assertRaisesRegex(ValueError, 'cached file'):
            bootstrap.settings_check(self.settings)

    def test_repository_and_reference_validation(self):
        """Verify repository and reference validation."""
        for key, value in [('repository', 'https://github.com/owner/repo'), ('repository', 'owner/repo\ncommand'),
                           ('runner_name', 'bad name'), ('admin_cidr', '0.0.0.0/0')]:
            settings = dict(self.settings); settings[key] = value
            with self.assertRaises(ValueError): bootstrap.settings_check(settings)

    def test_prepare_preserves_host_and_state_ownership(self):
        """Verify prepare preserves host and state ownership."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp); site = path / 'site.json'; settings = path / 'settings.json'
            bootstrap.write(site, self.catalog); bootstrap.write(settings, self.settings)
            out = path / 'bundle'
            report = bootstrap.prepare(site, settings, out)
            self.assertEqual(report['selected_guests'], ['deploy'])
            self.assertEqual(report['final_state_root'], 'bootstrap')
            self.assertFalse(report['live_execution_admitted'])
            self.assertFalse(report['existing_host_objects_managed'])
            self.assertIn('backend "local"', (out / 'tofu/backend.tf').read_text())
            source = (out / 'tofu/main.tf').read_text()
            self.assertIn('for_each        = { deploy = var.deploy }', source)
            self.assertIn('module.guests["deploy"].identity', source)
            inventory = bootstrap.read(out / 'inventory.json')
            self.assertEqual(list(inventory['all']['hosts']), ['deploy'])
            self.assertEqual(inventory['all']['hosts']['deploy']['ansible_user'], 'root')
            before = (out / 'preparation.json').read_bytes()
            with self.assertRaises(ValueError): bootstrap.prepare(site, settings, out)
            self.assertEqual(before, (out / 'preparation.json').read_bytes())

    def test_small_standalone_example_prepares_without_full_estate_or_database(self):
        """Verify small standalone example prepares without full estate or database."""
        catalog = bootstrap.read(BASE / 'site.example.json')
        catalog['site']['environment'] = 'synthetic'
        catalog['site']['ssh_public_keys'] = self.catalog['site']['ssh_public_keys']
        settings = bootstrap.read(BASE / 'settings.example.json')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bootstrap.write(root / 'site.json', catalog)
            bootstrap.write(root / 'settings.json', settings)
            report = bootstrap.prepare(root / 'site.json', root / 'settings.json', root / 'bundle')
            self.assertEqual(report['selected_guests'], ['deploy'])
            projected = bootstrap.read(root / 'bundle/tofu/site.auto.tfvars.json')
            self.assertEqual(projected['deploy']['vmid'], catalog['guests'][0]['vmid'])
            self.assertEqual(projected['site']['api_endpoint'], catalog['site']['api_endpoint'])

    def test_cached_template_is_hash_checked_and_staged_for_automatic_access_setup(self):
        """Verify cached template is hash checked and staged for automatic access setup."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / 'debian.tar.zst'
            archive.write_bytes(b'synthetic cached vendor template')
            template = {'file': str(archive), 'file_name': archive.name,
                        'sha256': hashlib.sha256(archive.read_bytes()).hexdigest(), 'datastore_id': 'local'}
            self.settings['template'] = template
            guest = next(g for g in self.catalog['guests'] if g['key'] == 'deploy')
            guest['template_file_id'] = 'local:vztmpl/' + archive.name
            bootstrap.write(root / 'site.json', self.catalog)
            bootstrap.write(root / 'settings.json', self.settings)
            bootstrap.prepare(root / 'site.json', root / 'settings.json', root / 'bundle')
            self.assertEqual((root / 'bundle/template.archive').read_bytes(), archive.read_bytes())
            self.assertEqual(bootstrap.read(root / 'bundle/template.json')['file_id'], guest['template_file_id'])
            self.assertNotIn('template', bootstrap.read(root / 'bundle/tofu/site.auto.tfvars.json'))
            archive.write_bytes(b'changed file')
            with self.assertRaises(ValueError):
                bootstrap.prepare(root / 'site.json', root / 'settings.json', root / 'changed')

    def test_cached_template_mount_is_read_only_and_does_not_depend_on_mac_paths_inside_docker(self):
        """Verify cached template mount is read only and does not depend on mac paths inside docker."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / 'debian.tar.zst'
            archive.write_bytes(b'synthetic template')
            settings = dict(self.settings, template={'file': str(archive), 'file_name': archive.name,
                            'sha256': hashlib.sha256(archive.read_bytes()).hexdigest(), 'datastore_id': 'local'})
            bootstrap.write(root / 'site.json', self.catalog)
            bootstrap.write(root / 'settings.json', settings)
            with patch.object(bootstrap, 'ROOT', root), patch.object(bootstrap, 'snapshot'), \
                    patch.object(bootstrap.subprocess, 'run') as process:
                bootstrap.container_prepare(root / 'site.json', root / 'settings.json', root / 'first')
            args = process.call_args_list[-1].args[0]
            self.assertIn(str(archive) + ':/inputs/template.archive:ro', args)
            self.assertIn('HOMELAB_TEMPLATE_FILE=/inputs/template.archive', args)

    def test_duplicate_json_rejected(self):
        """Verify duplicate JSON rejected."""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'bad.json'; p.write_text('{"a":1,"a":2}')
            with self.assertRaises(ValueError): bootstrap.read(p)

    def test_guest_id_and_key_are_required(self):
        """Verify guest id and key are required."""
        for vmid in (4914, 4915, 4920):
            catalog = copy.deepcopy(self.catalog)
            next(g for g in catalog['guests'] if g['key'] == 'deploy')['vmid'] = vmid
            with self.assertRaises(ValueError): bootstrap.select(catalog)
        self.catalog['site']['ssh_public_keys'] = []
        with self.assertRaises(ValueError): bootstrap.select(self.catalog)

    def test_saved_plan_binding_changes_with_configuration(self):
        """Verify saved plan binding changes with configuration."""
        sys.path.insert(0, str(BASE))
        from native import binding
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp); (work / 'tofu').mkdir()
            configuration = work / 'tofu/main.tf'
            configuration.write_text('original configuration')
            original = binding(work)
            configuration.write_text('different configuration')
            self.assertNotEqual(original, binding(work))

    def test_replacement_or_unrelated_plan_refused(self):
        """Verify replacement or unrelated plan refused."""
        sys.path.insert(0, str(BASE))
        from native import check_plan
        address = 'module.guests["deploy"].proxmox_virtual_environment_container.guest'
        check_plan({'resource_changes': [{'address': address, 'change': {'actions': ['create']}}]})
        for item in [
            {'address': address, 'change': {'actions': ['delete', 'create']}},
            {'address': 'other.resource', 'change': {'actions': ['create']}},
        ]:
            with self.assertRaises(ValueError): check_plan({'resource_changes': [item]})

    def test_snapshot_excludes_private_inputs_and_refuses_links(self):
        """Verify snapshot excludes private inputs and refuses links."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'source'; root.mkdir()
            names = ['proxmox/bootstrap', 'src/homelab', 'schemas', 'ansible/roles/homelab_admission',
                     'examples/site/catalog', 'infrastructure/proxmox/modules/lxc', 'infrastructure/proxmox/critical']
            for name in names: (root / name).mkdir(parents=True, exist_ok=True)
            for name in ['examples/site/catalog/site.json', 'infrastructure/proxmox/critical/versions.tf',
                         'infrastructure/proxmox/critical/.terraform.lock.hcl']:
                (root / name).write_text('public')
            private = root / 'proxmox/bootstrap/.local'; private.mkdir()
            (private / 'private-marker').write_text('synthetic private input')
            with patch.object(bootstrap, 'ROOT', root):
                output = Path(tmp) / 'snapshot'
                bootstrap.snapshot(output)
                self.assertFalse((output / 'proxmox/bootstrap/.local').exists())
                (root / 'proxmox/bootstrap/unsafe-link').symlink_to(private / 'private-marker')
                with self.assertRaises(ValueError): bootstrap.snapshot(Path(tmp) / 'linked-snapshot')


if __name__ == '__main__': unittest.main()
