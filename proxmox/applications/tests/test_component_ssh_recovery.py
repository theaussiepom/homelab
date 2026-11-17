"""Genuine ownership transactions cover root-key control changes and rollback."""
import base64
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT/'blueprints'), str(ROOT/'proxmox/applications')]
import component_ansible
import component_control
import component_generation
import component_plan
import component_packet
import component_recovery
import component_restore
import component_ssh
import proxmox_guest
from private_io import encoded, read_json, sha, write_bytes, write_new
import test_component_recovery as fixture
from test_component_ssh import KEY_A, KEY_B, KEY_C

EXECUTE = component_restore.execute
KEY_D = 'ssh-ed25519 ' + base64.b64encode(component_ssh.WIRE_PREFIX + b'd' * 32).decode()


class RootSSHRecovery(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        directory = self.root / '.ssh'
        directory.mkdir(mode=0o700)
        self.keys = directory / 'authorized_keys'
        self.original = ('# retained\nrestrict ' + KEY_C + ' unknown\n' + KEY_A + '\n').encode()
        self.keys.write_bytes(self.original)
        self.keys.chmod(0o600)
        for name, value in (('ROOT_KEYS', str(self.keys)), ('ROOT_UID', os.getuid()), ('ROOT_GID', os.getgid())):
            context = patch.object(component_ssh, name, value)
            context.start()
            self.addCleanup(context.stop)
        if not hasattr(os, 'listxattr'):
            context = patch.object(os, 'listxattr', return_value=[], create=True)
            context.start()
            self.addCleanup(context.stop)
        original_site = fixture.fixture.site
        def selected_site():
            value = original_site()
            value['contexts']['lab']['ssh_public_keys'] = [KEY_A]
            return value
        with patch.object(fixture.fixture, 'site', side_effect=selected_site):
            self.tx = fixture.RecoveryTransactions()
            self.tx.setUp()
        self.addCleanup(self.tx.doCleanups)
        # Only transport is fake. Root file capture, additive writing and exact
        # restoration use production code on this owned temporary filesystem.
        self.executions = []
        def controls(cfg, operation, selection, *, mode, captured=None, allowed=None):
            self.executions.append((mode, copy.deepcopy(allowed)))
            result = self.tx.controls(cfg, operation, selection, mode=mode, captured=captured, allowed=allowed)
            if str(self.keys) in selection['files']:
                if mode == 'restore':
                    component_control.restore_file(str(self.keys), captured['files'][str(self.keys)],
                                                   allowed[str(self.keys)])
                actual = component_control.capture_file(str(self.keys))
                if mode == 'verify':
                    self.assertEqual(actual, captured['files'][str(self.keys)])
                result['files'][str(self.keys)] = actual
            return result
        context = patch.object(component_restore, 'execute', side_effect=controls)
        context.start()
        self.addCleanup(context.stop)
        original_ansible = self.tx.case.ansible
        def ansible(argv, environment, log):
            original_ansible(argv, environment, log)
            values = read_json(Path(argv[-1][1:]), private=True)
            if 'component_root_keys' in values:
                result = component_ssh.run(values['component_root_keys']['request'])
                if result['changed']:
                    write_bytes(log, b'example : ok=1 changed=1 failed=0\n')
        context = patch.object(component_ansible, 'quiet', side_effect=ansible)
        context.start()
        self.addCleanup(context.stop)

    def select_next_keys(self):
        consumer = self.tx.case.root/'consumer/site.json'
        value = json.loads(consumer.read_text())
        value['contexts']['lab']['ssh_public_keys'] = [KEY_A, KEY_B]
        consumer.write_text(json.dumps(value))
        plan = component_plan.resolve(self.tx.case.root/'library', consumer)
        packet = component_packet.lower_plan(plan, inputs=self.tx.case.inputs)['resolver']
        write_bytes(self.tx.case.packet, encoded(packet))
        self.tx.case.cfg = json.loads(packet['files']['site.json'])
        self.tx.cfg = self.tx.case.cfg
        context = patch.dict(os.environ, {'GITHUB_SHA': 'd' * 40})
        context.start()
        self.addCleanup(context.stop)

    def test_addition_rollback_and_fresh_ordinary_deployment_preserve_all_prior_keys(self):
        self.select_next_keys()
        failed = self.tx.fail_after_preparation()
        self.assertEqual(self.keys.read_bytes(), self.original + (KEY_B + '\n').encode())
        before = read_json(failed/'controls-before.json', private=True)
        self.assertEqual(base64.b64decode(before['files'][str(self.keys)]['content']), self.original)
        self.assertEqual(component_recovery.restore(self.tx.cfg, failed)['status'], 'failed_rolled_back')
        self.assertEqual(self.keys.read_bytes(), self.original)
        self.assertEqual(self.keys.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.tx.work/'ordinary-complete.json').read_bytes(), self.tx.before)
        self.assertFalse((self.tx.work/'ORDINARY-HOLD.json').exists())
        restore = next(allowed for mode, allowed in self.executions if mode == 'restore')
        self.assertIn(sha(self.keys), restore[str(self.keys)])
        with patch.dict(os.environ, {'GITHUB_RUN_ID': '103', 'GITHUB_RUN_NUMBER': '12', 'GITHUB_SHA': 'e' * 40}):
            self.tx.case.all_phases()
            self.assertEqual(component_recovery.accept(self.tx.cfg, self.tx.work/'ordinary-103-1')['status'], 'accepted')
        self.assertEqual(self.keys.read_bytes(), self.original + (KEY_B + '\n').encode())
        self.assertIn('ordinary-103-1', read_json(self.tx.work/'ordinary-complete.json', private=True)['operation'])
        self.assertFalse((self.tx.work/'ORDINARY-HOLD.json').exists())
        self.assertTrue((self.tx.work/'recovery-102-1/result.json').exists())

    def test_foreign_added_authorization_is_not_erased_during_failed_rollback(self):
        self.select_next_keys()
        failed = self.tx.fail_after_preparation()
        foreign = self.keys.read_bytes() + (KEY_D + '\n').encode()
        self.keys.write_bytes(foreign)
        with self.assertRaises(ValueError):
            component_recovery.restore(self.tx.cfg, failed)
        self.assertEqual(self.keys.read_bytes(), foreign)
        self.assertEqual((self.tx.work/'ordinary-complete.json').read_bytes(), self.tx.before)
        self.assertTrue((self.tx.work/'ORDINARY-HOLD.json').exists())

    def test_legacy_inventory_without_key_preimage_stops_before_infrastructure_reversal(self):
        original = component_restore.descriptor
        def legacy(owner, cfg):
            result = original(owner, cfg)
            result['files'].pop(str(self.keys))
            result['metadata'].pop(str(self.keys))
            result.pop('root_ssh_keys')
            return result
        with patch.object(component_restore, 'descriptor', side_effect=legacy):
            failed = self.tx.fail_after_preparation()
        with patch.object(proxmox_guest, 'infrastructure') as native:
            with self.assertRaisesRegex(ValueError, 'Saved control inventory differs'):
                component_recovery.restore(self.tx.cfg, failed)
        native.assert_not_called()
        self.assertEqual(self.keys.read_bytes(), self.original)
        self.assertTrue((self.tx.work/'ORDINARY-HOLD.json').exists())

    def test_descriptor_and_source_reconciliation_verify_installed_keys_without_exclusive_ownership(self):
        selected = component_restore.descriptor(self.tx.owner, self.tx.cfg)
        self.assertEqual(selected['root_ssh_keys'], [KEY_A])
        self.assertEqual(selected['metadata'][str(self.keys)], {'uid': 0, 'gid': 0})
        row = component_control.capture_file(str(self.keys))
        choice = {'files': {str(self.keys): None}, 'root_ssh_keys': [KEY_A],
                  'expected': {}, 'metadata': {}, 'packages': []}
        component_restore.expected(choice, {'files': {str(self.keys): row}, 'packages': []})
        choice['root_ssh_keys'] = [KEY_A, KEY_B]
        with self.assertRaises(ValueError):
            component_restore.expected(choice, {'files': {str(self.keys): row}, 'packages': []})
        self.assertEqual(self.keys.read_bytes(), self.original)

    def test_preparation_transport_is_closed_public_key_only_and_uses_creation_only_provider_block(self):
        values = component_ansible.variables(self.tx.cfg, 'preparation')
        self.assertEqual(values['component_root_keys']['request'], {'mode': 'install', 'keys': [KEY_A]})
        self.assertNotIn(str(self.tx.trust/'key'), json.dumps(values['component_root_keys']))
        provider = (Path(component_ansible.__file__).parent/'tofu/guest/main.tf').read_text()
        self.assertIn('user_account { keys = var.ssh_public_keys }', provider)
        self.assertIn('initialization[0].user_account', provider)
        self.assertIn('prevent_destroy = true', provider)
        import yaml
        tasks = yaml.safe_load((Path(component_ansible.__file__).parent/'ansible/component-preparation.yml').read_text())[0]['tasks']
        task = next(row for row in tasks if row['name'].startswith('Add declared root SSH'))
        self.assertTrue(task['no_log'])
        self.assertEqual(task['when'], 'component_root_keys is defined')
        recovery = yaml.safe_load((Path(component_restore.__file__).parent/'ansible/component-rollback.yml').read_text())[0]['tasks']
        self.assertTrue(recovery[0]['no_log'])
        self.assertEqual(recovery[0]['when'], 'recovery_root_keys is defined')

    def test_restore_transport_checks_inventory_before_target_contact(self):
        choice = {'files': {str(self.keys): None}}
        for captured in (None, {}, {'files': None}, {'files': {}}, {'files': {'foreign': None}}):
            with self.subTest(captured=captured), patch.object(proxmox_guest, 'guest_trust') as trust:
                with self.assertRaisesRegex(ValueError, 'Saved control inventory differs'):
                    EXECUTE(self.tx.cfg, self.tx.work, choice, mode='restore', captured=captured)
                trust.assert_not_called()

    def test_restore_transport_verifies_shared_keys_before_any_control_write(self):
        choice = {'files': {str(self.keys): None}, 'root_ssh_keys': [KEY_A],
                  'expected': {}, 'metadata': {}, 'packages': [], 'images': [],
                  'projects': [], 'units': [], 'health': [], 'native_files': []}
        calls = []
        def local_transport(argv, environment, log):
            values = read_json(Path(argv[-1][1:]), private=True)
            request = values['recovery_root_keys']['request']
            wanted = {'mode': 'verify', 'keys': [KEY_A]}
            if values['recovery_mode'] != 'capture':
                wanted['metadata'] = {'uid': os.getuid(), 'gid': os.getgid(), 'mode': 0o600}
            self.assertEqual(request, wanted)
            component_ssh.run(request)
            calls.append(values['recovery_mode'])
            if values['recovery_mode'] == 'restore':
                component_control.run(values['recovery_restore'])
            result = component_control.run(values['recovery_request'])
            write_new(Path(values['recovery_output']), encoded(result))
        with patch.object(component_ansible, 'quiet', side_effect=local_transport):
            captured = EXECUTE(self.tx.cfg, self.tx.work, choice, mode='capture')
            self.keys.write_bytes(self.original + (KEY_B + '\n').encode())
            restored = EXECUTE(self.tx.cfg, self.tx.work, choice, mode='restore',
                               captured=captured, allowed={str(self.keys): [sha(self.keys)]})
            self.assertEqual(restored, captured)
            self.assertEqual(EXECUTE(self.tx.cfg, self.tx.work, choice, mode='verify',
                                     captured=captured), captured)
            self.assertEqual(calls, ['capture', 'restore', 'verify'])
            self.assertEqual(self.keys.read_bytes(), self.original)
            self.keys.chmod(0o640)
            with self.assertRaises(ValueError):
                EXECUTE(self.tx.cfg, self.tx.work, choice, mode='restore',
                        captured=captured, allowed={str(self.keys): [sha(self.keys)]})
            self.assertEqual(calls, ['capture', 'restore', 'verify'])
            self.assertEqual(self.keys.read_bytes(), self.original)
            self.assertEqual(self.keys.stat().st_mode & 0o777, 0o640)
            self.keys.chmod(0o600)
            self.keys.write_bytes((KEY_C + '\n').encode())
            with self.assertRaises(ValueError):
                EXECUTE(self.tx.cfg, self.tx.work, choice, mode='restore',
                        captured=captured, allowed={str(self.keys): [sha(self.keys)]})
            self.assertEqual(calls, ['capture', 'restore', 'verify'])
            self.assertEqual(self.keys.read_bytes(), (KEY_C + '\n').encode())
