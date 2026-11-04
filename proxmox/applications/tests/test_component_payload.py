"""Owned input component tests use real private files and existing attempt guards."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import component_payload as payloads
from deployment_state import DeploymentAttempt
from private_io import encoded, write_new


class PrivateInputsFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.identity = 'a' * 64

    def prepare(self, app='first', values=None):
        return payloads.prepare(self.root, self.identity, app,
                                {'selected-secret': b'synthetic-one'} if values is None else values)


class PayloadComponentTests(PrivateInputsFixture):
    def test_same_source_repeat_is_immutable_and_two_app_ids_do_not_share_values(self):
        first = self.prepare()
        before = {p.name: (p.stat().st_ino, p.read_bytes()) for p in first.directory.iterdir()}
        self.assertEqual(self.prepare().check(), first.check())
        self.assertEqual(before, {p.name: (p.stat().st_ino, p.read_bytes()) for p in first.directory.iterdir()})
        second = self.prepare('second', {'selected-secret': b'synthetic-two'})
        self.assertNotEqual(first.check()['payload_sha256'], second.check()['payload_sha256'])
        self.assertEqual(set(p.name for p in first.directory.iterdir()), {payloads.MANIFEST, 'selected-secret'})
        self.assertEqual((first.directory/'selected-secret').read_bytes(), b'synthetic-one')
        self.assertEqual((second.directory/'selected-secret').read_bytes(), b'synthetic-two')
        with self.assertRaises(ValueError):
            self.prepare(values={'selected-secret': b'changed'})

    def test_unsafe_identity_filename_types_and_bounds_refuse_before_creation(self):
        cases = [('a'*63, 'first', {}), ('a'*64, '../first', {}), ('a'*64, 'first', {'../file': b'x'}),
                 ('a'*64, 'first', {payloads.MANIFEST: b'x'}), ('a'*64, 'first', {'file': 'not-bytes'}),
                 ('a'*64, 'first', {'file': b'x'*(payloads.MAX_FILE+1)})]
        for identity, app, values in cases:
            with self.subTest(app=app, count=len(values)), self.assertRaises(ValueError):
                payloads.prepare(self.root, identity, app, values)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_partial_preparation_is_preserved_and_never_resumed(self):
        original = payloads.write_new
        def fail(name, raw, **kwargs):
            if name == payloads.MANIFEST:
                raise OSError('synthetic fsync/write failure')
            return original(name, raw, **kwargs)
        with patch.object(payloads, 'write_new', side_effect=fail), self.assertRaises(OSError):
            self.prepare()
        before = (self.root/'first'/'selected-secret').read_bytes()
        with self.assertRaises(FileNotFoundError):
            self.prepare()
        self.assertEqual((self.root/'first'/'selected-secret').read_bytes(), before)
        self.assertFalse((self.root/'first'/payloads.MANIFEST).exists())

    def test_manifest_extra_file_mode_owner_and_value_drift_fail_closed(self):
        for mutate in ('manifest', 'extra', 'mode', 'value', 'hardlink', 'symlink'):
            with self.subTest(mutate=mutate):
                app = 'case_' + mutate
                selected = self.prepare(app)
                leaf = selected.directory/'selected-secret'
                if mutate == 'manifest':
                    (selected.directory/payloads.MANIFEST).write_bytes(encoded({}))
                elif mutate == 'extra':
                    write_new(selected.directory/'unexpected', b'x')
                elif mutate == 'mode':
                    leaf.chmod(0o644)
                elif mutate == 'value':
                    leaf.write_bytes(b'changed')
                elif mutate == 'hardlink':
                    os.link(leaf, self.root/'hardlink')
                else:
                    leaf.unlink()
                    leaf.symlink_to(self.root/'absent')
                with self.assertRaises((ValueError, OSError)):
                    selected.check()
        selected = self.prepare('owner')
        with patch.object(payloads.os, 'getuid', return_value=os.getuid()+1), self.assertRaises(ValueError):
            selected.check()

    def test_symlink_directory_and_ancestor_swap_do_not_read_outside_bytes(self):
        holder = self.root/'holder'
        holder.mkdir(mode=0o700)
        selected = payloads.prepare(holder, self.identity, 'first', {'secret': b'inside'})
        outside = self.root/'outside'
        outside.mkdir(mode=0o700)
        payloads.prepare(outside, self.identity, 'first', {'secret': b'outside'})
        moved = self.root/'moved'
        original = payloads.os.open
        triggered = []
        def swap(name, flags, *args, **kwargs):
            if name == 'holder' and kwargs.get('dir_fd') is not None and not triggered:
                triggered.append(True)
                holder.rename(moved)
                holder.symlink_to(outside, target_is_directory=True)
            return original(name, flags, *args, **kwargs)
        with patch.object(payloads.os, 'open', side_effect=swap), self.assertRaises(OSError):
            selected.check()
        self.assertEqual(triggered, [True])
        self.assertEqual((outside/'first'/'secret').read_bytes(), b'outside')


class AttemptPayloadIntegrationTests(PrivateInputsFixture):
    def attempt(self):
        state = self.root/'state'; state.mkdir(mode=0o700)
        workspace = self.root/'workspace'; workspace.mkdir(mode=0o700)
        environment = {'GITHUB_RUN_ID': '101', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_RUN_NUMBER': '10',
            'GITHUB_REPOSITORY': 'example/private', 'HOMELAB_DEPLOYMENT_WORKFLOW':
            'example/private/.github/workflows/deploy.yml@' + 'b'*40,
            'GITHUB_SHA': 'c'*40, 'GITHUB_WORKSPACE': str(workspace)}
        context = patch.dict(os.environ, environment)
        context.start(); self.addCleanup(context.stop)
        cfg = {'schema': 'homelab-component-guest-v1', 'guest': {'vmid': 180}, 'app': {'kind': 'synthetic'},
            'paths': {'state_root': str(state)}, 'deployment': {
                'input_identity': self.identity, 'payload_phases': {'worker': 'first'}}}
        binding = {'schema': payloads.BINDING_SCHEMA, 'source_sha256': 'd'*64,
            'site_sha256': 'e'*64, 'vmid':180, 'input_identity':self.identity,
            'app_inputs_directory':str(self.root), 'input_hashes':{}}
        attempt = DeploymentAttempt(cfg, binding, ['preparation', 'worker'])
        attempt.__enter__(); self.addCleanup(attempt.__exit__, None, None, None)
        attempt.begin_infrastructure()
        write_new(attempt.work/'terraform.tfstate', b'{}')
        from private_io import sha
        attempt.infrastructure_complete({'state_sha256': sha(attempt.work/'terraform.tfstate'), 'changed': False})
        ready = attempt.begin_phase('preparation')
        attempt.phase_complete('preparation', {'changed': False}, ready)
        return attempt

    def test_phase_started_and_complete_bind_the_exact_selected_payload(self):
        attempt = self.attempt(); selected = self.prepare()
        ready = attempt.begin_phase('worker', payload=selected)
        started = json.loads((attempt.operation/'worker-started.json').read_bytes())
        self.assertEqual(started['phase_inputs'], selected.check())
        self.assertFalse(attempt.phase_complete('worker', {'changed': False}, ready, payload=selected))
        receipt = json.loads(attempt.receipt.read_bytes())
        self.assertEqual(receipt['schema'], 'homelab-component-ordinary-complete-v1')
        self.assertEqual(receipt['phase_inputs'], {'preparation': None, 'worker': selected.check()})
        self.assertFalse(attempt.hold.exists())

    def test_missing_wrong_app_identity_and_legacy_payloads_never_start_native_phase(self):
        attempt = self.attempt()
        selected = self.prepare('second')
        wrong_identity = payloads.prepare(self.root, 'e'*64, 'first', {})
        for value in (None, selected, wrong_identity, {}):
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError):
                attempt.begin_phase('worker', payload=value)
        self.assertFalse((attempt.operation/'worker-started.json').exists())
        attempt.binding = {'source_sha256': 'd'*64}
        with self.assertRaises(ValueError):
            attempt._phase_payload('worker', selected)

    def test_drift_before_and_during_native_work_preserves_hold_and_started_evidence(self):
        attempt = self.attempt(); selected = self.prepare()
        leaf = selected.directory/'selected-secret'
        leaf.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            attempt.begin_phase('worker', payload=selected)
        self.assertFalse((attempt.operation/'worker-started.json').exists())
        leaf.write_bytes(b'synthetic-one')
        ready = attempt.begin_phase('worker', payload=selected)
        before = (attempt.operation/'worker-started.json').read_bytes()
        leaf.write_bytes(b'changed-during')
        with self.assertRaises(ValueError):
            attempt.phase_complete('worker', {'changed': True}, ready, payload=selected)
        self.assertEqual((attempt.operation/'worker-started.json').read_bytes(), before)
        self.assertTrue(attempt.hold.exists())
        self.assertFalse((attempt.operation/'worker-complete.json').exists())

    def test_record_failure_preserves_input_and_hold_without_replay(self):
        attempt = self.attempt(); selected = self.prepare()
        original = __import__('deployment_state').write_new
        def fail(path, raw):
            if path.name == 'worker-started.json':
                original(path, raw)
                raise OSError('synthetic record failure')
            original(path, raw)
        with patch('deployment_state.write_new', side_effect=fail), self.assertRaises(OSError):
            attempt.begin_phase('worker', payload=selected)
        self.assertTrue(attempt.hold.exists())
        self.assertEqual(selected.check()['app'], 'first')
        with self.assertRaises(ValueError):
            attempt.begin_phase('worker', payload=selected)
        self.assertTrue(attempt.hold.exists())


if __name__ == '__main__':
    unittest.main()
