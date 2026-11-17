"""Effective ownership rejects tampering, newer history and false ordinary success."""
import copy
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import component_current as m
import component_recovery
from custody_records import Snapshot
from private_io import encoded, read_json, write_bytes, write_new
import test_component_recovery as fixture


class CurrentStateTests(unittest.TestCase):
    def setUp(self):
        self.tx = fixture.RecoveryTransactions(); self.tx.setUp(); self.addCleanup(self.tx.doCleanups)
        self.work = self.tx.work
        self.failed = self.tx.fail_after_preparation()
        component_recovery.restore(self.tx.cfg, self.failed)
        self.state, self.owner = m.read(self.work)

    def test_atomic_pointer_requires_closed_exact_immutable_proof(self):
        changes = [lambda v: v.update(extra=True), lambda v: v.update(schema='unknown'),
            lambda v: v.update(kind='passed'), lambda v: v.update(state_sha256='bad'),
            lambda v: v.update(state_identity=[]), lambda v: v.update(resolved=[]),
            lambda v: v.update(owner={'path': '/foreign/complete.json', 'sha256': 'a'*64}),
            lambda v: v['owner'].update(sha256='a'*64), lambda v: v['owner'].update(extra=True),
            lambda v: v['owner'].update(path='relative/complete.json'),
            lambda v: v.update(resolved={'bad': {}}),
            lambda v: next(iter(v['resolved'].values())).update(hold_sha256='bad'),
            lambda v: next(iter(v['resolved'].values())).update(markers={})]
        for change in changes:
            value = copy.deepcopy(self.state); change(value)
            with self.subTest(change=changes.index(change)), self.assertRaises(ValueError):
                m.validate(value, self.work, Snapshot())
        proof_path = Path(self.state['verification']['path'])
        raw = proof_path.read_bytes()
        for key, value in [('actor', ''), ('reason', ' '), ('source_revision', 'unversioned'),
                           ('status', 'failed'), ('kind', 'ordinary'), ('owner_sha256', 'b'*64)]:
            proof = read_json(proof_path, private=True); proof[key] = value
            write_bytes(proof_path, encoded(proof))
            candidate = copy.deepcopy(self.state); candidate['verification'] = m.reference(proof_path)
            with self.subTest(key=key), self.assertRaises(ValueError): m.validate(candidate, self.work, Snapshot())
            write_bytes(proof_path, raw)
        self.assertEqual(m.read(self.work)[0], self.state)

    def test_monotonic_publication_and_exact_backend_owner(self):
        proof = read_json(Path(self.state['verification']['path']), private=True)
        folder = self.work/'recovery-100-1'; folder.mkdir(mode=0o700)
        write_new(folder/'verified.json', encoded(proof))
        with self.assertRaisesRegex(ValueError, 'newer effective'):
            m.publish(self.work, 'rollback', Path(self.state['owner']['path']), folder/'verified.json')
        with self.assertRaisesRegex(ValueError, 'selected effective'):
            m.backend(self.work, {'foreign': True})
        expected = m.backend(self.work, self.owner)
        self.assertEqual(expected, (self.state['state_sha256'], self.state['state_identity']))
        self.assertEqual(m.generation_hash(self.work), m.sha(self.work/m.NAME))
        with patch.dict(os.environ, {'HOMELAB_CD_RECOVERY': ''}), self.assertRaisesRegex(ValueError, 'versioned'):
            self.tx.case.all_phases()

    def test_missing_pointer_legacy_backend_and_bounded_resolved_markers(self):
        raw = (self.work/m.NAME).read_bytes(); (self.work/m.NAME).unlink()
        self.assertIsNone(m.read(self.work))
        self.assertEqual(m.owner_path(self.work), self.work/'ordinary-complete.json')
        self.assertEqual(m.backend(self.work, self.owner)[0], self.owner['state_sha256'])
        self.assertEqual(m.generation_hash(self.work), m.sha(self.work/'ordinary-complete.json'))
        old = dict(self.owner); old.pop('state_identity')
        self.assertEqual(m.backend(self.work, old), (old['state_sha256'], None))
        write_new(self.work/m.NAME, raw)
        folder = self.work/'ordinary-99-1'; folder.mkdir(mode=0o700)
        write_new(folder/'HOLD.json', b'{}\n')
        with self.assertRaises(ValueError): m.markers(folder)
        (folder/'HOLD.json').unlink()
        for index in range(259): write_new(folder/('phase'+str(index)+'-started.json'), b'{}\n')
        with self.assertRaisesRegex(ValueError, 'Bound'): m.markers(folder)

    def test_reconciliation_is_not_an_ordinary_success_and_closed_owner_is_required(self):
        # A new failed run after rollback is independently reconciled.
        with patch.dict(os.environ, {'GITHUB_RUN_ID': '103', 'GITHUB_RUN_NUMBER': '12'}):
            self.tx.fail_after_preparation()
        failed = self.work/'ordinary-103-1'
        with patch.dict(os.environ, {'GITHUB_RUN_ID': '104', 'GITHUB_RUN_NUMBER': '13'}):
            component_recovery.reconcile(self.tx.cfg, failed, Path(self.state['owner']['path']), self.owner,
                reason='Engineer verified existing state', actor_context='protected-main-reconciliation')
        value, owner = m.read(self.work)
        self.assertEqual(owner['schema'], m.OWNER)
        path = Path(value['owner']['path']); raw = path.read_bytes()
        for key, wrong in [('workflow', ['invalid', 'invalid']), ('phase_inputs', {}), ('status', 'passed')]:
            broken = copy.deepcopy(owner); broken[key] = wrong
            write_bytes(path, encoded(broken))
            with self.assertRaises(ValueError): m.reconciled_owner(broken, path.parent)
            write_bytes(path, raw)
        candidate = copy.deepcopy(value); candidate['kind'] = 'ordinary'
        with self.assertRaisesRegex(ValueError, 'cannot become an ordinary'):
            m.validate(candidate, self.work, Snapshot())


if __name__ == '__main__': unittest.main()
