"""An operator-reviewed failed SDN update never becomes a completed phase."""
import copy
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import deploy
import initial_ordinary
import coordinated_generation as generation
import private_io as io
from custody_fixtures import save
import test_initial_ordinary as original_fixture


class InfrastructureFailureTests(unittest.TestCase):
    def setUp(self):
        self.case = original_fixture.InitialOrdinaryTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.cfg, self.work = self.case.cfg, self.case.work
        # Exercise the tagged VLAN and an unrelated untagged backend interface.
        self.cfg['guest']['interfaces'].append(
            {'ipv4': '198.18.30.8/24', 'mac': '02:00:00:00:01:08',
             'bridge': 'vmbr30', 'vlan': None})
        self.infra, self.apps = self.case.runtime()
        self.good_infra = self.infra.side_effect
        self.case.all_phases()
        self.previous = self.case.canonical.read_bytes()
        self.previous_backend = (self.work / 'terraform.tfstate').read_bytes()
        previous = json.loads(self.previous)
        self.operation = self.work / 'ordinary-778-1'

        def denied(cfg, site, work, operation, expected, **kwargs):
            state = json.loads((work / 'terraform.tfstate').read_bytes())
            state['serial'] += 1  # Native refresh was saved despite the denied PUT.
            save(work / 'terraform.tfstate', state)
            plan_sha = save(operation / 'guest.tfplan', b'fixture saved provider plan')
            save(operation / 'plan.json',
                 {'binding': expected, 'plan_sha256': plan_sha,
                  'existing_guest': True, 'changed': True})
            save(operation / 'apply-window.json',
                 {'plan_sha256': plan_sha, 'started_at_ns': 1})
            save(operation / 'infrastructure.log',
                 b'Error: received an HTTP 403 response - Reason: Permission check failed '
                 b'(/sdn/zones/localnetwork/vmbr0/25, SDN.Use)\n')
            raise RuntimeError('synthetic SDN.Use denied before guest update')

        self.infra.side_effect = denied
        with patch.dict(os.environ, {'GITHUB_RUN_ID': '778', 'GITHUB_RUN_NUMBER': '778',
                                     'GITHUB_SHA': self.case.revisions[1]}):
            with self.assertRaises(RuntimeError):
                deploy.run('infrastructure', self.case.site)
        self.infra.side_effect = self.good_infra
        self.hold = (self.work / 'ORDINARY-HOLD.json').read_bytes()
        held = json.loads(self.hold)
        snapshot = self.operation / 'infrastructure'
        save(snapshot / 'terraform.tfstate', (self.work / 'terraform.tfstate').read_bytes())
        save(snapshot / 'previous' / 'terraform.tfstate', self.previous_backend)
        state_hash, identity = generation.backend(snapshot, initial_ordinary.selection(self.cfg))
        self.review = {
            'schema': 'homelab-reviewed-infrastructure-failure-v1',
            'status': 'reviewed_failure', 'binding': held['binding'],
            'operation': str(self.operation), 'previous_operation': Path(previous['operation']).name,
            'previous_state_sha256': previous['state_sha256'],
            'state_sha256': state_hash, 'state_identity': identity,
            'plan_sha256': io.sha(self.operation / 'guest.tfplan'),
            'failure_kind': 'pve_sdn_use_denied_before_update',
            'permission_path': '/sdn/zones/localnetwork/vmbr0/25',
            'configuration_unchanged': True, 'guest_healthy': True,
        }
        self.review_path = snapshot / 'review.json'
        self.row = {
            'operation': self.operation.name, 'phase': 'infrastructure',
            'hold_sha256': io.digest(self.hold),
            'infrastructure_sha256': save(self.review_path, self.review),
            'log_sha256': io.sha(self.operation / 'infrastructure.log'),
            'previous_ordinary_sha256': io.digest(self.previous),
            'state_sha256': state_hash,
        }
        self.cfg['reviewed_ordinary_failures'] = [self.row]
        save(self.case.site, self.cfg)

    def next_run(self, number=779):
        return patch.dict(os.environ, {'GITHUB_RUN_ID': str(number),
                                      'GITHUB_RUN_NUMBER': str(number),
                                      'GITHUB_SHA': self.case.revisions[1]})

    def preserve_hold(self):
        (self.work / 'ORDINARY-HOLD.json').rename(self.operation / 'preserved-failed-hold.json')

    def test_deliberate_review_preserves_failed_bytes_and_allows_fresh_later_cd(self):
        self.assertFalse((self.operation / 'infrastructure-complete.json').exists())
        self.assertEqual(self.case.canonical.read_bytes(), self.previous)
        with self.next_run():
            before = self.infra.call_count
            with self.assertRaises((ValueError, OSError)):
                deploy.run('infrastructure', self.case.site)
            self.assertEqual(self.infra.call_count, before)
            self.preserve_hold()  # Explicit operator action, never a deploy helper action.
            original = {p: p.read_bytes() for p in self.operation.rglob('*') if p.is_file()}
            self.case.all_phases()
            self.assertIn('reviewed_drift', self.infra.call_args.kwargs)
        with self.next_run(780):
            self.case.all_phases()
            self.assertNotIn('reviewed_drift', self.infra.call_args.kwargs)
        self.assertEqual(json.loads(self.case.canonical.read_bytes())['run_number'], 780)
        for path, raw in original.items():
            self.assertEqual(path.read_bytes(), raw)
        self.assertFalse((self.operation / 'complete.json').exists())
        self.assertFalse((self.operation / 'infrastructure-complete.json').exists())
        self.assertEqual((self.operation / 'preserved-failed-hold.json').read_bytes(), self.hold)

    def test_rejects_changed_review_semantics_even_with_matching_source_hash(self):
        self.preserve_hold()
        mutations = [
            lambda r: r.update(schema='unknown'),
            lambda r: r.update(status='passed'),
            lambda r: r.update(failure_kind='unknown'),
            lambda r: r.update(configuration_unchanged=False),
            lambda r: r.update(guest_healthy=False),
            lambda r: r.update(permission_path=None),
            lambda r: r.update(permission_path='/sdn/zones/localnetwork/vmbr0/107'),
            lambda r: r.update(binding={}),
            lambda r: r.update(operation=str(self.work / 'ordinary-779-1')),
            lambda r: r.update(previous_operation='../ordinary-777-1'),
            lambda r: r.update(previous_operation='ordinary-779-1'),
            lambda r: r.update(previous_state_sha256='a' * 64),
            lambda r: r.update(state_sha256='a' * 64),
            lambda r: r.update(state_identity={}),
            lambda r: r.update(plan_sha256='a' * 64),
        ]
        for index, mutate in enumerate(mutations):
            current = copy.deepcopy(self.review)
            mutate(current)
            self.row['infrastructure_sha256'] = save(self.review_path, current)
            with self.subTest(index=index), self.next_run():
                before = self.infra.call_count
                with self.assertRaises((ValueError, OSError)):
                    deploy.run('infrastructure', self.case.site)
                self.assertEqual(self.infra.call_count, before)
                self.assertFalse((self.work / 'ordinary-779-1').exists())
        self.assertEqual(self.case.canonical.read_bytes(), self.previous)

    def test_rejects_finished_partial_foreign_or_unselected_attempts(self):
        self.preserve_hold()
        originals = {p: p.read_bytes() for p in self.operation.rglob('*') if p.is_file()}
        cases = ['unselected', 'complete', 'infra-complete', 'nested-hold', 'previous-snapshot', 'previous-array',
                 'previous-status', 'snapshot-vmid', 'window-finished', 'window-time-type',
                 'window-time-zero', 'window-plan', 'plan-binding', 'plan-existing', 'plan-changed',
                 'plan-bytes', 'log-other', 'log-partial-success', 'same-run']
        previous_op = self.work / self.review['previous_operation'] / 'complete.json'
        previous_bytes = previous_op.read_bytes()
        for name in cases:
            review = copy.deepcopy(self.review)
            row = copy.deepcopy(self.row)
            self.cfg['reviewed_ordinary_failures'] = [row]
            if name == 'unselected':
                self.cfg.pop('reviewed_ordinary_failures')
            if name == 'complete':
                save(self.operation / 'complete.json', {})
            if name == 'infra-complete':
                save(self.operation / 'infrastructure-complete.json', {})
            if name == 'nested-hold':
                save(self.operation / 'infrastructure' / 'PENDING-HOLD.json', {})
            if name == 'previous-snapshot':
                save(self.operation / 'infrastructure' / 'previous' / 'terraform.tfstate',
                     self.previous_backend + b' ')
            if name in {'previous-array', 'previous-status'}:
                v = [] if name == 'previous-array' else dict(json.loads(previous_bytes), status='failed')
                row['previous_ordinary_sha256'] = save(previous_op, v)
                # Preserve the hold/source binding too: the semantic guard still refuses.
                held = json.loads(self.hold)
                held['previous_ordinary_sha256'] = row['previous_ordinary_sha256']
                row['hold_sha256'] = save(self.operation / 'preserved-failed-hold.json', held)
            if name == 'snapshot-vmid':
                p = self.operation / 'infrastructure' / 'terraform.tfstate'
                value = json.loads(p.read_bytes())
                value['resources'][0]['instances'][0]['attributes']['vm_id'] = 809
                row['state_sha256'] = save(p, value)
                review['state_sha256'] = row['state_sha256']
            if name.startswith('window-'):
                p = self.operation / 'apply-window.json'
                v = json.loads(p.read_bytes())
                if name == 'window-finished': v['finished_at_ns'] = 2
                if name == 'window-time-type': v['started_at_ns'] = '1'
                if name == 'window-time-zero': v['started_at_ns'] = 0
                if name == 'window-plan': v['plan_sha256'] = 'a' * 64
                save(p, v)
            if name in {'plan-binding', 'plan-existing', 'plan-changed'}:
                p = self.operation / 'plan.json'
                v = json.loads(p.read_bytes())
                v[{'plan-binding': 'binding', 'plan-existing': 'existing_guest',
                   'plan-changed': 'changed'}[name]] = {} if name == 'plan-binding' else False
                save(p, v)
            if name == 'plan-bytes':
                save(self.operation / 'guest.tfplan', b'foreign plan')
            if name.startswith('log-'):
                p = self.operation / 'infrastructure.log'
                v = originals[p]
                v = b'other failure\n' if name == 'log-other' else v + b'Modifications complete\n'
                row['log_sha256'] = save(p, v)
            row['infrastructure_sha256'] = save(self.review_path, review)
            with self.subTest(change=name), self.next_run(778 if name == 'same-run' else 779):
                before = self.infra.call_count
                with self.assertRaises((ValueError, OSError)):
                    deploy.run('infrastructure', self.case.site)
                self.assertEqual(self.infra.call_count, before)
            for path in (self.operation / 'complete.json',
                         self.operation / 'infrastructure-complete.json',
                         self.operation / 'infrastructure' / 'PENDING-HOLD.json'):
                path.unlink(missing_ok=True)
            for path, raw in originals.items():
                save(path, raw)
            save(previous_op, previous_bytes)
        self.assertEqual(self.case.canonical.read_bytes(), self.previous)
