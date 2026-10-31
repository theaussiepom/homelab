"""Exact historical serializers and namespace, without legacy controller execution."""

import copy
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import coordinated_contract as contract
import coordinated_evidence as evidence
import coordinated_generation as generation
import deployment_state as state
import private_io as io
import deploy
from custody_records import decode
from custody_fixtures import backend, save, legacy_canonical, legacy_immutable
import test_custody_admission as cases


class InputCompatibilityTests(unittest.TestCase):
    def fixture(self, *, postgres=True, same_bytes=False):
        case = cases.AdmissionTests()
        self.addCleanup(case.doCleanups)
        return case, case.fixture(postgres=postgres, legacy_serializers=not same_bytes)

    def pair(self, value, role, canonical_value=None, immutable_value=None, *, canonical_raw=None, immutable_raw=None):
        member = value.group['members'][role]
        record = {'status': 'passed',
                  'binding': {'vmid': member['vmid'], 'source_sha256': 'a' * 64},
                  'state_sha256': member['initial_state_sha256'],
                  'result': {'status': 'passed', 'changed': True,
                             'metrics': [{'count': 1, 'ratio': 1.25}, False, 'retained']}}
        canonical_value = record if canonical_value is None else canonical_value
        immutable_value = record if immutable_value is None else immutable_value
        canonical_raw = legacy_canonical(canonical_value) if canonical_raw is None else canonical_raw
        immutable_raw = legacy_immutable(immutable_value) if immutable_raw is None else immutable_raw
        work = value.work(role)
        immutable_hash = save(work / 'ordinary-100-1/complete.json', immutable_raw)
        canonical_hash = save(work / 'ordinary-complete.json', canonical_raw)
        member['initial_ordinary'] = {'operation': 'ordinary-100-1', 'sha256': canonical_hash,
                                      'immutable_sha256': immutable_hash, 'source_sha256': 'a' * 64}
        self.sync(value)
        return record, canonical_raw, immutable_raw

    def sync(self, value):
        for role, cfg in value.cfgs.items():
            cfg['coordinated_custody']['group'] = copy.deepcopy(value.group)
            save(value.site(role), cfg)

    @staticmethod
    def real_git_and_fixture_mount(argv, **kwargs):
        if argv[0] == 'findmnt': return 'nfs4 nas.example.invalid:/backups\n'
        return subprocess.run(argv, check=True, stdout=subprocess.PIPE, **kwargs).stdout

    def test_actual_serializers_admit_each_supported_member_then_keep_new_receipts_raw_equal(self):
        for role in ('mariadb', 'postgresql', 'identity', 'db-tools'):
            case, value = self.fixture(postgres=role != 'mariadb')
            _, canonical, immutable = self.pair(value, role)
            self.assertNotEqual(canonical, immutable)
            self.assertEqual(decode(canonical), decode(immutable))
            self.assertTrue(canonical.endswith(b'\n') and immutable.endswith(b'\n'))
            cfg = value.cfgs[role]
            contract.configured_closure(value.resolved())
            proofs, lineage, baseline = evidence.inspect(cfg)
            self.assertEqual(baseline, immutable)
            self.assertNotIn(str(value.work(role) / 'ordinary-complete.json'), proofs)
            attempt = case.attempt(value, role, proofs)
            generation.classify(attempt, value.group['members'][role], lineage, baseline)
            self.assertEqual(attempt.initial_ordinary, canonical)
            self.assertFalse(attempt.completed(lambda *args: True))
            self.assertEqual((value.work(role) / 'ordinary-complete.json').read_bytes(), canonical)
            with patch.object(subprocess, 'check_output', side_effect=self.real_git_and_fixture_mount):
                runtime = case.runtime(value, role)
                case.all_phases(runtime)
                final = (runtime.work / 'ordinary-complete.json').read_bytes()
                receipt = decode(final)
                self.assertEqual(set(receipt), {'status', 'binding', 'state_sha256', 'state_identity',
                                               'result', 'workflow', 'run_number', 'site_revision', 'operation'})
                self.assertEqual(final, (Path(receipt['operation']) / 'complete.json').read_bytes())
                self.assertEqual((runtime.work / 'ordinary-100-1/complete.json').read_bytes(), immutable)
                runtime.infra.assert_called_once()
                self.assertFalse((runtime.work / 'ORDINARY-HOLD.json').exists())

    def test_same_byte_selection_retains_closed_default_and_two_serializers_require_both_pins(self):
        case, value = self.fixture(same_bytes=True)
        cfg = value.cfgs['identity']; member = value.group['members']['identity']
        self.assertNotIn('immutable_sha256', member['initial_ordinary'])
        proofs, lineage, baseline = evidence.inspect(cfg)
        attempt = case.attempt(value, 'identity', proofs)
        generation.classify(attempt, member, lineage, baseline)
        self.assertFalse(attempt.completed(lambda *args: True))
        self.assertEqual(baseline, (value.work('identity') / 'ordinary-complete.json').read_bytes())
        case, value = self.fixture()
        value.group['members']['identity']['initial_ordinary'].pop('immutable_sha256')
        self.sync(value)
        with self.assertRaisesRegex(ValueError, 'exact initial immutable'):
            evidence.inspect(value.cfgs['identity'])
        for field, bad in (('immutable_sha256', None), ('immutable_sha256', 'bad'),
                           ('canonical_sha256', 'f' * 64), ('unknown_legacy_mode', True)):
            cfg = copy.deepcopy(value.cfgs['identity'])
            cfg['coordinated_custody']['group']['members']['identity']['initial_ordinary'][field] = bad
            with self.subTest(field=field, bad=bad), self.assertRaises(ValueError): contract.selection(cfg)
        cfg = copy.deepcopy(value.cfgs['identity'])
        cfg['coordinated_custody']['group']['members']['identity']['initial_ordinary'] = []
        with self.assertRaises(ValueError): contract.selection(cfg)

    def test_changed_canonical_or_immutable_bytes_refuse_before_any_phase(self):
        for which in ('canonical', 'immutable'):
            case, value = self.fixture()
            _, canonical, immutable = self.pair(value, 'identity')
            work = value.work('identity')
            changed = work / ('ordinary-complete.json' if which == 'canonical' else 'ordinary-100-1/complete.json')
            save(changed, changed.read_bytes() + b' ')
            before = (work / 'terraform.tfstate').read_bytes()
            with self.subTest(which=which), self.assertRaises(ValueError):
                proofs, lineage, baseline = evidence.inspect(value.cfgs['identity'])
                generation.classify(case.attempt(value, 'identity', proofs), value.group['members']['identity'], lineage, baseline)
            self.assertEqual((work / 'terraform.tfstate').read_bytes(), before)
            self.assertFalse((work / 'ORDINARY-HOLD.json').exists())
            self.assertFalse((work / 'ordinary-777-1').exists())

    def test_exact_raw_pins_do_not_mask_content_or_nested_type_differences(self):
        for variant in ('result', 'nested-bool-int', 'nested-int-float', 'nested-list-order',
                        'binding-vmid-type', 'extra-field', 'missing-field', 'duplicate-field', 'malformed-json'):
            case, value = self.fixture()
            record, _, _ = self.pair(value, 'identity')
            canonical_value = copy.deepcopy(record)
            raw = None
            if variant == 'result': canonical_value['result']['status'] = 'different'
            if variant == 'nested-bool-int': canonical_value['result']['changed'] = 1
            if variant == 'nested-int-float': canonical_value['result']['metrics'][0]['count'] = 1.0
            if variant == 'nested-list-order': canonical_value['result']['metrics'].reverse()
            if variant == 'binding-vmid-type': canonical_value['binding']['vmid'] = float(record['binding']['vmid'])
            if variant == 'extra-field': canonical_value['extra'] = 'unqualified'
            if variant == 'missing-field': canonical_value.pop('result')
            if variant == 'duplicate-field': raw = legacy_canonical(record).replace(b'"status": "passed"', b'"status": "passed", "status": "passed"', 1)
            if variant == 'malformed-json': raw = b'{'
            _, canonical, immutable = self.pair(value, 'identity', canonical_value, record, canonical_raw=raw)
            if variant in ('nested-bool-int', 'nested-int-float', 'binding-vmid-type'):
                self.assertEqual(decode(canonical), decode(immutable))  # Python equality alone is too weak.
            proofs, lineage, baseline = evidence.inspect(value.cfgs['identity'])
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                generation.classify(case.attempt(value, 'identity', proofs), value.group['members']['identity'], lineage, baseline)
            self.assertFalse((value.work('identity') / 'ORDINARY-HOLD.json').exists())

    def test_full_equal_records_still_require_qualified_status_state_source_vmid_and_json(self):
        for variant in ('status', 'state', 'source', 'vmid', 'vmid-float', 'binding-type', 'extra-field', 'nonfinite'):
            case, value = self.fixture()
            record, _, _ = self.pair(value, 'identity')
            if variant == 'status': record['status'] = 'failed'
            if variant == 'state': record['state_sha256'] = 'b' * 64
            if variant == 'source': record['binding']['source_sha256'] = 'b' * 64
            if variant == 'vmid': record['binding']['vmid'] += 1
            if variant == 'vmid-float': record['binding']['vmid'] = float(record['binding']['vmid'])
            if variant == 'binding-type': record['binding'] = []
            if variant == 'extra-field': record['extra'] = True
            if variant == 'nonfinite': record['result']['value'] = float('nan')
            self.pair(value, 'identity', record, record)
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                proofs, lineage, baseline = evidence.inspect(value.cfgs['identity'])
                generation.classify(case.attempt(value, 'identity', proofs), value.group['members']['identity'], lineage, baseline)

    def test_changed_starting_backend_and_later_success_never_fall_back_to_legacy_anchor(self):
        case, value = self.fixture()
        self.pair(value, 'identity')
        save(value.work('identity') / 'terraform.tfstate', backend(809, 4))
        proofs, lineage, baseline = evidence.inspect(value.cfgs['identity'])
        with self.assertRaisesRegex(ValueError, 'initial backend has unproven'):
            generation.classify(case.attempt(value, 'identity', proofs), value.group['members']['identity'], lineage, baseline)
        case, value = self.fixture()
        _, canonical, immutable = self.pair(value, 'identity')
        original_state = (value.work('identity') / 'terraform.tfstate').read_bytes()
        with patch.object(subprocess, 'check_output', side_effect=self.real_git_and_fixture_mount):
            runtime = case.runtime(value, 'identity')
            case.all_phases(runtime)
            final = (runtime.work / 'ordinary-complete.json').read_bytes()
            self.assertNotEqual(final, canonical)
            save(runtime.work / 'ordinary-complete.json', canonical)
            save(runtime.work / 'terraform.tfstate', original_state)
            with patch.dict(os.environ, {'GITHUB_RUN_ID': '778', 'GITHUB_RUN_NUMBER': '778',
                                         'GITHUB_SHA': runtime.revisions[1]}), \
                 self.assertRaisesRegex(ValueError, 'latest ordinary success'):
                deploy.run('infrastructure', runtime.site)
            runtime.infra.assert_called_once()
            self.assertEqual((runtime.work / 'ordinary-100-1/complete.json').read_bytes(), immutable)
            self.assertFalse((runtime.work / 'ORDINARY-HOLD.json').exists())

    def test_historical_mariadb_namespace_is_exact_for_known_schema_role_and_operation(self):
        _, value = self.fixture(postgres=False)
        cfg = value.cfgs['mariadb']
        self.assertEqual(contract.selection(cfg)['directory'], 'database-network-cutover-mariadb-fixture')
        evidence.inspect(cfg)
        for directory in ('database-server-cutover-mariadb-fixture', 'database-network-cutover-postgresql-fixture',
                          '/database-network-cutover-mariadb-fixture', 'database-network-cutover-mariadb-other',
                          '../database-network-cutover-mariadb-fixture'):
            candidate = copy.deepcopy(cfg); candidate['coordinated_custody']['group']['directory'] = directory
            with self.subTest(directory=directory), self.assertRaises(ValueError): contract.selection(candidate)
        for field, bad in (('schema', 'unrecognized'), ('operation', 'postgresql-fixture'), ('operation', 'influxdb-fixture')):
            candidate = copy.deepcopy(cfg); candidate['coordinated_custody']['group'][field] = bad
            with self.assertRaises(ValueError): contract.selection(candidate)
        candidate = copy.deepcopy(cfg)
        candidate['coordinated_custody']['group']['members']['influxdb'] = candidate['coordinated_custody']['group']['members'].pop('mariadb')
        with self.assertRaises(ValueError): contract.selection(candidate)
