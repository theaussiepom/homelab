"""Backup inheritance preserves effective contracts without adding runtime modes."""
import copy
import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest

import yaml

import component_backup as backup
import component_backup_job as subject
from component_errors import ComponentError
import component_packet
import component_plan
import component_types as types
import component_workflows


ROOT = Path(__file__).resolve().parents[1]


class BackupBindingUnits(unittest.TestCase):
    def resolver(self, root, guests):
        """Use separate authored and resolved guest maps like the real resolver."""
        return SimpleNamespace(site={'backup': root, 'guests': copy.deepcopy(guests)},
                               guests=copy.deepcopy(guests))

    def test_null_empty_and_omission_keep_explicit_enrollment(self):
        """Defaults do not enroll omitted guests or depend on the deployment selector."""
        root = {'defaults': {'interface':'storage', 'staging_volume':'pbs_stage'}, 'job':{}}
        r = self.resolver(root, {'one':{'backup':None}, 'two':{'backup':{}}, 'other':{}})
        before = copy.deepcopy(r.site)
        self.assertEqual(subject.clients(r), {'one':root['defaults'], 'two':root['defaults']})
        r.guests['one']['backup'] = {'schema':'resolved-coverage'}
        self.assertEqual(subject.clients(r), {'one':root['defaults'], 'two':root['defaults']})
        self.assertEqual(r.site, before)
        for value in (None, {}):
            subject.enrollment(value)
            backup.presence(value)
        self.assertIsNone(subject.clients(self.resolver(None, {'one':{'backup':None}})))
        self.assertIsNone(subject.clients(self.resolver({}, {'one':{'backup':{}}})))

    def test_fields_override_independently_without_mutating_defaults(self):
        """An explicit guest field wins; no identity or budget is invented by defaults."""
        root = {'defaults': {'interface':'storage', 'staging_volume':'pbs_stage'}, 'job':{}}
        overrides = {'interface':'archive', 'backup_id':'chosen-id', 'limits':{'max_files':100}}
        r = self.resolver(root, {'one':{'backup':overrides}, 'two':{'backup':None}})
        before = copy.deepcopy(r.site)
        expected = {**root['defaults'], **overrides}
        self.assertEqual(subject.clients(r)['one'], expected)
        resolved = subject.clients(r)
        resolved['one']['limits']['max_files'] = 200
        self.assertEqual(r.site, before)
        r = self.resolver({'job':{}}, {'one':{'backup':{'interface':'storage','staging_volume':'pbs_stage'}}})
        self.assertEqual(subject.clients(r)['one'], {'interface':'storage','staging_volume':'pbs_stage'})

    def test_operational_fields_without_job_and_mixed_legacy_forms_refuse(self):
        """There is one source for bindings, and preparation never ignores operational fields."""
        for defaults in ({}, {'interface':'storage'}):
            r = self.resolver({'defaults':defaults}, {'one':{'backup':None}})
            with self.subTest(defaults=defaults), self.assertRaisesRegex(ComponentError, 'backup-job-required'):
                subject.clients(r)
        for field, value in [('interface','storage'), ('staging_volume','stage'),
                             ('backup_id','custom'), ('limits',{'max_bytes':1048576})]:
            r = self.resolver(None, {'one':{'backup':{field:value}}})
            with self.subTest(field=field), self.assertRaisesRegex(ComponentError, 'backup-job-required'):
                subject.clients(r)
        legacy = {'one': {'interface':'storage','staging_volume':'stage'}}
        for root, guest in [({'job':{'clients':legacy}, 'defaults':{}}, None),
                            ({'job':{'clients':legacy}}, {'interface':'storage'})]:
            with self.subTest(root=root), self.assertRaisesRegex(ComponentError, 'backup-client-form'):
                subject.clients(self.resolver(root, {'one':{'backup':guest}}))
        result = subject.clients(self.resolver({'job':{'clients':legacy}}, {'one':{'backup':{}}}))
        self.assertEqual(result, legacy)
        result['one']['interface'] = 'changed'
        self.assertEqual(legacy['one']['interface'], 'storage')

    def test_closed_binding_shapes_and_capacity_ranges_refuse_safely(self):
        """The new location retains strict scalar, identifier and limit validation."""
        invalid = [True, False, [], 'PRIVATE_SENTINEL', 1,
                   {'unknown':'PRIVATE_SENTINEL'}, {'interface':None}, {'staging_volume':{}},
                   {'interface':'bad/path'}, {'backup_id':None}, {'backup_id':'a'*33},
                   {'backup_id':'/unsafe'}, {'limits':None}, {'limits':{}},
                   {'limits':{'timeout_seconds':300}}, {'limits':{'max_bytes':True}},
                   {'limits':{'max_files':1.5}}, {'limits':{'max_files':1000001}},
                   {'limits':{'max_bytes':1048575}}, {'limits':{'max_bytes':2**50+1}}]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ComponentError) as caught:
                subject.enrollment(value)
            self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))
        for value in [None, True, [], {'backup_id':'id'}, {'limits':{'max_files':1}},
                      {'interface':'bad/path'}, {'staging_volume':None}]:
            r = self.resolver({'job':{}, 'defaults':value}, {'one':{'backup':None}})
            with self.subTest(defaults=value), self.assertRaises(ComponentError): subject.clients(r)
        for value in [{'limits':{'max_bytes':1048576}}, {'limits':{'max_bytes':2**50}},
                      {'limits':{'max_files':1}}, {'limits':{'max_files':1000000}}]:
            subject.enrollment(value)
        with self.assertRaisesRegex(ComponentError, 'fields'):
            subject.clients(self.resolver({'defaults':{}, 'job':{}}, {'one':{'backup':None}}))
        for field in ('interface','staging_volume','backup_id','limits'):
            with self.subTest(volume_field=field), self.assertRaisesRegex(ComponentError, 'backup-presence'):
                types.volume({'storage':'local','slot':0,'path':'/srv/stage','size_gib':1,
                              'backup':{field:'not-a-volume-marker'}})


class BackupDefaultsCompilation(unittest.TestCase):
    def setUp(self):
        """The public complete two-client example supplies real compiler collaborators."""
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()/'example'
        shutil.copytree(ROOT/'docs/examples/backup', self.root)
        self.path = self.root/'client-limits.yaml'
        self.site = yaml.safe_load(self.path.read_text())

    def plan(self, value=None, disabled=None):
        """Resolve a disposable source file without opening any protected input."""
        self.path.write_text(yaml.safe_dump(self.site if value is None else value))
        return component_plan.resolve(self.root, self.path, disabled)

    def test_new_and_legacy_forms_preserve_every_resolved_value_packet_and_workflow(self):
        """A syntax-only change retains IDs, keys, limits, capture and disabled membership."""
        inherited = self.plan()
        legacy = copy.deepcopy(self.site)
        defaults = legacy['backup'].pop('defaults')
        legacy['backup']['job']['clients'] = {}
        for key, guest in legacy['guests'].items():
            if 'backup' in guest:
                legacy['backup']['job']['clients'][key] = {**defaults, **(guest['backup'] or {})}
                guest['backup'] = None
        explicit = self.plan(legacy)
        self.assertEqual(explicit.resolved, inherited.resolved)
        self.assertEqual(component_packet.lower_plan(explicit), component_packet.lower_plan(inherited))
        self.assertEqual(component_workflows.model(explicit), component_workflows.model(inherited))
        for source in (self.site, legacy):
            disabled = self.plan(source, ['replica'])
            self.assertEqual(disabled.resolved['backup'], inherited.resolved['backup'])
            self.assertEqual(disabled.resolved['guests']['replica'], inherited.resolved['guests']['replica'])
        self.assertNotIn('defaults', json.dumps(inherited.resolved['backup']))

    def test_explicit_identity_and_partial_binding_overrides_preserve_their_effective_jobs(self):
        """Guest IDs, volume/NIC exceptions and capacity overrides reach actual packets."""
        self.site['guests']['resolver']['backup'].update(backup_id='chosen-id', interface='backend')
        selected = self.plan()
        job = selected.resolved['guests']['resolver']['backup']['job']
        self.assertEqual(job['destination']['backup_id'], 'chosen-id')
        self.assertEqual(job['transport']['device'], 'eth1')
        self.assertEqual(job['limits'], {'max_bytes':67108864,'max_files':20000,'timeout_seconds':300})
        self.assertIn('chosen-id', selected.resolved['backup']['group']['group']['members'])
        # No root defaults is also supported when each guest supplies both references.
        defaults = self.site['backup'].pop('defaults')
        for guest in self.site['guests'].values():
            guest['backup'] = {**defaults, **(guest['backup'] or {})}
        self.assertEqual(self.plan().resolved, selected.resolved)

    def test_reference_identity_and_staging_failures_include_disabled_guests(self):
        """Inheritance cannot hide an absent reference, unsafe volume, collision or 4L failure."""
        original = copy.deepcopy(self.site)
        cases = [
            (lambda s: s['backup']['defaults'].update(interface='missing'), 'backup-interface'),
            (lambda s: s['backup']['defaults'].update(staging_volume='missing'), 'backup-staging-volume'),
            (lambda s: s['guests']['replica'].update(backup={'interface':'missing'}), 'backup-interface'),
            (lambda s: (s['guests']['replica'].update(backup={'interface':'backend'}),
                s['guests']['replica']['interfaces']['backend'].update(
                    address={'mode':'dhcp','endpoint':'198.18.21.11'}),
                s['guests']['replica']['interfaces']['management'].update(default_route=False)), 'backup-interface'),
            (lambda s: s['guests']['resolver']['backup']['limits'].update(max_bytes=268435457), 'backup-staging-volume'),
            (lambda s: s['guests']['replica']['volumes']['backup-stage'].update(backup=None), 'backup-staging-volume'),
            (lambda s: [g.update(backup={'backup_id':'collision'}) for g in s['guests'].values()], 'backup-member-identity'),
            (lambda s: s['backup'].pop('job'), 'backup-recovery-key'),
        ]
        for mutate, code in cases:
            self.site = copy.deepcopy(original); mutate(self.site)
            with self.subTest(code=code), self.assertRaisesRegex(ComponentError, code):
                self.plan(disabled=['resolver','replica'])

    def test_preparation_only_and_unenrolled_guests_do_not_receive_operational_bindings(self):
        """Bare markers remain useful without a job; root-only selection never enrolls."""
        for name in ('job','management','recovery_public_key','defaults'):
            self.site['backup'].pop(name)
        self.site['guests']['resolver']['backup'] = None
        self.site['guests']['replica']['backup'] = {}
        first = self.plan()
        self.assertEqual(first.resolved['backup']['mode'], 'client-preparation')
        self.assertNotIn('job', first.resolved['guests']['resolver']['backup'])
        self.assertEqual(first.resolved, self.plan().resolved)
        self.site['guests']['replica'].pop('backup')
        self.assertNotIn('backup', self.plan().resolved['guests']['replica'])
        self.site['guests']['resolver']['backup'] = {'interface':'management'}
        with self.assertRaisesRegex(ComponentError, 'backup-job-required'): self.plan()


if __name__ == '__main__':
    unittest.main()
