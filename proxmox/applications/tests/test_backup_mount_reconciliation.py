"""Declared mount drift is eligible only; ownership remains a runtime proof."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import plan_policy as policy
from test_plan import existing_fixture, fixture


def mount(name, *, backup=False):
    volume = 'local-zfs:subvol-6100-disk-' + str(name)
    return {'path': '/srv/data' if name == 1 else '/srv/stage', 'size': '8G' if name == 1 else '4G',
            'volume': volume, 'path_in_datastore': volume, 'backup': backup, 'replicate': True,
            'acl': False, 'quota': False, 'read_only': False, 'shared': False, 'mount_options': []}


def selection():
    return {'path': '/srv/stage', 'size': '4G', 'volume': 'local-zfs'}


class DeclaredMountDriftTests(unittest.TestCase):
    def plan(self, empty=False):
        value = existing_fixture('no-op')
        resource = value['resource_changes'][0]
        old = copy.deepcopy(resource['change']['before'])
        old['mount_point'] = [] if empty else [mount(1)]
        new = copy.deepcopy(old)
        new['mount_point'] = ([] if empty else [mount(1, backup=True)]) + [mount(2)]
        resource['change'].update(before=copy.deepcopy(new), after=copy.deepcopy(new))
        drift = copy.deepcopy(resource)
        drift['change'].update(actions=['update'], before=old, after=new)
        value['resource_drift'] = [drift]
        return value

    def check(self, value, empty=False):
        policy.check_plan(value, 'pve-lab', 6100, existing=True, protected_guests=[900],
            backup_selection={**({} if empty else {'/srv/data': True}), '/srv/stage': False},
            backup_staging=selection())

    def test_nonempty_and_empty_prior_lists_append_one_exact_known_subvolume(self):
        for empty in (False, True):
            value = self.plan(empty); before = copy.deepcopy(value)
            self.check(value, empty)
            self.assertEqual(value, before)
        value = self.plan(True)
        value['resource_drift'][0]['change']['before']['mount_point'] = None
        self.check(value, True)

    def test_backup_metadata_only_matches_the_complete_selected_volume_set(self):
        value = self.plan(); change = value['resource_drift'][0]['change']
        change['before']['mount_point'].append(mount(2))
        policy.check_plan(value, 'pve-lab', 6100, existing=True, protected_guests=[],
                          backup_selection={'/srv/data': True, '/srv/stage': False}, backup_staging=selection())
        with self.assertRaises(ValueError):
            policy.check_plan(value, 'pve-lab', 6100, existing=True, protected_guests=[],
                              backup_selection={'/srv/data': True, '/srv/stage': False})
        with self.assertRaises(ValueError):
            policy.check_plan(value, 'pve-lab', 6100, existing=True, protected_guests=[])

    def test_every_existing_volume_field_except_declared_backup_is_immutable(self):
        changes = {'path': '/srv/other', 'size': '9G', 'volume': 'local-zfs:subvol-6100-other',
                   'path_in_datastore': 'other', 'replicate': False, 'acl': True, 'quota': True,
                   'read_only': True, 'shared': True, 'mount_options': ['bind'], 'extra': 'sentinel'}
        for field, replacement in changes.items():
            value = self.plan(); value['resource_drift'][0]['change']['after']['mount_point'][0][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(value)
        value = self.plan(); value['resource_drift'][0]['change']['after']['mount_point'][0]['backup'] = False
        with self.assertRaises(ValueError): self.check(value)

    def test_wrong_stage_owner_pool_slot_identity_options_and_unknowns_refuse(self):
        changes = {'path': '/srv/foreign', 'size': '8G', 'volume': 'local-zfs:subvol-6101-disk-2',
                   'path_in_datastore': 'local-zfs:subvol-6100-disk-3', 'backup': True,
                   'replicate': False, 'acl': True, 'quota': True, 'read_only': True,
                   'shared': True, 'mount_options': ['bind'], 'extra': 'sentinel'}
        for field, replacement in changes.items():
            value = self.plan(); value['resource_drift'][0]['change']['after']['mount_point'][-1][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError): self.check(value)
        for volume in ('local-zfs', 'elsewhere:subvol-6100-disk-2', 'local-zfs:basevol-6100-disk-2',
                       'local-zfs:subvol-6100-../disk', None, True):
            value = self.plan(); row = value['resource_drift'][0]['change']['after']['mount_point'][-1]
            row.update(volume=volume, path_in_datastore=volume)
            with self.subTest(volume=volume), self.assertRaises(ValueError): self.check(value)
        for mutation in (lambda rows: rows.reverse(), lambda rows: rows.append(mount(2)),
                         lambda rows: rows.pop(0)):
            value = self.plan(); mutation(value['resource_drift'][0]['change']['after']['mount_point'])
            with self.assertRaises(ValueError): self.check(value)
        value = self.plan(); value['resource_drift'][0]['change']['after_unknown'] = {'mount_point': True}
        with self.assertRaises(ValueError): self.check(value)

    def test_nonmount_drift_replacements_and_missing_selection_stay_refused(self):
        for field, new in [('protection', False), ('disk', []), ('memory', [{'dedicated': 1}]),
                           ('node_name', 'foreign'), ('id', 'foreign')]:
            value = self.plan(); value['resource_drift'][0]['change']['after'][field] = new
            with self.subTest(field=field), self.assertRaises(ValueError): self.check(value)
        value = self.plan(); value['resource_changes'][0]['change']['replace_paths'] = [['mount_point']]
        with self.assertRaises(ValueError): self.check(value)
        value = self.plan()
        with self.assertRaises(ValueError):
            policy.check_plan(value, 'pve-lab', 6100, existing=True, protected_guests=[],
                              backup_staging=selection())

    def test_prepared_shape_rejects_nonobjects_and_bad_selected_contract(self):
        for row, selected, vmid in [(None, selection(), 6100), (mount(2), None, 6100),
                                    (mount(2), selection(), True), (mount(2), {}, 6100)]:
            with self.subTest(row=row, selected=selected, vmid=vmid):
                self.assertFalse(policy.prepared_staging_mount(row, selected, vmid))
        self.assertFalse(policy.declared_backup_drift([], [mount(2)], None, selection(), 6100))

    def test_fresh_allocations_defer_only_provider_computed_names(self):
        for rows in ([mount(2)], [mount(1, backup=True), mount(2)]):
            value = fixture(); change = value['resource_changes'][0]['change']
            allocated = [{k: v for k, v in row.items() if k != 'path_in_datastore'} for row in rows]
            for row in allocated: row['volume'] = 'local-zfs'
            change['after']['mount_point'] = allocated
            change['after_unknown'] = {'mount_point': [{'path_in_datastore': True} for row in rows]}
            kwargs = {'existing': False, 'protected_guests': [],
                      'backup_selection': {row['path']: row['backup'] for row in rows}, 'backup_staging': selection()}
            policy.check_plan(value, 'pve-lab', 6100, **kwargs)
            for unknown in (True, [{'path': True}], [True], [{'volume': True}],
                            [{'backup': True} for row in rows], [{'size': True} for row in rows]):
                broken = copy.deepcopy(value); broken['resource_changes'][0]['change']['after_unknown']['mount_point'] = unknown
                with self.subTest(rows=len(rows), unknown=unknown), self.assertRaises(ValueError):
                    policy.check_plan(broken, 'pve-lab', 6100, **kwargs)


if __name__ == '__main__':
    unittest.main()
