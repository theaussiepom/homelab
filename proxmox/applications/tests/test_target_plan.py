"""Reconcile known current targets while retaining immutable ownership evidence."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import plan_policy as policy
from test_plan import existing_fixture
import test_backup_mount_reconciliation as mounts_fixture
from test_backup_mount_reconciliation import mount


def target_plan():
    """Build a known three-resource plan with an already-converged owned policy."""
    value = existing_fixture('no-op')
    for index, row in enumerate(value['resource_changes']):
        for side in ('before', 'after'):
            row['change'][side]['id'] = 'owned-resource-' + str(index)
    rules = value['resource_changes'][2]
    base = [{'type': 'in', 'action': 'ACCEPT', 'proto': 'tcp', 'dport': '22',
             'source': '198.18.25.11/32', 'pos': 0}]
    grants = [{'type': 'in', 'action': 'ACCEPT', 'proto': proto, 'dport': '53',
               'source': source, 'dest': '198.18.40.2/32', 'pos': index}
              for index, (source, proto) in enumerate((
                  ('192.0.2.0/24', 'tcp'), ('192.0.2.0/24', 'udp'),
                  ('198.51.100.0/24', 'tcp'), ('198.51.100.0/24', 'udp')))]
    current = copy.deepcopy(rules['change']['before'])
    current['rule'] = grants + [dict(row, pos=len(grants)) for row in base]
    old = dict(copy.deepcopy(current), rule=base)
    rules['change'].update(before=copy.deepcopy(current), after=copy.deepcopy(current))
    drift = copy.deepcopy(rules)
    drift['change'].update(actions=['update'], before=old, after=current)
    value['resource_drift'] = [drift]
    return value


def admit(value, **kwargs):
    """Use the real existing-resource plan gate without provider or target access."""
    policy.check_plan(value, 'pve-lab', 6100, existing=True, protected_guests=[900], **kwargs)


class TargetPlanTests(unittest.TestCase):
    def test_already_desired_four_grants_and_policy_correction_preserve_history(self):
        """Accept state-only convergence and an actual owned-policy target update."""
        value = target_plan()
        for correction in (False, True):
            current = copy.deepcopy(value)
            if correction:
                change = current['resource_changes'][2]['change']
                change['actions'] = ['update']
                change['after']['rule'] = change['after']['rule'][:-1]
            original = copy.deepcopy(current)
            admit(current)
            self.assertEqual(current, original)

    def test_mutable_resource_history_can_differ_consistently_from_current(self):
        """Allow known memory, description, NIC and policy changes toward source."""
        value = target_plan()
        guest = value['resource_changes'][0]
        old = dict(guest['change']['before'], memory=[{'dedicated': 1024}],
                   description='previous', network_interface=[{'name': 'eth0'}])
        current = dict(copy.deepcopy(old), memory=[{'dedicated': 2048}],
                       description='observed', network_interface=[{'name': 'eth0'}, {'name': 'eth1'}])
        proposed = dict(copy.deepcopy(current), memory=[{'dedicated': 4096}], description='declared')
        guest['change'].update(actions=['update'], before=current, after=proposed)
        drift = copy.deepcopy(guest)
        drift['change'].update(before=old, after=copy.deepcopy(current))
        options = value['resource_changes'][1]
        option_drift = copy.deepcopy(options)
        option_drift['change'].update(before=dict(options['change']['before'], log_level_in='nolog'),
                                     after=copy.deepcopy(options['change']['before']))
        value['resource_drift'].extend([drift, option_drift])
        original = copy.deepcopy(value)
        admit(value)
        self.assertEqual(value, original)

    def test_stage_and_firewall_refresh_are_independent_owned_evidence(self):
        """Keep the exact staging contract while allowing another refreshed resource."""
        value = mounts_fixture.DeclaredMountDriftTests().plan()
        firewall = target_plan()
        value['resource_changes'][2] = firewall['resource_changes'][2]
        value['resource_drift'].extend(firewall['resource_drift'])
        mounts_fixture.DeclaredMountDriftTests().check(value)
        for job in (False, True):
            broken = copy.deepcopy(value)
            # A swapped old volume is unsafe even when current == proposed.
            for side in ('before', 'after'):
                broken['resource_changes'][0]['change'][side]['mount_point'][0].update(
                    volume='local-zfs:subvol-6100-swapped', path_in_datastore='local-zfs:subvol-6100-swapped')
            broken['resource_drift'][0]['change']['after'] = copy.deepcopy(
                broken['resource_changes'][0]['change']['before'])
            with self.subTest(job=job), self.assertRaises(ValueError):
                if job:
                    mounts_fixture.DeclaredMountDriftTests().check(broken)
                else:
                    admit(broken)

    def test_root_and_existing_data_identity_cannot_be_adopted_from_refresh(self):
        """Reject historical immutable loss even if the proposed target matches it."""
        base = target_plan()
        guest = base['resource_changes'][0]
        old = dict(guest['change']['before'], disk=[{'datastore_id': 'pool', 'size': 8}],
                   operating_system=[{'type': 'debian', 'template_file_id': 'owned'}],
                   unprivileged=True, protection=True, purge_on_destroy=False,
                   mount_point=[mount(1, backup=True)])
        guest['change'].update(before=copy.deepcopy(old), after=copy.deepcopy(old))
        drift = copy.deepcopy(guest)
        base['resource_drift'].append(drift)
        for field, changed in [('disk', [{'datastore_id': 'other', 'size': 8}]),
                               ('disk', [{'datastore_id': 'pool', 'size': 16}]),
                               ('operating_system', [{'type': 'other'}]),
                               ('unprivileged', False), ('protection', False),
                               ('purge_on_destroy', True), ('mount_point', [])]:
            value = copy.deepcopy(base)
            for side in ('before', 'after'):
                value['resource_changes'][0]['change'][side][field] = copy.deepcopy(changed)
            value['resource_drift'][-1]['change']['after'][field] = copy.deepcopy(changed)
            with self.subTest(field=field, changed=changed), self.assertRaises(ValueError):
                admit(value)

    def test_malformed_foreign_replaced_partial_or_inconsistent_history_refuses(self):
        """Reject invalid evidence without interpreting it as safe convergence."""
        edits = [
            lambda v: v.update(resource_drift=True),
            lambda v: v['resource_drift'].append(None),
            lambda v: v['resource_drift'].append(copy.deepcopy(v['resource_drift'][0])),
            lambda v: v['resource_drift'][0].update(address=[]),
            lambda v: v['resource_drift'][0].update(address='foreign'),
            lambda v: v['resource_drift'][0].update(mode='data'),
            lambda v: v['resource_drift'][0].update(type='foreign'),
            lambda v: v['resource_drift'][0].update(previous_address='foreign'),
            lambda v: v['resource_drift'][0].update(deposed='old'),
            lambda v: v['resource_drift'][0].update(importing={}),
            lambda v: v['resource_drift'][0].update(change=[]),
            lambda v: v['resource_drift'][0]['change'].update(importing={}),
            lambda v: v['resource_drift'][0]['change'].update(generated_config='other'),
            lambda v: v['resource_drift'][0]['change'].update(replace_paths=[['id']]),
            lambda v: v['resource_drift'][0]['change'].update(actions=['delete']),
            lambda v: v['resource_drift'][0]['change'].update(before=None),
            lambda v: v['resource_drift'][0]['change'].update(after=None),
            lambda v: v['resource_drift'][0]['change']['before'].update(container_id=True),
            lambda v: v['resource_drift'][0]['change']['after'].update(node_name='foreign'),
            lambda v: v['resource_drift'][0]['change']['before'].update(id='foreign'),
            lambda v: v['resource_drift'][0]['change']['after'].update(id='foreign'),
            lambda v: v['resource_drift'][0]['change'].update(after_unknown={'rule': True}),
            lambda v: v['resource_drift'][0]['change']['after'].update(rule=[]),
        ]
        for index, edit in enumerate(edits):
            value = target_plan(); edit(value); original = copy.deepcopy(value)
            with self.subTest(index=index), self.assertRaises(ValueError):
                admit(value)
            self.assertEqual(value, original)
        value = target_plan()
        value['resource_drift'] *= 4
        with self.assertRaises(ValueError): admit(value)

    def test_unsafe_current_to_proposed_actions_still_refuse(self):
        """A valid historical explanation never authorizes an unsafe target plan."""
        for edit in (
            lambda c: c.update(actions=['delete']),
            lambda c: c.update(actions=['delete', 'create']),
            lambda c: c.update(replace_paths=[['disk']]),
            lambda c: c.update(after_unknown={'node_name': True}),
            lambda c: c['after'].update(node_name='foreign'),
            lambda c: c['after'].update(container_id=6101),
        ):
            value = target_plan(); edit(value['resource_changes'][2]['change'])
            with self.assertRaises(ValueError): admit(value)

    def test_malformed_current_running_state_is_not_an_observed_boolean_change(self):
        """Reject an ambiguous current state even when the target asks to run."""
        value = target_plan()
        guest = value['resource_changes'][0]
        old = dict(guest['change']['before'], started=True)
        current = dict(old, started=None)
        guest['change'].update(actions=['update'], before=current, after=dict(old))
        drift = copy.deepcopy(guest)
        drift['change'].update(before=old, after=copy.deepcopy(current))
        value['resource_drift'].append(drift)
        with self.assertRaises(ValueError): admit(value)


if __name__ == '__main__':
    unittest.main()
