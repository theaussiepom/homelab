"""Check that the one-guest CD plan cannot change another guest or delete data."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('app_plan', ROOT / 'plan.py')
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)


def fixture():
    """Provide the expected new container and its two firewall resources."""
    rows = []
    for kind, name, key in (
        ('proxmox_virtual_environment_container', 'guest', 'vm_id'),
        ('proxmox_virtual_environment_firewall_options', 'guest', 'container_id'),
        ('proxmox_virtual_environment_firewall_rules', 'guest', 'container_id'),
    ):
        rows.append({'address': f'module.guest.{kind}.{name}', 'type': kind,
                     'change': {'actions': ['create'], 'before': None,
                                'after': {key: 6100, 'node_name': 'pve-lab'}}})
    return {'resource_changes': rows}


class PlanTests(unittest.TestCase):
    """Validate actual OpenTofu plan structure, not a count-only summary."""

    def test_one_guest_create_update_and_noop_are_accepted(self):
        """Ordinary convergence stays limited to the selected guest."""
        for actions in (['create'], ['update'], ['no-op']):
            value = fixture()
            for row in value['resource_changes']:
                row['change']['actions'] = actions
                if actions != ['create']:
                    row['change']['before'] = copy.deepcopy(row['change']['after'])
            plan.check_plan(value, 'pve-lab', 6100)

    def test_destruction_and_replacement_are_refused(self):
        """Deletion is not admitted by this deployment path."""
        for actions in (['delete'], ['delete', 'create'], ['create', 'delete']):
            value = fixture(); value['resource_changes'][0]['change']['actions'] = actions
            with self.assertRaises(ValueError): plan.check_plan(value, 'pve-lab', 6100)

    def test_a_different_guest_node_or_resource_is_refused(self):
        """A correct resource count cannot disguise a different target."""
        for index, key, bad in ((0, 'vm_id', 900), (1, 'container_id', 6101), (2, 'node_name', 'other')):
            value = fixture(); value['resource_changes'][index]['change']['after'][key] = bad
            with self.assertRaises(ValueError): plan.check_plan(value, 'pve-lab', 6100)
        value = fixture(); value['resource_changes'][0]['address'] = 'module.other.proxmox_virtual_environment_container.guest'
        with self.assertRaises(ValueError): plan.check_plan(value, 'pve-lab', 6100)

    def test_an_update_cannot_adopt_a_different_existing_guest(self):
        """Both sides of an update must belong to this guest and node."""
        value = fixture(); row = value['resource_changes'][0]
        row['change']['actions'] = ['update']
        row['change']['before'] = {'vm_id': 6101, 'node_name': 'pve-lab'}
        with self.assertRaises(ValueError): plan.check_plan(value, 'pve-lab', 6100)

    def test_protected_targets_duplicate_and_missing_resources_are_refused(self):
        """The controller and retained test targets cannot be repurposed."""
        for vmid in (900, 4914, 4915, 4920, True, 0):
            with self.assertRaises(ValueError): plan.check_plan(fixture(), 'pve-lab', vmid)
        value = fixture(); value['resource_changes'].append(copy.deepcopy(value['resource_changes'][0]))
        with self.assertRaises(ValueError): plan.check_plan(value, 'pve-lab', 6100)
        with self.assertRaises(ValueError): plan.check_plan({'resource_changes': []}, 'pve-lab', 6100)


if __name__ == '__main__':
    unittest.main()
