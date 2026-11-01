"""Only the exact reviewed provider-failure refresh can enter an ordinary plan."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import deployment_inputs
import plan_policy
import private_io as io
import proxmox_guest as pve
from fixtures import guest
from test_plan import existing_fixture


def failure_plan():
    value = existing_fixture()
    current = dict(value['resource_changes'][0]['change']['before'],
                   id='retained', memory=[{'dedicated': 768}],
                   disk=[{'datastore_id': 'local-zfs', 'size': 8}])
    desired = copy.deepcopy(current)
    desired['memory'] = [{'dedicated': 1024}]
    value['resource_changes'][0]['change'].update(before=current, after=desired)
    drift = copy.deepcopy(value['resource_changes'][0])
    drift['change'].update(before=copy.deepcopy(desired), after=copy.deepcopy(current))
    value['resource_drift'] = [drift]
    return value, {'before': copy.deepcopy(desired), 'after': copy.deepcopy(current)}


class ReviewedDriftTests(unittest.TestCase):
    def test_exact_pair_is_pure_and_does_not_override_desired_plan_guards(self):
        value, reviewed = failure_plan()
        original = copy.deepcopy(value)
        with self.assertRaises(ValueError):
            plan_policy.check_plan(value, 'pve-lab', 6100, existing=True)
        plan_policy.check_plan(value, 'pve-lab', 6100, existing=True, reviewed_drift=reviewed)
        self.assertEqual(value, original)
        for change in ('destroy', 'disk', 'foreign-resource'):
            bad = copy.deepcopy(value)
            if change == 'destroy': bad['resource_changes'][0]['change']['actions'] = ['delete', 'create']
            if change == 'disk': bad['resource_changes'][0]['change']['after']['disk'][0]['size'] = 16
            if change == 'foreign-resource': bad['resource_changes'][1]['change']['after']['container_id'] = 6101
            with self.subTest(change=change), self.assertRaises(ValueError):
                plan_policy.check_plan(bad, 'pve-lab', 6100, existing=True, reviewed_drift=reviewed)

    def test_unrelated_unknown_and_unpinned_drift_always_refuses(self):
        changes = [
            lambda v, r: r.clear(),
            lambda v, r: r.update(after=None),
            lambda v, r: v.update(resource_drift={}),
            lambda v, r: v['resource_drift'].append(copy.deepcopy(v['resource_drift'][0])),
            lambda v, r: v['resource_drift'].__setitem__(0, None),
            lambda v, r: v['resource_drift'][0].update(address='other'),
            lambda v, r: v['resource_drift'][0].update(type='other'),
            lambda v, r: v['resource_drift'][0].update(mode='data'),
            lambda v, r: v['resource_drift'][0].update(previous_address='old'),
            lambda v, r: v['resource_drift'][0]['change'].update(actions=['delete']),
            lambda v, r: v['resource_drift'][0]['change'].update(before=None),
            lambda v, r: v['resource_drift'][0]['change'].update(after=None),
            lambda v, r: v['resource_drift'][0]['change'].update(after_unknown={'memory': True}),
            lambda v, r: v['resource_drift'][0]['change']['after'].update(vm_id=6101),
            lambda v, r: v['resource_drift'][0]['change']['after'].update(node_name='other'),
            lambda v, r: v['resource_drift'][0]['change']['after'].update(id='foreign'),
            lambda v, r: v['resource_drift'][0]['change']['after']['disk'][0].update(size=16),
            lambda v, r: v['resource_drift'][0]['change']['before']['memory'][0].update(dedicated=2048),
            lambda v, r: v['resource_drift'][0]['change']['after']['memory'][0].update(dedicated=512),
        ]
        for index, change in enumerate(changes):
            value, reviewed = failure_plan()
            change(value, reviewed)
            with self.subTest(index=index), self.assertRaises(ValueError):
                plan_policy.check_plan(value, 'pve-lab', 6100, existing=True, reviewed_drift=reviewed)

    def test_saved_plan_executor_enforces_the_pair_before_any_apply(self):
        for valid in (True, False):
            with self.subTest(valid=valid), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                cfg = guest(root)
                cfg['guest']['vmid'] = cfg['app']['vmid'] = 6100
                cfg['site']['node'] = 'pve-lab'
                work = root / 'work'; work.mkdir(mode=0o700)
                op = root / 'attempt'; op.mkdir(mode=0o700)
                io.write_new(work / 'terraform.tfstate', b'current failed provider metadata')
                io.write_new(root / 'api', b'fixture@pve!deploy=synthetic')
                value, reviewed = failure_plan()
                if not valid: reviewed['after']['memory'][0]['dedicated'] = 512
                commands = []
                def quiet(args, env, log):
                    commands.append(args)
                    if 'plan' in args: io.write_new(op / 'guest.tfplan', b'exact saved fixture plan')
                with patch.object(deployment_inputs, 'binding', return_value={}), \
                     patch.object(pve, 'backup'), patch.object(pve, 'quiet', side_effect=quiet), \
                     patch.object(pve.subprocess, 'check_output', return_value=json.dumps(value).encode()):
                    if valid:
                        result = pve.infrastructure(cfg, root / 'site', work, op, {}, reviewed_drift=reviewed)
                        self.assertTrue(result['changed'])
                        self.assertEqual(sum('apply' in command for command in commands), 1)
                    else:
                        with self.assertRaises(ValueError):
                            pve.infrastructure(cfg, root / 'site', work, op, {}, reviewed_drift=reviewed)
                        self.assertFalse(any('apply' in command for command in commands))
