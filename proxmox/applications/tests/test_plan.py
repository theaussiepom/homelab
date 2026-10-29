"""One saved-plan policy preserves identity/data in both current deployment modes."""

import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import plan_policy as plan


def fixture():
    rows = []
    for kind, name, key in (
        ("proxmox_virtual_environment_container", "guest", "vm_id"),
        ("proxmox_virtual_environment_firewall_options", "guest", "container_id"),
        ("proxmox_virtual_environment_firewall_rules", "guest", "container_id"),
    ):
        rows.append(
            {
                "address": f"module.guest.{kind}.{name}",
                "type": kind,
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {key: 6100, "node_name": "pve-lab"},
                },
            }
        )
    return {"resource_changes": rows}


def existing_fixture(action="update"):
    value = fixture()
    for row in value["resource_changes"]:
        row["change"].update(
            actions=[action], before=copy.deepcopy(row["change"]["after"])
        )
    return value


class PlanTests(unittest.TestCase):
    def test_creation_updates_and_noop_require_the_correct_custody_mode(self):
        plan.check_plan(fixture(), "pve-lab", 6100, existing=False)
        for action in ("update", "no-op"):
            value = existing_fixture(action)
            if action == "no-op":
                value["applyable"] = False
            plan.check_plan(value, "pve-lab", 6100, existing=True)
            with self.assertRaises(ValueError):
                plan.check_plan(value, "pve-lab", 6100, existing=False)
        with self.assertRaises(ValueError):
            plan.check_plan(fixture(), "pve-lab", 6100, existing=True)
        with self.assertRaises(TypeError):
            plan.check_plan(fixture(), "pve-lab", 6100)

    def test_both_modes_refuse_imports_moves_drift_incomplete_plans_and_unknown_identity(
        self,
    ):
        changes = [
            lambda v: v["resource_changes"][0]["change"].update(
                importing={"id": "6100"}
            ),
            lambda v: v["resource_changes"][0].update(importing={"id": "6100"}),
            lambda v: v["resource_changes"][0].update(
                previous_address="module.other.guest"
            ),
            lambda v: v["resource_changes"][0].update(deposed="old"),
            lambda v: v["resource_changes"][0]["change"].update(
                generated_config="resource..."
            ),
            lambda v: v["resource_changes"][0]["change"].update(
                replace_paths=[["disk"]]
            ),
            lambda v: v["resource_changes"][0]["change"].update(
                after_unknown={"vm_id": True}
            ),
            lambda v: v["resource_changes"][0]["change"].update(
                after_unknown={"node_name": True}
            ),
            lambda v: v["resource_changes"][0].update(type="unrelated_resource"),
            lambda v: v["resource_changes"][0].update(mode="data"),
            lambda v: v.update(errored=True),
            lambda v: v.update(complete=False),
            lambda v: v.update(deferred_changes=[{"reason": "unknown"}]),
            lambda v: v.update(resource_drift=[{"address": "other"}]),
        ]
        for existing in (False, True):
            for index, change in enumerate(changes):
                value = existing_fixture() if existing else fixture()
                change(value)
                with (
                    self.subTest(existing=existing, index=index),
                    self.assertRaises(ValueError),
                ):
                    plan.check_plan(value, "pve-lab", 6100, existing=existing)

    def test_creation_cannot_adopt_or_claim_an_unapplyable_plan(self):
        value = fixture()
        value["resource_changes"][0]["change"]["before"] = copy.deepcopy(
            value["resource_changes"][0]["change"]["after"]
        )
        with self.assertRaises(ValueError):
            plan.check_plan(value, "pve-lab", 6100, existing=False)
        value = fixture()
        value["applyable"] = False
        with self.assertRaises(ValueError):
            plan.check_plan(value, "pve-lab", 6100, existing=False)

    def test_data_and_identity_are_immutable_in_reconciliation(self):
        for key in plan.IMMUTABLE_GUEST_FIELDS:
            value = existing_fixture()
            value["resource_changes"][0]["change"]["after"][key] = "changed"
            with self.subTest(field=key), self.assertRaises(ValueError):
                plan.check_plan(value, "pve-lab", 6100, existing=True)
        value = existing_fixture()
        value["resource_changes"][1]["change"]["before"]["container_id"] = 6101
        with self.assertRaises(ValueError):
            plan.check_plan(value, "pve-lab", 6100, existing=True)

    def test_destruction_replacement_and_other_targets_are_refused(self):
        for existing in (False, True):
            for actions in (["delete"], ["delete", "create"], ["create", "delete"]):
                value = existing_fixture() if existing else fixture()
                value["resource_changes"][0]["change"]["actions"] = actions
                with (
                    self.subTest(existing=existing, actions=actions),
                    self.assertRaises(ValueError),
                ):
                    plan.check_plan(value, "pve-lab", 6100, existing=existing)
            for index, key, bad in (
                (0, "vm_id", 900),
                (1, "container_id", 6101),
                (2, "node_name", "other"),
            ):
                value = existing_fixture() if existing else fixture()
                value["resource_changes"][index]["change"]["after"][key] = bad
                with self.assertRaises(ValueError):
                    plan.check_plan(value, "pve-lab", 6100, existing=existing)
            for vmid in (900, 4914, 4915, 4920, True, 0):
                with self.assertRaises(ValueError):
                    plan.check_plan(fixture(), "pve-lab", vmid, existing=existing)
            value = fixture()
            value["resource_changes"].append(
                copy.deepcopy(value["resource_changes"][0])
            )
            with self.assertRaises(ValueError):
                plan.check_plan(value, "pve-lab", 6100, existing=existing)
            with self.assertRaises(ValueError):
                plan.check_plan(
                    {"resource_changes": []}, "pve-lab", 6100, existing=existing
                )


class ActiveDriftTests(unittest.TestCase):
    def test_stopped_guests_reconcile_to_active_without_accepting_other_drift(self):
        for previous, actual in ((True, False), (False, True)):
            value = existing_fixture()
            row = value["resource_changes"][0]
            before = dict(row["change"]["before"], started=previous)
            current = dict(before, started=actual)
            value["resource_drift"] = [
                {
                    "address": plan.GUEST_RESOURCE,
                    "change": {"before": before, "after": current},
                }
            ]
            row["change"].update(before=current, after=dict(current, started=True))
            plan.check_plan(value, "pve-lab", 6100, existing=True)
            for mutate in (
                lambda d: d["after"].update(started=None),
                lambda d: d["after"].update(memory=999),
                lambda d: d.update(after_unknown={"started": True}),
            ):
                broken = copy.deepcopy(value)
                mutate(broken["resource_drift"][0]["change"])
                with (
                    self.subTest(previous=previous, mutate=mutate),
                    self.assertRaises(ValueError),
                ):
                    plan.check_plan(broken, "pve-lab", 6100, existing=True)
            row["change"]["after"]["started"] = False
            with self.assertRaises(ValueError):
                plan.check_plan(value, "pve-lab", 6100, existing=True)
