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


class ComputedAddressDriftTests(unittest.TestCase):
    def observed_plan(self):
        value = existing_fixture("no-op")
        guest = value["resource_changes"][0]["change"]
        before = dict(
            guest["before"],
            started=True,
            disk=[{"datastore_id": "fixture", "size": 8}],
            mount_point=[],
            operating_system=[{"type": "debian", "template_file_id": "fixture"}],
            unprivileged=True,
            protection=True,
            purge_on_destroy=False,
            initialization=[{
                "ip_config": [{
                    "ipv4": [{"address": "dhcp", "gateway": ""}],
                    "ipv6": [{"address": "manual"}],
                }],
            }],
            network_interface=[{
                "name": "eth0", "bridge": "vmbr-fixture", "vlan_id": 31,
                "mac_address": "02:00:00:00:00:20", "firewall": True,
            }],
            ipv4=None,
            ipv6=None,
        )
        after = copy.deepcopy(before)
        after.update(ipv4={"eth0": "198.18.0.20"}, ipv6={"eth0": "2001:db8::20"})
        value["resource_drift"] = [{
            "address": plan.GUEST_RESOURCE,
            "type": "proxmox_virtual_environment_container",
            "mode": "managed",
            "change": {
                "actions": ["update"], "before": before, "after": after,
                "after_unknown": {},
            },
        }]
        guest.update(before=copy.deepcopy(after), after=copy.deepcopy(after))
        value.update(errored=False, complete=True, deferred_changes=[])
        return value

    def test_computed_refresh_with_three_noop_changes_is_accepted_unchanged(self):
        for fields in (("ipv4",), ("ipv6",), ("ipv4", "ipv6")):
            for old in (None, {}, {"eth0": "198.18.0.19"}):
                with self.subTest(fields=fields, old=old):
                    value = self.observed_plan()
                    drift = value["resource_drift"][0]["change"]
                    for key in ("ipv4", "ipv6"):
                        drift["before"][key] = (
                            {"eth0": "2001:db8::19"} if key == "ipv6" and old else old
                        )
                        if key not in fields:
                            drift["before"][key] = copy.deepcopy(drift["after"][key])
                    original = copy.deepcopy(value)
                    self.assertEqual(len(value["resource_drift"]), 1)
                    self.assertTrue(all(
                        r["change"]["actions"] == ["no-op"]
                        for r in value["resource_changes"]
                    ))
                    plan.check_plan(value, "pve-lab", 6100, existing=True)
                    self.assertEqual(value, original)
        value = self.observed_plan()
        change = value["resource_drift"][0]["change"]
        change["before"] = copy.deepcopy(change["after"])
        self.assertFalse(plan.allowed_guest_drift(
            value["resource_drift"], "pve-lab", 6100, None
        ))

    def test_observation_exception_preserves_config_data_and_identity_guards(self):
        mutations = [
            lambda d: d["after"]["initialization"][0]["ip_config"][0]["ipv4"][0].update(address="198.18.0.21/24"),
            lambda d: d["after"]["initialization"][0]["ip_config"][0]["ipv4"][0].update(gateway="198.18.0.1"),
            lambda d: d["after"]["initialization"][0]["ip_config"][0]["ipv6"][0].update(address="2001:db8::21/64"),
            lambda d: d["after"]["network_interface"][0].update(bridge="other"),
            lambda d: d["after"]["network_interface"][0].update(vlan_id=32),
            lambda d: d["after"]["network_interface"][0].update(mac_address="02:00:00:00:00:21"),
            lambda d: d["after"]["disk"][0].update(size=16),
            lambda d: d["after"].update(vm_id=6101),
            lambda d: d["after"].update(node_name="other"),
            lambda d: d["after"].update(mount_point=[{"path": "/data"}]),
            lambda d: d["after"].update(operating_system=[{"type": "other"}]),
            lambda d: d["after"].update(unprivileged=False),
            lambda d: d["after"].update(protection=False),
            lambda d: d["after"].update(purge_on_destroy=True),
            lambda d: d["after"].update(memory=[{"dedicated": 999}]),
            lambda d: d["after"].update(description="unrelated drift"),
            lambda d: d.update(after_unknown={"ipv4": True}),
            lambda d: d.update(after_unknown={"ipv6": {"eth0": True}}),
            lambda d: d.update(after_unknown={"network_interface": [True]}),
            lambda d: d["after"].update(started=None),
            lambda d: d["after"].update(device_passthrough=[{"path": "/dev/unselected"}]),
        ]
        for index, mutate in enumerate(mutations):
            value = self.observed_plan()
            mutate(value["resource_drift"][0]["change"])
            with self.subTest(index=index), self.assertRaises(ValueError):
                plan.check_plan(value, "pve-lab", 6100, existing=True)
        for mutate in (
            lambda v: v["resource_drift"][0].update(address="module.foreign.guest"),
            lambda v: v["resource_drift"].append(copy.deepcopy(v["resource_drift"][0])),
            lambda v: v["resource_changes"][0]["change"].update(actions=["delete"]),
            lambda v: v.update(complete=False),
            lambda v: v.update(deferred_changes=[{"reason": "unknown"}]),
        ):
            value = self.observed_plan()
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                plan.check_plan(value, "pve-lab", 6100, existing=True)


class OptionalEmptyRefreshTests(unittest.TestCase):
    def observed_plan(self, *, addresses=True):
        value = ComputedAddressDriftTests().observed_plan()
        change = value["resource_drift"][0]["change"]
        before = change["before"]
        before["disk"][0]["mount_options"] = None
        before.update(
            mount_point=[{"path": "/data", "volume": "fixture", "mount_options": None}],
            features=[{"nesting": True, "mount": None}],
            tags=None, environment_variables=None,
        )
        after = copy.deepcopy(before)
        after["disk"][0]["mount_options"] = []
        after["mount_point"][0]["mount_options"] = []
        after["features"][0]["mount"] = []
        after.update(tags=[], environment_variables={})
        if addresses:
            after.update(ipv4={"eth0": "198.18.0.20"}, ipv6={"eth0": "2001:db8::20"})
        change["after"] = after
        guest = value["resource_changes"][0]["change"]
        guest.update(actions=["update"], before=copy.deepcopy(after), after=copy.deepcopy(after))
        guest["after"]["description"] = "reviewed desired description"
        guest["after"]["initialization"][0]["hostname"] = "fixture"
        firewall = value["resource_changes"][2]["change"]
        firewall.update(actions=["update"], before=dict(firewall["before"], rule=[]),
                        after=dict(firewall["after"], rule=[{"action": "ACCEPT"}]))
        return value

    def test_exact_optional_empty_refresh_preserves_plan_and_desired_updates(self):
        for addresses in (False, True):
            value = self.observed_plan(addresses=addresses)
            original = copy.deepcopy(value)
            plan.check_plan(value, "pve-lab", 6100, existing=True)
            self.assertEqual(value, original)
        value = self.observed_plan(addresses=False)
        change = value["resource_drift"][0]["change"]
        change["before"], change["after"] = change["after"], change["before"]
        plan.check_plan(value, "pve-lab", 6100, existing=True)

    def test_nonempty_or_wrong_empty_values_and_desired_disk_changes_still_refuse(self):
        changes = [
            lambda d: d["after"]["disk"][0].update(mount_options=["noatime"]),
            lambda d: d["after"]["mount_point"][0].update(mount_options=["ro"]),
            lambda d: d["after"]["features"][0].update(mount=["nfs"]),
            lambda d: d["after"].update(tags=["unreviewed"]),
            lambda d: d["after"].update(environment_variables={"FIXTURE": "changed"}),
            lambda d: d["after"].update(tags={}),
            lambda d: d["after"].update(environment_variables=[]),
            lambda d: d["after"]["disk"][0].update(mount_options=False),
            lambda d: d["after"]["disk"][0].pop("mount_options"),
            lambda d: d["after"].update(features=[]),
            lambda d: d["after"].update(memory=[{"dedicated": 999}]),
            lambda d: d["after"]["mount_point"][0].update(path="/other-data"),
            lambda d: d["after"]["disk"][0].update(size=999),
            lambda d: d.update(after_unknown={"disk": [{"mount_options": True}]}),
            lambda d: d.update(after_unknown={"environment_variables": True}),
        ]
        for index, mutate in enumerate(changes):
            value = self.observed_plan()
            mutate(value["resource_drift"][0]["change"])
            with self.subTest(index=index), self.assertRaises(ValueError):
                plan.check_plan(value, "pve-lab", 6100, existing=True)
        for field in ("disk", "mount_point"):
            value = self.observed_plan()
            value["resource_changes"][0]["change"]["after"][field][0]["mount_options"] = ["ro"]
            with self.subTest(field=field), self.assertRaises(ValueError):
                plan.check_plan(value, "pve-lab", 6100, existing=True)
        malformed = {"disk": [None, {}, {"mount_options": False}], "features": None}
        self.assertEqual(plan.refresh_values(malformed), malformed)
        value = self.observed_plan(addresses=False)
        change = value["resource_drift"][0]["change"]
        change["before"] = copy.deepcopy(change["after"])
        change["before"]["device_passthrough"] = None
        change["after"]["device_passthrough"] = []
        self.assertFalse(plan.allowed_guest_drift(value["resource_drift"], "pve-lab", 6100, None))
