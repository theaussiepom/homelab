"""One saved-plan policy for fresh creation and existing-guest reconciliation."""

from private_io import require
from host_device_helper import device_spec

GUEST_RESOURCE = "module.guest.proxmox_virtual_environment_container.guest"
RESOURCES = {
    GUEST_RESOURCE: "vm_id",
    "module.guest.proxmox_virtual_environment_firewall_options.guest": "container_id",
    "module.guest.proxmox_virtual_environment_firewall_rules.guest": "container_id",
}
PROTECTED = {900, 4914, 4915, 4920}
IMMUTABLE_GUEST_FIELDS = (
    "node_name",
    "vm_id",
    "disk",
    "mount_point",
    "operating_system",
    "unprivileged",
    "protection",
    "purge_on_destroy",
)


def has_unknown(value):
    if isinstance(value, dict):
        return any(has_unknown(item) for item in value.values())
    if isinstance(value, list):
        return any(has_unknown(item) for item in value)
    return value is not None and value is not False


def allowed_guest_drift(rows, node, vmid, serial_device):
    """Reconcile active state and the registered host-owned device, preserving all else."""
    if not rows:
        return True
    if not isinstance(rows, list) or len(rows) != 1:
        return False
    row = rows[0]
    if not isinstance(row, dict) or row.get("address") != GUEST_RESOURCE:
        return False
    change = row.get("change", {})
    before, after = change.get("before"), change.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        return False
    if (
        before.get("vm_id") != vmid
        or before.get("node_name") != node
        or has_unknown(change.get("after_unknown", {}))
        or {
            k: v
            for k, v in before.items()
            if k not in {"started", "device_passthrough"}
        }
        != {
            k: v for k, v in after.items() if k not in {"started", "device_passthrough"}
        }
    ):
        return False
    old_devices, new_devices = (
        before.get("device_passthrough") or [],
        after.get("device_passthrough") or [],
    )
    if old_devices != new_devices:
        if (
            not serial_device
            or old_devices
            or new_devices != [device_spec(serial_device["path"])]
        ):
            return False
    was, now = before.get("started"), after.get("started")
    if was != now and not (type(was) is bool and type(now) is bool):
        return False
    return was != now or old_devices != new_devices


def check_plan(value, node, vmid, *, existing, serial_device=None):
    """Validate the exact saved plan under an explicit backend custody decision."""
    require(type(existing) is bool, "Select creation or reconciliation explicitly")
    require(
        type(vmid) is int and vmid >= 100 and vmid not in PROTECTED,
        "Preserve protected guest identities",
    )
    require(isinstance(node, str) and node, "Select a known Proxmox node")
    require(
        isinstance(value, dict)
        and value.get("errored") is not True
        and value.get("complete") is not False
        and not value.get("deferred_changes")
        and allowed_guest_drift(value.get("resource_drift"), node, vmid, serial_device),
        "Review incomplete, deferred or drifted plans before deployment",
    )
    rows = value.get("resource_changes", [])
    require(
        isinstance(rows, list)
        and all(isinstance(row, dict) for row in rows)
        and len(rows) == len(RESOURCES)
        and {row.get("address") for row in rows} == set(RESOURCES),
        "The plan must contain only this guest and its firewall resources",
    )
    for row in rows:
        change = row.get("change")
        require(isinstance(change, dict), "Require a complete resource change")
        require(
            row.get("mode", "managed") == "managed"
            and row.get("type") == row["address"].split(".")[2]
            and row.get("previous_address") is None
            and row.get("deposed") is None
            and "importing" not in row
            and "importing" not in change
            and change.get("generated_config") is None
            and not change.get("replace_paths"),
            "Never import, move, adopt or replace a guest resource",
        )
        before, after = change.get("before"), change.get("after")
        key = RESOURCES[row["address"]]
        require(isinstance(after, dict), "Require known planned resource identity")
        for side in (before, after):
            require(
                side is None
                or (
                    isinstance(side, dict)
                    and type(side.get(key)) is int
                    and side[key] == vmid
                    and side.get("node_name") == node
                ),
                "Every resource must retain the selected guest and node identity",
            )
        unknown = change.get("after_unknown", {})
        require(
            isinstance(unknown, dict)
            and not unknown.get(key)
            and not unknown.get("node_name"),
            "Do not defer the selected guest or node identity",
        )
        if row["address"] == "module.guest.proxmox_virtual_environment_container.guest":
            require(
                after.get("started", True) is True
                and not has_unknown(unknown.get("started")),
                "The planned guest must be active",
            )
            selected = (
                [] if serial_device is None else [device_spec(serial_device["path"])]
            )
            previous = (before or {}).get("device_passthrough") or []
            require(
                previous in ([], selected)
                and (after.get("device_passthrough") or []) == previous
                and not has_unknown(unknown.get("device_passthrough")),
                "The host capability owns coordinator attachment; API plans cannot change it",
            )
        if existing:
            require(
                change.get("actions") in (["update"], ["no-op"])
                and isinstance(before, dict),
                "Never recreate an installed guest resource",
            )
            if (
                row["address"]
                == "module.guest.proxmox_virtual_environment_container.guest"
            ):
                require(
                    all(
                        before.get(key) == after.get(key)
                        for key in IMMUTABLE_GUEST_FIELDS
                    ),
                    "Preserve the guest identity and managed application data",
                )
        else:
            require(
                value.get("applyable") is not False
                and change.get("actions") == ["create"]
                and before is None,
                "Fresh creation requires exactly three new resources",
            )
