"""One saved-plan policy for fresh creation and existing-guest reconciliation."""

from private_io import require
from host_device_helper import device_spec
import ipaddress
import re

GUEST_RESOURCE = "module.guest.proxmox_virtual_environment_container.guest"
RESOURCES = {
    GUEST_RESOURCE: "vm_id",
    "module.guest.proxmox_virtual_environment_firewall_options.guest": "container_id",
    "module.guest.proxmox_virtual_environment_firewall_rules.guest": "container_id",
}
IP_FILTER_RESOURCE = "module.guest.proxmox_virtual_environment_firewall_ipset.ip_filter"
IP_FILTER_COMMENT = "HomeLab per-interface source IP filter"


def resource_fields(ip_filter_slots=()):
    require(isinstance(ip_filter_slots, (list, tuple))
            and all(type(slot) is int and 0 <= slot <= 31 for slot in ip_filter_slots)
            and len(set(ip_filter_slots)) == len(ip_filter_slots),
            'Select unique declared NIC slots for IP filters')
    return dict(RESOURCES, **{f'{IP_FILTER_RESOURCE}["{slot}"]': 'container_id'
                             for slot in ip_filter_slots})


def ip_filter_slots(interfaces):
    require(isinstance(interfaces, list) and len(interfaces) <= 32,
            'Select the compiled guest NICs for IP filters')
    selected = []
    for slot, nic in enumerate(interfaces):
        require(isinstance(nic, dict) and type(nic.get('ip_filter', False)) is bool,
                'Use Boolean per-interface IP filter selections')
        if nic.get('ip_filter', False):
            try:
                address = ipaddress.IPv4Interface(nic['ipv4'])
            except (ValueError, TypeError, KeyError):
                raise ValueError('IP filters require a configured static IPv4 NIC') from None
            require(str(address) == nic['ipv4'] and nic.get('ipv6') in (None, 'manual'),
                    'IP filters require static IPv4 and manual IPv6')
            selected.append(slot)
    return selected


def ip_filter_values(value, slot):
    return (isinstance(value, dict)
            and set(value) <= {'id', 'node_name', 'container_id', 'vm_id', 'name', 'comment', 'cidr'}
            and value.get('name') == f'ipfilter-net{slot}'
            and value.get('id') in (None, f'ipfilter-net{slot}')
            and value.get('comment') == IP_FILTER_COMMENT
            and value.get('cidr') in (None, []) and value.get('vm_id') in (None, 0))


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


def refresh_values(value):
    """Normalize only bpg 0.117.0 optional null/empty refresh representations."""
    result = dict(value)
    for name, empty in (("tags", []), ("environment_variables", {})):
        if name in result and result[name] is None:
            result[name] = empty
    for block, field in (("disk", "mount_options"),
                         ("mount_point", "mount_options"), ("features", "mount")):
        rows = result.get(block)
        if isinstance(rows, list):
            result[block] = [
                dict(row, **{field: []})
                if isinstance(row, dict) and field in row and row[field] is None
                else row for row in rows
            ]
    return result


def owned_resource_drift(rows, changes, node, vmid, serial_device, *, backup_selection=None,
                         backup_staging=None, recording_mount=None, resources=None):
    """Retain ownership evidence without vetoing mutable current-to-target updates."""
    if rows is None or rows == []:
        return True
    resources = RESOURCES if resources is None else resources
    if not isinstance(rows, list) or len(rows) > len(resources):
        return False
    current = {row['address']: row['change']['before'] for row in changes}
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            return False
        address = row.get('address')
        if not isinstance(address, str) or address not in resources or address in seen:
            return False
        seen.add(address)
        change = row.get('change')
        if not isinstance(change, dict):
            return False
        before, after = change.get('before'), change.get('after')
        key = resources[address]
        if (
            row.get('mode', 'managed') != 'managed'
            or row.get('type', address.split('.')[2]) != address.split('.')[2]
            or row.get('previous_address') is not None or row.get('deposed') is not None
            or 'importing' in row or 'importing' in change
            or change.get('generated_config') is not None or change.get('replace_paths')
            or change.get('actions', ['update']) not in (['update'], ['no-op'])
            or not isinstance(before, dict) or not isinstance(after, dict)
            or any(type(side.get(key)) is not int or side[key] != vmid
                   or side.get('node_name') != node for side in (before, after))
            or before.get('id') != after.get('id')
            or has_unknown(change.get('after_unknown', {}))
            or refresh_values(after) != refresh_values(current[address] or {})
        ):
            return False
        if address != GUEST_RESOURCE:
            continue
        old, new = refresh_values(before), refresh_values(after)
        if not all(
            declared_backup_drift(old.get(field), new.get(field),
                                 backup_selection, backup_staging, vmid, recording_mount=recording_mount)
            if field == 'mount_point' else old.get(field) == new.get(field)
            for field in IMMUTABLE_GUEST_FIELDS
        ):
            return False
        old_devices, new_devices = before.get('device_passthrough') or [], after.get('device_passthrough') or []
        if old_devices != new_devices and (not serial_device or old_devices
                or new_devices != [device_spec(serial_device['path'])]):
            return False
        was, now = before.get('started'), after.get('started')
        if was != now and not (type(was) is bool and type(now) is bool):
            return False
    return True




def staging_mount(row, selected):
    """Only a new empty provider allocation in the selected pool is admitted."""
    return (isinstance(row, dict) and isinstance(selected, dict)
        and set(selected) == {'path', 'size', 'volume'}
        and isinstance(selected['path'], str) and re.fullmatch(r'/srv/[a-z0-9][a-z0-9_/-]*', selected['path'])
        and '..' not in selected['path'].split('/') and '//' not in selected['path']
        and isinstance(selected['size'], str) and re.fullmatch(r'[1-9][0-9]*G', selected['size'])
        and isinstance(selected['volume'], str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,62}', selected['volume'])
        and set(row) <= {'path', 'size', 'volume', 'backup', 'replicate', 'acl', 'quota',
                         'read_only', 'shared', 'mount_options', 'path_in_datastore'}
        and all(row.get(key) == value for key, value in selected.items())
        and row.get('backup') is False and row.get('replicate') is True
        and all(row.get(key) in (None, False) for key in ('acl', 'quota', 'read_only', 'shared'))
        and row.get('mount_options') in (None, []))


def prepared_staging_mount(row, selected, vmid):
    """A known subvolume is only eligible; trusted API/filesystem proof is separate."""
    if not isinstance(row, dict) or not isinstance(selected, dict):
        return False
    volume = row.get('volume')
    if (not isinstance(volume, str) or type(vmid) is not int
            or not re.fullmatch(re.escape(str(selected.get('volume'))) +
                                r':subvol-' + str(vmid) + r'-[A-Za-z0-9_-]{1,128}', volume)
            or row.get('path_in_datastore') != volume):
        return False
    return staging_mount(dict(row, volume=selected.get('volume')), selected)


def declared_backup_drift(before, after, selection, staging, vmid, *, recording_mount=None):
    """Reconcile only declared metadata and one identity-verified staging append."""
    if before == after:
        return True
    if recording_mount is not None:
        from scrypted_mount import provider_row
        if (isinstance(before, list) and isinstance(after, list)
                and len(after) == len(before) + 1
                and recording_mount['slot'] == len(before)
                and provider_row(after[-1], recording_mount)):
            return before == after[:-1]
    if (not isinstance(staging, dict) or not isinstance(selection, dict) or not isinstance(after, list)
            or selection.get(staging.get('path')) is not False
            or sum(prepared_staging_mount(row, staging, vmid) for row in after) != 1):
        return False
    if (staging is not None and isinstance(before, (list, type(None)))
            and isinstance(after, list) and len(after) == len(before or []) + 1):
        return (prepared_staging_mount(after[-1], staging, vmid)
                and backup_flags(before or [], after[:-1],
                                 {key: value for key, value in selection.items() if key != staging['path']}))
    return backup_flags(before, after, selection)


def backup_flags(before, after, selection, staging=None):
    """Only explicit backup metadata may change; volume identity stays exact."""
    if selection is None:
        return before == after
    if not isinstance(selection, dict) or not all(isinstance(key, str) and key.startswith('/')
            and type(value) is bool for key, value in selection.items()):
        return False
    if (staging is not None and isinstance(before, (list, type(None))) and isinstance(after, list)
            and len(after) == len(before or [])+1):
        if not staging_mount(after[-1], staging) or selection.get(staging['path']) is not False:
            return False
        return backup_flags(before or [], after[:-1], {key: value for key, value in selection.items()
                            if key != staging['path']})
    if not selection and before in (None, []) and after in (None, []):
        return True
    if not isinstance(before, list) or not isinstance(after, list) or len(before) != len(after):
        return False
    if not all(isinstance(row, dict) and isinstance(row.get('path'), str) for row in [*before, *after]):
        return False
    if len(after) != len(selection) or {row['path'] for row in after} != set(selection):
        return False
    return all({key: value for key, value in old.items() if key != 'backup'} ==
               {key: value for key, value in new.items() if key != 'backup'}
               and type(old.get('backup')) is bool and type(new.get('backup')) is bool
               and new['backup'] == selection[new['path']]
               for old, new in zip(before, after, strict=True))


def backup_unknowns(before, after, unknown, staging):
    """Only the provider's allocated-name metadata may be new/unknown."""
    if not has_unknown(unknown):
        return True
    if (staging is None or not isinstance(before, (list, type(None))) or not isinstance(after, list)
            or len(after) != len(before or [])+1 or not staging_mount(after[-1], staging)
            or not isinstance(unknown, list) or len(unknown) != len(after)
            or any(has_unknown(row) for row in unknown[:-1]) or not isinstance(unknown[-1], dict)):
        return False
    return not has_unknown({key: value for key, value in unknown[-1].items() if key != 'path_in_datastore'})


def fresh_mount_unknowns(after, unknown):
    """New allocations may defer only their provider-computed datastore names."""
    return (not has_unknown(unknown)
            or isinstance(after, list) and isinstance(unknown, list) and len(after) == len(unknown)
            and all(isinstance(row, dict) and not has_unknown({key: value for key, value in row.items()
                    if key != 'path_in_datastore'}) for row in unknown))


def check_plan(value, node, vmid, *, existing, protected_guests, serial_device=None,
               backup_selection=None, backup_staging=None, recording_mount=None, ip_filter_slots=()):
    """Validate the exact saved plan under an explicit backend custody decision."""
    require(type(existing) is bool, "Select creation or reconciliation explicitly")
    protected = protected_guests
    require(isinstance(protected,(list,set)) and all(type(value) is int and value >= 1 for value in protected)
            and len(protected)==len(set(protected)), 'Preserve the explicit execution context protection policy')
    require(
        type(vmid) is int and vmid >= 100 and vmid not in protected,
        "Preserve protected guest identities",
    )
    require(isinstance(node, str) and node, "Select a known Proxmox node")
    require(
        isinstance(value, dict)
        and value.get("errored") is not True
        and value.get("complete") is not False
        and not value.get("deferred_changes"),
        "Review incomplete or deferred plans before deployment",
    )
    resources = resource_fields(ip_filter_slots)
    rows = value.get("resource_changes", [])
    require(
        isinstance(rows, list)
        and all(isinstance(row, dict) for row in rows)
        and len(rows) == len(resources)
        and {row.get("address") for row in rows} == set(resources),
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
        key = resources[row["address"]]
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
        ip_filter = row['address'] not in RESOURCES
        if ip_filter:
            slot = next(slot for slot in ip_filter_slots
                        if row['address'] == f'{IP_FILTER_RESOURCE}["{slot}"]')
            require(all(side is None or ip_filter_values(side, slot) for side in (before, after))
                    and not has_unknown({k: v for k, v in unknown.items() if k != 'id'}),
                    'Preserve only the selected empty per-NIC IP filter')
            if before is None:
                require(change.get('actions') == ['create'] and value.get('applyable') is not False,
                        'Only create a missing selected IP filter')
                continue
        if row["address"] == "module.guest.proxmox_virtual_environment_container.guest":
            if recording_mount is not None:
                from scrypted_mount import declaration, provider_row
                declaration(recording_mount)
                mounts = after.get('mount_point')
                require(existing and isinstance(mounts, list)
                        and len(mounts) == recording_mount['slot'] + 1
                        and provider_row(mounts[-1], recording_mount),
                        'Commission the exact recording bind on an already owned guest first')
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
            if not existing and backup_selection is not None:
                require(fresh_mount_unknowns(after.get('mount_point'), unknown.get('mount_point'))
                        and backup_flags(after.get('mount_point'), after.get('mount_point'), backup_selection),
                        'Bind native backup flags to the exact compiled volume selection')
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
                        (backup_flags(before.get(key), after.get(key), backup_selection, backup_staging)
                         and (backup_selection is None or backup_unknowns(before.get(key), after.get(key),
                              unknown.get(key), backup_staging)))
                        if key == 'mount_point' else before.get(key) == after.get(key)
                        for key in IMMUTABLE_GUEST_FIELDS
                    ),
                    "Preserve the guest identity and managed application data",
                )
        else:
            require(
                value.get("applyable") is not False
                and change.get("actions") == ["create"]
                and before is None,
                "Fresh creation requires exactly the selected guest and firewall resources",
            )
    require(owned_resource_drift(value.get('resource_drift'), rows, node, vmid, serial_device,
                                backup_selection=backup_selection, backup_staging=backup_staging,
                                recording_mount=recording_mount,
                                resources=resources),
            'Preserve owned resource identities, immutable data and complete refreshed evidence')
