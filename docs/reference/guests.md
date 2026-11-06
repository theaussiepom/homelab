# Guests

A guest selects a template and allocates a Debian LXC instance.
Entries are inline or complete `kind: guest` [sources](sources.md).

## Properties

| Field | Type / requirement / default | Constraint and meaning |
| --- | --- | --- |
| context | Required ID | Existing context |
| template | Required ID | Library guest template |
| lifecycle | Required enum | `fresh` or `retained`; an ownership assertion, not an import override |
| identity | Required object | Exactly positive integer `vmid` and `hostname` |
| identity.hostname | Required string | `[a-z][a-z0-9-]{0,62}` |
| template_file_id | Required text | Existing provider template file identity |
| root_storage | Required ID | Storage pool in same context |
| interfaces | Required nonempty named map | [NICs](networks.md#guest-nic) |
| control_interface | Required ID | This guest's static/DHCP NIC used for management |
| display_name | Optional text | Default hostname; nonempty, at most 4096 characters |
| resources | Optional partial object | Inherits template, fields below |
| startup | Optional partial object | Inherits template, fields below |
| security | Optional partial object | Inherits template, fields below |
| ssh_public_keys | Optional unique string list | Inherits context; explicit [] remains empty and cannot pass deployment key admission |
| dns_servers | Optional nonempty endpoint list | Inherits context; resolved DNS port 53 |
| timezone | Optional timezone string | Guest, then context, then `Etc/UTC` |
| volumes | Optional named map, {} | Provider-backed [data volumes](storage.md) |
| root_paths | Optional named map, {} | Owned root-filesystem [data paths](storage.md) |
| compose_projects | Optional named map, {} | `{name: text, file?: filename}`; file default `compose-<map-key>.yml` |
| software / runtime | Optional unique ID lists, [] | Appended to template selections; guest runtime cannot own containers/native budgets |
| network_policy | Optional ordered list, [] | Policy ID or explicit [policy binding](policies.md#bindings) |
| readiness | Optional list, [] | Each `{stage: preparation, target: {app: id, endpoint: name}}`; target must be on another guest |
| source_policy_route | Optional object | Exactly `{interface: nic_id}`; non-default static NIC with gateway distinct from its own address |
| monitoring | Optional object | `{profile: id}`; overrides template's monitoring selection |

VMIDs are unique across a declared API authority, including different nodes.
MAC/address identities, ports, device owners and runtime paths also have their
own collision checks. Reserved guest/app/phase IDs include execution stage names;
do not use those as app instances.

## Defaults and resolution

Only `resources`, `startup`, `security` merge by direct field:
complete template followed by explicitly supplied guest fields.
An omitted field inherits; an explicitly repeated equal value is redundant.
There is no recursive overlay language. Guest software/runtime lists append to
template lists; conflicting versions/security settings refuse.

| Resource field | Template required / guest optional | Bounds |
| --- | --- | --- |
| cpu_cores | Integer | 1–2147483647 |
| memory_mib | Integer | 256–2147483647 |
| root_gib | Integer | 4–2147483647 |
| os_reserve_mib | Integer | 0–2147483647; less than memory_mib |

Runtime requirements can increase the effective reserve (at least 256 MiB when
budgeting workloads). Selected native/container reservations must fit.
These syntax bounds do not promise physical host capacity.

Startup: `started` and `start_on_boot` are Booleans; `boot_order` is integer
0–2147483647. All three are required in a template.
Security: `unprivileged`, `protection`, `nesting`, `keyctl` are Booleans,
all required in a template. `unprivileged` and `protection` must be true.
Runtime requirements may require nesting/keyctl.

Compose project filenames match `[a-z][a-z0-9_-]{0,62}.yaml` or `.yml`
and are unique within a guest. Project names are nonempty text; execution
additionally validates the actual closed runtime identities.

## Changes

Display names are cosmetic. VMID, hostname, provider authority, persistent
storage and owned app namespaces are continuity identities. Changing CPU,
memory or startup changes desired infrastructure and requires the actual
guarded native plan; interruption is not universally specified.
Retained state cannot become fresh by changing a label.
See [Lifecycle](lifecycle.md).

## Worked guest and inherited defaults

This complete `guests.resolver` value works with the tutorial's context,
`primary` network, `local` pool and `base` template. Those referenced objects
must also exist; the example is synthetic and cannot pass deployment admission.

<!-- example: guest-minimal -->
```yaml
context: lab
template: base
lifecycle: fresh
identity: {vmid: 610, hostname: example-dns}
template_file_id: example:vztmpl/debian.tar.zst
root_storage: local
control_interface: management
interfaces:
  management:
    network: primary
    slot: 0
    mac: 02:00:00:20:00:10
    address: {mode: static, value: 198.18.20.10}
    default_route: true
```

Omitting resources/startup/security inherits the complete template. Add
`resources: {memory_mib: 1024}` to keep its CPU/root/reserve defaults while
allocating more memory. This is a direct-field merge, not recursive YAML merging.
**Invalid variation:** `resources: {memory_mib: true}` refuses because a Boolean
is not an integer allocation. A second NIC also cannot reuse slot zero.

The same `fresh` source is used for first installation and subsequent owned
updates. The runtime distinguishes them from genuine receipts and backend state;
changing the label to `retained` is neither a required next step nor an import.

[Reference index](README.md) · [Apps](apps.md)
