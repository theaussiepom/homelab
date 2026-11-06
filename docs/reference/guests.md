# Guests

A guest is one `guests.<id>` value in a [site](site.md), inline or in a complete
`kind: guest` [typed leaf](sources.md). It selects a library template and describes
one Debian LXC allocation, its control interface and owned data/runtime space.
The [complete tutorial](../examples/first-configuration/site.yaml) supplies a
working offline composition; real use also requires [deployment preparation](../guides/prepare-deployment.md).

<a id="properties"></a>
## Guest property index

All objects are closed. Required fields have no default. Null is not an
inheritance marker; optional maps/lists use the explicitly stated behavior.
Named IDs and scalar paths follow [shared type rules](supporting-types.md#scalar-and-path-types).

| Path under `guests.<id>` | Presence / accepted type | Default or effect |
| --- | --- | --- |
| <a id="guest-context"></a>`context` | Required ID | Existing [context](contexts.md); owns provider/trust/controller inputs |
| <a id="guest-template"></a>`template` | Required ID | Existing library [guest template](library.md#guest-template) |
| <a id="guest-lifecycle"></a>`lifecycle` | Required `fresh` or `retained` | [Ownership policy](lifecycle.md); no import override |
| <a id="guest-identity"></a>`identity` | Required closed object | Required `vmid` and `hostname`, below |
| <a id="guest-identity-vmid"></a>`identity.vmid` | Required integer 1–2147483647 | Unique across declared API address/port, including nodes; native plan additionally requires at least 100 and excludes protected IDs |
| <a id="guest-identity-hostname"></a>`identity.hostname` | Required string | `[a-z][a-z0-9-]{0,62}`; stable ownership identity |
| <a id="guest-template-file-id"></a>`template_file_id` | Required nonempty text, ≤4096, no NUL | Existing provider template identity; source validation does not fetch it |
| <a id="guest-root-storage"></a>`root_storage` | Required ID | [Storage pool](storage.md#storage-pool) in the same context |
| <a id="guest-interfaces"></a>`interfaces` | Required nonempty named map | Exact [NIC records and address branches](networks.md#nic-property-index) |
| <a id="guest-control-interface"></a>`control_interface` | Required ID | One declared static/DHCP NIC; supplies management address/MAC, never a manual NIC |
| <a id="guest-display-name"></a>`display_name` | Optional nonempty text, ≤4096, no NUL | Defaults to hostname; cosmetic, not an identity rename |
| <a id="guest-resources"></a>`resources` | Optional partial object | Direct-field template inheritance; [resource records](#resource-fields) |
| <a id="guest-startup"></a>`startup` | Optional partial object | Direct-field template inheritance; [startup records](#startup-fields) |
| <a id="guest-security"></a>`security` | Optional partial object | Direct-field template inheritance; [security records](#security-fields) |
| <a id="guest-ssh-public-keys"></a>`ssh_public_keys` | Optional unique string list | Omission inherits context; explicit `[]` stays empty and fails deployment key admission |
| <a id="guest-dns-servers"></a>`dns_servers` | Optional nonempty endpoint-reference list | Omission inherits context; resolved TCP/UDP IPv4 DNS port 53 |
| <a id="guest-timezone"></a>`timezone` | Optional timezone string | Guest, then context, then `Etc/UTC`; shared timezone rules |
| <a id="guest-volumes"></a>`volumes` | Optional named map; omitted `{}` | Provider [volumes](storage.md#guest-volume-fields) |
| <a id="guest-root-paths"></a>`root_paths` | Optional named map; omitted `{}` | Owned [root-filesystem paths](storage.md#guest-root-paths) |
| <a id="guest-compose-projects"></a>`compose_projects` | Optional named map; omitted `{}` | [Project records](#compose-project-fields) |
| <a id="guest-software"></a>`software` | Optional unique ID list; omitted `[]` | Append to template software; [software declarations](supporting-types.md#software) |
| <a id="guest-runtime"></a>`runtime` | Optional unique ID list; omitted `[]` | Append to template runtime; guest selection cannot own app container/native budgets |
| <a id="guest-network-policy"></a>`network_policy` | Optional ordered list; omitted `[]` | Policy ID or explicit [policy binding](policies.md#bindings) |
| <a id="guest-readiness"></a>`readiness` | Optional ordered list; omitted `[]` | Each exactly `{stage: preparation, target: {app: id, endpoint: name}}`; target must be on another guest |
| <a id="guest-source-policy-route"></a>`source_policy_route` | Optional closed object | Exactly `{interface: nic_id}`; selected non-default static NIC requires a gateway different from its address |
| <a id="guest-monitoring"></a>`monitoring` | Optional closed object | Exactly `{profile: id}`; replaces template selection; see [monitoring](zabbix.md) |

## Defaults and resolution

Only resources, startup and security merge by direct field: complete template
first, then explicit guest keys. Omitted blocks and empty partial maps inherit;
null refuses. Software/runtime lists append to template lists; an empty guest
list contributes nothing and cannot erase a template selection. Monitoring
selection replaces the complete template reference; empty/null does not disable it.

For the tutorial's `base` template, adding `resources: {memory_mib: 1024}` produces
CPU 1, memory 1024 MiB, root 8 GiB and authored OS reserve 128 MiB. Runtime
budgeting can raise the effective reserve to its 256 MiB floor and selected
requirements. The source values and runtime allocation are different layers;
see the [complete library](../examples/first-configuration/stack.json).

### Resource fields

These full paths are `guests.<id>.resources.<field>`; the same object is complete
in a template. Each field is an actual integer, never Boolean. Guest omission
inherits the corresponding template value; no framework scalar default replaces it.

| Field | Inclusive domain | Consumer and change limit |
| --- | --- | --- |
| <a id="guest-resources-cpu-cores"></a>`cpu_cores` | 1–2147483647 | Desired CPU allocation; native capacity and guarded plan remain required |
| <a id="guest-resources-memory-mib"></a>`memory_mib` | 256–2147483647 MiB | Must cover effective OS reserve and selected app reservations |
| <a id="guest-resources-root-gib"></a>`root_gib` | 4–2147483647 GiB | Existing guest disk block is immutable; growth and shrink are both refused by ordinary policy |
| <a id="guest-resources-os-reserve-mib"></a>`os_reserve_mib` | 0–2147483647 MiB | Resolved value must be less than memory; runtime requirements may raise its effective reserve |

### Startup fields

Full paths are `guests.<id>.startup.<field>`. All fields are required in the
template and individually optional in the guest.

| Field | Accepted type / effect | Additional boundary |
| --- | --- | --- |
| <a id="guest-startup-started"></a>`started` | Boolean desired running state | False is structurally valid but the saved-plan policy requires an active planned guest |
| <a id="guest-startup-start-on-boot"></a>`start_on_boot` | Boolean boot policy | No general interruption guarantee from changing it |
| <a id="guest-startup-boot-order"></a>`boot_order` | Integer 0–2147483647 | Host startup order; distinct from app/guest readiness dependencies |

### Security fields

Full paths are `guests.<id>.security.<field>`. All fields are required in the
template, individually optional in the guest and actual Booleans.

| Field | Accepted values / resolved effect |
| --- | --- |
| <a id="guest-security-unprivileged"></a>`unprivileged` | Must be true; false refuses structurally and identity is preserved by the native plan |
| <a id="guest-security-protection"></a>`protection` | Must be true; removing protection is not ordinary maintenance |
| <a id="guest-security-nesting"></a>`nesting` | Boolean; selected runtime may require true |
| <a id="guest-security-keyctl"></a>`keyctl` | Boolean; selected runtime may require true |

### Compose project fields

Each `guests.<id>.compose_projects.<id>` requires `name` (nonempty text ≤4096,
no NUL) and optionally `file`. The file defaults to `compose-<map-key>.yml` and
must match `[a-z][a-z0-9_-]{0,62}.yaml` or `.yml`; files are unique within the
guest. Null/empty is not the default. Execution validates the selected closed
runtime identity in addition to source shape. [App identity](apps.md#runtime-identity)
uses the map key as the project reference.

## Resolution and relationships

VMIDs are unique within API address/port scope, including different nodes.
[NIC identity conflicts](networks.md#field-guest-nic-mac), ports, devices and
owned paths have separate collision scopes. Provider NIC order follows slots;
volume slots are contiguous from zero. App placement contributes software and
runtime requirements and must fit the guest's effective budget.

Readiness creates only its explicit dependency. Network policy supplies access;
DNS/endpoint references supply values. The [relationship guide](../guides/references-and-reuse.md)
explains why none substitutes for the others. Reserved guest/app IDs include
execution phase names and cannot be used as instance keys.

## First installation

The selected template is a default source, not a guest provisioning procedure.
A supported `fresh` guest requires absent owner/backend, admitted allocations,
real trust/material/platform prerequisites and compatible app creation paths.
See [preparation](../guides/prepare-deployment.md) and [lifecycle](lifecycle.md).
The example below deliberately cannot pass deployment admission.

<a id="changes"></a>
## Later deployments

Keep the supported `fresh` source for owned updates. VMID, hostname, provider,
storage and app namespaces remain continuity identities; changing a label does
not create a new owner. CPU/memory/startup/NIC changes alter desired infrastructure
and require the actual [saved-plan policy](lifecycle.md#infrastructure-plan-policy).
Disk and mount-point changes, replacement/import/adoption and an inactive planned
guest are refused. No universal online resizing, relocation or rollback is implied.

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

## Verification and navigation

The structural owner is [`guest`](../../blueprints/component_types.py), the
resolved owner is [`guest_values`](../../blueprints/component_plan.py), and the
native policy is [`check_plan`](../../proxmox/applications/plan_policy.py).
[Reference examples](../../blueprints/test_component_reference_examples.py)
exercise the real inherited override and invalid Boolean allocation without
native execution. These checks do not establish live capacity or service continuity.

[Reference index](README.md) · [Networks/NICs](networks.md) · [Apps](apps.md) ·
[Offline tutorial](../guides/first-configuration.md)
