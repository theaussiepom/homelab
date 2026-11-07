# Guests

A guest is one `guests.<id>` value in your [site](site.md), declared inline or in a complete `kind: guest` [source file](sources.md). It selects a library template and defines one Debian LXC container, its control interface and the paths HomeLab manages for its data and runtime files. The [complete tutorial](../examples/first-configuration/site.yaml) provides a working offline configuration. A real installation also requires [deployment preparation](../guides/prepare-deployment.md).

<a id="properties"></a>
## Guest property index

Use only the listed fields. Required fields have no default, and null does not request an inherited value. Optional maps and lists follow the behavior stated below. IDs and paths follow the [shared type rules](supporting-types.md#scalar-and-path-types).

| Path under `guests.<id>` | Presence / accepted type | Default or effect |
| --- | --- | --- |
| <a id="guest-context"></a>`context` | Required ID | Existing [context](contexts.md) supplying provider, trust and controller inputs |
| <a id="guest-template"></a>`template` | Required ID | Existing library [guest template](library.md#guest-template) |
| <a id="guest-lifecycle"></a>`lifecycle` | Required `fresh` or `retained` | [Ownership policy](lifecycle.md); no import override |
| <a id="guest-identity"></a>`identity` | Required closed object | Required `vmid` and `hostname`, below |
| <a id="guest-identity-vmid"></a>`identity.vmid` | Required integer 1–2147483647 | Unique within the declared API address and port, including across nodes. The infrastructure plan also requires at least 100 and excludes protected IDs. |
| <a id="guest-identity-hostname"></a>`identity.hostname` | Required string | `[a-z][a-z0-9-]{0,62}`; stable ownership identity |
| <a id="guest-template-file-id"></a>`template_file_id` | Required nonempty text, ≤4096, no NUL | Identifies an existing provider template; source validation does not fetch it |
| <a id="guest-root-storage"></a>`root_storage` | Required ID | [Storage pool](storage.md#storage-pool) in the same context |
| <a id="guest-interfaces"></a>`interfaces` | Required nonempty named map | Exact [NIC records and address branches](networks.md#nic-property-index) |
| <a id="guest-control-interface"></a>`control_interface` | Required ID | Selects a declared static/DHCP NIC for its management address and MAC; a manual NIC is forbidden |
| <a id="guest-display-name"></a>`display_name` | Optional nonempty text, ≤4096, no NUL | Defaults to hostname; cosmetic, not an identity rename |
| <a id="guest-resources"></a>`resources` | Optional partial object | Inherits template values, overridden by individual guest fields; [resource records](#resource-fields) |
| <a id="guest-startup"></a>`startup` | Optional partial object | Inherits template values, overridden by individual guest fields; [startup records](#startup-fields) |
| <a id="guest-security"></a>`security` | Optional partial object | Inherits template values, overridden by individual guest fields; [security records](#security-fields) |
| <a id="guest-ssh-public-keys"></a>`ssh_public_keys` | Optional unique string list | Omission inherits the context; explicit `[]` stays empty and is rejected by deployment key admission |
| <a id="guest-dns-servers"></a>`dns_servers` | Optional nonempty endpoint-reference list | Omission inherits context; resolved TCP/UDP IPv4 DNS port 53 |
| <a id="guest-timezone"></a>`timezone` | Optional timezone string | Guest, then context, then `Etc/UTC`; shared timezone rules |
| <a id="guest-volumes"></a>`volumes` | Optional named map; omitted `{}` | Provider [volumes](storage.md#guest-volume-fields) |
| <a id="guest-root-paths"></a>`root_paths` | Optional named map; omitted `{}` | Owned [root-filesystem paths](storage.md#guest-root-paths) |
| <a id="guest-compose-projects"></a>`compose_projects` | Optional named map; omitted `{}` | [Project records](#compose-project-fields) |
| <a id="guest-software"></a>`software` | Optional unique ID list; omitted `[]` | Append to template software; [software declarations](supporting-types.md#software) |
| <a id="guest-runtime"></a>`runtime` | Optional unique ID list; omitted `[]` | Appends to template runtime; cannot reserve resources for app containers or native workloads |
| <a id="guest-network-policy"></a>`network_policy` | Optional ordered list; omitted `[]` | Policy ID or explicit [policy binding](policies.md#bindings) |
| <a id="guest-readiness"></a>`readiness` | Optional ordered list; omitted `[]` | Each exactly `{stage: preparation, target: {app: id, endpoint: name}}`; target must be on another guest |
| <a id="guest-source-policy-route"></a>`source_policy_route` | Optional closed object | Exactly `{interface: nic_id}`; selected non-default static NIC requires a gateway different from its address |
| <a id="guest-monitoring"></a>`monitoring` | Optional closed object | Exactly `{profile: id}`; replaces template selection; see [monitoring](zabbix.md) |

## Defaults and resolution

The compiler merges resources, startup and security by direct field: it starts with the complete template, then applies the guest's explicit keys. Omitting a block or supplying an empty map preserves the template values; null is rejected. Guest software and runtime lists append to the template lists, so an empty guest list cannot remove a template selection. A guest monitoring selection replaces the complete template reference. Empty or null values do not disable monitoring.

For the tutorial's `base` template, adding `resources: {memory_mib: 1024}` produces CPU 1, memory 1024 MiB, root 8 GiB and an authored OS reserve of 128 MiB. Runtime budgeting can raise the effective OS reserve to its minimum of 256 MiB or to meet selected requirements. The declared reserve and effective allocation can therefore differ. See the [complete library](../examples/first-configuration/stack.json).

### Resource fields

These full paths are `guests.<id>.resources.<field>`; the same object is complete in a template. Each field is an actual integer, never Boolean. Guest omission inherits the corresponding template value; no framework scalar default replaces it.

| Field | Inclusive domain | Consumer and change limit |
| --- | --- | --- |
| <a id="guest-resources-cpu-cores"></a>`cpu_cores` | 1–2147483647 | Requested CPU allocation; actual capacity and plan checks still apply |
| <a id="guest-resources-memory-mib"></a>`memory_mib` | 256–2147483647 MiB | Must cover effective OS reserve and selected app reservations |
| <a id="guest-resources-root-gib"></a>`root_gib` | 4–2147483647 GiB | An existing guest's disk block must remain unchanged; ordinary policy rejects increases and decreases |
| <a id="guest-resources-os-reserve-mib"></a>`os_reserve_mib` | 0–2147483647 MiB | Must resolve to less than memory; runtime requirements may raise the effective reserve |

### Startup fields

Full paths are `guests.<id>.startup.<field>`. All fields are required in the template and individually optional in the guest.

| Field | Accepted type / effect | Additional boundary |
| --- | --- | --- |
| <a id="guest-startup-started"></a>`started` | Boolean desired running state | False passes structural validation, but the saved-plan policy requires the planned guest to be active |
| <a id="guest-startup-start-on-boot"></a>`start_on_boot` | Boolean boot policy | No general interruption guarantee from changing it |
| <a id="guest-startup-boot-order"></a>`boot_order` | Integer 0–2147483647 | Host startup order; distinct from app/guest readiness dependencies |

### Security fields

Full paths are `guests.<id>.security.<field>`. All fields are required in the template, individually optional in the guest and actual Booleans.

| Field | Accepted values / resolved effect |
| --- | --- |
| <a id="guest-security-unprivileged"></a>`unprivileged` | Must be true; structural validation rejects false, and the infrastructure plan preserves the setting |
| <a id="guest-security-protection"></a>`protection` | Must be true; removing protection is not ordinary maintenance |
| <a id="guest-security-nesting"></a>`nesting` | Boolean; the selected runtime may require true |
| <a id="guest-security-keyctl"></a>`keyctl` | Boolean; the selected runtime may require true |

### Compose project fields

Each `guests.<id>.compose_projects.<id>` requires `name`, nonempty text of at most 4096 characters without NUL, and optionally accepts `file`. The file defaults to `compose-<map-key>.yml` and must match `[a-z][a-z0-9_-]{0,62}.yaml` or `.yml`. Filenames must be unique within the guest. Null and empty values do not request the default. Execution also checks the allowed runtime identity fields and values. [App identity](apps.md#runtime-identity) references the project by its map key.

## Resolution and relationships

VMIDs are unique within API address/port scope, including different nodes. [NIC identity conflicts](networks.md#field-guest-nic-mac), ports, devices and owned paths have separate collision scopes. Provider NIC order follows slots; volume slots are contiguous from zero. App placement contributes software and runtime requirements and must fit the guest's effective budget.

Readiness creates only its explicit dependency. Network policy supplies access; DNS/endpoint references supply values. The [relationship guide](../guides/references-and-reuse.md) explains why none substitutes for the others. Reserved guest/app IDs include execution phase names and cannot be used as instance keys.

## First installation

The selected template supplies defaults; it does not provision a guest by itself. Creating a supported `fresh` guest requires that neither its HomeLab owner nor its backend already exist. Its allocations must pass admission, its trust files, credentials and platform must meet the prerequisites, and its apps must support creation. See [preparation](../guides/prepare-deployment.md) and [lifecycle](lifecycle.md). The synthetic example below deliberately cannot pass deployment admission.

<a id="changes"></a>
## Later deployments

Keep the supported `fresh` configuration for ordinary updates. Ownership checks preserve the VMID, hostname, provider, storage and app names and paths; changing a label does not establish new ownership. CPU, memory, startup and NIC changes must pass the [saved-plan policy](lifecycle.md#infrastructure-plan-policy). That policy rejects disk and mount-point changes, replacement, import, adoption and an inactive planned guest. It does not guarantee online resizing, relocation or rollback.

## Worked guest and inherited defaults

This complete `guests.resolver` value works with the tutorial's context, `primary` network, `local` pool and `base` template. Those referenced objects must also exist; the example is synthetic and cannot pass deployment admission.

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

Omit resources, startup and security to inherit the complete template. Add `resources: {memory_mib: 1024}` to allocate more memory while keeping the template's CPU, root disk and OS reserve values. This merges direct fields rather than recursively merging YAML. **Invalid variation:** `resources: {memory_mib: true}` is rejected because a Boolean is not an integer allocation. A second NIC also cannot reuse slot zero.

The same `fresh` source is used for first installation and subsequent owned updates. The runtime distinguishes them from genuine receipts and backend state; changing the label to `retained` is neither a required next step nor an import.

## Verification and navigation

[`guest`](../../blueprints/component_types.py) validates the input structure, [`guest_values`](../../blueprints/component_plan.py) applies inherited values and checks references, and [`check_plan`](../../proxmox/applications/plan_policy.py) checks the infrastructure plan before execution. [Reference example tests](../../blueprints/test_component_reference_examples.py) exercise the inherited override and reject a Boolean allocation without running native commands. These checks do not establish live capacity or uninterrupted service.

[Reference index](README.md) · [Networks/NICs](networks.md) · [Apps](apps.md) · [Offline tutorial](../guides/first-configuration.md)
