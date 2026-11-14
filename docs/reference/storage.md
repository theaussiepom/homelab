# Storage and owned data

Storage is configured in four places: the site names provider pools, the guest allocates data roots, a library profile declares storage roles, and the app binds those roles to storage. A path string alone does not create a mount or adopt existing data. Read [guest placement](guests.md) and the selected profile's complete example to see how these declarations fit together.

<a id="pool-and-guest-storage"></a>
## Storage pool

Each site `storage.<id>` accepts exactly two required fields: `context`, an identifier, and `pool`, nonempty text of at most 4096 characters without NUL. Neither field has a default or accepts null. The context must match that of the guest using the pool; the guest selects it through `root_storage`. Checking that the pool exists and has enough capacity is a [deployment prerequisite](../guides/prepare-deployment.md#qualify-platform-and-ownership).

## Guest volume fields

Each `guests.<id>.volumes.<id>` value requires `storage`, `slot`, `path` and `size_gib`, with no inheritance. These required fields reject omitted, null or empty values. The optional `backup` field accepts null or an empty object; unknown fields are rejected.

| Path within the volume | Type / inclusive domain | Resolution and effect |
| --- | --- | --- |
| <a id="volume-storage"></a>`storage` | Identifier | Existing pool; resolver requires the guest's selected root pool |
| <a id="volume-slot"></a>`slot` | Integer 0–255 | Unique and contiguous from zero across the guest's volumes |
| <a id="volume-path"></a>`path` | Canonical absolute data path | Provider mount target using a supported form below; must not overlap other managed roots |
| <a id="volume-size-gib"></a>`size_gib` | Integer 1–2147483647 GiB | Requested allocation; a valid value does not permit changing an existing mount |
| <a id="volume-backup"></a>`backup` | Optional null or empty object | On an explicitly enrolled guest with the required site-root backup selection, presence includes this managed volume in native full-guest backup; omission excludes it. Without the root feature, existing provider defaults remain unchanged. See [backup selection](backup.md#syntax). |

Volume paths match `/srv/<lowercase-name>[/...]` or `/var/lib/mysql`, `/var/lib/postgresql`, `/var/lib/influxdb` with lowercase subdirectories. Data paths cannot be `/`, contain traversal or overlap each other as parent/child. They cannot overlap OS/framework control roots such as `/etc`, `/usr`, `/dev`, `/run`, the defined `/var/lib/homelab*` roots or `/opt/homelab-app`. See [canonical path rules](supporting-types.md#scalar-and-path-types) and the actual [`data_path`/`volume` owner](../../blueprints/component_types.py).

## Guest root paths

`guests.<id>.root_paths.<id>` requires `path` and optionally accepts the closed `host_bind` object below. The general absolute data-path and overlap checks above apply. A root without `host_bind` does not allocate another provider volume. App bindings resolve their paths relative to the selected root. Editing a declaration does not move data on the target.

### NFS recording bind

Only Scrypted's complete `recordings` root binding may select `host_bind`. Exactly one Scrypted app must own it, with `subpath: ''`; it cannot be an unused mount or another app's storage. No field has a default, and omitted, null, empty or unknown fields are rejected. The target `path` must be a literal directory below `/srv/`. Source and target path segments accept letters, digits, `_`, `-` and `.`, excluding `.` and `..` segments, whitespace and option separators.

| Field under `host_bind` | Type / accepted value | Effect |
| --- | --- | --- |
| `source` | Absolute directory below `/mnt/` | Exact existing host NFS subdirectory exposed to the guest |
| `slot` | Integer 0–255, equal to the number of managed guest volumes | Append the bind after every managed volume, with no gaps or collisions |
| `filesystem_source` | Literal DNS/IPv4 host plus `:/export/path` | Exact expected NFS source from the guest's mount view; no whitespace or mount options |
| `filesystem` | `nfs` or `nfs4` | Exact filesystem type required before starting the writer |
| `filesystem_root` | Literal absolute path, including `/` | Exact directory within the exported filesystem; path segments follow the literal restrictions above |

The compiler derives one `guest.recording_mount` for the provider and the app's storage guard from this declaration. OpenTofu keeps the bind writable, with `backup=false` and `replicate=false`; PBS captures the separately classified local Scrypted state. NAS recordings are persistent external data and are not part of that capture.

First create the guest and its local volumes through normal CD without selecting the recording bind or Scrypted app. The pinned provider and API-token authentication cannot attach an absolute host path through ordinary CD. A separately authorised commissioning operation must attach the exact declared bind and prepare the local Scrypted state. This exception is limited to work that CD cannot perform; it does not authorise recurring host changes. Review the host, guest identity, complete earlier mount sequence, NAS source, absent destination slot and source data before that operation.

Subsequent CD requires the genuine prior guest success and refuses an existing undeclared bind in its prior backend. It admits only the exact newly appended native mount after matching the whole active mount sequence and a read-only guest NFS check. Pending mount changes, different options, replacement, earlier-volume changes and unknown mount identities remain refusals. CD then records the append in its existing OpenTofu state, with no state editing or ignored mount drift. Ordinary repeat deployments preserve that exact identity and recheck the NAS before and after infrastructure reconciliation and before application start. A missing NAS mount never creates a local recording fallback.

See the library's complete Scrypted example and recovery classification. These source and runtime checks do not prove usable cameras, decoding, recording continuity, NAS capacity or an independent recording backup.

## Profile storage roles

Each `app_profiles.<id>.storage.<role>` describes the destination and access expected by its adapter. It accepts only the fields listed below.

| Field | Presence / accepted type | Meaning and constraints |
| --- | --- | --- |
| <a id="storage-role-target"></a>`target` | Required canonical absolute path | Adapter's container/native target; no default |
| <a id="storage-role-read-only"></a>`read_only` | Required Boolean | Declared access mode; asset bindings require true |
| <a id="storage-role-required"></a>`required` | Required Boolean | Whether the instance must supply this role; the adapter may impose stricter requirements |
| <a id="storage-role-kind"></a>`kind` | Required `file` or `directory` | Kind of file or directory to bind |
| <a id="storage-role-initialize"></a>`initialize` | Optional closed object | Requests supported initialization of a writable directory using exactly the fields below |

If you supply `initialize`, all four fields are required: `type` must be `directory`, `uid` and `gid` must be integers from 0 through 65535, and `mode` must be the string `"0700"`. Omit the object to request no initialization; null and empty objects are rejected. Initialization requires `kind: directory`, `read_only: false` and a fresh binding beneath a provider volume. It verifies ownership and only creates a new directory; it cannot empty or replace retained data. The selected adapter must support the storage role.

## App storage bindings

One `apps.<id>.storage.<role>` selects exactly one branch:

| Variant | Required fields | Reference and effect |
| --- | --- | --- |
| volume | `volume`, `subpath` | Guest volume ID plus relative path within its root |
| root path | `root_path`, `subpath` | Guest root-path ID plus relative path within its root |
| asset | `asset` | Library asset ID; only a read-only profile role |

Each branch requires its own fields, has no defaults and rejects keys belonging to another branch. `subpath: ""` selects the whole root; other values follow the [canonical relative path rules](supporting-types.md#scalar-and-path-types). Unknown roles and missing required roles are rejected. Literal assets follow the [exact-byte and hash rules](supporting-types.md#evidence-and-assets) and cannot serve as private credential sources. App bindings must also meet the adapter's target-path and runtime-name restrictions.

## First installation

A supported guest or app installation uses these declarations. The actual pools, capacity, private files and any preexisting data required by the profile must meet the [preparation requirements](../guides/prepare-deployment.md). An initializer supports only its declared creation procedure, not general bootstrapping or migration. Compilation does not mount storage or inspect data ownership on the target.

## Later deployments

The ordinary infrastructure plan preserves the existing guest's disk and mount-point blocks, including their sizes and order. The [PBS backup contract](backup.md#syntax) permits only two specific mount changes: backup flags that exactly match the compiled selection, and one new, empty, unprotected staging volume appended after the existing slots. For an already managed guest, the pinned provider cannot attach that staging mount through ordinary CD without replacement. Complete [separately approved environmental storage preparation](../backup/configure.md#prepare-storage-for-an-already-managed-guest) first; subsequent operational CD reconciles the prepared active desired state and applies the read-only staging checks. Fresh creation allocates its declared mounts normally. Other changes, including size increases and decreases, are rejected even when individual values pass validation. Editing paths or owners does not relocate or adopt data. There is no general procedure for retiring, importing, replacing, restoring or rolling back data. See [Lifecycle](lifecycle.md#infrastructure-plan-policy) for these restrictions. Any separately supported procedure would need its own evidence and authorisation.

## Worked pool and data bindings

This is the complete value of tutorial `storage.local`:

<!-- example: pool-minimal -->
```yaml
context: lab
pool: example-local
```

The following is a **combination fragment**, not a site root: the guest declares a provider volume, a profile declares a writable role, and the instance binds that role. The selected profile must support this target and initializer.

<!-- example: storage-combination -->
```yaml
volume:
  storage: local
  slot: 0
  path: /srv/example-data
  size_gib: 8
profile_role:
  target: /data
  read_only: false
  required: true
  kind: directory
  initialize: {type: directory, uid: 1000, gid: 1000, mode: "0700"}
app_binding:
  volume: data
  subpath: application
```

Use the `volume` value at `guests.<id>.volumes.data`, the `profile_role` value at `app_profiles.<id>.storage.data`, and `app_binding` at `apps.<id>.storage.data`. The three wrapper labels explain the parts of this example; they are not accepted configuration fields. The example demonstrates the volume, role and binding validators, rather than a complete app profile or an actual mount operation. Select a library profile that explicitly supports the storage target and initializer, and follow its complete example. Do not add them to an arbitrary profile.

**Invalid variation:** set the volume path to `/etc/example-data`, or add `initialize` to a read-only role. Both are rejected before execution. Reusing a volume slot or overlapping another selected root is also rejected. Later deployments preserve data: apart from the [specific PBS changes](#later-deployments), the existing guest's disk and mount-point blocks must stay unchanged. A larger valid integer does not make resizing supported.

## Verification and navigation

[`volume`, `root_path`, `storage_role` and app binding validators](../../blueprints/component_types.py) check field shapes and paths. The [resolver](../../blueprints/component_plan.py) and [app binding resolution](../../blueprints/component_plan.py) check relationships between declarations. The [reference example tests](../../blueprints/test_component_reference_examples.py) validate the pool and combined values through those implementations. They do not test an arbitrary app initializer or a real mount operation.

[Reference index](README.md) · [Guest fields](guests.md) · [App bindings](apps.md)
