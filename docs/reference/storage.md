# Storage and owned data

Storage declarations have four owners: a site names provider pools, a guest
allocates data roots, a library profile declares storage roles, and an app binds
those roles. A path string alone neither creates a mount nor adopts existing data.
Use [guest placement](guests.md) and the selected profile's complete example to
establish the surrounding contract.

<a id="pool-and-guest-storage"></a>
## Storage pool

One site `storage.<id>` is a closed object with required `context` (identifier)
and `pool` (nonempty text ≤4096 without NUL). Neither defaults or accepts null.
The context must match a consuming guest's context; `root_storage` selects the
pool. The provider pool's actual existence/capacity is a
[preparation prerequisite](../guides/prepare-deployment.md#qualify-platform-and-ownership).

## Guest volume fields

A `guests.<id>.volumes.<id>` value has exactly these required fields. There is
no inheritance; omission/null/empty and unknown fields refuse.

| Path within the volume | Type / inclusive domain | Resolution and effect |
| --- | --- | --- |
| <a id="volume-storage"></a>`storage` | Identifier | Existing pool; resolver requires the guest's selected root pool |
| <a id="volume-slot"></a>`slot` | Integer 0–255 | Unique and contiguous from zero across the guest's volumes |
| <a id="volume-path"></a>`path` | Canonical absolute data path | Provider mount target; supported forms below; no overlap with other owned roots |
| <a id="volume-size-gib"></a>`size_gib` | Integer 1–2147483647 GiB | Desired allocation; source validity is not permission for an existing mount change |

Volume paths match `/srv/<lowercase-name>[/...]` or `/var/lib/mysql`,
`/var/lib/postgresql`, `/var/lib/influxdb` with lowercase subdirectories. Data
paths cannot be `/`, contain traversal or overlap each other as parent/child.
They cannot overlap OS/framework control roots such as `/etc`, `/usr`, `/dev`,
`/run`, the defined `/var/lib/homelab*` roots or `/opt/homelab-app`. See
[canonical path rules](supporting-types.md#scalar-and-path-types) and the actual
[`data_path`/`volume` owner](../../blueprints/component_types.py).

## Guest root paths

`guests.<id>.root_paths.<id>` contains required `path` only. It uses the general
absolute data-path guard and overlap checks above, but does not allocate another
provider volume. An app binding resolves relative to this selected root.
Changing its declaration is not a native data-move operation.

## Profile storage roles

Each `app_profiles.<id>.storage.<role>` is closed and describes the destination
and access expected by its adapter.

| Field | Presence / accepted type | Meaning and constraints |
| --- | --- | --- |
| <a id="storage-role-target"></a>`target` | Required canonical absolute path | Adapter's container/native target; no default |
| <a id="storage-role-read-only"></a>`read_only` | Required Boolean | Declared access mode; asset bindings require true |
| <a id="storage-role-required"></a>`required` | Required Boolean | Whether the instance must supply this role; adapter floors may be stricter |
| <a id="storage-role-kind"></a>`kind` | Required `file` or `directory` | Selected material kind |
| <a id="storage-role-initialize"></a>`initialize` | Optional closed object | Supported writable directory initialization only, with exact fields below |

`initialize.type` is exactly `directory`; `uid` and `gid` are integers 0–65535;
`mode` is exactly the string `"0700"`. All four are required when the object is
present; omission means no requested initializer. Null/empty refuse. Initialization
requires `kind: directory` and `read_only: false`, and its actual fresh binding
must be below a provider volume. It is create-only and verifies ownership; it
cannot empty or replace retained data. The selected adapter must support the role.

## App storage bindings

One `apps.<id>.storage.<role>` selects exactly one branch:

| Variant | Required fields | Reference and effect |
| --- | --- | --- |
| volume | `volume`, `subpath` | Guest volume ID plus relative path within its root |
| root path | `root_path`, `subpath` | Guest root-path ID plus relative path within its root |
| asset | `asset` | Library asset ID; only a read-only profile role |

No branch has a default or accepts another branch's keys. `subpath: ""` selects
the whole root; otherwise the [canonical relative path rules](supporting-types.md#scalar-and-path-types)
apply. Unknown roles and missing required roles refuse. Literal assets follow
[exact-byte/hash ownership](supporting-types.md#evidence-and-assets); they are not
private credential sources. App bindings must also satisfy adapter-specific target
and runtime namespace restrictions.

## First installation

A supported guest/app creation path consumes these declarations. Actual pools,
capacity, private files and any preexisting data required by the selected profile
must already satisfy [preparation](../guides/prepare-deployment.md). A configured
initializer is not a general bootstrap or migration mechanism. A compile never
mounts storage or inspects data ownership on the target.

## Later deployments

The ordinary native plan preserves the whole existing guest disk and mount-point
blocks. Size growth, shrink and other changes to these blocks refuse, even if
individual values validate. Path/owner changes are not relocation or adoption.
There is no generic data retirement, import, replacement, restore or rollback
contract. [Lifecycle](lifecycle.md#infrastructure-plan-policy) owns these restrictions;
a separately supported procedure would need its own evidence and authority.

## Worked pool and data bindings

This is the complete value of tutorial `storage.local`:

<!-- example: pool-minimal -->
```yaml
context: lab
pool: example-local
```

The following is a **combination fragment**, not a site root: the guest declares
a provider volume, a profile declares a writable role, and the instance binds
that role. The selected profile must support this target and initializer.

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

Use the `volume` value at `guests.<id>.volumes.data`, the `profile_role` value at
`app_profiles.<id>.storage.data`, and `app_binding` at `apps.<id>.storage.data`.
The three wrapper labels above are explanatory, not accepted source fields.
This combination illustrates the direct volume/role/binding validators, not a
complete supported app profile or a native mount procedure. Do not add this
target/initializer to an arbitrary profile. Select a library profile that
explicitly supports its storage role and use that profile's complete example.
**Invalid variation:** set the volume path to `/etc/example-data`, or set
`initialize` on a read-only role. Both refuse before execution. Reusing a volume
slot or overlapping its path with another selected root also refuses.
Later deployments preserve data. The ordinary existing-guest plan treats the
entire disk and mount-point blocks as immutable, so a size increase as well as
a shrink is refused; a valid larger integer does not make resizing supported.

## Verification and navigation

[`volume`, `root_path`, `storage_role` and app binding validators](../../blueprints/component_types.py)
check shape/path boundaries; the [resolver](../../blueprints/component_plan.py)
and [app binding resolution](../../blueprints/component_plan.py) check relationships.
The [reference examples](../../blueprints/test_component_reference_examples.py)
exercise pool and combination values at their actual source boundary. They do
not qualify an arbitrary app initializer or native mount.

[Reference index](README.md) · [Guest fields](guests.md) · [App bindings](apps.md)
