# Storage

Storage pools, guest paths and profile mount roles are separate contracts.
Compilation validates declarations; it does not create a mount or adopt data.

## Pool and guest storage

Site `storage.<id>` is exactly `{context: context_id, pool: text}`.
A guest selects `root_storage` from its context.

| Guest declaration | Fields | Constraints |
| --- | --- | --- |
| volumes.<id> | Required `storage`, `slot`, `path`, `size_gib` | Pool ID; slot integer 0–255 unique within guest; size positive integer; canonical supported data path |
| root_paths.<id> | Required `path` only | Canonical data path on root filesystem |

Volume paths match `/srv/<lowercase-name>[/...]` or
`/var/lib/mysql`, `/var/lib/postgresql`, `/var/lib/influxdb` with lowercase
subdirectories. Root paths have the general data-path guard.
Paths cannot be `/`, overlap each other as parent/child, or overlap framework/
OS control roots such as `/etc`, `/usr`, `/dev`, `/run`,
`/var/lib/homelab*`, `/opt/homelab-app`. See
[scalar/path rules](supporting-types.md#scalar-and-path-types).

## Profile storage roles

Each role requires `target` (absolute container/native target), `read_only`
(Boolean), `required` (Boolean), `kind` (`file` or `directory`).
Optional `initialize` is exactly
`{type: directory, uid: integer, gid: integer, mode: "0700"}`.
UID/GID are 0–65535. Initialization is only for writable directory roles;
the actual fresh binding must be beneath its provider volume. It is create-only
and verifies ownership, not permission to empty or replace retained data.

## App storage bindings

Each app role contains exactly one of:

- `{volume: guest_volume_id, subpath: relative_path}`
- `{root_path: guest_root_path_id, subpath: relative_path}`
- `{asset: library_asset_id}`

`subpath` can be `""` for the whole selected root; otherwise it is canonical
relative data with no traversal. Asset binding is allowed only for read-only
profile roles. Missing required/unknown roles refuse.

Changing a path, slot or owner can affect resource/data identity and is not an
automatic relocation. Shrink, import, destructive replacement, restore and
retirement require their separate supported procedures. Ordinary CD preserves
unselected data and will refuse unsafe plans. [Lifecycle](lifecycle.md) supplies
the shared update boundary.

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
A later deployment preserves data; increasing a requested size still requires
the guarded provider plan and is not an automatic data migration.

[Reference index](README.md) · [Apps](apps.md)
