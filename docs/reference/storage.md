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

[Reference index](README.md) · [Apps](apps.md)
