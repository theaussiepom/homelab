# Supporting types

These shared declarations complete the library/site reference. Objects are
closed and optional maps/lists default empty unless stated.

## Scalar and path types

Identifiers match `[a-z][a-z0-9_-]{0,62}`; maps contain at most 1024 named entries.
General text is a nonempty string ≤4096 without NUL. Generic string lists have
at most1024 nonempty strings ≤4096, unique unless a specific type permits repeats.
Integer means actual integer (not Boolean), default structural range
0–2147483647.

Canonical paths contain no dot/dotdot segments, repeated separators, dollar,
colon, backslash, control characters or DEL. Absolute paths start with one slash;
relative paths do not. Data paths additionally exclude OS/framework control roots.
[Source paths](sources.md) have their own anchored confined reader.

## Profile interface, listener and endpoint types

| Declaration | Required fields | Optional fields / constraints |
| --- | --- | --- |
| interfaces.<role> | required:Boolean, accepts:list | Nonempty unique accepts subset guest-interface/guest-loopback/app-network |
| listeners.<id> | service, namespace, interface, bind, protocol, port | publish |
| listener.service | Adapter service/native role | Must be owned by adapter |
| listener.namespace | host or app-network | Must agree with selected interface scope |
| listener.interface | Profile interface role ID | Must be bound by instance |
| listener.bind | interface, wildcard or loopback | Derives address, no raw host override |
| listener.protocol / port | tcp or udp / integer1–65535 | Socket collision checks apply |
| listener.publish | scope, port | scope guest-interface requires interface role; guest-loopback forbids interface |
| endpoints.<id> | listener, protocol, via | protocol http/https/tcp/udp; listener and interface role must exist |
| endpoints.<id> internal alternative | internal: dashboard | Traefik only; authenticated owned exposure required |

Profile `connections.<role>` requires `type`
(dns/mqtt/postgresql/mariadb/influxdb/http/https) and Boolean `required`.
Optional `readiness` list is a unique subset configure/start; optional
`accounts` list a unique subset postgresql-admin/mariadb-admin/mqtt-client.
Profile `devices.<role>` is `{type: serial, required: Boolean}`.
Storage-role fields are in [Storage](storage.md).

## Software

Software requires no fields. Optional packages is a unique list of exact
Debian package=version strings: lower-case package name with optional
architecture suffix, non-whitespace version without equals.
Optional images maps adapter service roles to image-catalogue IDs.
Optional repositories is a list of closed `{name, source, key_asset}` objects:
name/key_asset are IDs, source nonempty text, key_asset an existing raw asset.
Different versions/definitions for the same aggregated package/repository refuse.

## Runtime and allocations

A runtime profile optionally has `packages` (software-ID list),
`requirements`, `containers`, `native`, `minimums`.

| Field | Accepted nested fields |
| --- | --- |
| requirements | Optional nesting/keyctl Booleans and os_reserve_mib positive integer |
| native | Required memory_mib positive integer; native adapter only |
| minimums | Required containers map; each service has one or more allocation fields |
| containers.<role> | memory_mib, pids_limit, cpu_limit, read_only, cap_drop, cap_add, no_new_privileges, user, tmpfs |

Memory/PIDs are positive integers; cpu_limit number >0 ≤256.
Boolean fields are exact Booleans.
cap_drop is a unique list subset [ALL]; cap_add subset [NET_ADMIN].
NET_ADMIN is only supported by the declared Home Assistant mDNS/startup path.
user is nonempty text. tmpfs is a unique list matching
`/tmp:rw,nosuid,nodev,size=<positive-integer>m`.
Every final container requires memory_mib/cpu_limit/pids_limit.
Allocation overrides/minimums accept only those three numeric fields and a
nonempty object. Runtime security conflicts refuse; minima must hold.
Guest runtime selections may add package/OS requirements, not containers/native
workload reservations. Total app reservations plus effective OS reserve must fit.

## Images

Library `images.json` is a named map of image records.
Normal form requires repository, tag and digest. Repository matches
[a-z0-9][a-z0-9./_-]*, tag null or [A-Za-z0-9_.-]+, digest
sha256: followed by64lowercasehex. It renders literal repository[:tag]@digest.

The only unpinned-latest records accepted are exact repository/tag/digest forms
for ghcr.io/bitwarden/lite and ghcr.io/music-assistant/server with tag latest
and digest null. Choosing one deliberately follows that policy; it is not
equivalent to an immutable reference.

Custom archive form requires local_id (sha256:64hex), archive (absolute path),
archive_sha256 (64lowercasehex). It is a genuine versioned artifact capability,
not permission to capture or upgrade a running image. Site images may bind only
a library record already using that exact archive shape. Normal registry image
versions remain library-owned; an instance cannot override one with an archive.

## Health and monitoring

A health definition is `{type: adapter, check: readiness}`, optionally
source_interface ID. Profile health can instead use `{profile: id}` with optional
source_interface override. The final source-interface health capability is
currently Music Assistant's physical web role; other adapter/source combinations
refuse. Lowering requires applicable readiness declarations; selecting a
profile does not mean the service has already been observed healthy.

Monitoring profile requires type zabbix-agent and nonempty unique profiles list
subset linux/docker/postgresql/mysql/influxdb. A monitoring reference is exactly
`{profile: id}`. Root monitoring requires linux in every selected guest's
combined profile set. [Zabbix](zabbix.md) describes expansion.

## Devices

Site devices require type serial, context ID, path and capability ID.
Path must be canonical under /dev/serial/by-id/; capability must exist in that
context and be serial-device. App device bindings name declared profile roles.
A physical context/path has one owner. This does not discover a coordinator or
establish physical device acceptance.

## Evidence and assets

A library asset is exactly
`{type: raw-utf8, source: relative_path, sha256: lower64hex}`.
The reader checks actual bytes/hash and valid UTF-8, retaining literal text.

Site evidence accepts that same raw form, or ongoing identity-callbacks:
`{type: identity-callbacks, document: [...]}` or
`{type: identity-callbacks, source: file.json, sha256: lower64hex}`.
The source form must be JSON. No active one-time migration evidence types exist.

Callback document is a list of1–8 records, unique positive provider_id.
Each record requires application_id (canonical UUID), client_id_sha256,
provider_metadata_sha256, application_metadata_sha256, policy_metadata_sha256
(all lowercase64hex), existing_redirects (1–20 objects with
matching_mode:strict and url), additions (1–4 unique HTTPS URLs).
No credentials/query/fragment/backslash/whitespace are allowed in URLs; optional
port1–65535. New additions use exact /oauth2/callback.
All old+new URLs are unique. Installed validators still bind actual IdP metadata;
source evidence alone cannot authorize an account/provider change.

## Update behavior

Library changes can affect every profile consumer. Files remain literal,
owned runtime leaves and selected private material remain sealed. Capacity,
capability, mount, image and listener changes must survive both compiler and
native guards. No type here implements generic commands, replacement or rollback.

[Reference index](README.md) · [Library](library.md)
