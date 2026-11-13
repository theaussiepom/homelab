# Supporting types

These shared types complete the library and site reference. Objects accept only their listed fields. Unless stated otherwise, omitted optional maps and lists default to empty.

## Scalar and path types

Identifiers must match `[a-z][a-z0-9_-]{0,62}`, and named maps accept at most 1024 entries. General text must be a nonempty string of at most 4096 characters without NUL. Generic string lists accept at most 1024 such strings, with no duplicates unless the specific type permits them. Integer fields reject Booleans and use the default structural range 0–2147483647 unless another range is stated.

Canonical paths cannot contain dot or dotdot segments, repeated separators, dollar signs, colons, backslashes, control characters or DEL. Absolute paths start with one slash; relative paths do not. Data paths also exclude operating-system and framework control directories. [Source paths](sources.md) use a separate reader that keeps access within the source root.

## Profile interface, listener and endpoint types

| Declaration | Required fields | Optional fields / constraints |
| --- | --- | --- |
| interfaces.<role> | required:Boolean, accepts:list | accepts must select one or more of guest-interface/guest-loopback/app-network, without duplicates |
| listeners.<id> | service, namespace, interface, bind, protocol, port | publish |
| listener.service | Adapter service/native role | Must be owned by adapter |
| listener.namespace | host or app-network | Must agree with selected interface scope |
| listener.interface | Profile interface role ID | Must be bound by instance |
| listener.bind | interface, wildcard or loopback | Derives the address; does not accept a raw host override |
| listener.protocol / port | tcp or udp / integer 1–65535 | Socket collision checks apply |
| listener.publish | scope, port | guest-interface scope requires an interface role; guest-loopback forbids interface |
| endpoints.<id> | listener, protocol, via | protocol must be http/https/tcp/udp; listener and interface role must exist |
| endpoints.<id> internal alternative | internal: dashboard | Traefik only; requires an authenticated exposure belonging to that instance |

Maintained app profiles use `<purpose>_interface`, `<purpose>_listener` and `<purpose>_endpoint` to distinguish these namespaces. Guest NIC names such as `primary` keep their own names. A listener references an app interface role; an endpoint references a listener and the app role supplying its address. These names express relationships and do not change bind scope. See [the complete resolution chain](apps.md#instance-interface-role-and-exported-endpoint).

Each profile `connections.<role>` requires `type` (dns/mqtt/postgresql/mariadb/influxdb/http/https) and the Boolean `required`. Optional `readiness` selects zero or more of configure and start, without duplicates. Optional `accounts` selects zero or more of postgresql-admin, mariadb-admin and mqtt-client, also without duplicates. Both lists may be empty. A profile `devices.<role>` has the form `{type: serial, required: Boolean}`. See [Storage](storage.md) for storage-role fields.

## Software

All software fields are optional. `packages` is a list of unique, exact Debian package=version strings: use a lowercase package name with an optional architecture suffix, and a version containing neither whitespace nor equals. `images` maps adapter service roles to image-catalogue IDs. `repositories` is a list of objects containing exactly `name`, `source` and `key_asset`. Both name and key_asset are IDs, source is nonempty text, and key_asset must select an existing raw asset. Combining different versions or definitions of the same package or repository is rejected.

## Runtime and allocations

A runtime profile optionally has `packages` (software-ID list), `requirements`, `containers`, `native`, `minimums`.

| Field | Accepted nested fields |
| --- | --- |
| requirements | Optional nesting and keyctl Booleans, and optional positive integer os_reserve_mib |
| native | Requires positive integer memory_mib; supported only for a native adapter |
| minimums | Requires a containers map with at least one allocation field per service |
| containers.<role> | memory_mib, pids_limit, cpu_limit, read_only, cap_drop, cap_add, no_new_privileges, user, tmpfs |

Memory and PID limits must be positive integers; cpu_limit must be a number greater than 0 and at most 256. Boolean fields require actual Booleans. cap_drop is a unique list selected from [ALL], and cap_add from [NET_ADMIN]. NET_ADMIN is supported only by the declared Home Assistant mDNS/startup configuration. user must be nonempty text. tmpfs is a unique list whose values match `/tmp:rw,nosuid,nodev,size=<positive-integer>m`. Every final container requires memory_mib/cpu_limit/pids_limit. Allocation overrides and minimums accept a nonempty object containing only those three numeric fields. Checks reject conflicting runtime security settings and allocations below the minimums. Guest runtime selections may add package and OS requirements, but cannot reserve resources for container or native app workloads. App reservations and the effective OS reserve must fit within the guest's capacity.

## Images

The library's `images.json` is a named map of image records. A normal record requires repository, tag and digest. The repository must match `[a-z0-9][a-z0-9./_-]*`; tag must be null or match `[A-Za-z0-9_.-]+`; digest must be sha256: followed by 64 lowercase hexadecimal characters. The generated image reference is literal repository[:tag]@digest.

The catalogue parser accepts unpinned-latest records only as exact repository/tag/digest forms for ghcr.io/bitwarden/lite and ghcr.io/music-assistant/server with tag latest and digest null. Catalogue acceptance is structural, not adapter support: the current Bitwarden adapter requires an official immutable digest reference and refuses latest. Music Assistant supports its declared latest selection; that floating policy is not equivalent to an immutable reference.

A custom archive record requires `local_id`, `archive` and `archive_sha256`. `local_id` must be `sha256:` followed by 64 lowercase hexadecimal characters. `archive` must be an absolute path, and `archive_sha256` must contain 64 lowercase hexadecimal characters. This supports a versioned artifact; it does not authorise capturing or upgrading a running image. A site image binding may select only a library record that already uses this exact archive form. Normal registry image versions belong to the library, and an instance cannot replace one with an archive.

## Health and monitoring

A health definition has the form `{type: adapter, check: readiness}`, with an optional source_interface ID. Profile health may instead use `{profile: id}`, optionally overriding source_interface. Music Assistant's physical web role is currently the only supported source-interface health selection; other adapter and source combinations are rejected. Packet generation requires the applicable readiness declarations. Selecting a health profile does not establish that the running service is healthy.

A monitoring profile requires type zabbix-agent and a nonempty, unique profiles list selected from linux/docker/postgresql/mysql/influxdb. A monitoring reference has exactly the form `{profile: id}`. Root monitoring requires linux in every selected guest's combined profile set. See [Zabbix](zabbix.md) for the resulting configuration.

## Devices

A site device requires type serial, a context ID, path and capability ID. The path must be canonical and beneath /dev/serial/by-id/. The capability must exist in that context and have type serial-device. An app binds devices through its declared profile roles. Each physical device, identified by context and path, can have only one owner. This declaration does not discover a coordinator or test the physical device.

## Evidence and assets

A library asset is exactly `{type: raw-utf8, source: relative_path, sha256: lower64hex}`. The reader checks actual bytes/hash and valid UTF-8, retaining literal text.

Site evidence accepts that same raw form, or ongoing identity-callbacks: `{type: identity-callbacks, document: [...]}` or `{type: identity-callbacks, source: file.json, sha256: lower64hex}`. The source form must be JSON. No active one-time migration evidence types exist.

A callback document contains 1–8 records, each with a unique positive provider_id. Each record requires application_id (a canonical UUID), client_id_sha256, provider_metadata_sha256, application_metadata_sha256 and policy_metadata_sha256 (each 64 lowercase hexadecimal characters), existing_redirects (1–20 objects containing matching_mode:strict and url), and additions (1–4 unique HTTPS URLs). URLs cannot contain credentials, a query, fragment, backslash or whitespace. An optional port must be 1–65535. New additions must use exactly /oauth2/callback, and all old and new URLs must be unique. Runtime validators still check the actual IdP metadata. Source evidence alone cannot authorise an account or provider change.

## Update behavior

A library change can affect every app or guest using its profiles. File contents remain literal, and sealed records continue to protect managed runtime files and selected private inputs. Changes to capacity, capabilities, mounts, images and listeners must pass both compiler and runtime checks. These types do not provide arbitrary commands, replacement or rollback.

## Worked profile and runtime combination

This complete profile body describes the tutorial's single Unbound socket. It is a value under `app_profiles.recursive`; a standalone leaf additionally needs `schema` and `kind: app-profile` headers.

<!-- example: profile-minimal -->
```yaml
adapter: unbound
display_name: Recursive DNS
interfaces:
  private_interface:
    required: true
    accepts:
    - app-network
  local_interface:
    required: true
    accepts:
    - guest-loopback
listeners:
  udp_listener:
    service: unbound
    namespace: app-network
    interface: private_interface
    bind: wildcard
    protocol: udp
    port: 53
    publish:
      scope: guest-loopback
      port: 5335
endpoints:
  dns_endpoint:
    listener: udp_listener
    protocol: udp
    via: local_interface
software: [resolver]
runtime: [resolver]
health:
  ready:
    type: adapter
    check: readiness
```

Its selected `runtime_profiles.resolver` is a complete runtime value:

<!-- example: runtime-minimal -->
```yaml
containers:
  unbound:
    memory_mib: 256
    cpu_limit: 1
    pids_limit: 128
```

The [tutorial library](../examples/first-configuration/stack.json) supplies the matching software and image declarations. Your site binds both interface roles as shown on [Apps](apps.md). The endpoint describes the protocol other declarations can reference, while its listener defines the actual UDP socket and where it is published. **Invalid variation:** change the listener's `interface` to an undeclared role, or use `cpu_limit: true`. Both fail their own validators. A valid profile can still fail later resource, namespace, image or traffic checks when composed with other apps.

A serial declaration is another complete supporting value, placed in `devices.coordinator` and bound through an app's declared device role:

<!-- example: device-minimal -->
```yaml
type: serial
context: lab
path: /dev/serial/by-id/example-coordinator
capability: host_serial
```

`host_serial` must be a capability of context `lab`. The path is a synthetic identity, not a claim that a device exists. `/dev/ttyUSB0` is not an accepted substitute for the required stable by-id path. Later deployment verifies the actual selected device; changing the declaration is not radio commissioning.

[Reference index](README.md) · [Library](library.md)
