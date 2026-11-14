# Supported scope

The application platform supports Debian 13 LXC containers on Proxmox. This does not establish support for VM guests, arbitrary physical machines or all hardware. Host bootstrap, ISO installation and network recovery are separate subsystems.

## First installation and later deployments

The `fresh` column describes first-installation support. Keep the same supported `fresh` configuration for later updates. `retained` requires genuine HomeLab receipts, state and app payloads proving that HomeLab already manages the installation; it cannot import an arbitrary existing service. A retained-only adapter does not support first installation.

For example, the [Unbound tutorial](../guides/first-configuration.md) compiles a supported fresh configuration offline. An already owned Bitwarden installation uses its retained contract and normal declared image, preserving its database, keys and data. Neither example promises general restore, replacement or rollback.

## Adapter capability matrix

This table describes the framework adapters. It does not establish that every library profile or individual installation has been commissioned and tested on a target.

| Adapter | Execution | Fresh behavior / important limits |
| --- | --- | --- |
| unbound | Compose | Fresh apps use packaged configuration without empty storage bindings; retained apps use explicit configuration. Multiple instances require distinct published loopback sockets. |
| pihole | Compose host network | Supports the fresh and later-update helper procedure with a declared upstream and storage. Its supporting DNS files use fixed paths, limiting it to one instance per guest. |
| homeassistant | Compose | Supports creating a new directory. The retained custom mDNS/startup configuration requires its existing capability and files. |
| node_red | Compose host network | Supports a new directory for fresh installation. Retained apps must preserve the exact OIDC, settings and health wrapper and process identity. |
| mqtt | Compose | Requires explicit probe, password and storage inputs. Preserves existing broker and account identities; no general credential bootstrap is provided. |
| mqtt_explorer | Compose gateway + app | Supports a fresh or retained workspace with a managed broker account or explicit existing credential, plus the required outpost and origin. |
| cloudbeaver | Compose gateway + app | Supports a fresh or retained managed workspace with OIDC, a recovery identity and selected database accounts. |
| authentik | Compose server/worker/Redis | Requires an existing database and private inputs. Supports the specific optional callback-update procedure; selecting the app does not commission an IdP. |
| traefik | Compose | Requires declared ACME, provider and runtime settings, with the necessary trust files and tokens prepared. |
| zabbix | Compose server/web | Ordinary preparation requires the credentials and files managed by root monitoring. Database and authentication prerequisites and explicit placement also apply. |
| renovate | Compose bridge | Fresh CE server with an explicitly owned PostgreSQL database and protected App/licence/terms inputs. No public listener or Enterprise Web UI. Source tests do not prove scans or recovery; see [Renovate](renovate.md). |
| postgresql | Native packages/systemd | Requires the specified version and verified ownership of data, listeners and accounts. Supports ordinary updates; generating native configuration does not prove first-time database commissioning. |
| mariadb | Native packages/systemd | Checks the package account, existing data and credentials. Does not automatically import resources or rotate credentials. |
| influxdb | Native packages/systemd | Requires the fixed native account and ownership of data and configuration. Does not automatically create organizations or buckets. |
| bitwarden | Compose | Retained only. Verifies the existing environment, installation, database and data identities, and uses the normal declared image. |
| zigbee2mqtt | Compose | Retained only, with one managed serial coordinator. First-time commissioning is rejected. |
| music_assistant | Compose host network | Retained only. Requires existing /data, the specified process and listeners, a public HTTPS connection and its own HTTPS origin. |
| scrypted | Compose host network | Starts prepared local configuration/database and an exact NFS recording bind. Empty installation and automatic restore are unsupported. The startup guard requires software decoding, keeps user0:0 and maps no graphics devices. First guest creation precedes separately authorised NAS bind commissioning; later CD retains its exact mount identity. |
| pegaprox | Compose | Requires an existing database key and data, plus a trusted private proxy. Does not permit arbitrary backend publication. |
| winet | Compose | Supports one inverter with the specified existing options and credentials. Arbitrary vendor options are rejected. |

Each library profile specifies its required interfaces, storage, minimum resources and software versions, and may be more restrictive than this table. Passing source checks does not prove that an installation works on a target, or establish a first-installation procedure absent from the table. CloudBeaver currently requires at least one managed database account and connection, even when it also selects unmanaged database metadata. CloudBeaver and Music Assistant need an explicit public HTTPS connection and their own HTTPS origin to generate health checks. Omitting them may pass structural validation but fail when the complete configuration is compiled.

## Placement and repeat instances

Multiple instances of a profile must not overlap in their listeners, data and private files, runtime paths, service or project names, or native account names and numeric IDs. Source and packet tests cover repeated Unbound and supported proxy instances. Pi-hole and Zigbee supporting files use fixed paths, and native services use fixed unit names. Instances on the same guest would share these paths or names, so they are limited to one instance per guest. PostgreSQL and InfluxDB can conflict in their declared numeric group IDs; checks reject that conflict before generating a packet. Apps on the same guest still cannot share another app's private directory.

## Evidence levels

- Component unit tests check accepted values and intended failures.
- Compiler and receiver tests check combined configuration and the exact generated deployment packets.
- Controller tests use genuine local receipts, state and app payloads while replacing native operations with fakes.
- Docker/native fixtures verify their named isolated protocols or filesystem behavior only.
- Protected CD and real service/user/device verification establish an installation.

Passing source tests does not authorise deployment. See [Lifecycle](lifecycle.md) and the selected library's profile-specific support page.

[Reference index](README.md)
