# Application properties

Properties live in `app_profiles.<id>.properties` (partial library defaults) and
`apps.<id>.properties` (explicit overrides). The effective object merges direct
keys and must match the adapter's closed form below. Omitted optional properties
have no effect unless a default is stated. Unknown properties refuse.

## Network and home adapters

| Adapter | Fields and constraints |
| --- | --- |
| unbound | Optional publish_port integer 1–65535; guest-loopback publication default 5335 |
| pihole | Empty object only; managed records derive from exposures and one explicit DNS upstream connection is required |
| homeassistant | Optional mdns object with required interface and startup IDs; physical interface plus selected read-only /startup storage role; retained lifecycle and exact NET_ADMIN runtime capability required for this path |
| node_red | Empty object only; runtime/auth selection owns the settings wrapper |
| mqtt | Optional password_file matching /mosquitto/config/[A-Za-z0-9_.-]{1,100}, excluding dot/dotdot; required when serving managed Explorer account |
| mqtt_explorer | Required connection_name, single nonempty line ≤100; broker and outpost connections plus owned HTTPS origin required |
| music_assistant | Empty object only |
| mariadb / influxdb | Empty object only |

## Authentik and Zabbix

Both require `database: {name: sql_id, user: sql_id}`.
SQL ID matches `[a-z][a-z0-9_]{0,62}` and excludes postgres/template0/template1.
The database connection must be PostgreSQL port 5432.

Authentik additionally accepts:
- `smtp`: required host/from (single nonempty lines ≤253), port (1–65535),
  use_tls/use_ssl (Booleans, not both true), username (single line ≤256,
  empty allowed); optional timeout integer 1–300.
- `callbacks: {evidence: id}`: existing identity-callbacks evidence, finite
  provider/application metadata and exact additions. It is not general IdP
  provisioning.

Zabbix accepts no other properties. Source binding outside root monitoring
accepts a selected `database_password` role, but that is not a supported ordinary
deployment path: current app preparation requires root monitoring's owned
credential and exact monitoring files, with no selected scalar password. Root
monitoring owns the generated credential and refuses a duplicate selected role.

## PostgreSQL

Optional `client_access` is an ordered list (default [], maximum 128).
Each row requires `source: {app: id, interface: role}`,
`database: all`, `user: all`, `method: scram-sha-256`.
The source must resolve a physical non-loopback/non-link-local IPv4 address,
unique in that selection. It is not a generic authored HBA line.
Native listeners, account identities and existing data checks remain required.

## Traefik

| Field | Shape / default / constraints |
| --- | --- |
| dashboard | Optional Boolean, false |
| provider | Structurally optional, required by current rendered adapter; context ID and token_id are required |
| provider.token_id | Non-whitespace realm-qualified identity with one ! suffix, e.g. synthetic reader@pve!discovery |
| provider.discovery | Optional closed object: local_directory, mirror_directory, owner_sha256, guests |
| discovery directories | Canonical absolute paths ending /service-discovery, distinct |
| discovery.owner_sha256 | Lowercase 64-hex owner digest |
| discovery.guests | Unique 1–32 guest IDs in the same context, lowered to their VMIDs |
| acme | Structurally optional, required by current adapter; email and resolvers required |
| acme.email | Non-whitespace email with one @ and dotted domain |
| acme.resolvers | 1–3 endpoint references, unique resolved IPv4 DNS port53 TCP/UDP |
| acme.propagation_timeout_seconds | Optional integer 120–2100; omitted leaves adapter default |

Selected cloudflare_dns_token and proxmox_token roles remain required by the
current adapter; existing provider trust/API endpoint comes from its context.
Route-specific CAs derive from transport policies, not arbitrary runtime files.

## Zigbee2MQTT

Required `adapter` matches `[a-z][a-z0-9_-]{0,62}` and
`mqtt_base_topic` matches `[a-zA-Z0-9][a-zA-Z0-9/_-]{0,127}`.
Retained lifecycle, declared serial coordinator, broker connection and exact
adapter-owned settings are required. Fresh radio commissioning is unsupported.

## Bitwarden

Required `issuer: {protocol: http|https, domain: site_domain_id}`,
`database_name` matching `[A-Za-z0-9_]+`, positive integer `data_uid/data_gid`.
The app is retained-only, requires an owned HTTPS origin, MariaDB database
connection port3306 and file role runtime_environment.
Software supplies the normal declared image; local image IDs, authored environment
checksums and file locators are not properties. Closed runtime input version is
homelab-bitwarden-runtime-v2; old sealed v1 remains read-only history.

## PegaProx and WiNet

PegaProx requires `trusted_proxy: {app: id, interface: role}`: a Traefik physical
private IPv4 role distinct from its own web address, excluding unspecified,
loopback/link-local/multicast. Its file database_key remains selected.
The Pega backend web listener independently retains the private management-address floor.

WiNet requires `mqtt_prefix` matching
`[a-zA-Z0-9][a-zA-Z0-9/_-]{0,127}`.
Broker connection must be MQTT port1883 and inverter HTTPS IPv4 port443,
excluding unspecified/loopback/link-local/multicast. File role options retains
the exact closed vendor options/credential contract; arbitrary endpoints,
environment overrides and multiple inverters are unsupported.

## CloudBeaver

| Property | Type / constraint |
| --- | --- |
| server_name | Required single nonempty line ≤100 |
| recovery_admin | Required [a-z][a-z0-9_-]{2,63} |
| heap_mib | Required integer 256–16384 |
| auth_headers | Required object with user/team, distinct case-insensitive X- headers ≤63; forwarded-for/proto/host/port and real-ip reserved headers refuse |
| connections | Required named map, 1–24 roles matching resolved PostgreSQL/MariaDB connections |
| connections.<role>.name | Required single nonempty line ≤100 |
| connections.<role>.database | Required single line ≤128; empty allowed |
| connections.<role>.sslmode | disable/prefer/require; required only for unmanaged PostgreSQL, forbidden for managed connections/MariaDB |
| mariadb_jdbc | Library-owned only, required exactly when managed MariaDB exists |

At most 16 unmanaged and 8 managed connections, 24 total.
The current complete compiler path additionally requires **at least one managed
connection**: its account binder validates the nonempty owned administrator set.
Unmanaged metadata can accompany that set; an unmanaged-only configuration is
currently unsupported even though its property object validates structurally.
JDBC object has exactly version, sha256, image_filename: version 3.5.N
(N 11–999), lowercase 64-hex SHA256, filename matching that version's JAR or
the fixed image compatibility filename mariadb-java-client-3.5.10.jar.
The official Maven URL is derived. Instance properties cannot override this
software authority. The retired pgAdmin image is not an active property.

Cloud requires its owned HTTPS origin and selected OIDC contract; recovery admin,
workspace/custody, SQL/account/HOLD and private roles remain guarded.
Its final health rows also require the explicit `public` HTTPS connection to
IPv4 ingress port 443. Music Assistant has the same public-route floor, with
its physical web source. See [Connections](connections.md).

## Changes and validation

These are configuration values, not vendor commands or arbitrary Compose bags.
Public metadata can evolve when runtime validators and ownership permit.
Persistent data, selected role material, process identities and canonical origin
relationships remain protected. A property table does not promise that every
syntactically valid change can be applied online. Use
[Lifecycle](lifecycle.md), the library's selected profile page and the actual
native plan/service verification.

## Worked property objects

Each value below is a complete **effective properties object for the named
adapter**, not a whole app or a selection of every adapter at once. Put only the
chosen value under `apps.<id>.properties`, or let the library supply some direct
keys. Reference IDs must then resolve through the accompanying app/site.
These examples pass property validators; that is weaker than a supported complete
profile, native commissioning or working external services.

<!-- example: properties-adapters -->
```yaml
unbound: {publish_port: 5335}
pihole: {}
homeassistant: {mdns: {interface: web, startup: startup}}
node_red: {}
mqtt: {password_file: /mosquitto/config/passwords}
mqtt_explorer: {connection_name: Example broker}
music_assistant: {}
mariadb: {}
influxdb: {}
authentik:
  database: {name: example_identity, user: example_identity}
  smtp:
    host: mail.example.invalid
    port: 587
    use_tls: true
    use_ssl: false
    from: identity@example.invalid
    username: ""
    timeout: 30
zabbix: {database: {name: example_monitoring, user: example_monitoring}}
postgresql:
  client_access:
    - source: {app: client, interface: database}
      database: all
      user: all
      method: scram-sha-256
traefik:
  dashboard: false
  provider: {context: lab, token_id: reader@pve!discovery}
  acme: {email: ops@example.invalid, resolvers: [{external: dns}]}
zigbee2mqtt: {adapter: zstack, mqtt_base_topic: example/zigbee}
bitwarden:
  issuer: {protocol: https, domain: vault}
  database_name: example_vault
  data_uid: 1000
  data_gid: 1000
pegaprox: {trusted_proxy: {app: ingress, interface: web}}
winet: {mqtt_prefix: example/inverter}
cloudbeaver:
  server_name: Example database browser
  recovery_admin: recovery_admin
  heap_mib: 512
  auth_headers: {user: X-Example-User, team: X-Example-Team}
  connections:
    reporting: {name: Reporting, database: reports, sslmode: require}
```

The CloudBeaver `reporting` example is for an **unmanaged PostgreSQL** connection;
its matching connection and existing credential are required separately. A
managed connection omits `sslmode` and uses its owned account. Do not copy that
key into managed PostgreSQL or any MariaDB metadata. The `reporting` property
object alone is not a complete supported Cloud app: include at least one managed
DB connection/account and the public/OIDC/origin prerequisites above.
The Home Assistant mDNS
example needs retained supported storage/capability/runtime selections; MQTT
needs its file probe, and the retained-only apps above cannot be installed fresh
just because their property values validate.

For a practical change, increase CloudBeaver `heap_mib` to 768 and review the
selected container budget; changing the property does not allocate RAM for you.
**Invalid variations:** both SMTP TLS flags true, `data_uid: true`, a newline in
Explorer's connection name, or unknown `image_id` on Bitwarden all refuse at the
owning property boundary. Changes to actual credentials/data identities remain
subject to [private material continuity](identity-and-secrets.md#protected-material-continuity).

[Reference index](README.md) · [Apps](apps.md)
