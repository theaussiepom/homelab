# Application properties

Set library defaults in `app_profiles.<id>.properties` and override them in `apps.<id>.properties`. The compiler merges these objects by direct key, then checks the result against the selected adapter's fields below. An omitted optional property has no effect unless its reference states a default. Unknown properties are rejected.

## Network and home adapters

| Adapter | Fields and constraints |
| --- | --- |
| unbound | Optional publish_port is an integer 1–65535; the published guest-loopback port defaults to 5335. |
| pihole | Accepts an empty object only. Exposures supply managed DNS records, and one explicit DNS upstream connection is required. |
| homeassistant | Optional mdns requires interface and startup IDs. It needs a physical interface, a selected read-only /startup storage role, retained lifecycle and exactly the NET_ADMIN runtime capability. |
| node_red | Accepts an empty object only. Runtime and authentication selections determine the settings wrapper. |
| mqtt | password_file is optional and must match /mosquitto/config/[A-Za-z0-9_.-]{1,100}, excluding the . and .. filenames. It is required when serving a managed MQTT Explorer account. |
| mqtt_explorer | connection_name is required: one nonempty line of at most 100 characters. Broker and outpost connections and the app's own HTTPS origin are also required. |
| music_assistant | Empty object only |
| scrypted | Empty object only; decoder and NAS admission are fixed adapter checks |
| mariadb / influxdb | Empty object only |

## Authentik and Zabbix

Both adapters require `database: {name: sql_id, user: sql_id}`. Each SQL ID must match `[a-z][a-z0-9_]{0,62}` and cannot be postgres, template0 or template1. The database connection must use PostgreSQL on port 5432.

Authentik additionally accepts:

- `smtp`: `host` and `from` are required, each a single nonempty line of at most 253 characters. `port` is required and must be 1–65535. The required `use_tls` and `use_ssl` fields must be Booleans and cannot both be true. `username` is required and must be a single line of at most 256 characters; it may be empty. Optional `timeout` must be an integer from 1 through 300.
- `callbacks: {evidence: id}`: selects existing identity-callbacks evidence that identifies the provider and application metadata and the exact callback additions. It does not provision an IdP generally.

Zabbix accepts no other properties. Configuration checks allow a selected `database_password` role when root monitoring is absent, but ordinary deployment does not support that configuration. App preparation currently requires the credential owned by root monitoring and its exact monitoring files, with no selected scalar password. Root monitoring generates and owns the credential, and rejects a duplicate selected role.

## PostgreSQL

The optional `client_access` list preserves order, defaults to [] and accepts at most 128 entries. Each entry requires `source: {app: id, interface: role}`, `database: all`, `user: all` and `method: scram-sha-256`. The selected source must provide a unique physical IPv4 address that is neither loopback nor link-local. These fields do not accept arbitrary HBA lines. Deployment also checks the actual listeners, account identities and existing data.

## Traefik

| Field | Shape / default / constraints |
| --- | --- |
| dashboard | Optional Boolean; defaults to false |
| provider | Optional in structural validation but required by the current rendered adapter. Requires context ID and token_id. |
| provider.token_id | Non-whitespace realm-qualified identity with one ! suffix, e.g. synthetic reader@pve!discovery |
| provider.discovery | Optional object accepting only local_directory, mirror_directory, owner_sha256 and guests |
| discovery directories | Distinct canonical absolute paths ending in /service-discovery |
| discovery.owner_sha256 | Lowercase 64-hex owner digest |
| discovery.guests | 1–32 unique guest IDs from the same context; the compiler substitutes their VMIDs |
| acme | Optional in structural validation but required by the current adapter. Requires email and resolvers. |
| acme.email | Non-whitespace email with one @ and dotted domain |
| acme.resolvers | 1–3 endpoint references that resolve to unique IPv4 DNS sockets on port 53 using TCP/UDP |
| acme.propagation_timeout_seconds | Optional integer 120–2100; omission preserves the adapter default |

The current adapter requires the selected `cloudflare_dns_token` and `proxmox_token` roles; a route selecting `cloudflare-source` middleware also requires `cloudflare_origin_token`. Use the canonical [private-role inventory](identity-and-secrets.md#adapter-private-roles) and [Cloudflare boundary requirements](policies.md#cloudflare-source-boundary) when selecting those inputs. It obtains provider trust and the API endpoint from its context, and route-specific CAs from transport policies. You cannot supply those CAs through arbitrary runtime files.

## Zigbee2MQTT

The required `adapter` must match `[a-z][a-z0-9_-]{0,62}`, and the required `mqtt_base_topic` must match `[a-zA-Z0-9][a-zA-Z0-9/_-]{0,127}`. The app also requires retained lifecycle, a declared serial coordinator, a broker connection and the exact settings owned by the adapter. Commissioning a new radio is unsupported.

| Property | Presence / default | Effect |
| --- | --- | --- |
| `watchdog` | Optional string; only `default` is accepted. Omission leaves the environment variable unset. Null, Booleans and custom delays are rejected. | Sets `Z2M_WATCHDOG=default` on the owned Zigbee2MQTT container. |

The [upstream watchdog](https://www.zigbee2mqtt.io/guide/installation/15_watchdog.html) retries recognized soft failures internally after 1, 5, 15, 30 and 60 minutes, then exits after repeated failed recovery. It requires an initial successful start and respects deliberate stops and configuration errors. Enabling it through protected CD can recreate the service; it preserves the image, coordinator, network identity, data and MQTT settings. It does not commission a radio or establish that an underlying serial fault is fixed.

## Bitwarden

Bitwarden requires `issuer: {protocol: http|https, domain: site_domain_id}`, a `database_name` matching `[A-Za-z0-9_]+`, and positive integers for `data_uid/data_gid`. It supports retained lifecycle only and requires an owned HTTPS origin, a MariaDB connection on port 3306 and the file role runtime_environment. Select its image through software declarations; local image IDs, environment checksums and file locators are not accepted properties. Runtime input must follow the exact homelab-bitwarden-runtime-v2 format. Previously sealed v1 input remains read-only history.

## PegaProx and WiNet

PegaProx requires `trusted_proxy: {app: id, interface: role}`. That reference must select a Traefik role with a physical private IPv4 address different from the PegaProx web address. Unspecified, loopback, link-local and multicast addresses are rejected. The database_key file must still be selected. The Pega backend web listener also requires a private management address.

WiNet requires `mqtt_prefix` matching `[a-zA-Z0-9][a-zA-Z0-9/_-]{0,127}`. Its broker connection must use MQTT on port 1883, and its inverter connection must use HTTPS with an IPv4 address on port 443. Unspecified, loopback, link-local and multicast addresses are rejected. The options file must follow the exact vendor options and credential format. Arbitrary endpoints, environment overrides and multiple inverters are unsupported.

## CloudBeaver

| Property | Type / constraint |
| --- | --- |
| server_name | Required single nonempty line ≤100 |
| recovery_admin | Required `[a-z][a-z0-9_-]{2,63}` |
| heap_mib | Required integer 256–16384 |
| auth_headers | Required object containing user/team. Header names must start with X-, be at most 63 characters and differ when compared without case. Reserved forwarded-for/proto/host/port and real-ip headers are rejected. |
| connections | Required named map of 1–24 roles, matching resolved PostgreSQL/MariaDB connections |
| connections.<role>.name | Required single nonempty line ≤100 |
| connections.<role>.database | Required single line ≤128; empty allowed |
| connections.<role>.sslmode | disable/prefer/require. Required for unmanaged PostgreSQL; forbidden for managed connections and MariaDB. |
| mariadb_jdbc | Selected only by the library. Required when managed MariaDB exists and forbidden otherwise. |

CloudBeaver accepts at most 16 unmanaged and 8 managed connections, with a total limit of 24. Compiling the complete configuration also requires **at least one managed connection**, because account binding requires a nonempty set of managed administrators. Unmanaged connections may accompany that set. An unmanaged-only properties object can pass structural validation but is not a supported complete configuration.

The JDBC object contains exactly version, sha256 and image_filename. The version must be 3.5.N, where N is 11–999. SHA256 must contain 64 lowercase hexadecimal characters. The filename must match that version's JAR or the fixed compatibility filename mariadb-java-client-3.5.10.jar. The compiler derives the official Maven URL. The library controls this software selection; app properties cannot override it. The retired pgAdmin image is not an active property.

CloudBeaver requires an HTTPS origin it owns and a selected OIDC configuration. Deployment checks protect its recovery administrator, workspace and private files, SQL accounts, HOLDs and private roles. Its generated health checks also require an explicit `public` HTTPS connection to IPv4 ingress port 443. See [Connections](connections.md) for the shared connection fields.

## Music Assistant

Music Assistant requires an explicit `public` HTTPS connection to IPv4 ingress port 443 and an HTTPS origin it owns. Its HTTPS probe binds the connection’s resolved source address, which must belong to a declared app interface role; this can differ from the local web and player addresses. Local web and stream probes still check their own listeners. The separate `health.source_interface` restriction still selects the web role for the local health check; it does not override the public connection’s source. See [connection source selection](connections.md#connection-source-interface).

## Optional listener selections

Pi-hole profiles can opt into a separate `web_interface` role with an interface-bound host `web_listener` on TCP 80 and `web_endpoint` through that role. The runtime derives `FTLCONF_webserver_port` from the resolved address and verifies the selected socket, rejecting wildcard or other-address web binds. DNS listeners, upstreams, data, image and authentication remain unchanged. The ordinary profile without this role retains its existing environment and behavior. The [Pi-hole FTL reference](https://docs.pi-hole.net/ftldns/configfile/#port) documents the address-and-port setting; a declared endpoint alone does not rebind FTL.

A retained Home Assistant profile can explicitly declare `web_interface` and `transition_web_interface`, each with its corresponding interface-bound host TCP 8123 listener and endpoint. This opt-in dual-web check requires both distinct declared IPv4 sockets plus `127.0.0.1`; it permits optional `::1` and rejects wildcard or additional addresses. Its ordinary loopback HTTP/API probe remains unchanged. Prepare the matching HTTP settings through the supported configuration path before deployment: declaring listeners does not rewrite Home Assistant configuration, environment, data or authentication. Existing single-web profiles and other apps retain their original checks.

## Changes and validation

Use these fields to configure the adapter; they do not accept vendor commands or arbitrary Compose options. Runtime validation and ownership checks determine which public metadata may change while protecting persistent data, private files and credentials, process identities and public origins. A valid property value does not guarantee that a change can be applied without interruption. Review [Lifecycle](lifecycle.md), the selected library profile and the actual deployment plan, then verify the service result.

## Worked property objects

Each value below is a complete **effective properties object for the named adapter**. Choose the one for your adapter and put it under `apps.<id>.properties`, or let the library supply some direct keys. The surrounding app and site must declare the referenced IDs. These examples pass property validation; they are not whole apps and do not establish support for a complete profile, target commissioning or working external services.

<!-- example: properties-adapters -->
```yaml
unbound:
  publish_port: 5335
pihole: {}
homeassistant:
  mdns:
    interface: web_interface
    startup: startup
node_red: {}
mqtt:
  password_file: /mosquitto/config/passwords
mqtt_explorer:
  connection_name: Example broker
music_assistant: {}
scrypted: {}
mariadb: {}
influxdb: {}
authentik:
  database:
    name: example_identity
    user: example_identity
  smtp:
    host: mail.example.invalid
    port: 587
    use_tls: true
    use_ssl: false
    from: identity@example.invalid
    username: ""
    timeout: 30
zabbix:
  database:
    name: example_monitoring
    user: example_monitoring
postgresql:
  client_access:
    - source:
        app: client
        interface: database_interface
      database: all
      user: all
      method: scram-sha-256
traefik:
  dashboard: false
  provider:
    context: lab
    token_id: reader@pve!discovery
  acme:
    email: ops@example.invalid
    resolvers:
    - external: dns
zigbee2mqtt:
  adapter: zstack
  mqtt_base_topic: example/zigbee
  watchdog: default
bitwarden:
  issuer:
    protocol: https
    domain: vault
  database_name: example_vault
  data_uid: 1000
  data_gid: 1000
pegaprox:
  trusted_proxy:
    app: ingress
    interface: web_interface
winet:
  mqtt_prefix: example/inverter
cloudbeaver:
  server_name: Example database browser
  recovery_admin: recovery_admin
  heap_mib: 512
  auth_headers:
    user: X-Example-User
    team: X-Example-Team
  connections:
    reporting:
      name: Reporting
      database: reports
      sslmode: require
```

The CloudBeaver `reporting` example describes an **unmanaged PostgreSQL** connection. Declare its connection and existing credential separately. A managed connection omits `sslmode` and uses its managed account, so do not copy that key into managed PostgreSQL or any MariaDB metadata. To complete a supported CloudBeaver app, include at least one managed database connection and account, plus the public connection, OIDC and origin prerequisites above.

The Home Assistant mDNS example requires retained lifecycle and its supported storage, capabilities and runtime selections. MQTT requires its probe file. Passing property validation does not add first-installation support to any of the retained-only apps above.

For a practical change, increase CloudBeaver `heap_mib` to 768 and review the selected container budget; changing the property does not allocate RAM for you. **Invalid variations:** property validation rejects setting both SMTP TLS flags to true, `data_uid: true`, a newline in MQTT Explorer's connection name, or an unknown `image_id` on Bitwarden. Changes to credentials and data identities remain subject to the [rules protecting private inputs](identity-and-secrets.md#protected-material-continuity).

[Reference index](README.md) · [Apps](apps.md)
