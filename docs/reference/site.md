# Site

Your site declares the guests, apps, allocations and relationships you want. The library supplies reusable profiles and templates; you choose the guests that use them.

```yaml
schema: homelab-components-v1
kind: site
contexts: {}
networks: {}
storage: {}
guests: {}
apps: {}
```

This shows the required sections, not a deployable installation. The [tutorial](../guides/first-configuration.md) supplies complete useful values.

## Minimal useful worked site

The following complete synthetic site uses the [tutorial library](../examples/first-configuration/stack.json) and its adjacent images.json. It compiles offline without contacting a target or reading private inputs, and deliberately fails deployment admission. You need the library because it defines `base` and `recursive`; those names are not built-in defaults.

<!-- example: site-worked -->
```yaml
schema: homelab-components-v1
kind: site
contexts:
  lab:
    backend: proxmox-lxc
    node: example-node
    api_endpoint: {external: api}
    trust: {ca_file: /example/ca.pem, known_hosts: /example/known_hosts}
    credentials: {api_token: token, ssh_private_key: ssh}
    paths: {state_root: /example/state, backup_directory: /example/backup/data, backup_mount: /example/backup, backup_source: "example:/backup"}
    protected_guests: [9900]
    ssh_public_keys: []
    dns_servers: [{external: dns}]
secret_sources:
  token: {type: file, path: /never-read/token}
  ssh: {type: file, path: /never-read/ssh}
external_endpoints:
  api: {protocol: https, address: 192.0.2.10, port: 8006}
  dns: {protocol: udp, address: 198.18.21.53, port: 53}
networks:
  primary: {context: lab, cidr: 198.18.20.0/24, bridge: example0, vlan: null, gateway: 198.18.20.1}
storage:
  local: {context: lab, pool: example-local}
guests:
  resolver:
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
apps:
  recursive_a:
    profile: recursive
    guest: resolver
    lifecycle: fresh
    interfaces:
      private: {scope: app-network, network: default}
      local: {scope: guest-loopback}
```

To split the configuration into files, move `apps.recursive_a` into the complete typed source shown on [Sources](sources.md#worked-extraction-without-an-overlay). The resulting app and dependency graph stay the same. **Invalid variation:** change its guest to an unknown ID. Parsing succeeds, but reference resolution rejects the unknown guest.

## Properties

Each named map contains at most 1024 entries. IDs match `[a-z][a-z0-9_-]{0,62}`. References use those keys. Lists and maps must have the documented type; null does not stand for an empty map.

| Property | Type / required / default | Meaning and constraints |
| --- | --- | --- |
| <a id="site-schema"></a>`schema` | String, required | Exactly `homelab-components-v1` |
| <a id="site-kind"></a>`kind` | String, required | Exactly `site` |
| <a id="site-contexts"></a>`contexts` | Named map, required | [Contexts](contexts.md) |
| <a id="site-networks"></a>`networks` | Named map, required | [Networks](networks.md) |
| <a id="site-storage"></a>`storage` | Named map, required | Context/pool [storage declarations](storage.md) |
| <a id="site-guests"></a>`guests` | Named map, required | Complete inline [guest](guests.md) or `{source: path}` |
| <a id="site-apps"></a>`apps` | Named map, required | Complete inline [app](apps.md) or `{source: path}` |
| <a id="site-connections"></a>`connections` | Named map, optional, {} | Complete [connection](connections.md) or typed source |
| <a id="site-exposures"></a>`exposures` | Named map, optional, {} | Complete [exposure](exposures.md) or typed source |
| <a id="site-domains"></a>`domains` | Named map of host strings, optional, {} | Valid DNS labels, total length 1–253; no URL/path |
| <a id="site-external-endpoints"></a>`external_endpoints` | Named map, optional, {} | Protocol/address/port [endpoints](networks.md#external-endpoints) |
| <a id="site-host-aliases"></a>`host_aliases` | Named map, optional, {} | Docker-local `{hostname: text}`; underscores allowed in labels |
| <a id="site-address-groups"></a>`address_groups` | Named map, optional, {} | Bounded ordered [address groups](networks.md#address-groups) |
| <a id="site-secret-sources"></a>`secret_sources` | Named map, optional, {} | [File/environment/generated metadata](identity-and-secrets.md#secret-sources), never secret values |
| <a id="site-accounts"></a>`accounts` | Named map, optional, {} | [Create-once account declarations](connections.md#accounts) |
| <a id="site-identity-providers"></a>`identity_providers` | Named map, optional, {} | [OIDC/SAML declarations](identity-and-secrets.md#identity-providers) |
| <a id="site-devices"></a>`devices` | Named map, optional, {} | [Serial declarations](supporting-types.md#devices) |
| <a id="site-images"></a>`images` | Named map, optional, {} | Only declared custom archive replacement bindings; normal image versions belong to library software |
| <a id="site-evidence"></a>`evidence` | Named map, optional, {} | Ongoing callback records or raw UTF-8 [evidence](supporting-types.md#evidence-and-assets) |
| <a id="site-policies"></a>`policies` | Closed map, optional | Submaps `network/transport/tls/middlewares/authentication`, each defaults {} |
| <a id="site-backup"></a>`backup` | Optional null or closed object | Defines [shared PBS settings](backup.md); guests enroll individually. Add management/recovery inputs and `job` for the coordinated schedule. |
| <a id="site-zabbix"></a>`zabbix` | Optional null or `{server: app_id}` | Absent disables root monitoring expansion; [Zabbix](zabbix.md) |

Validation rejects unknown fields, the former fixed-bundle configuration and migration exceptions written into configuration. Library and site policy names must not collide; your site can add policies but cannot override library policies. A source reference loads a complete declaration without recursively merging sections.

## First installation

A complete site describes your desired allocations and relationships. Passing configuration checks does not establish target trust, available capacity, prepared credentials or files, or support for commissioning a service. After the offline checks, follow [preparation](../guides/prepare-deployment.md) and check [support for each selected adapter](support.md).

<a id="resolution-and-changes"></a>
## Resolution and later deployments

The compiler validates every declared component, including disabled guests. It resolves values first, then checks exposures, authentication and connections, ordered policies, software budgets, managed files, monitoring, backup coverage and required traffic. Disabling a guest excludes it from ordinary deployment but does not exempt it from configuration checks.

Keep guest and app keys and persistent identities stable. Even a change to a domain, value or display name produces a new configuration snapshot and must pass the normal ownership checks. Removing an app declaration does not authorise deletion of its data or unselected containers. See [Lifecycle](lifecycle.md).

## PBS client preparation

Enable the root [`backup`](backup.md) feature by adding the property. Null or an empty object selects the sole registered backup profile; `{profile: id}` selects one explicitly. Only guests with their own [`backup:` marker](backup.md#backup-guest) receive client software and recovery coverage. Optional [`backup.defaults`](backup.md#binding-defaults-and-guest-overrides) supplies interface/staging identifiers to enrolled guests; guest fields override them. Add the closed [`backup.job`](backup.md#operational-job) object and its management/recovery inputs for a coordinated encrypted backup schedule. Its membership includes exactly the enrolled guests, even when deployment to an enrolled guest is disabled. Complete [backup setup](../backup/README.md) before deployment.

[Reference index](README.md) · [Library](library.md) · [Sources](sources.md)
