# Site

A site declares concrete allocations and relationships. The library supplies
profiles and templates, but never a fixed guest inventory.

```yaml
schema: homelab-components-v1
kind: site
contexts: {}
networks: {}
storage: {}
guests: {}
apps: {}
```

This shows the required sections, not a deployable installation.
The [tutorial](../guides/first-configuration.md) supplies complete useful values.

## Minimal useful worked site

The following is a complete synthetic site for the [tutorial library](../examples/first-configuration/stack.json)
(and its adjacent images.json). It compiles offline without any target or private
input read. It is deliberately not deployment-admissible. The library is a
prerequisite: `base` and `recursive` are actual definitions, not magic defaults.

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

For a practical extension, put `apps.recursive_a` in the complete typed leaf shown
on [Sources](sources.md#worked-extraction-without-an-overlay). The effective app
and graph remain the same. **Invalid variation:** change its guest to an unknown
ID; parsing succeeds but real reference resolution refuses.

## Properties

Each named map contains at most 1024 entries. IDs match
`[a-z][a-z0-9_-]{0,62}`. References use those keys. Lists and maps must have the
documented type; null does not stand for an empty map.

| Property | Type / required / default | Meaning and constraints |
| --- | --- | --- |
| schema | String, required | Exactly `homelab-components-v1` |
| kind | String, required | Exactly `site` |
| contexts | Named map, required | [Contexts](contexts.md) |
| networks | Named map, required | [Networks](networks.md) |
| storage | Named map, required | Context/pool [storage declarations](storage.md) |
| guests | Named map, required | Complete inline [guest](guests.md) or `{source: path}` |
| apps | Named map, required | Complete inline [app](apps.md) or `{source: path}` |
| connections | Named map, optional, {} | Complete [connection](connections.md) or typed source |
| exposures | Named map, optional, {} | Complete [exposure](exposures.md) or typed source |
| domains | Named map of host strings, optional, {} | Valid DNS labels, total length 1–253; no URL/path |
| external_endpoints | Named map, optional, {} | Protocol/address/port [endpoints](networks.md#external-endpoints) |
| host_aliases | Named map, optional, {} | Docker-local `{hostname: text}`; underscores allowed in labels |
| address_groups | Named map, optional, {} | Bounded ordered [address groups](networks.md#address-groups) |
| secret_sources | Named map, optional, {} | [File/environment/generated metadata](identity-and-secrets.md#secret-sources), never secret values |
| accounts | Named map, optional, {} | [Create-once account declarations](connections.md#accounts) |
| identity_providers | Named map, optional, {} | [OIDC/SAML declarations](identity-and-secrets.md#identity-providers) |
| devices | Named map, optional, {} | [Serial declarations](supporting-types.md#devices) |
| images | Named map, optional, {} | Only declared custom archive replacement bindings; normal image versions belong to library software |
| evidence | Named map, optional, {} | Ongoing callback records or raw UTF-8 [evidence](supporting-types.md#evidence-and-assets) |
| policies | Closed map, optional | Submaps `network/transport/tls/middlewares/authentication`, each defaults {} |
| zabbix | Optional null or `{server: app_id}` | Absent disables root monitoring expansion; [Zabbix](zabbix.md) |

Unknown fields, former fixed-bundle configuration and authored migration
admissions refuse. Library and site policy names may not collide: the site
adds named policies, not overrides. A source reference does not recursively
merge sections.

## Resolution and changes

The compiler validates every declared component, including disabled guests.
It resolves values, then exposure/auth/connection bindings, ordered policies,
software budgets, owned files, monitoring and required traffic.
Disabled selection changes execution, not source validity.

Guest/app keys and persistent identities should remain stable. Changing a
domain, value or display name still produces a new source snapshot and must pass
normal continuity. Removing an app does not authorize deleting its data or
unselected containers. See [Lifecycle](lifecycle.md).

[Reference index](README.md) · [Library](library.md) · [Sources](sources.md)

## PBS client preparation

Optional root [`backup`](backup.md) is enabled by presence. Null/empty selects the only registered backup profile; `{profile: id}` selects it explicitly. It prepares clients and coverage without creating a server or backup schedule.
