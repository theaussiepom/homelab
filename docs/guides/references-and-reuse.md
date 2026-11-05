# References and reuse

Keep one authority for a value, and bind it through the appropriate typed form.
Reference names are identifiers, not expressions.

| Need | Form | Meaning |
| --- | --- | --- |
| App socket | `{app: broker, endpoint: backend}` | Named profile endpoint of that instance |
| Unmanaged socket | `{external: directory}` | Declared external endpoint |
| Same address, different protocol/port | External `address: {external: other}` | Reuses address only |
| Guest NIC | App role `{interface: backend}` | This guest's physical interface |
| App-local network | `{scope: app-network, network: default}` | Adapter-owned network role |
| Loopback | `{scope: guest-loopback}` | Same guest's 127.0.0.1 |
| Public URL | App `origin: {exposure: ui}` | Selected exposure and optional declared alias domain |
| Connection hostname | `{domain: broker}`, `{alias: local_broker}` or `{exposure: ui}` | Typed DNS/Docker/origin name |
| Persistent mount | `{volume: data, subpath: ""}` or `{root_path: data, subpath: app}` | Existing guest storage role |
| Public file | `{asset: vendor_key}` | Hash-pinned library raw UTF-8 asset |
| Secret | App role maps to a `secret_sources` ID | Private source metadata, never a public value |
| Managed account | Connection `account: browser_db` | Separately owned create-once account |
| Ordered address values | `{address_group: clients}` | Expands values in place, preserving duplicates |

## Link a consumer

A connection is a complete relationship, inline or in a typed file:

```yaml
connections:
  browser_broker: {source: connections/browser-broker.yaml}
```

```yaml
schema: homelab-components-v1
kind: connection
consumer: {app: browser, connection: broker}
target: {app: broker, endpoint: backend}
source_interface: broker
hostname: {domain: broker}
account: browser_account
```

This fragment assumes those apps, profile roles, account and domain exist.
Only adding a permitted `readiness: start` or `configure` creates an ordering edge.
For cross-guest traffic, both managed guests need matching explicit rules.
Connections do not add rules. Missing access refuses compilation.

## Reuse address facts

```yaml
address_groups:
  vpn: {members: [198.18.15.0/28]}
  clients:
    members:
      - {network: home}
      - {address_group: vpn}
policies:
  middlewares:
    lan_only:
      type: ip-allow-list
      ranges: [{address_group: clients}]
```

Here `home` is a real declared network. A network-policy fragment uses local
roles such as `source: {address_group: clients}`; its guest binding maps
`address_groups: {clients: clients}`. Missing and unused bindings refuse.
Expansion is ordered, bounded and cycle-checked. It neither creates endpoints
nor changes firewall policy.

Read [Sources](../reference/sources.md), [Connections](../reference/connections.md)
and [Policies](../reference/policies.md) for complete shapes and invalid cases.
