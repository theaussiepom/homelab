# References and reuse

Keep one authority for a value, and bind it through the form defined for that type. Reference names are identifiers, not expressions. This guide builds on the [complete broker/browser/HTTPS composition](../examples/relationships/README.md), whose accompanying site, library and catalogue contain every required declaration. The blocks below explain selected relationships. They are fragments unless marked as complete typed leaves: separate source files containing a complete declaration and its type headers.

| Need | Form | Meaning |
| --- | --- | --- |
| App socket | `{app: broker, endpoint: backend_endpoint}` | Named profile endpoint of that instance |
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
  broker:
    source: connections/browser-broker.yaml
```

```yaml
schema: homelab-components-v1
kind: connection
consumer:
  app: browser
  connection: broker
target:
  app: broker
  endpoint: backend_endpoint
source_interface: broker_interface
hostname:
  domain: broker
account: client
```

This typed leaf uses the complete example's `browser` and `broker` apps, `client` account and `broker` domain. To try extraction, copy that whole example directory to a disposable directory, using its actual filesystem path rather than a symlink. The [tutorial](first-configuration.md) shows how to obtain that path. Move the complete `connections.broker` body into this leaf and reference it under the same `broker` key. Keeping the instance key preserves the relationship identity; the filename is an organizational choice. Only adding a permitted `readiness: start` or `configure` creates a dependency that controls order. For cross-guest traffic, both managed guests need matching explicit rules. Connections do not add rules. The compiler rejects the configuration if required access is missing.

## Reuse address facts

```yaml
address_groups:
  vpn:
    members:
    - 198.18.15.0/28
  clients:
    members:
      - network: primary
      - address_group: vpn
policies:
  middlewares:
    lan_only:
      type: ip-allow-list
      ranges:
        - address_group: clients
```

Here `primary` is the network declared in the complete relationship example. A network-policy fragment uses local roles such as `source: {address_group: clients}`; its guest binding maps `address_groups: {clients: clients}`. Compilation rejects missing or unused bindings. Expansion preserves order, enforces size limits and checks for cycles. A group expansion only yields values; an explicitly selected policy consumes them. Merely declaring the group creates neither an endpoint nor a permission.

Read [Sources](../reference/sources.md), [Connections](../reference/connections.md) and [Policies](../reference/policies.md) for complete shapes and invalid cases.

## Verify the combined result

Run the [complete composition command](../examples/relationships/README.md) in the selected locked environment. Its tests use the real compiler to resolve the managed broker account, outpost connection, origin owned by the app, selected middleware and explicit policy, then generate their deployment inputs. Add both `account` and `credential` to the same broker connection to check that the compiler rejects these mutually exclusive credential sources; restore the valid source after the experiment.

The result establishes source relationships. It does not create an account, authenticate to a broker or verify public TLS. For first installation use the profile's [support boundary](../reference/support.md) and [preparation](prepare-deployment.md); for later changes preserve ownership of accounts and protected inputs and [verify the actual service](../operations/verify-and-maintain.md).

[Configuration model](../concepts.md) · [Reference index](../reference/README.md)
