# Policies

Both a library and a site can declare named policies under `network`, `transport`, `tls`, `middlewares` and `authentication`. These maps are optional and default to {}. A policy of the same kind and name cannot appear in both places. You may put a complete policy in a [typed source file](sources.md), but cannot use it to override another policy.

## Network rules

A network policy has exactly the form `{rules: [...]}` and accepts at most 4096 authored rules. Rules retain their declared order. Each requires `direction`, `proto` and `comment`.

| Field | Type / default | Constraint |
| --- | --- | --- |
| direction | Required enum | `in` or `out` |
| proto | Required enum | `tcp`, `udp`, `icmp`, `icmpv6`, `igmp` |
| comment | Required text | Nonempty, at most 4096 characters |
| port | Optional string, null or reference | TCP/UDP: ports/ranges 1–65535 in ascending colon syntax, or `{endpoint: local_role}`. ICMP/ICMPv6: one decimal type 0–255. IGMP: omitted or null |
| source / destination | Optional address value | IPv4 or IPv6 address/CIDR literal, or one of `{interface: role}`, `{network: role}`, `{endpoint: role}`, `{address_group: role}` |
| interface | Optional role ID | Binds a declared guest NIC to provider iface `netN` |

The resolved source and destination must use the same address family. `icmp` and `igmp` support IPv4 only; `icmpv6` supports IPv6 only. Scoped literals such as `fe80::1%eth0` are rejected; select the physical interface through its role instead. Unrestricted inbound rules with `source: 0.0.0.0/0` or `source: ::/0` are also rejected. The provider receives explicit ACCEPT rules. The configuration has no deny rules, priorities or template commands. Policy address literals do not allocate IPv6 addresses, enable filtering globally, join multicast groups or add routes. Networks, NICs and endpoint references still use their documented IPv4 allocation rules; IPv6 literals can describe policy for a separately managed link.

## Bindings

Guest `network_policy` is an ordered list of policy IDs or objects with required `policy` and optional maps `interfaces`, `networks`, `endpoints`, `address_groups`. Map keys are policy-local roles.

- Interfaces map to a guest NIC ID or `{app: id, interface: role}` for a physical app role. A remote app role may supply an address value, not a local NIC selector.
- Networks map to site network IDs.
- Endpoints map to ordinary endpoint references.
- Address groups map to site group IDs.

Bind every local role used by the policy and omit unused bindings. When expanding source and destination groups, the compiler processes each source in turn and emits its destinations in order. It checks the total row limit before allocating the expanded rows. Connections do not fill in missing policy rules. Required traffic is checked against both managed guests' policies.

For example, this complete policy permits only an IPv6 MLDv2 membership report on a separately bound interface. PVE carries the ICMP type in its existing destination-port field; it is not a UDP port. Bind `link` to the actual local guest NIC. Select groups, query/report compatibility and discovery replies according to that link's declared policy; this row alone is not a complete multicast policy.

```yaml
rules:
  - direction: out
    proto: icmpv6
    source: fe80::/64
    destination: ff02::16/128
    port: '143'
    interface: link
    comment: IPv6 multicast membership report on selected link
```

Changing the destination to `224.0.0.22/32` is rejected because it mixes address families. IPv4 IGMP membership uses `proto: igmp` without `port`. mDNS/SSDP discovery and unicast replies need separate UDP permissions. A rule accepting a multicast destination does not allow arbitrary unicast responses.

## TLS and backend transport

A TLS policy requires `type: acme` and `resolver: identifier`. The current Traefik route adapter requires `letsencrypt` as the resolver.

A transport policy requires `type: tls` and at least one of `context` or `server_name`. The context supplies its trusted CA path. `server_name` must have the form `{domain: site_domain_id}`. An HTTPS exposure can use this policy to verify its backend, independently of public TLS. The compiler does not convert an HTTP backend to HTTPS.

## Middlewares

| type | Required additional fields | Behavior |
| --- | --- | --- |
| default-headers | None | Fixed adapter-owned response headers |
| forward-auth | endpoint | HTTP/HTTPS endpoint reference to the existing authentication service |
| ip-allow-list | ranges | Nonempty ordered IPv4/CIDR, `{network: id}` or `{address_group: id}` list; final maximum 4096 values |
| canonical-home-redirect | app | Existing app with canonical origin; only a separate alias route with exactly canonical middleware list plus this final middleware |

The redirect policy redirects to the canonical root; it does not accept arbitrary regular expressions. It cannot be attached to the canonical route itself. The redirect and canonical routes must use the same target and ingress, with no shared hostnames. Arbitrary Traefik or Compose middleware options are not accepted.

## Authentication policies

| type | Required fields | Constraints |
| --- | --- | --- |
| cloudbeaver-oidc | provider, client_id, client_secret, display_name, user_claim | OIDC provider; secret-source ID; claim sub/preferred_username/email |
| node-red-retained-oidc | provider, client_id | Matching retained-node-red-oidc provider, no nonstandard origin port |
| zabbix-saml | provider, default_login | SAML provider; default_login zabbix or saml |

Client IDs must be nonempty text of at most 256 characters with no CR/LF; the Cloud display name has the same limits. Each policy applies only to its matching adapter and an HTTPS origin belonging to that app. A profile may require a particular authentication type. See [providers and secret sources](identity-and-secrets.md) for the nested fields.

Changing policy values changes the requested configuration or access rules. It does not authorise execution or bypass an existing HOLD. After an authorised deployment, verify public TLS, backend trust, authentication and reachability separately.

## Worked rule, binding and route middleware

The complete [relationship composition](../examples/relationships/README.md) shows explicit endpoint-bound access and a selected `office_only` middleware in its actual [site.yaml](../examples/relationships/site.yaml). The minimal rule below can instead be added to the first tutorial's existing guest/context.

This is a complete network-policy value. The guest binds the local role `service` to one endpoint, which supplies both the target address and port.

<!-- example: policy-network -->
```yaml
rules:
  - direction: out
    proto: tcp
    destination: {endpoint: service}
    port: {endpoint: service}
    comment: Selected HTTPS service
```

Select it as `policies.network.selected_service`, then bind it on a guest:

<!-- example: policy-binding -->
```yaml
policy: selected_service
endpoints:
  service: {external: api}
```

This deliberately requests access to the declared endpoint; merely referencing it in an app does not add this rule. For an HTTP client allowlist, a complete middleware value uses a **list**, including when it selects one group:

<!-- example: policy-middleware -->
```yaml
type: ip-allow-list
ranges: [{address_group: clients}]
```

Declare `clients` in the site and select the named middleware on an exposure for it to affect that route. **Invalid variation:** `ranges: {address_group: clients}` is rejected because it is a map rather than the required list. A missing endpoint binding or an unused extra binding is also rejected. Valid policy changes describe the requested access and configuration; they do not prove that the firewall, TLS endpoint or login flow works.

The backend may combine adjacent TCP/UDP rules when their only difference is literal destination addresses in the same address family. Each provider row contains at most eight destinations and 512 ASCII bytes. Other fields and the logical order remain unchanged. This limits provider API work without changing the declared rules or adding resources. ICMP, ICMPv6 and IGMP rows remain separate.

[Reference index](README.md) · [Connections](connections.md) · [Exposures](exposures.md)
