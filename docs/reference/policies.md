# Policies

Library and site `policies` each contain optional named submaps:
`network`, `transport`, `tls`, `middlewares`, `authentication`.
Missing submaps default {}. The same kind/name cannot occur in both owners.
Policies may use complete [typed files](sources.md); they are not overrides.

## Network rules

A network policy is exactly `{rules: [...]}`, at most 4096 authored rules.
Rows keep declared order and require `direction`, `proto`, `comment`.

| Field | Type / default | Constraint |
| --- | --- | --- |
| direction | Required enum | `in` or `out` |
| proto | Required enum | `tcp`, `udp`, `icmp`, `icmpv6`, `igmp` |
| comment | Required text | Nonempty, at most 4096 characters |
| port | Optional string, null or reference | TCP/UDP: ports/ranges 1–65535 in ascending colon syntax, or `{endpoint: local_role}`. ICMP/ICMPv6: one decimal type 0–255. IGMP: omitted or null |
| source / destination | Optional address value | IPv4 or IPv6 address/CIDR literal, or one of `{interface: role}`, `{network: role}`, `{endpoint: role}`, `{address_group: role}` |
| interface | Optional role ID | Binds a declared guest NIC to provider iface `netN` |

Resolved source and destination must have the same address family. `icmp` and
`igmp` are IPv4-only; `icmpv6` is IPv6-only. A scoped literal such as
`fe80::1%eth0` refuses: select the physical interface through its role instead.
Inbound unrestricted `source: 0.0.0.0/0` or `source: ::/0` refuses.
The current provider receives explicit ACCEPT rows; there is no authored deny/
priority/template-command language. Policy literals do not allocate an IPv6
address, enable filtering globally, join a multicast group or add a route.
Network, NIC and endpoint reference allocation retains its existing IPv4
contract; literal IPv6 policy values can describe a separately managed link.

## Bindings

Guest `network_policy` is an ordered list of policy IDs or objects with required
`policy` and optional maps `interfaces`, `networks`, `endpoints`,
`address_groups`. Map keys are policy-local roles.

- Interfaces map to a guest NIC ID or `{app: id, interface: role}` for a physical
  app role. A remote app role may supply an address value, not a local NIC selector.
- Networks map to site network IDs.
- Endpoints map to ordinary endpoint references.
- Address groups map to site group IDs.

All used local roles must be bound and no unused binding is accepted.
Group source/destination expansion is source-outer, destination-inner, with the
total row bound checked before allocation. A policy does not derive missing
access from a connection. Required traffic validates both managed sides.

For example, this complete policy permits only an IPv6 MLDv2 membership report
on a separately bound interface. PVE carries the ICMP type in its existing
destination-port field; it is not a UDP port. Bind `link` to the actual local
guest NIC. Select groups, query/report compatibility and discovery replies
according to that link's declared policy; this row alone is not a complete
multicast policy.

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

Changing the destination to `224.0.0.22/32` refuses the mixed family. IPv4 IGMP
membership instead uses `proto: igmp` without `port`. mDNS/SSDP discovery and
unicast replies are separate UDP permissions; accepting only a multicast
destination does not admit arbitrary unicast responses.

## TLS and backend transport

TLS policy: required `type: acme`, `resolver: identifier`.
The current Traefik route adapter requires resolver `letsencrypt`.

Transport policy: required `type: tls`; optional `context` and `server_name`,
with at least one supplied. Context selects its trust CA path.
`server_name` is exactly `{domain: site_domain_id}`.
This is backend trust, separate from public TLS. A selected HTTPS exposure can
use it; the compiler does not turn an HTTP backend into HTTPS.

## Middlewares

| type | Required additional fields | Behavior |
| --- | --- | --- |
| default-headers | None | Fixed adapter-owned response headers |
| forward-auth | endpoint | HTTP/HTTPS endpoint reference to the existing authentication service |
| ip-allow-list | ranges | Nonempty ordered IPv4/CIDR, `{network: id}` or `{address_group: id}` list; final maximum 4096 values |
| canonical-home-redirect | app | Existing app with canonical origin; only a separate alias route with exactly canonical middleware list plus this final middleware |

Redirect policy is a finite canonical-root redirect, not arbitrary regex input.
It may not be attached to its own canonical route. Target/ingress must agree and
route hosts must be disjoint. No raw Traefik/Compose middleware bags are accepted.

## Authentication policies

| type | Required fields | Constraints |
| --- | --- | --- |
| cloudbeaver-oidc | provider, client_id, client_secret, display_name, user_claim | OIDC provider; secret-source ID; claim sub/preferred_username/email |
| node-red-retained-oidc | provider, client_id | Matching retained-node-red-oidc provider, no nonstandard origin port |
| zabbix-saml | provider, default_login | SAML provider; default_login zabbix or saml |

Client IDs are nonempty text ≤256 with no CR/LF; Cloud display name has the same
bound. Policies apply only to their matching adapter and owned HTTPS origin.
Profiles can require a matching authentication type.
[Providers and secret sources](identity-and-secrets.md) define their nested fields.

Changing policy values changes selected configuration/access. It grants no
authority to execute or bypass an existing HOLD. Verify public TLS, backend trust,
authentication and actual reachability separately after authorised deployment.

## Worked rule, binding and route middleware

The complete [relationship composition](../examples/relationships/README.md)
shows explicit endpoint-bound access and a selected `office_only` middleware in
its actual [site.yaml](../examples/relationships/site.yaml). The minimal rule
below can instead be added to the first tutorial's existing guest/context.

This is a complete network-policy value. `service` is a local role whose target
address and port are both bound by the guest, so the rule keeps one authority
for the selected socket.

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

This deliberately requests access to the declared endpoint; merely referencing
it in an app does not add this rule. For an HTTP client allowlist, a complete
middleware value uses a **list**, including when it selects one group:

<!-- example: policy-middleware -->
```yaml
type: ip-allow-list
ranges: [{address_group: clients}]
```

The site must declare `clients`; an exposure must explicitly select this named
middleware for it to affect a route. **Invalid variation:** `ranges:
{address_group: clients}` is a mapping, not the required list, and refuses.
Likewise a missing endpoint binding or an unused extra binding refuses.
Policy changes are desired access/configuration changes; they are not evidence
that a firewall, TLS endpoint or login flow was observed working.

[Reference index](README.md) · [Connections](connections.md) · [Exposures](exposures.md)
