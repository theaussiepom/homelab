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
| proto | Required enum | `tcp`, `udp`, `icmp`, `icmpv6` |
| comment | Required text | Nonempty, at most 4096 characters |
| port | Optional string, null or reference | Numeric comma-separated ports/ranges (colon syntax); or `{endpoint: local_role}` |
| source / destination | Optional address value | IPv4/CIDR literal or one of `{interface: role}`, `{network: role}`, `{endpoint: role}`, `{address_group: role}` |
| interface | Optional role ID | Binds a declared guest NIC to provider iface `netN` |

Traffic matching further requires ports/ranges in 1–65535 and ascending bounds.
Inbound unrestricted `source: 0.0.0.0/0` refuses.
The current provider receives explicit ACCEPT rows; there is no authored deny/
priority/template-command language. IPv4 address allocation remains the
supported network contract despite the finite protocol enum.

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

[Reference index](README.md) · [Connections](connections.md) · [Exposures](exposures.md)
