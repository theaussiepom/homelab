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

A backend transport verifies Traefik's connection to an existing HTTPS service.
It is independent of the ACME certificate presented to a browser. Select the
policy through an [exposure's `transport` field](exposures.md); the endpoint must
already declare `protocol: https`. Selecting a transport does not convert HTTP
to HTTPS, grant [network access](#network-rules), create the external server or
add a deployment wait.

Declare a complete map value at `policies.transport.<id>` in a library or site,
or reference a [typed source](sources.md) with `kind: transport-policy`. Library
and site policies share a namespace; duplicate IDs and unknown fields are
rejected. The complete [backend transport example](../examples/backend-transport/README.md)
uses the real public library and a synthetic public certificate.

### Backend transport properties

| Path | Variant | Presence | Type | Record |
| --- | --- | --- | --- | --- |
| `policies.transport.<id>.type` | TLS | Required | String | [Type](#transport-type) |
| `policies.transport.<id>.context` | TLS | Optional; excludes certificate | Context ID | [Context trust](#transport-context) |
| `policies.transport.<id>.certificate` | TLS | Optional; excludes context | Public PEM string | [Public certificate](#transport-certificate) |
| `policies.transport.<id>.server_name` | TLS | Optional | Closed map | [Backend name](#transport-server-name) |
| `policies.transport.<id>.server_name.domain` | TLS | Required when server_name is present | Domain ID | [Domain reference](#transport-server-name-domain) |

At least one of `context`, `certificate` or `server_name` must be present. All
three are optional individually, have no implicit value and reject null or an
empty value. A policy with only `type: tls` is rejected. The compiler validates
declared policies, then emits trust files only for transports selected by this
ingress's routes. It does not merge two trust sources or modify the system-wide
certificate store.

<a id="transport-type"></a>
#### Type

`policies.transport.<id>.type` must be the string `tls`. No default is applied.
Arbitrary Traefik options, including `insecureSkipVerify`, are not accepted.
Return to the [property index](#backend-transport-properties).

<a id="transport-context"></a>
#### Context trust

`policies.transport.<id>.context` references an existing
[context](contexts.md). Its `trust.ca_file` supplies the public CA path; the
compiler does not read the file. The normal deployment input boundary later
supplies the selected file's bytes. Do not invent a provider context solely to
attach an unrelated backend certificate. Omission supplies no context CA.
`context` and [certificate](#transport-certificate) cannot coexist.

<a id="transport-certificate"></a>
#### Public certificate

`policies.transport.<id>.certificate` is a literal UTF-8 string containing
exactly one parseable X.509 PEM certificate, at most 65,536 bytes. Null, empty
strings, NUL bytes, private-key material, multiple certificates and text outside
the PEM markers are rejected. Surrounding whitespace is allowed and the input
bytes are preserved. This field accepts public material, never a private key,
secret-source ID, filename, URL or arbitrary certificate bundle.

Use this explicit trust anchor for an independently identified self-signed
backend or a selected public CA. The compiler checks syntax, not remote
possession, expiry or hostname validity. The HTTPS handshake must still verify
the actual peer and effective server name. If both trust fields are omitted,
the transport uses the existing system trust store instead.

The complete [typed policy](../examples/backend-transport/transport.yaml) uses a
synthetic public certificate; its private key is not retained. The
[companion site](../examples/backend-transport/site.yaml) supplies the endpoint,
domain, ingress and explicit outbound rule. Neither example contacts a service.
Return to the [property index](#backend-transport-properties).

<a id="transport-server-name"></a>
#### Backend name

`policies.transport.<id>.server_name` is a closed map containing only `domain`.
It sets the verified TLS server name and SNI, independently of the backend IP
address and the browser's route. Omission leaves the endpoint URL's host as the
TLS name. Empty maps, null and additional fields are rejected.

<a id="transport-server-name-domain"></a>
#### Domain reference

`policies.transport.<id>.server_name.domain` is an existing ID in the site's
[domains map](exposures.md). It is a reference, not a literal hostname or URL;
the resolved hostname must satisfy the normal hostname contract. A missing or
unknown ID is rejected. In the [complete example](../examples/backend-transport/README.md),
`domain: backend` resolves to `backend.example.invalid`, which is named in the
synthetic certificate. Return to [backend name](#transport-server-name).

### Invalid trust combination

This map is intentionally invalid. Even a valid public certificate cannot be
combined with a context trust source:

<!-- example: transport-conflicting-trust -->
```yaml
type: tls
context: lab
certificate: replace-with-one-public-PEM
```

The source binder rejects it with `component.transport` at
`policies.transport.<id>`, before reading certificate contents. Remove either
`context` or `certificate` and supply the remaining source in its documented
form. An unknown field such as `insecure_skip_verify` fails the closed-map
check; changing a test or disabling verification is not a supported correction.

### Installation, updates and verification

Before first installation, prepare the external HTTPS service and independently
identify its certificate. A successful source compile does not prove a CA file
exists, a private network path works or the backend accepts a login. This
transport supplies trust values to an existing ingress; it does not install a
server, provision accounts or renew backend certificates.

On an authorised later deployment, normal reconciliation writes the selected
public certificate to an ingress-owned `route-<id>.pem` file, owned by root with
mode `0400`, and mounts it read-only for that transport. Changing it changes the
requested trust; normal protected CD must reconcile and verify the result.
Existing provider CA input, accounts, data and certificate private keys retain
their owners. Apply the [ordinary lifecycle](lifecycle.md) and verify browser
HTTPS, backend hostname/trust and application behavior separately; ingress
reconciliation can interrupt proxied connections.

The [source validator](../../blueprints/component_auth.py),
[selected-file binding](../../blueprints/component_foundations.py),
[runtime transport parser](../../proxmox/applications/discovery.py) and
[owned-file builder](../../proxmox/applications/component_foundation_files.py)
share this contract across separate boundaries. The
[transport units](../../blueprints/test_component_auth.py) mock the certificate
validator to test delegation; its own units exercise public-PEM refusals.
[Runtime tests](../../proxmox/applications/tests/test_discovery.py) cover malformed,
oversized and conflicting trust, and
[file integration tests](../../proxmox/applications/tests/test_component_foundation_files.py)
verify exact content, selected scope, modes and preservation. The maintained
[reference tests](../../blueprints/test_component_reference_examples.py) compile
the complete example with real components; they do not contact targets or prove
a native Traefik handshake. Follow the [example check](../examples/backend-transport/README.md)
and [testing guide](../contributing/testing.md) before publication.

## Middlewares

| type | Required additional fields | Behavior |
| --- | --- | --- |
| default-headers | None | Fixed adapter-owned response headers |
| forward-auth | endpoint | HTTP/HTTPS endpoint reference to the existing authentication service |
| ip-allow-list | ranges | Nonempty ordered IPv4/CIDR, `{network: id}` or `{address_group: id}` list; final maximum 4096 values |
| cloudflare-source | local_allowlist, origin_header | Socket-peer Cloudflare gate with a named internal allowlist and retained origin secret; see below |
| canonical-home-redirect | app | Existing app with canonical origin; only a separate alias route with exactly canonical middleware list plus this final middleware |

The redirect policy redirects to the canonical root; it does not accept arbitrary regular expressions. It cannot be attached to the canonical route itself. The redirect and canonical routes must use the same target and ingress, with no shared hostnames. Arbitrary Traefik or Compose middleware options are not accepted.

## Cloudflare source boundary

A `cloudflare-source` middleware has exactly `type`, `local_allowlist` and `origin_header`. `local_allowlist` names an `ip-allow-list` middleware whose at most 256 resolved IPv4 ranges lie entirely within RFC1918 networks (10/8, 172.16/12 or 192.168/16). `origin_header` is a lowercase `x-` header name of at most 64 characters; forwarded identity header names are rejected. Bare IPv4 values become `/32` ranges and CIDRs with host bits are normalized, matching the existing allowlist contract. Attach exactly one such middleware first on selected public HTTP exposures. Combining this middleware with `forward-auth` is currently rejected at source because authenticated callback routes have a separate fixed contract. The owning Traefik app must bind the [`cloudflare_origin_token` secret role](identity-and-secrets.md#adapter-private-roles) through an existing protected file or scalar source. The token must be 16–4096 UTF-8 bytes with no line breaks. It is placed only in a root-owned mode-0400 runtime secret file, never dynamic configuration or provider discovery annotations, and removed from backend requests.

The framework bundles a reviewed local Traefik plugin adapted from the retained MIT Cloudflare middleware. It authorizes the socket peer, never `X-Forwarded-For`. Declared internal sources bypass Cloudflare verification and have supplied proxy/Cloudflare identity headers removed. A Cloudflare peer must supply one exact origin token and one valid visitor IP. The retained token is mounted as a fixed protected read-only file; its value is absent from the dynamic middleware configuration and Traefik configuration API. A supplied visitor scheme must be `http` or `https`; when omitted the actual incoming TLS state determines it. Forwarded identity is replaced with the validated visitor.

The plugin fetches Cloudflare IPv4 and IPv6 ranges over verified HTTPS, with a five-second timeout, 64 KiB response bound and at most 256 ranges. Refresh is synchronized, normally every 24 hours; failure retries after five minutes and retains the last successful ranges for at most 72 hours. Missing or expired trust denies public requests while declared internal access remains available. Configuration compilation does not fetch ranges or prove plugin/network acceptance.

For first installation, preserve provider/ACME connectivity and provision the retained token through the normal protected input path. For updates, deploy and verify middleware and every internal route restriction before widening frontend firewall reachability: infrastructure applies before application configuration. Keep the firewall opening in a later reviewed deployment. No extra Proxmox Cloudflare feed updater is required.

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
