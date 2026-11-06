# Networks and guest NICs

A network is one `networks.<id>` value in a `homelab-components-v1`
[site](site.md). A guest NIC is one `guests.<id>.interfaces.<id>` value.
Together they describe the bridge, VLAN, IPv4 allocation and route consumed by
[guest infrastructure](guests.md). They do not create host bridges, provision
switch VLANs or reserve DHCP leases.

Start with the [complete offline tutorial](../guides/first-configuration.md) to
see these values in context. For real changes, review the
[preparation requirements](../guides/prepare-deployment.md#network-and-control-access)
and [update policy](lifecycle.md#infrastructure-plan-policy) before execution.
Identifiers in both maps match `[a-z][a-z0-9_-]{0,62}`; `<id>` denotes a user
chosen key, not literal YAML. Each named map has at most 1024 entries.

## Network syntax

This is the complete value of `networks.primary`, with required `context: lab`
supplied by the [complete site](../examples/first-configuration/site.yaml).
It is synthetic source for offline validation.

<!-- example: network-minimal -->
```yaml
context: lab
cidr: 198.18.20.0/24
bridge: example0
vlan: null
gateway: 198.18.20.1
```

Network objects are closed. Extra keys refuse `component.fields`; required
fields have no default. There is no template inheritance or overlay. Null is
accepted only for `vlan`; empty strings/maps/lists do not replace required values.

## Network property index

| Path | Variant | Presence | Type | Record |
| --- | --- | --- | --- | --- |
| `networks.<id>.context` | all | Required | Identifier string | [Context](#field-network-context) |
| `networks.<id>.cidr` | all | Required | Canonical IPv4 CIDR string | [CIDR](#field-network-cidr) |
| `networks.<id>.bridge` | all | Required | Text | [Bridge](#field-network-bridge) |
| `networks.<id>.vlan` | all | Required | Integer or null | [VLAN](#field-network-vlan) |
| `networks.<id>.gateway` | all | Optional | Canonical IPv4 string | [Gateway](#field-network-gateway) |

<a id="field-network-context"></a>
### Network context

`networks.<id>.context` is a required identifier, with no default. Omission,
null and empty strings refuse. A consuming guest must declare an existing
[context](contexts.md) and the network's context must equal that guest context.
The structural validator checks identifier syntax; the resolver checks the
relationship when a guest consumes the network. An unused network's context
existence is not unconditionally checked. A successful compile therefore does
not establish every unused network's placement.

<a id="field-network-cidr"></a>
### Network CIDR

`networks.<id>.cidr` is a required canonical strict IPv4 network string.
`198.18.20.0/24` is accepted; `198.18.20.10/24`, IPv6, null and empty values
refuse. No noncanonical spelling is normalized. The resolver uses the prefix
for [static NIC output](#field-guest-nic-address-value) and requires static and
DHCP endpoints to be usable subnet members. The CIDR allocates no external route.

<a id="field-network-bridge"></a>
### Network bridge

`networks.<id>.bridge` is required text of 1–4096 characters without NUL. It has
no default and cannot be null or empty. Resolution copies it into the
provider-facing NIC. The field's structural acceptance does not establish the
bridge's existence, interface membership or reachability on a host; those are
[deployment prerequisites](../guides/prepare-deployment.md#network-and-control-access).

<a id="field-network-vlan"></a>
### Network VLAN

`networks.<id>.vlan` is required. Null means no tag; otherwise it is an integer
1–4094 inclusive. Boolean values, numeric strings, zero and 4095 refuse. There
is no implicit default or inheritance. The complete tutorial's secondary
network demonstrates a tagged value. Changing a tag changes desired NIC input;
it does not configure the corresponding physical network.

<a id="field-network-gateway"></a>
### Network gateway

`networks.<id>.gateway` is optional, with no inserted default. If supplied it
must be a canonical IPv4 address within the CIDR, excluding network and
broadcast addresses. Null and empty strings refuse. A static NIC with
[`default_route: true`](#field-guest-nic-default-route) requires it. An explicitly
selected [source-policy route](guests.md#guest-source-policy-route) also requires
it and requires that gateway to differ from the NIC address. DHCP uses an
external lease; this field neither reserves nor proves that lease.

## Guest NIC

This complete NIC value belongs at
`guests.resolver.interfaces.management` in the
[complete site](../examples/first-configuration/site.yaml). The selected
`primary` network is the network above.

<!-- example: nic-minimal -->
```yaml
network: primary
slot: 0
mac: 02:00:00:20:00:10
address: {mode: static, value: 198.18.20.10}
default_route: true
ipv6: manual
```

The NIC is closed, with no inherited fields. Required keys cannot be omitted,
null or empty. Network resolution supplies the explicitly described
bridge/VLAN/prefix/gateway effects; it does not merge the network into the NIC.

## NIC property index

| Path | Variant | Presence | Type | Record |
| --- | --- | --- | --- | --- |
| `guests.<id>.interfaces.<id>.network` | all | Required | Identifier string | [Network reference](#field-guest-nic-network) |
| `guests.<id>.interfaces.<id>.slot` | all | Required | Integer | [Slot](#field-guest-nic-slot) |
| `guests.<id>.interfaces.<id>.mac` | all | Required | MAC string | [MAC identity](#field-guest-nic-mac) |
| `guests.<id>.interfaces.<id>.address` | all | Required | Tagged object | [Address branches](#field-guest-nic-address) |
| `guests.<id>.interfaces.<id>.default_route` | all | Optional | Boolean | [Default route](#field-guest-nic-default-route) |
| `guests.<id>.interfaces.<id>.ipv6` | all | Optional | String | [IPv6](#field-guest-nic-ipv6) |

<a id="field-guest-nic-network"></a>
### NIC network reference

`guests.<id>.interfaces.<id>.network` is a required identifier selecting
`networks.<id>`. Its context must match the guest's declared existing context.
There is no default. Resolution copies bridge/VLAN and derives address/prefix
and route output. Unknown selections refuse during resolution; see
[diagnostics](#network-and-nic-diagnostics).

<a id="field-guest-nic-slot"></a>
### NIC slot

`guests.<id>.interfaces.<id>.slot` is a required integer 0–31 inclusive.
Booleans and strings refuse. Across a guest, slots must be exactly contiguous
from zero, without gaps or duplicates. Provider NIC order follows slot, not
map order. Reordering can affect reachability; no hot-plug or uninterrupted
renumbering guarantee follows from source validity.

<a id="field-guest-nic-mac"></a>
### NIC MAC identity

`guests.<id>.interfaces.<id>.mac` is required text of six hexadecimal octets
separated by colons. Both letter cases are accepted; collisions are compared
case-insensitively in provider-address/node scope. The example uses a locally
administered synthetic value. There is no automatic allocation or search for
external conflicts. This identity is consumed by control/trust checks and cannot
waive [owned-update continuity](lifecycle.md#later-deployments-and-ownership-checks).

<a id="field-guest-nic-ipv6"></a>
### NIC IPv6 setting

`guests.<id>.interfaces.<id>.ipv6` is optional. When present its only accepted
value is the string `manual`; null, empty and other values refuse. Omission
leaves the field absent from provider output. This is not a general IPv6
allocation contract. IPv6 literals accepted by [address groups](#address-groups)
remain policy values, not guest addresses.

<a id="field-guest-nic-address"></a>
### NIC address branches

`guests.<id>.interfaces.<id>.address` is a required closed object. Its `mode`
selects the complete shape below; branch fields are not endpoint references.

| Mode | Exact accepted example | Resolution and restriction |
| --- | --- | --- |
| static | `{mode: static, value: 198.18.20.10}` | Requires `value`; app address is that value and provider address includes the network prefix. Forbids `endpoint`. |
| dhcp | `{mode: dhcp, endpoint: 198.18.20.10}` | Requires expected `endpoint`; provider mode is DHCP with a declared endpoint/prefix. External lease is a prerequisite. Forbids `value`. |
| manual | `{mode: manual}` | No resolved app address; cannot be the control interface or an app binding requiring an address. Forbids `value` and `endpoint`. |

| Path | Variant | Presence | Type | Record |
| --- | --- | --- | --- | --- |
| `guests.<id>.interfaces.<id>.address.mode` | static | Required | String discriminator | [Mode](#field-guest-nic-address-mode) |
| `guests.<id>.interfaces.<id>.address.mode` | dhcp | Required | String discriminator | [Mode](#field-guest-nic-address-mode) |
| `guests.<id>.interfaces.<id>.address.mode` | manual | Required | String discriminator | [Mode](#field-guest-nic-address-mode) |
| `guests.<id>.interfaces.<id>.address.value` | static | Required | Canonical IPv4 string | [Static value](#field-guest-nic-address-value) |
| `guests.<id>.interfaces.<id>.address.endpoint` | dhcp | Required | Canonical IPv4 string | [DHCP endpoint](#field-guest-nic-address-endpoint) |

<a id="field-guest-nic-address-mode"></a>
#### Address mode

The full path is `guests.<id>.interfaces.<id>.address.mode`. This required
string is exactly `static`, `dhcp` or `manual`, with no default. Null/empty and
unknown values refuse. The selected variant determines required/forbidden keys.
Mode changes also affect the [ordinary route rule](#field-guest-nic-default-route)
and control reachability; structural acceptance is not a live transition plan.

<a id="field-guest-nic-address-value"></a>
#### Static address value

`guests.<id>.interfaces.<id>.address.value` is required only for `static` and
forbidden otherwise. It is a canonical IPv4 address without prefix or port.
Omission/null/empty refuse; there is no default. Resolution requires a member
of the selected subnet other than its network/broadcast address, appends the
prefix for provider output and checks declared address conflicts in
provider-address/node/bridge/VLAN scope. It does not discover outside allocations.

<a id="field-guest-nic-address-endpoint"></a>
#### DHCP expected endpoint

`guests.<id>.interfaces.<id>.address.endpoint` is required only for `dhcp` and
forbidden otherwise. Its canonical IPv4, absence/null/empty, usable-subnet and
conflict rules match [static value](#field-guest-nic-address-value). It names an
expected lease address, not a lease reservation. Actual DHCP/trust admission
belongs to the [target preparation boundary](../guides/prepare-deployment.md#network-and-control-access).

<a id="field-guest-nic-default-route"></a>
### NIC default route

`guests.<id>.interfaces.<id>.default_route` is optional Boolean. The validator
and resolver read omission as false; null, numbers and strings refuse. True is
accepted only for `static` and requires the selected network's
[gateway](#field-network-gateway).

Each guest must have exactly one effective ordinary route: one DHCP NIC **or**
one static NIC with `default_route: true`. DHCP already contributes the route;
retaining that static-only flag refuses. Manual contributes none.
[Source-policy routing](guests.md#guest-source-policy-route) is separately declared.

For a valid variation, replace management `address` with
`{mode: dhcp, endpoint: 198.18.20.10}` and remove `default_route` (or set false).
The tutorial's second NIC stays static and non-default. To exercise manual mode,
change only that second NIC's address to `{mode: manual}`. Its address then
becomes unavailable to app roles; the static management NIC remains the control
and default route. These are independent changes to the complete tutorial.

## Resolution and output

The static example resolves to a provider NIC with `bridge: example0`,
`vlan: null`, its selected MAC, `ipv4: 198.18.20.10/24` and
`gateway: 198.18.20.1`. The interface-address lookup yields `198.18.20.10`.
The selected `ipv6: manual` is copied. Omitting that source key omits it from output.
DHCP output uses `ipv4: dhcp`, `gateway: null` and a declared `ipv4_endpoint`.
Manual output uses `ipv4: manual` and has no resolved app address.

An [app interface binding](apps.md#interface-roles) consumes these values through
its accepted profile role. A NIC alone publishes no app endpoint, grants no
traffic and creates no readiness edge. Those belong to [listeners](supporting-types.md),
[policies](policies.md), [connections](connections.md) and [exposures](exposures.md).

## Network and NIC diagnostics

Each variation starts from the valid complete tutorial and changes one input.
The relevant error path is available when the owning boundary attaches one;
a generic `component.invalid` must not be interpreted as a more specific code.

| Change | Stage / actual refusal | Supported correction |
| --- | --- | --- |
| CIDR `198.18.20.10/24` | Structural; `component.invalid at networks.primary` | Use canonical network address `198.18.20.0/24`. |
| VLAN `4095` | Structural; `component.integer at networks.primary` | Choose null or integer 1–4094 for the intended network. |
| Gateway null | Structural; `component.invalid at networks.primary` | Supply a usable IPv4 member, or omit only if no consumer requires it. |
| DHCP plus `default_route: true` | Structural; `component.invalid at guests.resolver.interfaces.management` | Remove/false the flag; retain exactly one effective route. |
| Unknown selected network | Resolution; `component.invalid` | Declare/select the network in the guest's context. |
| No effective ordinary route | Guest structural rule; `component.default-route` | Supply one DHCP route or one static default route. |
| Manual control NIC | Guest structural rule; `component.control-interface` | Select a static/DHCP interface with the required management reachability. |

These corrections establish source acceptance only. For later failures use
[troubleshooting](../operations/troubleshooting.md) and preserve ownership evidence.

## First installation

A network has no independent installation action. The [guest](guests.md) consumes
it through a supported creation path with real host bridge/VLAN/subnet/capacity,
allocation and trust prerequisites. The tutorial intentionally fails deployment
admission. Use [preparation](../guides/prepare-deployment.md), the selected profile's
capability and [deployment procedure](../operations/deployment.md).

## Later deployments

Bridge/VLAN/address/MAC/slot/route changes affect provider NIC input and can
interrupt management or service reachability. The saved-plan policy permits
only its guarded actions and [refuses replacement/import/adoption](lifecycle.md#infrastructure-plan-policy).
An allowed update is not proof of an interruption-free change. No automatic
bridge provisioning, lease management, renumbering recovery or rollback is
provided. Review effective values and the consumer's actual procedure before CD.

## External endpoints

Site `external_endpoints.<id>` requires `protocol` (`http/https/tcp/udp`),
`address` (nonempty host/IPv4 text without URL separators or space), and integer
`port` 1–65535. Optional `transport` is retained endpoint metadata; it does not
automatically select a connection/route transport policy.
Alternatively `address: {external: another_id}` reuses only that endpoint's
address. Unknown references and cycles refuse. No DNS lookup is performed.

General endpoint references are exactly `{external: id}` or
`{app: id, endpoint: name}`. Where a binder needs IPv4, a hostname is insufficient.

## Domains and host aliases

`domains.<id>` is a hostname of 1–253 characters, labels 1–63 characters,
letters/digits with internal hyphens. It is not a URL. Exposure hostname
collisions are case-insensitive.
`host_aliases.<id>: {hostname: name}` is Docker-local metadata with the same
label rules plus internal underscores. It does not publish DNS.

## Address groups

Each object contains only nonempty `members`, an ordered list of literal IPv4 or
IPv6 addresses/CIDRs, `{network: id}` or `{address_group: id}`.
Network members expand to the existing canonical CIDR. Group expansion
preserves duplicates and order; unknown references and cycles refuse even for
unused groups. No automatic subnet union or deduplication occurs.
The example below uses `primary` from the [complete tutorial](../examples/first-configuration/site.yaml).
IPv6 literals are policy values, not IPv6 allocations. Each expanded firewall
row must keep one address family and a compatible protocol. HTTP IP allowlists
retain their IPv4-only contract and refuse groups containing IPv6 values.

Bounds: 256 authored members/group, 4096 expanded values/group, depth 64,
65,536 aggregate expanded values, 4096 final policy rows/guest.
Cartesian policy row count is checked before allocating it.

The address group example below is a map value fragment for `address_groups`.
It uses `primary` from the complete tutorial. These values neither grant traffic
nor create endpoints or readiness edges; the consuming [policy](policies.md)
adds its own restrictions.

A useful group combination reuses this network and one shared VPN atom without
changing order or adding a dependency:

<!-- example: network-groups -->
```yaml
vpn: {members: [198.18.15.0/28]}
clients: {members: [{network: primary}, {address_group: vpn}]}
```

It expands `clients` to `[198.18.20.0/24, 198.18.15.0/28]`. A self-reference
refuses at group resolution; no automatic union or deduplication occurs.

## Verification and navigation

Structural owners are [`network`, `interface` and `guest`](../../blueprints/component_types.py).
The [`guest_values` resolver](../../blueprints/component_plan.py) owns consumed
references and output. The maintained [reference examples](../../blueprints/test_component_reference_examples.py)
parse the named examples through the real authored reader and resolve/lower
complete sources. The [assurance record](../contributing/documentation-assurance.md)
states which field records receive additional conformance checks. Source tests
do not qualify host networking, DHCP leases or live management continuity.

[Reference index](README.md) · [Guest contract](guests.md) ·
[Relationship guide](../guides/references-and-reuse.md) ·
[Offline tutorial](../guides/first-configuration.md)
