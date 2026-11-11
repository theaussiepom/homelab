# Networks and guest NICs

A network is one `networks.<id>` value in a `homelab-components-v1` [site](site.md). A guest NIC is one `guests.<id>.interfaces.<id>` value. Together they configure the bridge, VLAN, IPv4 address and route for a [guest](guests.md). You must prepare the host bridges, switch VLANs and any DHCP leases separately.

Start with the [complete offline tutorial](../guides/first-configuration.md) to see these values in context. For real changes, review the [preparation requirements](../guides/prepare-deployment.md#network-and-control-access) and [update policy](lifecycle.md#infrastructure-plan-policy) before execution. Identifiers in both maps match `[a-z][a-z0-9_-]{0,62}`; `<id>` denotes a user chosen key, not literal YAML. Each named map has at most 1024 entries.

## Network syntax

This is the complete value of `networks.primary`, with required `context: lab` supplied by the [complete site](../examples/first-configuration/site.yaml). It is synthetic source for offline validation.

<!-- example: network-minimal -->
```yaml
context: lab
cidr: 198.18.20.0/24
bridge: example0
vlan: null
gateway: 198.18.20.1
```

Network objects accept only the listed fields. Extra keys produce `component.fields`, and required fields have no default. Values are not inherited from a template or overlaid from another declaration. Only `vlan` accepts null; empty strings, maps and lists cannot replace required values.

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

`networks.<id>.context` is a required identifier with no default. It cannot be omitted, null or empty. A guest using the network must select an existing [context](contexts.md), and the network must name that same context. The structural validator checks the identifier format; the resolver checks the context relationship when a guest uses the network. It does not always check whether an unused network's context exists, so successful compilation does not validate the placement of every unused network.

<a id="field-network-cidr"></a>
### Network CIDR

`networks.<id>.cidr` is a required IPv4 network string in strict canonical form. For example, `198.18.20.0/24` is accepted, but `198.18.20.10/24`, IPv6, null and empty values are rejected. The validator does not normalize noncanonical input. The resolver uses the prefix for [static NIC output](#field-guest-nic-address-value) and requires static addresses and expected DHCP endpoints to be usable members of the subnet. Declaring the CIDR does not create an external route.

<a id="field-network-bridge"></a>
### Network bridge

`networks.<id>.bridge` is required text of 1–4096 characters without NUL. It has no default and cannot be null or empty. The compiler copies it into the NIC configuration sent to the provider. Accepting the value does not prove that the bridge exists, has the required interfaces or is reachable on the host. Those are [deployment prerequisites](../guides/prepare-deployment.md#network-and-control-access).

<a id="field-network-vlan"></a>
### Network VLAN

`networks.<id>.vlan` is required. Use null for no VLAN tag, or an integer from 1 through 4094 inclusive. Booleans, numeric strings, zero and 4095 are rejected. There is no implicit default or inherited value. The complete tutorial's secondary network demonstrates a VLAN tag. Changing the tag changes the requested NIC configuration; the corresponding physical network must be configured separately.

<a id="field-network-gateway"></a>
### Network gateway

`networks.<id>.gateway` is optional and has no default. If supplied, it must be a canonical IPv4 address within the CIDR, excluding the network and broadcast addresses. Null and empty strings are rejected. A static NIC with [`default_route: true`](#field-guest-nic-default-route) requires a gateway. An explicitly selected [source-policy route](guests.md#guest-source-policy-route) also requires one, and it must differ from the NIC address. DHCP relies on an externally supplied lease; this field does not reserve or verify that lease.

## Guest NIC

This complete NIC value belongs at `guests.resolver.interfaces.management` in the [complete site](../examples/first-configuration/site.yaml). The selected `primary` network is the network above.

<!-- example: nic-minimal -->
```yaml
network: primary
slot: 0
mac: 02:00:00:20:00:10
address:
  mode: static
  value: 198.18.20.10
default_route: true
ipv6: manual
```

The NIC accepts only the listed fields and does not inherit fields. Required values cannot be omitted, null or empty. The compiler derives the bridge, VLAN, prefix and gateway from the selected network as described below; it does not merge the network object into the NIC.

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

`guests.<id>.interfaces.<id>.network` is a required identifier selecting `networks.<id>`, with no default. The selected network's context must match the guest's existing context. The resolver copies the bridge and VLAN, then derives the address, prefix and route. It rejects unknown selections; see [diagnostics](#network-and-nic-diagnostics).

<a id="field-guest-nic-slot"></a>
### NIC slot

`guests.<id>.interfaces.<id>.slot` is a required integer from 0 through 31 inclusive. Booleans and strings are rejected. A guest's slots must start at zero and continue without gaps or duplicates. The provider receives NICs in slot order, regardless of map order. Reordering can affect reachability. Valid configuration does not guarantee hot-plug support or uninterrupted renumbering.

<a id="field-guest-nic-mac"></a>
### NIC MAC identity

`guests.<id>.interfaces.<id>.mac` is required text containing six hexadecimal octets separated by colons. Uppercase and lowercase letters are accepted; collision checks ignore case within the same provider address and node. The example uses a synthetic, locally administered value. HomeLab does not allocate MAC addresses or search for external conflicts. Control and trust checks use this identity, and [ownership checks for later deployments](lifecycle.md#later-deployments-and-ownership-checks) still apply.

<a id="field-guest-nic-ipv6"></a>
### NIC IPv6 setting

`guests.<id>.interfaces.<id>.ipv6` is optional. If present, it must be the string `manual`; null, empty and other values are rejected. Omitting it leaves the field out of the provider output. This field does not support general IPv6 allocation. IPv6 literals in [address groups](#address-groups) are policy values and do not allocate guest addresses.

<a id="field-guest-nic-address"></a>
### NIC address branches

`guests.<id>.interfaces.<id>.address` is required. Its `mode` determines exactly which fields it accepts, as shown below. The address fields contain values, not references to endpoint objects.

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

The full path is `guests.<id>.interfaces.<id>.address.mode`. This required string must be exactly `static`, `dhcp` or `manual`, with no default. Null, empty and unknown values are rejected. The selected mode determines which keys are required and which are forbidden. Changing mode also affects the [ordinary route rule](#field-guest-nic-default-route) and control reachability. Passing structural validation does not establish a safe transition on the running guest.

<a id="field-guest-nic-address-value"></a>
#### Static address value

`guests.<id>.interfaces.<id>.address.value` is required for `static` and forbidden in the other modes. It must be a canonical IPv4 address without a prefix or port. There is no default; omitted, null and empty values are rejected. The resolver requires a usable member of the selected subnet, excluding its network and broadcast addresses. It appends the prefix for provider output and checks for duplicate declared addresses within the same provider address, node, bridge and VLAN. It does not discover allocations outside the configuration.

<a id="field-guest-nic-address-endpoint"></a>
#### DHCP expected endpoint

`guests.<id>.interfaces.<id>.address.endpoint` is required for `dhcp` and forbidden in the other modes. It follows the [static value rules](#field-guest-nic-address-value) for canonical IPv4 format, missing or empty values, usable subnet addresses and duplicate addresses. It names the expected lease address without reserving a lease. Check the actual DHCP and trust prerequisites during [target preparation](../guides/prepare-deployment.md#network-and-control-access).

<a id="field-guest-nic-default-route"></a>
### NIC default route

`guests.<id>.interfaces.<id>.default_route` is an optional Boolean. The validator and resolver treat omission as false and reject null, numbers and strings. Only `static` mode accepts true, and the selected network must provide a [gateway](#field-network-gateway).

Each guest must have exactly one effective ordinary route: one DHCP NIC **or** one static NIC with `default_route: true`. A DHCP NIC already supplies that route, so setting the static-only flag on it is rejected. A manual NIC supplies no route. Declare [source-policy routing](guests.md#guest-source-policy-route) separately.

For a valid variation, replace management `address` with `{mode: dhcp, endpoint: 198.18.20.10}` and remove `default_route` (or set false). The tutorial's second NIC stays static and non-default. To exercise manual mode, change only that second NIC's address to `{mode: manual}`. Its address then becomes unavailable to app roles; the static management NIC remains the control and default route. These are independent changes to the complete tutorial.

## Resolution and output

The static example resolves to a provider NIC with `bridge: example0`, `vlan: null`, its selected MAC, `ipv4: 198.18.20.10/24` and `gateway: 198.18.20.1`. The interface-address lookup yields `198.18.20.10`. The selected `ipv6: manual` is copied. Omitting that source key omits it from output. DHCP output uses `ipv4: dhcp`, `gateway: null` and a declared `ipv4_endpoint`. Manual output uses `ipv4: manual` and has no resolved app address.

An [app interface binding](apps.md#interface-roles) assigns these values to a role accepted by its profile. Configuring a NIC does not publish an app endpoint, grant network access or make execution wait for another app. Configure those relationships through [listeners](supporting-types.md), [policies](policies.md), [connections](connections.md) and [exposures](exposures.md).

## Network and NIC diagnostics

Each variation starts from the valid complete tutorial and changes one input. The relevant error path is available when the owning boundary attaches one; a generic `component.invalid` must not be interpreted as a more specific code.

| Change | Stage / actual refusal | Supported correction |
| --- | --- | --- |
| CIDR `198.18.20.10/24` | Structural; `component.invalid at networks.primary` | Use canonical network address `198.18.20.0/24`. |
| VLAN `4095` | Structural; `component.integer at networks.primary` | Choose null or integer 1–4094 for the intended network. |
| Gateway null | Structural; `component.invalid at networks.primary` | Supply a usable IPv4 member, or omit only if no consumer requires it. |
| DHCP plus `default_route: true` | Structural; `component.invalid at guests.resolver.interfaces.management` | Remove `default_route` or set it to false; retain exactly one effective route. |
| Unknown selected network | Resolution; `component.invalid` | Declare the required network or select an existing network in the guest's context. |
| No effective ordinary route | Guest structural rule; `component.default-route` | Supply one DHCP route or one static default route. |
| Manual control NIC | Guest structural rule; `component.control-interface` | Select a static/DHCP interface with the required management reachability. |

These corrections establish source acceptance only. For later failures use [troubleshooting](../operations/troubleshooting.md) and preserve ownership evidence.

## First installation

A network is not installed independently. The [guest](guests.md) uses it during a supported installation, which requires the actual host bridge, VLAN, subnet, capacity, address allocation and trust inputs to be ready. The tutorial intentionally fails deployment admission. Follow [preparation](../guides/prepare-deployment.md), check the selected profile's capabilities and use the [deployment procedure](../operations/deployment.md).

## Later deployments

Changing a bridge, VLAN, address, MAC, slot or route changes the NIC configuration sent to the provider and can interrupt management or service access. The saved-plan policy [rejects replacement, import and adoption](lifecycle.md#infrastructure-plan-policy) and permits only the actions it explicitly checks. An allowed update may still cause an interruption. HomeLab does not automatically provision bridges, manage leases, recover from renumbering or roll back these changes. Review the resulting values and your deployment procedure before CD.

## External endpoints

Each site `external_endpoints.<id>` requires `protocol` (`http/https/tcp/udp`), `address` and `port`. The address must be nonempty hostname or IPv4 text without URL separators or spaces. The port must be an integer from 1 through 65535. Optional `transport` is stored as endpoint metadata; it does not automatically select a transport policy for a connection or route. Alternatively, `address: {external: another_id}` reuses only the other endpoint's address. Unknown references and cycles are rejected. The compiler does not perform a DNS lookup.

General endpoint references are exactly `{external: id}` or `{app: id, endpoint: name}`. Where a binder needs IPv4, a hostname is insufficient.

## Domains and host aliases

`domains.<id>` is a hostname of 1–253 characters, labels 1–63 characters, letters/digits with internal hyphens. It is not a URL. Exposure hostname collisions are case-insensitive. `host_aliases.<id>: {hostname: name}` is Docker-local metadata with the same label rules plus internal underscores. It does not publish DNS.

## Address groups

An address group contains only `members`: a nonempty, ordered list of literal IPv4 or IPv6 addresses/CIDRs, `{network: id}` references or `{address_group: id}` references. A network reference expands to its canonical CIDR. Group expansion preserves duplicates and order; it does not combine subnets or deduplicate values. Unknown references and cycles are rejected even in unused groups.

The example below uses `primary` from the [complete tutorial](../examples/first-configuration/site.yaml). IPv6 literals describe policy and do not allocate IPv6 addresses. Each expanded firewall rule must use one address family and a compatible protocol. HTTP IP allowlists support IPv4 only and reject groups containing IPv6 values.

The limits are 256 authored members per group, 4096 expanded values per group, nesting depth 64, 65,536 expanded values in total and 4096 final policy rows per guest. The compiler checks the number of source-and-destination combinations before allocating those rows.

The following fragment supplies map values for `address_groups` using `primary` from the complete tutorial. These values do not grant access, create endpoints or make execution wait for another component. The [policy](policies.md) using them applies its own restrictions.

This example combines the network with a shared VPN subnet while preserving order and adding no execution dependency:

<!-- example: network-groups -->
```yaml
vpn:
  members:
  - 198.18.15.0/28
clients:
  members:
  - network: primary
  - address_group: vpn
```

The resolver expands `clients` to `[198.18.20.0/24, 198.18.15.0/28]`. It rejects a group that references itself and does not automatically combine or deduplicate the resulting subnets.

## Verification and navigation

[`network`, `interface` and `guest`](../../blueprints/component_types.py) validate the input structure. The [`guest_values` resolver](../../blueprints/component_plan.py) checks references and generates the corresponding values. The maintained [reference example tests](../../blueprints/test_component_reference_examples.py) parse the named examples with the actual source reader and compile complete configurations into deployment packets. The [assurance record](../contributing/documentation-assurance.md) lists the field records covered by additional checks against the implementation. These source tests do not verify host networking, DHCP leases or continued management access on a running guest.

[Reference index](README.md) · [Guest contract](guests.md) · [Relationship guide](../guides/references-and-reuse.md) · [Offline tutorial](../guides/first-configuration.md)
