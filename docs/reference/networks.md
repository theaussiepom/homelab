# Networks and address values

Networks bind guest NICs to a context, bridge and IPv4 subnet.
A network is a site `networks.<id>` object.

| Field | Type / requirement | Constraint |
| --- | --- | --- |
| context | Required ID | Existing context |
| cidr | Required string | Canonical strict IPv4 network, including network address/prefix |
| bridge | Required text | Nonempty, at most 4096 characters |
| vlan | Required integer or null | null means no VLAN tag; otherwise 1–4094 |
| gateway | Optional IPv4 | Usable member of subnet; not network/broadcast address |

## Guest NIC

A guest's `interfaces.<id>` object has required `network`, `slot`, `mac`,
`address`; optional `default_route` and `ipv6`.

| Field | Type / default | Constraint |
| --- | --- | --- |
| network | Required ID | Existing network in the guest's context |
| slot | Required integer | 0–31; guest slots exactly contiguous from zero |
| mac | Required string | Six hexadecimal octets separated by colons; globally scoped identity conflicts refuse |
| address | Required tagged object | Static: `{mode: static, value: IPv4}`; DHCP: `{mode: dhcp, endpoint: IPv4}`; manual: `{mode: manual}` |
| default_route | Optional Boolean, false | True only for static address; network must supply gateway |
| ipv6 | Optional string | If supplied, exactly `manual`; no general IPv6 allocation contract |

Static/DHCP endpoints must be usable subnet members. DHCP's declared endpoint
does not reserve a lease; the real environment must provide it.
Exactly one effective ordinary route is required: one DHCP NIC or one static
`default_route: true`. A control interface must use static or DHCP addressing.
Manual NICs cannot supply a resolved app address. Source-policy routes require
an additional declared non-default static interface and its gateway.

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

```yaml
address_groups:
  vpn: {members: [198.18.15.0/28]}
  clients: {members: [{network: primary}, {address_group: vpn}]}
```

Each object contains only nonempty `members`, an ordered list of literal IPv4 or
IPv6 addresses/CIDRs, `{network: id}` or `{address_group: id}`.
Network members expand to the existing canonical CIDR. Group expansion
preserves duplicates and order; unknown references and cycles refuse even for
unused groups. No automatic subnet union or deduplication occurs.
This fragment uses the `primary` network from the worked example below.
IPv6 literals are policy values, not IPv6 allocations. Each expanded firewall
row must keep one address family and a compatible protocol. HTTP IP allowlists
retain their IPv4-only contract and refuse groups containing IPv6 values.

Bounds: 256 authored members/group, 4096 expanded values/group, depth 64,
65,536 aggregate expanded values, 4096 final policy rows/guest.
Cartesian policy row count is checked before allocating it.

Changing network/NIC identity affects the guarded infrastructure plan; source
validity does not promise online renumbering. Address groups are values only and
never create permission, endpoint or readiness edges.

## Worked network and NIC

This complete `networks.primary` value and `guests.resolver.interfaces.management`
value work together in the offline tutorial. `lab` must be a declared context.

<!-- example: network-minimal -->
```yaml
context: lab
cidr: 198.18.20.0/24
bridge: example0
vlan: null
gateway: 198.18.20.1
```

<!-- example: nic-minimal -->
```yaml
network: primary
slot: 0
mac: 02:00:00:20:00:10
address: {mode: static, value: 198.18.20.10}
default_route: true
```

A useful group combination reuses this network and one shared VPN atom without
changing order or adding a dependency:

<!-- example: network-groups -->
```yaml
vpn: {members: [198.18.15.0/28]}
clients: {members: [{network: primary}, {address_group: vpn}]}
```

It expands `clients` to `[198.18.20.0/24, 198.18.15.0/28]`.
**Invalid variation:** `cidr: 198.18.20.10/24` is not a canonical network address;
a group referencing itself also refuses. Changing the NIC to DHCP while retaining
`default_route: true` refuses: DHCP declares its ordinary route through its
address mode, not that static-only flag. Real lease management is external.

[Reference index](README.md) · [Policies](policies.md)
