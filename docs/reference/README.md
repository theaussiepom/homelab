# Configuration reference

This reference describes `homelab-components-v1`. Each declaration belongs to a
site, library or named nested contract; generated packets are outputs, not a
second authoring language. Start with the owning object, then follow its links
to the fields and relationships you need.

## Find a contract by the decision you are making

| Decision | Canonical contract | Next relationship |
| --- | --- | --- |
| Define the desired installation | [Site](site.md) | [Complete typed sources](sources.md) |
| Supply reusable choices and defaults | [Library](library.md) | [Supporting types](supporting-types.md) |
| Select provider/trust/controller inputs | [Contexts](contexts.md) | [Guest placement](guests.md#guest-context) |
| Allocate an IPv4 NIC and route | [Networks and NICs](networks.md) | [Address branches](networks.md#field-guest-nic-address), [control interface](guests.md#guest-control-interface) |
| Allocate a guest and inherit defaults | [Guests](guests.md) | [Resource records](guests.md#resource-fields), [plan restrictions](lifecycle.md#infrastructure-plan-policy) |
| Place an app and bind profile roles | [Apps](apps.md) | [Adapter properties](app-properties.md), [runtime identity](apps.md#runtime-identity) |
| Select data roots and mount roles | [Storage](storage.md) | [App storage branches](storage.md#app-storage-bindings) |
| Connect a consumer to an endpoint | [Connections](connections.md) | [Managed accounts](connections.md#accounts), [explicit policy](policies.md#bindings) |
| Publish a DNS/HTTPS name | [Exposures](exposures.md) | [Owned public origin](exposures.md#public-origin), [TLS/backend trust](policies.md#tls-and-backend-transport) |
| Declare access, trust or authentication | [Policies](policies.md) | [Identity and secrets](identity-and-secrets.md) |
| Select protected material or provider identity | [Identity and secrets](identity-and-secrets.md) | [Material continuity](identity-and-secrets.md#protected-material-continuity) |
| Select runtime/software/health/devices/assets | [Supporting types](supporting-types.md) | [Library selection](library.md), [adapter support](support.md) |
| Enable the explicit monitoring feature | [Zabbix](zabbix.md) | [Guest monitoring](guests.md#guest-monitoring) |

## Read acceptance at the right stage

Objects are closed: unknown keys refuse. Required fields have no implicit
default; null is not interchangeable with omission. A list is ordered unless
its owner says otherwise. Named-map IDs and scalar/path rules are defined in
[shared types](supporting-types.md#scalar-and-path-types).

A structural value may still fail reference resolution, selected-profile binding,
lowering, admission or a native guard. A profile's optional metadata cannot
weaken an adapter requirement. See [support](support.md), [lifecycle](lifecycle.md)
and [evidence levels](../concepts/evidence.md) before interpreting a successful
example as operating support.

## Use the examples

The [first configuration](../guides/first-configuration.md) is a complete offline
site/library/catalogue. The [relationship composition](../examples/relationships/README.md)
adds broker, browser, account, policy and HTTPS ownership. Named reference fences
are complete typed values or clearly labelled fragments, validated by their
actual component owners; complete examples also resolve and lower.

The detailed network/NIC [property indexes](networks.md#network-property-index)
are the initial source-derived conformance scope. Broader reference pages are
authored explanations with maintained examples; a reconciled automated inventory
of every semantic condition is still outside that pilot. The
[assurance record](../contributing/documentation-assurance.md) states the denominator.

## Commands and operation

Use [CLI](cli.md) for exact flags/output, [validate and generate](../guides/validate-and-generate.md)
for the authoring task, [preparation](../guides/prepare-deployment.md) for real
prerequisites and [operations](../operations/README.md) for execution/verification.

[Documentation index](../README.md) · [Configuration model](../concepts.md) ·
[Glossary](../glossary.md)
