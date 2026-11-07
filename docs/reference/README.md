# Configuration reference

This reference describes configuration written with `homelab-components-v1`. Declarations belong in a site, a library or one of the nested types documented here. The compiler generates deployment packets—files containing the inputs for deployment—from that configuration; you do not write those files yourself. Start with the object you want to configure, then follow its links to the fields and relationships you need.

## Find a contract by the decision you are making

| Decision | Canonical contract | Next relationship |
| --- | --- | --- |
| Define the desired installation | [Site](site.md) | [Complete typed sources](sources.md) |
| Supply reusable choices and defaults | [Library](library.md) | [Supporting types](supporting-types.md) |
| Set provider, trust and controller inputs | [Contexts](contexts.md) | [Guest placement](guests.md#guest-context) |
| Allocate an IPv4 NIC and route | [Networks and NICs](networks.md) | [Address branches](networks.md#field-guest-nic-address), [control interface](guests.md#guest-control-interface) |
| Allocate a guest and inherit defaults | [Guests](guests.md) | [Resource records](guests.md#resource-fields), [plan restrictions](lifecycle.md#infrastructure-plan-policy) |
| Place an app and bind profile roles | [Apps](apps.md) | [Adapter properties](app-properties.md), [runtime identity](apps.md#runtime-identity) |
| Select data roots and mount roles | [Storage](storage.md) | [App storage branches](storage.md#app-storage-bindings) |
| Connect a consumer to an endpoint | [Connections](connections.md) | [Managed accounts](connections.md#accounts), [explicit policy](policies.md#bindings) |
| Publish a DNS or HTTPS name | [Exposures](exposures.md) | [Owned public origin](exposures.md#public-origin), [TLS/backend trust](policies.md#tls-and-backend-transport) |
| Declare access, trust or authentication | [Policies](policies.md) | [Identity and secrets](identity-and-secrets.md) |
| Select protected material or provider identity | [Identity and secrets](identity-and-secrets.md) | [Material continuity](identity-and-secrets.md#protected-material-continuity) |
| Choose runtime settings, software, health checks, devices or assets | [Supporting types](supporting-types.md) | [Library selection](library.md), [adapter support](support.md) |
| Configure backup coverage and coordinated encrypted archives | [PBS backup](backup.md) | [Protected volumes](storage.md#volume-backup), [backup profiles](backup.md#backup-profiles) |
| Enable the explicit monitoring feature | [Zabbix](zabbix.md) | [Guest monitoring](guests.md#guest-monitoring) |

## Read acceptance at the right stage

Use only the fields listed for each object; validation rejects unknown keys. Required fields have no implicit default, and setting a field to null is different from omitting it. Lists preserve order unless their reference says otherwise. See [shared types](supporting-types.md#scalar-and-path-types) for rules about map IDs, scalar values and paths.

A value can have the right shape and still fail later checks: its references may be invalid, its profile may impose additional requirements, or the compiler may be unable to generate a supported deployment packet. Further checks run before and during deployment. A profile cannot make a required adapter input optional. See [support](support.md), [lifecycle](lifecycle.md) and [evidence levels](../concepts/evidence.md) to understand what a successful example proves.

## Use the examples

The [first configuration](../guides/first-configuration.md) includes a complete site, library and catalogue for offline use. The [relationship composition](../examples/relationships/README.md) adds a broker, browser, account, policies and an owned HTTPS route. Named code examples on reference pages are either complete values of a stated type or clearly labelled fragments. Tests run them through the relevant component validators and compile the complete examples into deployment packets.

Automated checks currently compare the detailed network/NIC [property indexes](networks.md#network-property-index) with their implementation. Other reference pages have maintained examples and reviewed explanations, but the checks do not yet inventory every condition across those pages. The [assurance record](../contributing/documentation-assurance.md) lists exactly what is checked.

## Commands and operation

Use [CLI](cli.md) for exact flags and output, [validate and generate](../guides/validate-and-generate.md) for the authoring task, [preparation](../guides/prepare-deployment.md) for real prerequisites and [operations](../operations/README.md) for execution and verification.

[Documentation index](../README.md) · [Configuration model](../concepts.md) · [Glossary](../glossary.md)
