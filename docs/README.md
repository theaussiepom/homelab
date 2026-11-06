# HomeLab documentation

Use this suite to learn the configuration model, look up exact accepted input,
and follow a supported configuration through preparation, execution and evidence.
It documents the framework's `homelab-components-v1` contracts. Library defaults
belong to the selected library; real allocations and operating authority belong
to the consuming site.

## Build your first understanding

| Stage | What you finish with | Start here |
| --- | --- | --- |
| 1. Learn and compile offline | A complete synthetic site, a validated plan and an inspectable guest packet | [Start here](start-here.md), [model](concepts.md), [first configuration](guides/first-configuration.md) |
| 2. Prepare real inputs | A reviewed compatibility selection and consumer-owned prerequisites | [Prepare a deployment](guides/prepare-deployment.md) |
| 3. Install through the supported path | Evidence for the exact source, workflow and affected phases | [Deployment](operations/deployment.md), [adapter support](reference/support.md) |
| 4. Verify and maintain | Fresh service observations and a deliberate owned-update process | [Verify and maintain](operations/verify-and-maintain.md), [lifecycle](reference/lifecycle.md) |

A stage does not establish the next one. The [evidence guide](concepts/evidence.md)
explains the boundary between source checks, controller tests, deployment and
service acceptance.

## Author or review a configuration

The [reference index](reference/README.md) routes by ownership and task. Start
with [site structure](reference/site.md), then follow a declaration to its nested
type. The detailed [network and guest NIC reference](reference/networks.md)
shows exact field records, all address branches, resolution and diagnostics.

To combine objects, use [references and reuse](guides/references-and-reuse.md)
and the [complete broker/browser/HTTPS example](examples/relationships/README.md).
To inspect generated results use [validate and generate](guides/validate-and-generate.md)
and the [CLI contract](reference/cli.md). [Glossary](glossary.md) defines recurring
terms with routes back to their owners.

## Operate or extend

[Operations](operations/README.md) links preparation, first installation,
verification, updates and [troubleshooting](operations/troubleshooting.md).
[Host bootstrap, installer and recovery](framework-reference.md) have separate
contracts and are not application recovery shortcuts.

Contributors start with the [change workflow](contributing/README.md), then
[component boundaries](contributing/components.md), [testing](contributing/testing.md)
and the [canonical documentation standard](contributing/documentation-standard.md).
The [assurance record](contributing/documentation-assurance.md) states the exact
automated documentation scope and what still requires review. It does not claim
that every public semantic condition is mechanically inventoried.

## Existing entry links

Earlier links to [component configuration](components.md) and [testing](testing.md)
remain supported navigation pointers. Focused [Authentik callbacks](authentik-callback.md),
[WiNet behavior](winet.md) and [Zabbix integration](zabbix-blueprint.md) notes connect
to the current canonical field records and preserve their specific operating limits.
