# Library and site contract

The current authored schema is `homelab-components-v1`. A reusable library selects
framework contracts and declares templates, independent app profiles, software,
runtime, health, monitoring and policy components. It has no fixed guest graph.
A consuming site selects those definitions and owns concrete allocations, instance
placement, reference bindings, private input sources and execution policy.

Use [component configuration](components.md) for authoring/API and extension rules,
and [testing](testing.md) for the test layers and complete gate commands. The
selected framework owns parsing, validation, graph resolution, packet compilation
and workflow generation; consumers do not add another parser or deployment engine.
JSON and YAML representations share the same safe reader. Runtime packets, state,
credential records, receipt schemas and the disabled-list API remain JSON.

The Python entrypoints are `compile.resolve_plan`, `compile.lower_plan` and
`compile.compile_site`. Both compiler and workflow generator consume the explicit
site source. Value references do not create deployment waits or firewall grants.
Required traffic is checked against the declared source and destination guest
rules; actual readiness edges and ordered grants remain separate declarations.

Source versions use exact immutable library/framework selections. Older pins
retain their previous APIs; this head rejects fixed bundles and one-time authored
admission fields. Compilation is not native admission or deployment acceptance.
Versioned component history remains read-only proof; unrelated older records are
not reinterpreted as component success.

[Ordinary ownership](components.md#ordinary-ownership) describes the retained proof boundary.
State, data, credentials, resource identities and holds cannot be reset or adopted
by choosing another lifecycle label. OpenTofu and Ansible remain the engines under
protected CD.
