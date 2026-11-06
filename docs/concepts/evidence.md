# What the evidence establishes

Use the narrowest description supported by the actual check. An authored value,
a valid plan and a working service are different outcomes. This distinction
lets a reviewer decide whether a proposed change has the evidence it needs.

| Evidence | Established by | Remaining boundary |
| --- | --- | --- |
| Parsed | Real authored reader accepts source bytes | Component constraints and references |
| Direct component validation | Real owning validator, including intended refusal cases | Cross-object resolution and selected-profile floors |
| App/guest unit | Orchestration with specified component collaborators mocked | Real collaborator integration |
| Compiler integration | Real components resolve names, defaults, graphs and lower packets | Material/trust existence, native state and services |
| Controller/receiver test | Named packet, receipt and ownership flow, often with native bodies faked | Real platform execution |
| Isolated protocol fixture | A named filesystem, process or service protocol in its stated fixture | Full consumer deployment and physical/user behavior |
| Deployment | Exact source/workflow/run/attempt completes the relevant target phases | Untested authentication, persistence, devices and user outcomes |
| Service acceptance | Fresh named target observations demonstrate the intended result | Future updates, recovery and unrelated services |

## Read a claim in context

The [first tutorial](../guides/first-configuration.md) reaches parsing, validation,
resolution and lowering. Its packet is deliberately unsuitable for admission.
A maintained example test may reject subprocess/network calls; that establishes
its source-only boundary without proving every runtime path is sandboxed.

A controller fixture using genuine local receipts can establish that ownership
guards refuse a changed identity. If its native body is faked, it does not
establish that a real OpenTofu plan or service restart succeeded. A successful
workflow does not prove public TLS or a device command unless that observation
was included and recorded.

## Record a useful result

Name the selected revisions, input/example, command or scenario, actual outcome,
mock/native boundary and remaining qualification. For deployment add the exact
run and attempt; for services add the endpoint/behavior and observation time.
Keep private outputs in their owning boundary. Do not substitute a green summary,
a text-presence check or a coverage percentage for the actual layer being claimed.

[Documentation assurance](../contributing/documentation-assurance.md) applies
this rule to reference coverage. [Verify and maintain](../operations/verify-and-maintain.md)
applies it to operations. [Testing](../contributing/testing.md) defines contributor gates.

[Configuration model](../concepts.md) · [Documentation index](../README.md)
