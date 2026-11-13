# What the evidence establishes

Use the narrowest description supported by the actual check. An authored value, a valid plan and a working service are different outcomes. This distinction lets a reviewer decide whether a proposed change has the evidence it needs.

| Evidence | Established by | Remaining boundary |
| --- | --- | --- |
| Parsed | The actual source reader accepts the YAML or JSON file | Component constraints and references |
| Direct component validation | The validator responsible for the type, including cases it must reject | References between objects and minimum requirements of the selected profile |
| App/guest unit | App or guest orchestration tested with specified components replaced by mocks | Integration with the real components |
| Compiler integration | Real components resolve names, defaults and dependencies, then produce deployment packets | Existence of protected files and trust inputs, actual platform state and services |
| Controller/receiver test | The specified flow of deployment inputs, result records and ownership checks, often with platform operations replaced by test doubles | Real platform execution |
| Isolated protocol fixture | A named filesystem, process or service protocol in its stated fixture | A complete site deployment and physical device or user behavior |
| Deployment | The exact source, workflow, run and attempt complete the relevant phases on the target | Untested authentication, persistence, devices and user outcomes |
| Service acceptance | Fresh named target observations demonstrate the intended result | Future updates, recovery and unrelated services |

## Read a claim in context

The [first tutorial](../guides/first-configuration.md) parses and validates source, resolves references and generates deployment inputs. Its output deliberately fails the checks required before deployment. A maintained example test may reject subprocess/network calls; that establishes its source-only boundary without proving every runtime path is sandboxed.

A controller test using genuine local receipts can establish that ownership checks reject a changed identity. If the test replaces the actual platform operation with a test double, it does not establish that a real OpenTofu plan or service restart succeeded. A successful workflow does not prove public TLS or a device command unless that observation was included and recorded.

## Record a useful result

Name the selected revisions, input/example, command or scenario, actual outcome, which operations used mocks, which ran against real systems, and what still needs verification. For deployment add the exact run and attempt; for services add the endpoint/behavior and observation time. Keep private outputs within the protected system responsible for them. Do not substitute a green summary, a text-presence check or a coverage percentage for the actual layer being claimed.

[Documentation assurance](../contributing/documentation-assurance.md) applies this rule to reference coverage. [Verify and maintain](../operations/verify-and-maintain.md) applies it to operations. [Testing](../contributing/testing.md) defines contributor gates.

[Configuration model](../concepts.md) · [Documentation index](../README.md)
