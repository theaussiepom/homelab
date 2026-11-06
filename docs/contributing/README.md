# Contributing to the framework

The framework owns accepted grammar, validation, resolution, compilation and
execution capabilities. The library owns selected profiles/defaults/software;
consumers own allocations, protected input custody and operating procedures.
Start at the actual owner of the change and reuse an existing component before
adding a new contract.

## Change workflow

1. Establish the current accepted behavior and the requested difference. Read
   [component boundaries](components.md), [reference](../reference/README.md) and
   existing evidence; separate source behavior from native qualification.
2. Implement the smallest closed typed change with useful diagnostics and
   explicit references. Preserve the existing architecture and ownership rules.
3. Update the canonical [property/rule records](documentation-standard.md#4-property-records-and-nested-types),
   contextual links and complete examples. Update test-local source/document
   pointers where the [conformance scope](documentation-assurance.md) applies.
4. Exercise valid and intended invalid cases at the actual owning boundary.
   Use [testing](testing.md) for focused and complete gates; coverage and field
   presence do not replace behavioral evidence or prose review.
5. Review rendered navigation and the newcomer path. Apply the
   [documentation review rubric](documentation-standard.md#10-review-rubric-and-definition-of-done)
   and identify unavailable native or hosted evidence precisely.
6. Retire superseded code/docs/tests after proving replacements, preserving
   useful regressions and historical evidence. Publication uses the repository's
   [security/signing/review procedure](../contributing-safely.md); merge and
   deployment remain separate actions.

## Author documentation

The [documentation standard](documentation-standard.md) is the single normative
policy. Choose the [reference](../templates/configuration-reference.md),
[task-guide](../templates/task-guide.md) or [tutorial](../templates/tutorial.md)
template, replace instructions with reader-facing content and validate examples
through existing contracts. Templates are authoring aids, not executable source.

For network/NIC changes, the [assurance guide](documentation-assurance.md) explains
the pointer mapping, source-derived inventory, exact destinations and negative
checker fixtures. For other contracts, review accepted optional/nested branches
explicitly; the pilot does not claim automatic coverage of them.

[Documentation index](../README.md) · [Repository working agreement](../../AGENTS.md)
