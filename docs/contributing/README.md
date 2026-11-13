# Contributing to the framework

The framework defines the configuration language, validation, reference resolution, compilation and supported deployment operations. The library selects profiles, defaults and software. Your deployment repository supplies allocations, protects private inputs and defines operating procedures. Start with the repository responsible for the change, and reuse an existing component before adding a new one.

## Change workflow

1. Establish the current behavior and the requested change. Read [component boundaries](components.md), the [reference](../reference/README.md) and existing evidence. Distinguish behavior established by source tests from behavior tested on a target.
2. Make the smallest change that defines the accepted fields and types, provides useful diagnostics and uses explicit references. Preserve the existing architecture and ownership rules.
3. Update the canonical [property/rule records](documentation-standard.md#4-property-records-and-nested-types), contextual links and complete examples. Update test-local source/document pointers where the [conformance scope](documentation-assurance.md) applies.
4. Test valid inputs and intended failures through the implementation responsible for them. Use [testing](testing.md) for focused tests and the complete required checks. Coverage and field-name checks do not replace behavior tests or prose review.
5. Read the rendered pages and follow the newcomer route. Apply the [documentation review rubric](documentation-standard.md#10-review-rubric-and-definition-of-done), including its plain-language criterion. State exactly which target or hosted checks have not been performed.
6. Retire superseded code/docs/tests after proving replacements, preserving useful regressions and historical evidence. Publication uses the repository's [security/signing/review procedure](../contributing-safely.md); merge and deployment remain separate actions.

## Author documentation

The [documentation standard](documentation-standard.md) is the single normative policy. Choose the [reference](../templates/configuration-reference.md), [task-guide](../templates/task-guide.md) or [tutorial](../templates/tutorial.md) template, replace instructions with reader-facing content and validate examples through existing contracts. Templates are authoring aids, not executable source.

For network and NIC changes, the [assurance guide](documentation-assurance.md) explains how checks connect implementation, documentation and examples, and how tests exercise failures in those checks. For other types, explicitly review optional fields and nested variants; the pilot does not automatically cover them.

[Documentation index](../README.md) · [Repository working agreement](../../AGENTS.md)
