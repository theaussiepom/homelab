# Template: configuration reference

**Reusable template, not a finished reference or runnable source.** Replace every
bracketed instruction and type placeholder before publishing a real page. Follow
the [documentation standard](../contributing/documentation.md).

## Purpose and location

[Name the owning component, where this value belongs, what it controls and which
existing contracts it references. State whether the block is a complete root,
typed leaf, map value or fragment. Link a complete tested composition.]

## Syntax

The following is **non-runnable syntax**. `TYPE` labels are placeholders, not
accepted literal values or instructions for a custom templating language.

```yaml
required_field: TYPE
optional_field: TYPE
```

[Replace with real fields; list nested alternatives and conditional shapes.]

## Fields

| Field | Type | Required/condition | Omitted/default/null | Constraints and effect |
| --- | --- | --- | --- | --- |
| [actual field] | [exact type] | [condition] | [exact behavior] | [bound/enum/path/reference] |

[Cover every nested field. Explain unknown keys and actual inheritance/override
order. Do not replace property documentation with “see source.”]

## Minimal valid worked example

[Insert concrete synthetic YAML, its exact placement and all required surrounding
declarations. Explain expected resolved output. Link the complete tested source
and name its owning validator/compiler test. No placeholders in this example.]

## Practical combination and invalid case

[Show a useful combination of actual fields/contracts. Include a meaningful
invalid variation with the exact reason it refuses and a test reaching that
boundary. Explain reference/dependency/permission differences.]

## First installation

[State whether creation is implemented for this contract/profile. Name real
prerequisites and create-only limits; structural success is not commissioning.
For a pure value type, state why installation is not applicable and link its
consumer instead of inventing an installation procedure.]

## Later deployments

[Explain keeping fresh source for owned updates, what can change, immutable
identities/material, expected effects and unsupported/unknown interruption,
import/replacement/deletion/rotation/rollback. Retained is not import.]

## Validation and navigation

[Give commands from a defined working directory, expected outcome, evidence
limits, related reference/guide links and the canonical index.]
