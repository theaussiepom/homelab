# Template: configuration reference

This is an **authoring template**, not executable configuration or a finished
reference. Replace all bracketed instructions; use actual accepted fields and
synthetic values. The [canonical standard](../contributing/documentation-standard.md)
is the policy; this template implements its page/property/link requirements.

## Purpose and placement

[Name the contract/schema, owner and full placement path. Identify root, typed
leaf, map value or fragment. Explain what the consumer controls and link its
parent, relevant concept and complete coherent example.]

## Syntax and property index

[Show actual accepted syntax; label type placeholders as non-executable when
needed. State closed-object behavior, omitted/null/empty distinctions and which
rules apply uniformly. Every public nested branch needs a record.]

| Path | Variant | Presence | Type | Record |
| --- | --- | --- | --- | --- |
| [full symbolic path] | [discriminator or all] | [required/optional/condition] | [actual type] | [link to canonical field record] |

[Use stable explicit anchors or unique headings. The pilot uses these normal
columns as the reader-facing conformance surface; do not invent another schema
or repeat source defaults in a separate mapping.]

## Canonical property records

### [Owning type and field]

[Give exact full path/variant, purpose, required/conditional rule, accepted type,
omission/default and applying layer. Explain null/empty behavior, actual units,
bounds/enums/format, inheritance and reference namespace. Link the nested type,
interacting condition, consumer effect, example and diagnostic where encountered.]

### [Named nested type or union]

[Show every discriminator branch and its exact required/forbidden keys. Give
full-path records for nested fields and a return link to the enclosing field.
A shared discriminator can have one anchor with explicitly separate variant
rows when the semantics are explained together.]

## Resolution and output

[Identify the source/resolver/lowerer applying defaults or conditions. Show an
input-to-effective-result example. Distinguish values, readiness, grants,
publication and runtime ownership. Describe relevant outputs without exposing
private material or promoting incidental internal data to a public input API.]

## Complete and invalid examples

[Supply a minimal valid typed value and link its complete library/site/catalogue.
Label fragments clearly. Add stable example IDs, a useful nested/conditional
variation and a negative input with actual stage/code/path and supported repair.
Keep exact excerpts synchronized with their canonical files.]

## First installation

[State implemented support and actual prerequisites. If the type is only a value,
name and link the consuming owner instead of inventing its own install process.
Source acceptance does not qualify material, native state or service behavior.]

## Later deployments

[Explain what can change, affected consumers, stable identity/material and actual
restart/disruption/replacement/refusal limits. Keep supported fresh source for
ordinary owned updates. Retained is not import. Label unknown qualification and
link canonical lifecycle/operations rather than repeating a generic procedure.]

## Verification and navigation

[Link actual source owners and executable tests. Name evidence levels/fakes,
meaningful refusal cases and unavailable qualification. For a checked contract,
update source/document/example/evidence pointers as described by
[documentation assurance](../contributing/documentation-assurance.md). Link the
parent/index, task, concept, complete example and related nested types.]
