# Template: configuration reference

This **authoring template** shows how to organise a reference page. Replace its instructions with explanations of the accepted fields and use synthetic example values. It is not executable configuration. Follow the [canonical standard](../contributing/documentation-standard.md) for page content, property records and links.

## Purpose and placement

Name the type, schema, responsible component and full configuration path. Say whether the example is a root document, typed source file, map value or fragment. Explain what the reader can configure and link to the parent page, relevant concept and complete example.

## Syntax and property index

Show the accepted syntax and label placeholders as non-executable notation. State that unknown keys are rejected, explain omitted, null and empty values, and group rules that apply to every field. Document every public nested variant.

| Path | Variant | Presence | Type | Record |
| --- | --- | --- | --- | --- |
| [full symbolic path] | [discriminator or all] | [required/optional/condition] | [actual type] | [link to canonical field record] |

Use stable explicit anchors or unique headings. The pilot checks these table columns against the implementation. Do not create another schema or copy defaults into a separate mapping.

## Canonical property records

### [Owning type and field]

Give the exact path and variant, purpose, required or conditional rule, accepted type, omission behavior and default, including where the default is applied. Explain null and empty values, units, limits, enumerated values, format, inheritance and where references are looked up. Link relevant nested types, interacting conditions, effects, examples and diagnostics where readers need them.

### [Named nested type or union]

Show every discriminator value and the exact fields each variant requires or forbids. Document nested fields with their full paths and a return link to the enclosing field. A shared discriminator may use one anchor if separate table rows identify the variants and the explanation covers each one.

## Resolution and output

Name the part of the implementation that applies each default or condition. Show how an input becomes an effective value or generated output. Explain values, execution waits, access rules, publication and runtime ownership separately. Describe useful outputs without exposing credentials or presenting internal data as user-configurable fields.

## Complete and invalid examples

Supply a minimal valid value and link to the complete library, site and catalogue it needs. Label fragments clearly. Add stable example IDs, a useful nested or conditional variation, and an invalid input with its actual failing stage, code, path and supported correction. Keep exact excerpts synchronized with their canonical files.

## First installation

State what installation support exists and which prerequisites must be prepared. If the type only supplies a value, link to the component that uses it instead of inventing a separate installation procedure. Configuration checks do not verify actual files, credentials, target state or service behavior.

## Later deployments

Explain what can change, which apps or guests are affected, which identities, files and credentials must remain unchanged, and any restart, disruption, replacement or rejection rules. Keep supported fresh configuration for ordinary HomeLab-managed updates; retained does not import an installation. State what has not been tested on a target and link to the lifecycle and operations pages rather than duplicating procedures.

## Verification and navigation

Link to the implementation and executable tests. State what each check proves, what it replaces with fakes, which failures it exercises and what remains untested. For a checked contract, update the source, documentation, example and evidence pointers described in [documentation assurance](../contributing/documentation-assurance.md). Link to the parent or index, task, concept, complete example and related nested types.

Before publication, read the complete page as a new user would. Use ordinary verbs, name who performs each action and explain project-specific terms at first use. Preserve exact field names, requirements and evidence limits. Remove these instructions from the finished reference.
