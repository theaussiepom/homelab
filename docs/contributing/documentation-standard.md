# HomeLab documentation standard

This standard governs documentation for **homelab**: its reusable configuration language, components, compiler and deployment capabilities. Documentation is part of the public API. Readers must be able to write valid configuration, understand the resulting values and actions, and identify what HomeLab supports without reading implementation discussions.

**MUST** is a review requirement. **SHOULD** is the expected approach; a documented reason may justify an alternative that meets the reader's need. **MAY** is optional. These words govern documentation, not permission to change contracts or operate an installation. A proposed documentation improvement never authorizes an implementation change.

This is the canonical framework documentation policy. Adopting it sets the review requirements; it does not certify every existing field or target operation. The [documentation assurance record](documentation-assurance.md) lists the checks in place and the review work that remains.

## Contents

- [1. Ownership and audiences](#1-ownership-and-audiences)
- [2. Information architecture and reader journeys](#2-information-architecture-and-reader-journeys)
- [3. Reference page contract](#3-reference-page-contract)
- [4. Property records and nested types](#4-property-records-and-nested-types)
- [5. Contextual linking and navigation](#5-contextual-linking-and-navigation)
- [6. Examples and reproducible commands](#6-examples-and-reproducible-commands)
- [7. Installation, maintenance and failure semantics](#7-installation-maintenance-and-failure-semantics)
- [8. Authoring and structural generation](#8-authoring-and-structural-generation)
- [9. Coverage and evidence](#9-coverage-and-evidence)
- [10. Review rubric and definition of done](#10-review-rubric-and-definition-of-done)
- [11. Worked reference specimen: network and guest NIC](#11-worked-reference-specimen-network-and-guest-nic)
- [12. Contributor integration](#12-contributor-integration)
- [13. Design sources](#13-design-sources)

## 1. Ownership and audiences

### 1.1 Public boundaries

The framework MUST document its accepted configuration, how references are resolved, how deployment inputs are generated, which capabilities can be selected and which execution limits are enforced. These definitions MUST apply to anyone using the framework. They MUST NOT require readers to reproduce a particular operator's environment.

| Owner | Canonical documentation | Boundary |
| --- | --- | --- |
| homelab | The configuration API, typed components, validators, compiler, diagnostics, deployment protocol, adapter capabilities and support limits | Defines what the framework accepts, produces, executes and refuses |
| [homelab-stack](https://github.com/theaussiepom/homelab-stack) or another compatible library | Reusable guest/app profiles, supplied defaults, software/runtime selections and compositions | Selects and combines framework capabilities; cannot widen their support contract |
| Consumer deployment repository | Concrete allocations, endpoint identities, protection of credentials, runner and environment selections, approvals and operating procedures | Supplies site-specific inputs and authority; must not redefine reusable field meanings |
| Upstream software/platform | Its supported product behavior | Explains product behavior; does not prove that a HomeLab adapter implements or has tested that behavior |

Public pages MUST exclude private configuration, credentials, actual site allocations, private repository identities, local workstation paths and environmental recovery history. A concrete path required by an API is appropriate when synthetic and clearly explained; an operator's actual path is not. Migration/recovery evidence belongs to its actual owner and task. It MUST NOT become a new ordinary configuration prerequisite unless the accepted contract really requires it.

OpenTofu manages infrastructure and state; Ansible manages configuration and services. Documentation MUST preserve that division and require protected CD for ordinary maintenance. It MUST NOT recommend direct commands or edits that compete with those declared owners.

### 1.2 Reader needs

Every page MUST choose a primary audience and question. The suite MUST support:

- A newcomer learning how a site, library, guest, app and service relate.
- An author composing a valid desired configuration, including nested and conditional cases.
- A reviewer checking effects, continuity, support and compatibility before a change.
- An operator preparing or verifying a supported installation and diagnosing a refused operation.
- A contributor extending a component's accepted fields without creating a second source of truth.

A reference page may serve several readers through links, but MUST make accepted fields and behavior easy to look up. It MUST NOT hide a tutorial inside a property definition or assume the reader has followed a previous conversation.

Authors and reviewers MUST read each changed page as connected prose, not only scan it for required words. Use familiar words and ordinary verbs, name the actor and action, and explain project-specific terms at first use. A reader should understand what to configure, what HomeLab checks or generates, and what remains unverified without translating implementation shorthand. Preserve exact field names, requirements and evidence limits. Reviewers MUST request revision when dense noun phrases or unexplained internal terms obstruct that understanding.

### 1.3 Version and compatibility

References MUST identify the configuration schema and supported version. Cross-repository examples MUST state the compatible set of revisions: framework, library, example and any fixed catalogue or tooling selection. Evidence from the framework revision selected by a library does not establish compatibility with a different revision on framework main. Documentation MUST NOT silently change either selection.

Change notes MUST distinguish fields added/removed, defaults changed, accepted shapes changed, diagnostics changed and execution support changed. Link the first relevant release/commit and replacement guidance where known. Do not invent API version numbers or deprecation periods. A dated inspection or passing source test is not an ongoing compatibility guarantee.

## 2. Information architecture and reader journeys

### 2.1 Page responsibilities

Keep the root README concise: purpose, supported scope, repository boundary and clear links to learn, reference, operate and contribute. The documentation index MUST expose those paths. Comprehensive coverage belongs in linked Markdown pages; an HTML platform and an enormous README are not prerequisites.

| Page type | Use it when the reader needs to… | Required contents | Exclude |
| --- | --- | --- | --- |
| Overview/index | Choose a route through the suite | State the purpose, audience and scope, then provide ordered entry points and canonical indexes | Exhaustive fields or repeated procedures |
| Concept | Understand a model or relationship | Explain vocabulary, ownership, relationships and constraints, with a small illustration and links to exact types and tasks | Unsupported architecture proposals stated as fact |
| Tutorial | Learn by completing a bounded result | Give the starting state, complete files, ordered steps, expected or observed result, a useful change, next steps and limits of the evidence | Undefined existing resources or implied deployment from compilation |
| How-to/task | Complete one known task | State the outcome and prerequisites, give exact steps and verification, and explain failures and relevant fields | General introduction replacing actionable steps |
| Component/type reference | Look up accepted declarations and effects | [Reference page contract](#3-reference-page-contract), [property records](#4-property-records-and-nested-types), variants and examples | Source-code links substituting for field explanation |
| App/adapter reference | Determine the reusable adapter contract | Explain accepted properties, required bindings and private inputs, generated effects, supported operations and lifecycle limits | Library defaults represented as framework-wide requirements |
| Composition guide | Combine components correctly | Provide complete consistent configuration. Explain relationships, values, readiness and permissions separately, including reference resolution and generated output. | Fragments requiring readers to invent missing surroundings |
| Operations | Prepare, run or maintain a supported deployment | State authorisation, prerequisites, ownership, phases, exact actions and verification, and supported handling of failures | Invented import, HOLD release, retry, rollback or restore |
| Troubleshooting/diagnostic | Explain an actual failure | Give the error or symptom, stage, supported causes, a limited diagnostic, practical correction and safe stopping point | Sensitive-value dumps or generic “check logs” advice |
| Contribution | Change and review the public contract | Identify the responsible component, templates, inventory changes, tests, evidence and publication and review requirements | A parallel undocumented authoring standard |

A page combining responsibilities MUST separate them with explicit headings and links, and retain one canonical definition of each fact. Split a page when independent lookup targets or long unrelated sections obscure its primary task, not merely to satisfy a page-count goal.

### 2.2 A complete newcomer route

The suite MUST expose four distinct stages, with links in both directions:

1. **Offline synthetic tutorial:** author, validate, resolve and inspect a safe example without target access, credential reads, image pulls or service startup. State deliberate synthetic restrictions.
2. **Deployment preparation:** select a compatible library and supported profile. In the deployment repository, supply real allocations, trust inputs, protected credentials and files, capacity, platform prerequisites and workflow settings. Explain what configuration checks cannot establish.
3. **First supported installation:** link to the implemented deployment procedure and profile-specific limits. Identify prerequisites supplied outside HomeLab and the operator's procedure for preparing them. If installation is unsupported, say so and explain which next step is supported.
4. **Service verification and later maintenance:** distinguish successful workflow completion from fresh observations of service, authentication, data or device behavior; describe ordinary declared updates and failure handling.

A safe compiler tutorial is valuable but does not by itself complete this journey. A tutorial MUST finish at its stated outcome and provide the next link without pretending to execute a later stage.

## 3. Reference page contract

### 3.1 Required structure

Every component/type reference MUST use the following reusable structure, adapted by the applicability rules below. These are content requirements, not instructions to publish empty headings.

| Section | Required authoring content |
| --- | --- |
| Purpose and location | Name the exact type, schema, responsible component and configuration path. Identify a root, map value, typed source file or fragment, and explain what it controls and which component uses it. |
| Syntax | Show exact YAML shapes and alternatives. Link field names or adjacent index entries to their canonical records, and label placeholders as non-executable notation. |
| Properties | Provide a compact linked field index and stable records for each property, including every nested type and conditional variant. |
| Resolution and effects | Explain where and in what order references are looked up, how inheritance and overrides work, which values are computed and which component produces each significant output. |
| Worked examples | Give a minimal value accepted by its validator and a complete configuration using it, a nested or conditional example, and a meaningful invalid variation with its diagnostic and correction. |
| First installation and later deployments | State actual support, prerequisites, identities, data and private inputs that must be preserved, effects of changes, rejected operations and unknown behavior. |
| Verification and diagnostics | Identify the validator and compiler checks, relevant failures and what the evidence establishes. Link to operations pages rather than duplicating execution instructions. |
| Navigation | Link the parent or index, related concepts, tasks and types, compatibility changes and a complete example. |

For a small type, combine sections when all facts remain easy to find. For a large type, split named reusable nested objects into their own anchored sections/pages and link from every use. Field-name search and direct deep links MUST work without requiring a reader to infer the type from prose.

### 3.2 Applicability rules

| Topic | Required when… | Correct handling when inapplicable |
| --- | --- | --- |
| Creation/update/restart/replacement | The object controls or changes execution, persistent identity, runtime configuration or provider resources | For a value type, identify the component that uses it and link directly to that component's lifecycle |
| Secret/material handling | A field selects, transports, derives or exposes credentials or other private data | State that the value contains no private data only when useful; do not add a generic warning to every scalar |
| Units/ranges/format | The accepted value has such constraints | Do not invent a range for an unconstrained field; name the actual validator limits |
| Null/empty/omitted | They are accepted, rejected or semantically distinct | Group an identical rejection rule at the object/type level and link to it; record exceptions at their fields |
| Inheritance/override | A template/profile/context/source contributes values | Show precedence and explain which values are merged, replaced or appended; a standalone value may state that it has no inheritance |
| Outputs | Compilation or execution produces a meaningful result | For a helper type, name the consumer and resolved value; do not invent a resource or packet |
| External prerequisites | A declaration depends on trust, artifacts, platform capacity, files, services or authority | Do not invent setup steps; explain only what configuration validation establishes |
| Version/change notes | Availability, behavior or compatibility depends on a revision | Give the known boundary; do not add an empty change-history table |

Authors MUST provide the applicable facts, not repeated “N/A” boilerplate. When an expected topic would otherwise mislead, one sentence explaining its inapplicability is sufficient. An unknown is not inapplicable: label it explicitly and prevent stronger claims.

## 4. Property records and nested types

### 4.1 Reusable property record

Each accepted field MUST have one canonical, directly linkable record containing the following information. A compact table may satisfy simple records; complex fields need prose beneath it.

| Record element | Required precision |
| --- | --- |
| Name and placement | Give the exact key, full path and variant, for example `guests.<id>.interfaces.<id>.address.value`. Explain that `<id>` represents a user-chosen key. |
| Purpose/effect | Explain what the value does, distinguishing the requested configuration, resolved value and later action |
| Type | Name the exact scalar, container or union type and link nested types. Distinguish integers, numbers, Booleans and strings. |
| Presence | State whether the field is required, optional or conditionally required, and give a condition a reader can test instead of “if needed” |
| Omitted/default | Give the literal default or how it is derived, and identify where it is applied. Do not invent defaults for required fields. |
| Null/empty | Whether null, `""`, `{}` and `[]` are accepted and what they mean where relevant; omission is not assumed equivalent |
| Inheritance | Identify where inherited values come from and their precedence. Explain whether fields or containers are appended, replaced or merged, including exceptions. |
| Domain | Give the enforced units, inclusive or exclusive limits, enumerated values, patterns, order, uniqueness, case sensitivity, size limits and canonical form |
| Relationships | Identify reference targets and lookup scope, when resolution occurs, prerequisites, dependencies, conflicts and permitted combinations. Link each relevant definition. |
| Outputs/security | Describe resulting values and files, who protects private data, and whether compilation reads private contents or only metadata |
| Change behavior | Explain supported changes, what the consuming component does, possible restarts or interruptions, and provider actions that trigger replacement and whether HomeLab rejects them. State what has not been tested. |
| Examples/diagnostics | Small meaningful example or link to a named example; relevant failure and practical correction |

“Optional string” is not a complete record. “See schema” is not a substitute. A prose field list without anchors is insufficient for a nested public API.

### 4.2 Nested, alternative and conditional structures

A named object MUST have its own syntax, property inventory and contextual return link to its enclosing type. Tagged unions MUST document every discriminator value and the exact keys accepted/required for each branch. Document mutually exclusive alternatives, shared fields and unknown-key rejection. A single example of one branch is not coverage of the others.

Explain where each check runs. Parsing, component validation, reference resolution, profile binding, packet generation (lowering), deployment admission and runtime checks may impose different conditions. A value that passes structural validation MUST NOT be described as supported by a profile that rejects it later. A schema default MUST NOT be described as a value inserted at runtime unless the identified implementation actually applies it.

Explain how declarations are reused: a guest NIC references a network, an app binds an interface to an allowed role and scope, a connection selects its endpoint, account and transport, and an exposure declares publication. A reference that supplies a value MUST NOT be described as creating an execution wait, access rule, route, reservation, DNS record or credential unless its documented behavior does so.

For defaults, give one precedence example with input and effective result. For a conditional rule spanning objects, place the rule at its owning canonical type and link from all affected properties; do not copy divergent versions.

## 5. Contextual linking and navigation

### 5.1 Links where the decision occurs

References MUST link in context. At the property or sentence where the reader encounters a requirement, link to its named type, prerequisite, interacting setting, lifecycle limit, diagnostic and worked example as applicable. A final “related links” section alone does not meet this requirement.

Use descriptive labels such as “guest NIC address variants” or “plan restrictions for later updates”. Avoid “here”, implementation filenames without an explanation, and links to a broad index when a stable field anchor exists. Syntax blocks cannot reliably contain ordinary Markdown links, so put a linked field index alongside them.

Every reference page MUST link to its parent/index and concept/task entry. Every complete example MUST link to the contracts it demonstrates. Concepts/tasks MUST link back to exact reference records. A nested type MUST link back to its principal uses; a shared type may list representative consumers and link to an index rather than repeat hundreds of links. A new leaf page MUST have at least one intentional inbound link from its owning index or parent.

### 5.2 Stable anchors and canonical definitions

Use explicit, descriptive headings and unique anchors. Repeated generic headings such as `Properties` under multiple types produce fragile ordinal anchors; prefer names such as `Guest NIC address` or stable explicit anchors where necessary. Preserve anchors when renaming headings, or update every maintained inbound link in the same change and provide a replacement where external links are likely.

Use repository-relative links for maintained pages in the same repository when they remain correct at the adopted location. Use public repository URLs for cross-repository targets, with immutable revisions for compatibility-sensitive examples and factual baselines. Normal navigation may use maintained branch documentation, but MUST identify that it can drift. Do not use workstation paths, staging paths, private hosts or undocumented website macros. Public reusable repositories may link to each other.

Link to one canonical definition; summarize a consumer-specific restriction and link to that definition. Avoid linking every repeated common noun. Link the first meaningful use within a section and repeat at a later decision point when the reader would otherwise need to search. Useful links reduce inference; redundant links add noise. Review both the click destination and whether the link actually answers the surrounding question.

### 5.3 Link maintenance

For changed pages, check local file existence, anchor existence, case, duplicate headings, renamed targets and incoming links. Review orphan pages and canonical-index reachability. Check external links or record the access limit; a network error is not proof that a target is obsolete. Link checks alone do not prove semantic relevance. Versioned links MUST point to the revision actually tested; changing an example pin requires compatibility validation.

## 6. Examples and reproducible commands

### 6.1 Example classes

Every code block MUST be identifiable as one of:

| Class | Meaning and validation |
| --- | --- |
| Syntax notation | Shows the shape with explicit type placeholders and discriminators, clearly marked as non-executable |
| Complete typed value | Passes the named component or source-file validator and identifies its placement and required surrounding declarations |
| Explanatory fragment | Demonstrates a relationship or change that cannot compile alone; links to the complete configuration |
| Complete offline composition | Supplies the required library, site, catalogue and typed files, tested through actual parsing, reference resolution and packet generation without target access |
| Deployment procedure | Requires compatible configuration, a supported profile, prepared platform and trust inputs, protected private files and authorisation; claims only the outcome actually evidenced |
| Invalid variation | Deliberately fails the named check, with an expected diagnostic and correction |

A “minimal” example MUST include everything required by its validator and identify all necessary surrounding configuration. A useful complete example MAY include more than the minimal value. Show how the minimal value fits into the complete configuration. Do not imply that unrelated fragments can simply be joined into a valid site.

Use synthetic coherent names, locally administered MACs, documentation/test addresses and example domains. Synthetic private-material examples MUST contain references or obvious nonfunctional sample metadata, never real credentials. If a value deliberately cannot pass deployment admission, say so next to the example. Do not obscure invalid values with unexplained placeholders in a block claimed to execute.

### 6.2 Required demonstrations

A new component MUST have a minimal valid example, a practical composition and meaningful failure examples for its major semantic boundaries. A union MUST demonstrate each materially different branch somewhere in the maintained suite; repetitive scalar permutations do not require a separate tutorial. Conditional reference/role/credential/default rules need examples that reach the relevant boundary.

A failure example MUST state: input change, failing stage, actual code/message, cause, supported correction and what remains unproved. Reuse an existing tested case when it supplies this evidence. Do not engineer an unrelated earlier error merely to make an example fail. If a diagnostic is generic, document it honestly and add the useful interpretation in prose; do not invent a more descriptive emitted code.

Examples MUST have stable IDs and an inventory linking them to their validators and integration tests. Use the repository's actual source reader and accepted grammar. Tests may select named YAML code blocks, but MUST NOT introduce a separate grammar for documentation. Keep complete configurations readable as source files rather than hiding required declarations inside a Python fixture.

### 6.3 Commands

Before a command sequence, define the checkout/revision, starting directory, interpreter/tool versions, locked dependencies, input files, environment and output location. Commands MUST preserve quoting, real newlines and exit status. Define variables before use and avoid common system-variable names. Explain expected output and a concrete inspection/next check.

Run source checks in disposable temporary directories and resolve symlinks in their root paths before using the confined source reader. Commands that create packets or reports require a new child path that does not yet exist, rather than the existing temporary parent. Keep private runtime output outside committed source and out of logs. Rehearse executable tutorial or task commands in the stated isolated environment. Documentation validation must not trigger a real deployment.

## 7. Installation, maintenance and failure semantics

### 7.1 Required lifecycle language

Use **First installation** and **Later deployments** as reader-facing headings. Explain actual behavior before exposing internal labels:

- `fresh` allows supported creation when neither a HomeLab owner nor the backend exists. Keep the same configuration for later updates to that HomeLab-managed installation.
- `retained` requires genuine evidence that HomeLab already manages the installation. It does not import or adopt resources, or create a missing owner.
- Guest and app policies are separate. A supported new app may be created on a guest already managed by HomeLab if the app meets its prerequisites and does not overlap another app's names, paths or resources.
- A retained-only adapter does not gain a creation path by changing a lifecycle value.

Never tell readers to toggle `fresh` after successful installation. Creation support depends on adapter, selected profile and external prerequisites, not merely accepted YAML. State whether data initialization, account creation, credential bootstrap, image provisioning and commissioning are actually implemented.

### 7.2 Change-effect record

For each object or profile that controls execution, document the applicable situations below:

| Situation | Facts to state |
| --- | --- |
| First installation | Give the supported platform and procedure, required backend absence and conflicts, trust, file, artifact, credential and traffic prerequisites, and what may only be created once |
| Ordinary owned update | State which configuration to keep, required ownership records, receipts, state and app inputs, which effective inputs change and which phases are affected |
| Disruptive change | Explain effects on restarts, recreation, processes and networks supported by code inspection or tests; state operational uncertainty |
| Provider replacement | Which change can produce a replacement and whether the HomeLab policy refuses it; do not equate provider capability with framework permission |
| Persistent identity/material | Identify names, VMID, node, storage, runtime files, services, accounts and devices that must remain unchanged, and the checks protecting them |
| Removal/rotation/import/restore | Describe the supported procedure or state that it is absent or rejected. Do not infer cleanup or recovery guarantees. |
| Failure | State effects that may already have occurred, evidence and markers to preserve, supported diagnostic limits and the need for separate recovery authorisation |

Calling a plan “guarded” is insufficient. Explain the checks and their limits, with links to the implementation and operating procedure. The current ordinary LXC saved-plan policy accepts exactly the selected guest and its two firewall resources; first installation requires three create actions. Existing resources permit updates or no-ops, preserve the selected identity and data fields, and reject import, move, adoption and replacement. An allowed update may still interrupt service. Profile references MUST state any tighter limits.

### 7.3 Deployment and CD

Operations documentation MUST identify the workflow responsible for execution and explain its phase order: infrastructure, preparation, app phases and the optional monitoring agent. Explain how declared dependencies and readiness checks affect that order. Identify which operation runs OpenTofu and which configures services through Ansible. Keep value references, access rules and readiness dependencies distinct.

For later maintenance, explain how to change configuration, check the resulting output and select compatible immutable dependencies. Describe how the deployment repository's protected CD supplies the reviewed environment, runner, secrets and authorisation, and which receipts and target checks establish completion. Public documentation MUST link to the reusable protocol and identify the setup the operator supplies without publishing a default production site.

Successful compilation does not test configured secret/trust files, real allocations or target services. Successful CD does not itself establish public TLS, authentication, data integrity or device/user behavior unless those checks were actually performed. No generic retry, HOLD deletion, rollback, restore or import procedure may be invented. Failure documentation MUST retain the actual stopping boundary and preserve current evidence.

## 8. Authoring and structural generation

### 8.1 Source-led authoring workflow

Before editing reference text, inspect the implementation at the selected revision. Inventory parsing rules, validators and their accepted fields, nested helper types, reference and binding conditions, defaults, packet generators, receiver checks, admission and runtime checks, diagnostics and relevant tests. Follow internal calls and references because a schema may not contain every effective requirement.

For every contract change:

1. Record the changed path and variant, the implementation layer involved and the code responsible for it.
2. Establish whether behavior changed or the documentation was wrong. Challenge conflicts rather than copying either side uncritically.
3. Update the canonical record, contextual links, affected examples, concepts and task guides, and the compatibility or change note.
4. Update the inventory and evidence mappings, reusing meaningful existing checks.
5. Run the relevant source, example and link checks, then read the rendered Markdown and follow the full reader route.
6. Report what was inspected or tested and what remains unverified. Before changing a failed test's expectation, establish whether the implementation or the test is wrong.

An unrelated implementation defect discovered during documentation work MUST be surfaced separately. Documentation may accurately describe a limit or discrepancy; it MUST NOT silently fix behavior, introduce migration flags or claim unsupported capability.

### 8.2 What may be generated

Tools MAY extract accepted paths, named types, required and optional keys, enumerated values, limits, diagnostic codes, source references and initial traceability records when the implementation explicitly encodes them. Every generated record MUST retain its path, variant, implementation layer and source location. Generated output MUST be reviewable and deterministic.

Authors MUST explain purpose, conditions spanning objects, inheritance, supported combinations, lifecycle behavior, operating limits, responsibility for security and practical diagnostic steps, unless trustworthy source metadata already explains them explicitly. Authors MUST check generated defaults against the implementation that applies them.

Do not duplicate schema definitions in a generator merely to print tables. Do not publish giant dumps of implementation internals, repeated low-value records or placeholder prose. Preserve authored explanations and canonical nested definitions. Generating field names is assistance, not proof of completeness. Implementing a generator is a separate engineering decision; this standard does not require one before useful documentation can be written.

## 9. Coverage and evidence

### 9.1 Inventory and traceability

Maintain a reviewable inventory with stable row IDs. Coverage counts must use the complete set of accepted public inputs and behavior at a named revision; do not invent a count of missing fields. Include roots, nested paths, alternatives, conditions, defaults, references, diagnostics, support and lifecycle rules, CLI arguments and outputs. Distinguish new configuration inputs from immutable historical evidence formats.

Each row MUST contain at least:

`ID | owner/source/revision | full path + variant | validating/applying layer | rule/default/effect | canonical page#anchor | example ID(s) | evidence/test ID(s) | evidence level | status/exception`

A cross-object rule may have its own ID linked from affected field rows. Dynamic maps need the key grammar and value type, not one row for every possible user ID. A field accepted in multiple variants needs separate rows when its semantics differ. Output and runtime rules need rows even when absent from an input schema.

Completeness criteria:

- **100% inventoried public paths/variants** link to a canonical explanation, or have a justified exclusion identifying them as internal-only.
- **100% inventoried semantic conditions/defaults/reference rules** link to an explanation and relevant evidence. Merely finding the field name in prose does not count.
- **100% public diagnostic codes** identify the stage that emits them and give useful handling instructions, either individually or in a shared category that preserves the distinctions readers need.
- **100% claimed executable examples** have evidence from the responsible validators. Complete configurations also have evidence from actual reference resolution and packet generation.
- **Zero unresolved broken local links/anchors, orphan references, unresolved placeholders or contradictory duplicate definitions** in the changed scope.
- **Zero unsupported operational guarantees**. Unknowns and behavior not tested on a target are stated explicitly and cannot be counted as verified.

Report covered/total counts and exclusions by category. Record unknown inventory boundaries separately; a percentage with an incomplete denominator is not completeness. Full-suite coverage requires a reconciled full inventory, not extrapolation from sampled pages.

### 9.2 Evidence ladder

| Evidence | Establishes | Does not establish |
| --- | --- | --- |
| Parsed | Accepted YAML/JSON bytes and authored-reader behavior | Component meaning or references |
| Direct component test | Checks of actual fields, types and constraints, including invalid inputs | App/guest orchestration or real deployment |
| App/guest unit with component collaborators mocked | The unit calls and combines its collaborators as intended | Acceptance by actual collaborators or integrated packet generation |
| Real compiler integration | Names, profiles, bindings, dependencies, defaults and generated packets and workflows agree | Actual target trust, credential or file availability, installation or service health |
| Receiver/controller test with native operations faked | Control flow for the tested packet, receipt, state and ownership checks | Actual platform commands or live service behavior |
| Isolated protocol/native fixture | The named filesystem, command or service behavior under the fixture's stated conditions | A complete deployment or behavior in the operator's environment |
| Deployment evidence | The stated source, workflow, run, attempt and phases completed on the target | Every service, authentication, data, device or user outcome |
| Service acceptance | A newly observed, specific outcome in the target environment | Untested future updates, recovery or unrelated services |

Use evidence that supports the claim and reuse trustworthy tests rather than adding assertions that merely repeat the implementation. Text-presence tests, AST key scans and code-coverage percentages can detect regressions. They do not establish complete configuration path or variant coverage, accurate field explanations, useful navigation or beginner usability. The current field-name test is useful, but it must not be described as an audit of all field meanings.

### 9.3 Verification process

Check changed examples with the actual source parser and component validators. Compile complete configurations through reference resolution and packet generation using the real components and a compatible library. Confirm that invalid examples reach the intended error without disclosing private values. Compare descriptions of defaults and limits with both validation and resolved behavior. Rehearse executable shell steps in a disposable environment. Run the applicable checks from the testing guide and do not claim checks that were not run.

Review the rendered Markdown on GitHub or an equivalent Markdown renderer: headings, tables, code fences, contextual links, nested navigation and example placement. Walk a newcomer from entry to offline result and onward to real preparation; walk an experienced reader from field to nested constraint to diagnostic and back. Report rendering/navigation inspections separately from automated checks.

## 10. Review rubric and definition of done

### 10.1 Severity and blocking criteria

| Severity | Examples | Disposition |
| --- | --- | --- |
| Blocker | Real secrets or private identities; dangerous operations described as ordinary maintenance; invented support for import, replacement, rotation or recovery; false deployment or service claims | Must fix before publication; do not publish a known misleading contract |
| Major | A missing path, variant or conditional rule; wrong default, type, unit or precedence; broken required example; incorrect support or lifecycle limit; a missing link needed for correct use | Blocks affected page/contract acceptance |
| Moderate | A missing useful failure example; insufficient diagnostic guidance; an unclear transition; an unlinked page; a fragile anchor or incomplete update to incoming links | Fix within scope, or record who will follow up and why it is deferred without claiming full completion |
| Minor | Redundant wording or links, inconsistent style, or a small presentation issue that preserves meaning and navigation | May defer with a specific reason |

Reviewers MUST distinguish a style preference from an error in the documented behavior. A table or prose may satisfy a requirement if the explanation is complete, easy to find and precise. Assess proposed exceptions against the reader's task. It is acceptable to say that target behavior is unknown; making an unsupported promise is a blocker or major defect, depending on its consequences.

### 10.2 Definition of done

A documentation change is complete when all of the following hold:

- Its scope and source revisions are explicit, and changed inventory rows link to the correct canonical records.
- The applicable [page](#3-reference-page-contract), [property](#4-property-records-and-nested-types), [link](#5-contextual-linking-and-navigation), [example](#6-examples-and-reproducible-commands) and [lifecycle](#7-installation-maintenance-and-failure-semantics) requirements are met.
- Meaningful existing checks pass at the stated layers, and reviewers have read the rendered pages and followed their links.
- Privacy, ownership and compatibility requirements remain satisfied.
- No blocker or major defect remains.

The review record MUST list evidence obtained, tests and checks not run, unresolved facts and accepted exceptions. It MUST record a full-page reading review against the plain-language criterion in [Reader needs](#12-reader-needs), not just a keyword scan. Self-review is not independent peer review. A documentation-only review MUST NOT be used to claim that broader checks passed or that behavior was verified on a target.

## 11. Worked reference specimen: network and guest NIC

This historical example illustrates the standard at a fixed revision. Use [Networks and guest NICs](../reference/networks.md) for the maintained current reference. The example describes the accepted `homelab-components-v1` contract at framework revision [`93ffed7cd5c30b23786e858b1134317b2ccb9118`](https://github.com/theaussiepom/homelab/tree/93ffed7cd5c30b23786e858b1134317b2ccb9118), where it was checked. Its pinned links preserve that evidence. Authors adopting the example MUST recheck the facts against the revision they document.

### 11.1 Purpose and placement

A network is one `networks.<id>` value in a site. It names the bridge, VLAN and IPv4 subnet used by [guest NICs](#114-guest-nic). It describes desired inputs; it does not create a host bridge, configure an external DHCP server or reserve a lease. The guest deployment procedure applies these values. See the complete [offline site](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/examples/first-configuration/site.yaml), [library](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/examples/first-configuration/stack.json) and [image catalogue](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/examples/first-configuration/images.json).

### 11.2 Network syntax and field index

The block below is a **complete network value** placed at `networks.primary`; it needs the surrounding site and context from the linked complete example. It uses synthetic values validated offline and cannot pass deployment admission.

```yaml
context: lab
cidr: 198.18.20.0/24
bridge: example0
vlan: null
gateway: 198.18.20.1
```

| Field | Presence/type | Canonical record |
| --- | --- | --- |
| `context` | Required identifier string | [Network context](#field-network-context) |
| `cidr` | Required string | [Network CIDR](#field-network-cidr) |
| `bridge` | Required string | [Network bridge](#field-network-bridge) |
| `vlan` | Required integer or null | [Network VLAN](#field-network-vlan) |
| `gateway` | Optional IPv4 string | [Network gateway](#field-network-gateway) |

Network objects accept only the listed fields; extra keys produce `component.fields`. Fields are not inherited or merged from a template. Required fields have no defaults, so an empty map is invalid. Only `vlan` accepts null. The value contains no credentials or other private data and does not reference a secret source.

### 11.3 Network property records

<a id="field-network-context"></a>
#### Network context

`networks.<id>.context` is a required identifier matching `[a-z][a-z0-9_-]{0,62}`. It cannot be omitted, null or empty. It identifies the context of a guest using the network. Structural validation checks the identifier format. When a guest uses the network, the resolver requires its context to match the guest's existing context. The inspected resolver did not always check whether an unused network's context existed; successful validation therefore cannot establish that fact. See [context contracts](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/reference/contexts.md) and [guest placement](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/reference/guests.md).

<a id="field-network-cidr"></a>
#### Network CIDR

`networks.<id>.cidr` is a required IPv4 network string in strict canonical form. `198.18.20.0/24` is valid; `198.18.20.10/24` is rejected because it is not the network address. IPv6 networks, null and empty values are also rejected. The resolver uses its prefix length for [static NIC values](#field-guest-nic-address) and checks declared static and DHCP addresses against the subnet. It does not promise to normalize noncanonical input.

<a id="field-network-bridge"></a>
#### Network bridge

`networks.<id>.bridge` is required text of 1–4096 characters without NUL. Omitted, null and empty values are rejected. The compiler copies the value into the NIC configuration sent to the provider, but accepting it does not prove that the bridge exists. Host-side bridge/VLAN availability is an external [deployment prerequisite](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/operations/deployment.md#prerequisites).

<a id="field-network-vlan"></a>
#### Network VLAN

`networks.<id>.vlan` is required. Use null for no VLAN tag, or an integer from 1 through 4094 inclusive. Booleans, numeric strings, zero and 4095 are rejected. There is no implicit default or inherited VLAN. A network with `vlan: 121` uses the same shape as the untagged example; the linked complete site shows that tagged secondary network. This declaration does not create a VLAN on a physical switch or bridge.

<a id="field-network-gateway"></a>
#### Network gateway

`networks.<id>.gateway` is an optional canonical IPv4 address string. If supplied, it must belong to the subnet and cannot be its network or broadcast address. It has no default: omitting it supplies no gateway, while null and empty values are rejected. A static NIC with [`default_route: true`](#field-guest-nic-default-route) requires this field, as does a selected non-default static source-policy-route NIC under its separate [guest rule](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/reference/guests.md). DHCP mode does not use this field to reserve or verify an external lease.

### 11.4 Guest NIC

A NIC is one `guests.<id>.interfaces.<id>` value that uses the selected [network](#112-network-syntax-and-field-index). This **complete NIC value** belongs at `guests.resolver.interfaces.management` in the complete offline site:

```yaml
network: primary
slot: 0
mac: 02:00:00:20:00:10
address: {mode: static, value: 198.18.20.10}
default_route: true
ipv6: manual
```

| Field | Presence/type | Exact semantics |
| --- | --- | --- |
| `network` | Required identifier | [Network reference](#field-guest-nic-network) |
| `slot` | Required integer | [Slot](#field-guest-nic-slot) |
| `mac` | Required string | [MAC identity](#field-guest-nic-mac) |
| `address` | Required object selected by its mode | See [address branches](#field-guest-nic-address). No default for omitted, null or empty values. |
| `default_route` | Optional Boolean | The resolver treats omission as false and rejects null, numbers and strings. See [route rules](#field-guest-nic-default-route). |
| `ipv6` | Optional string | [IPv6 setting](#field-guest-nic-ipv6) |

The NIC accepts only the listed fields. Required values have no defaults and cannot be omitted, null or empty. Exceptions for optional fields are stated in their records. The compiler derives the bridge, VLAN, prefix and gateway from the network as described below; it does not otherwise inherit network fields. The NIC has no credential fields.

<a id="field-guest-nic-network"></a>
#### Guest NIC network

`guests.<id>.interfaces.<id>.network` is a required identifier using the same format as [network context](#field-network-context). It selects a site `networks.<id>` object whose context must match the guest's context. The resolver copies the bridge and VLAN and derives the address, prefix and gateway. A network is never selected implicitly. See the [network field index](#112-network-syntax-and-field-index) and [missing-network failure](#116-failures-and-correction).

<a id="field-guest-nic-slot"></a>
#### Guest NIC slot

`slot` is a required integer from 0 through 31 inclusive. Slots on a guest must start at zero and continue without gaps or duplicates. Booleans and strings are rejected. The resolver sends NICs to the provider in slot order, regardless of map order. Changing slots changes that order and must satisfy the [update limits](#117-first-installation-and-later-deployments). Valid slot values do not guarantee safe hot-plug or reordering.

<a id="field-guest-nic-mac"></a>
#### Guest NIC MAC

`mac` is a required string containing six hexadecimal octets separated by colons. Uppercase and lowercase letters are accepted, and collision checks ignore case within the same provider address and node. The synthetic example uses a locally administered value. HomeLab does not allocate MAC addresses or discover their use outside the configuration. Later trust and reachability checks use this identity; changing it does not permit import or bypass ownership checks.

<a id="field-guest-nic-ipv6"></a>
#### Guest NIC IPv6

`ipv6` is optional. If supplied, it must be exactly the string `manual`; null, empty and other values are rejected. Omitting it leaves the field out of the NIC configuration sent to the provider. It does not support general IPv6 allocation, and IPv6 literals accepted in policies do not add values to this field.

<a id="field-guest-nic-address"></a>
#### Guest NIC address

`address.mode` is required and must be exactly `static`, `dhcp` or `manual`. It determines which fields the object accepts:

| Mode | Exact accepted value shape | Conditions and resolved effect |
| --- | --- | --- |
| `static` | `{mode: static, value: 198.18.20.10}` | Requires a canonical IPv4 `value` that is a usable member of the selected subnet. The resolver appends its prefix. `endpoint` is forbidden. |
| `dhcp` | `{mode: dhcp, endpoint: 198.18.20.10}` | Requires a canonical IPv4 `endpoint` that is a usable subnet member. It names the expected address; the environment must supply the lease. `value` is forbidden. |
| `manual` | `{mode: manual}` | Forbids `value` and `endpoint` and supplies no app address. Cannot be the guest's control interface or supply a role requiring an address. |

The table shows the exact accepted syntax for each mode. These fields hold address values; they do not reference endpoint objects.

| Nested field | Presence | Canonical record |
| --- | --- | --- |
| `address.mode` | Required discriminator string | [Address mode](#field-guest-nic-address-mode) |
| `address.value` | Required for static; forbidden otherwise | [Static address value](#field-guest-nic-address-value) |
| `address.endpoint` | Required for DHCP; forbidden otherwise | [DHCP endpoint](#field-guest-nic-address-endpoint) |

The mode and required fields cannot be omitted, null or empty, and extra fields are rejected. A usable address is neither the selected subnet's network address nor its broadcast address. Duplicate declared addresses are rejected within the same provider address, node, bridge and VLAN. This check does not discover external allocations.

<a id="field-guest-nic-address-mode"></a>
##### Guest NIC address mode

`address.mode` is required and must be exactly `static`, `dhcp` or `manual`, with no default. It determines the required and forbidden fields and the resulting values in the [branch table](#field-guest-nic-address). Null and empty values are rejected. Changing mode also changes the [ordinary-route calculation](#field-guest-nic-default-route) and may affect reachability; it is not guaranteed to be seamless.

<a id="field-guest-nic-address-value"></a>
##### Guest NIC address value

`address.value` is required when `mode: static` and forbidden in the other modes. It must be a canonical IPv4 address without a prefix or port. It has no default and rejects null and empty values. The resolver requires a usable member of the selected [network CIDR](#field-network-cidr), checks for duplicates within the same provider address, node, bridge and VLAN, and appends the network prefix for provider output.

<a id="field-guest-nic-address-endpoint"></a>
##### Guest NIC address endpoint

`address.endpoint` is required when `mode: dhcp` and forbidden in the other modes. It follows the same canonical IPv4, usable-subnet and duplicate-address rules as [static value](#field-guest-nic-address-value). It has no default and rejects null and empty values. It records the expected DHCP address without allocating a lease. Deployment checks the actual DHCP and trust prerequisites later.

<a id="field-guest-nic-default-route"></a>
#### Guest NIC default route

Only a static NIC may set `default_route: true`, and its network must provide a [gateway](#field-network-gateway). Each guest needs exactly one effective ordinary route: one DHCP NIC or one static NIC with the flag true. A DHCP NIC already supplies the ordinary route, so setting the static-only flag on it is rejected. A manual NIC cannot supply that route. Source-policy routing is a separate guest setting and does not provide a second ordinary route.

For a valid DHCP variation, change the management address to `{mode: dhcp, endpoint: 198.18.20.10}` and remove `default_route` or set it false. The other NIC in the complete example remains static and non-default. This offline variation does not test a real lease or target trust. Each mode has its own accepted fields, and all remain subject to ownership and address checks.

### 11.5 Resolution and output

For the static example the resolved provider NIC contains `bridge: example0`, `vlan: null`, the selected MAC, `ipv4: 198.18.20.10/24`, `gateway: 198.18.20.1`, and `ipv6: manual`. The guest's interface-address lookup yields `198.18.20.10`. App roles can use that guest interface only through the scopes and bindings their profile accepts. A NIC does not automatically publish an app endpoint, grant network access or make execution wait for service readiness. See [app bindings](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/reference/apps.md), [connections](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/reference/connections.md) and [exposures](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/reference/exposures.md).

### 11.6 Failures and correction

At the stated revision, the following variations were checked through actual reference resolution and packet generation using a disposable copy of the linked complete example. Each changed one input from the valid baseline.

| Change | Actual refusal | Correction and boundary |
| --- | --- | --- |
| Set primary CIDR to `198.18.20.10/24` | `component.invalid at networks.primary` | Use the canonical network address, `198.18.20.0/24`; does not verify host routes. |
| Set VLAN to `4095` | `component.integer at networks.primary` | Select null or an integer 1–4094 according to the actual environment. |
| Set gateway to null | `component.invalid at networks.primary` | Omit it when no static default route or source-policy route requires it, or supply a usable subnet member. |
| Change management to DHCP while retaining `default_route: true` | `component.invalid at guests.resolver.interfaces.management` | Remove `default_route` or set it to false. Supply the required DHCP endpoint and retain exactly one effective route. |
| Change management network to `missing` | `component.invalid` | Declare the required network or select an existing network in the guest's context; the diagnostic does not emit a more detailed missing-network code. |

Do not “fix” these by disabling validation or changing a test expectation. For generic failures, compare the named declaration with its canonical field/rule record and preserve the source/revision needed to reproduce the refusal without disclosing values.

### 11.7 First installation and later deployments

A network value is not installed separately. A supported guest installation uses it and requires a compatible host bridge, VLAN, subnet, address allocation and trust inputs. The [guest lifecycle](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/reference/lifecycle.md) governs installation and updates. The linked tutorial is offline-only and deliberately unsuitable for deployment admission.

Later changes affect the NIC configuration sent to the provider and can alter reachability. At the inspected revision, the saved-plan policy rejected replacement, import, move, adoption and changes to immutable guest fields. An allowed update or no-op did not guarantee online renumbering or uninterrupted management access. MAC, control-interface, address and reachability checks still applied. The inspected contract provided no automatic bridge provisioning, lease reservation, destructive replacement, arbitrary import or rollback. Review the deployment procedure before a potentially disruptive change.

### 11.8 Verification and navigation

The functions [`network` and `interface`](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/blueprints/component_types.py) validate the input structure, with guest route and layout checks in the same module. [`guest_values`](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/blueprints/component_plan.py) resolves references and generates provider values. The maintained [reference example tests](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/blueprints/test_component_reference_examples.py) parse named examples and perform actual reference resolution and packet generation. They fake or block native and network operations and do not install a guest.

The checked source baseline passed all ten tests in that module. The network and NIC code blocks were parsed with the actual source reader and directly validated. Complete variants with static addressing, DHCP management and a manual secondary NIC also passed reference resolution and packet generation. The additional diagnostic cases above failed at the expected configuration checks. This historical evidence establishes parsing, validation, reference resolution and packet generation only; it does not establish deployment or working services. To reproduce the complete offline result, follow the pinned [first configuration tutorial](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/guides/first-configuration.md), including its environment preparation and new output path. For actual operation use [deployment prerequisites](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/operations/deployment.md), [support](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/reference/support.md) and [troubleshooting](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/operations/troubleshooting.md).

Return to the [reference index](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/reference/README.md), [network field index](#112-network-syntax-and-field-index), [nested address](#field-guest-nic-address) or [standard contents](#contents).

## 12. Contributor integration

This file is the single normative framework documentation standard. The former [documentation entry point](documentation.md) remains a compatibility pointer. The [contributor route](README.md), repository AGENTS and [reference](../templates/configuration-reference.md), [task](../templates/task-guide.md) and [tutorial](../templates/tutorial.md) templates all lead here. Existing security, signing, coverage and review gates continue to apply.

When a public field, rule or default changes, update its canonical record, affected complete examples and test pointers to implementation, documentation and evidence in the same reviewed change. Validators and declarations remain authoritative. Mappings contain locations, not a second catalogue of accepted values.

The [assurance record](documentation-assurance.md) distinguishes the automated network/NIC pilot from the wider reference pages. Before expanding it, inspect the responsible implementation, retain exact paths, variants and implementation layers, run the appropriate checks and read the rendered pages in context. A passing pilot does not establish complete semantic coverage of the repository.

New components still need a closed schema, useful diagnostics, explicit references, compiler integration, complete examples and appropriate evidence. Retire duplicate descriptions only after their replacements and incoming links are established. Do not alter production behavior or dependency selections to make a documentation assertion pass.

## 13. Design sources

The following sources informed this standard; they do not establish HomeLab support. The requirements above apply their useful documentation practices to a declarative YAML compiler and a deployment API that checks each operation.

| Primary source | Applied lesson and limit |
| --- | --- |
| [CloudFormation EC2 Instance](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-instance.html), [BlockDeviceMapping](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ec2-instance-blockdevicemapping.html), [update behavior definitions](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html) | Predictable syntax, per-property presence/type/effect records and nested links help lookup. Broad interruption labels need the conditional detail beside them. HomeLab must describe replacement refusal rather than borrow AWS replacement permission. |
| [Azure virtualMachines](https://learn.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines), [API change log](https://learn.microsoft.com/en-us/azure/templates/microsoft.compute/change-log/virtualmachines) | Named nested objects and explicit version changes support traceability. Large repeated language surfaces and catalogues are not a beginner route; HomeLab should keep one authored YAML contract and targeted complete examples. |
| [Compose specification](https://github.com/compose-spec/compose-spec/blob/main/spec.md), [services](https://github.com/compose-spec/compose-spec/blob/main/05-services.md), [Docker Compose reference](https://docs.docker.com/reference/compose-file/) | Readable declarative configuration, directly linked fields and composed objects inform contextual navigation. Similar syntax does not make Compose options accepted HomeLab input. |
| [Terraform AWS instance](https://github.com/hashicorp/terraform-provider-aws/blob/main/website/docs/r/instance.html.markdown), [provider introduction](https://github.com/hashicorp/terraform-provider-aws/blob/main/website/docs/index.html.markdown), [authoring guidance](https://github.com/hashicorp/terraform-provider-aws/blob/main/docs/end-user-documentation.md), [Registry documentation](https://developer.hashicorp.com/terraform/registry/providers/docs) | Separate inputs, outputs, interactions and operational limits; make examples and reference records usable. Import/state capabilities belong only where HomeLab actually implements them. |
| [Kubernetes Pod API](https://kubernetes.io/docs/reference/kubernetes-api/core/pod-v1/) | Link nested fields to concepts/tasks and explain lifecycle at the right owner. A dense generated API surface does not replace learning material or prove a deployment. |
| [Stripe PaymentIntent creation](https://docs.stripe.com/api/payment_intents/create), [confirmation](https://docs.stripe.com/api/payment_intents/confirm), [payment flow](https://docs.stripe.com/payments/payment-intents) | Concrete inputs/results and contextual operation links help readers distinguish stages and prerequisites. HomeLab output packets and observed native status are different stages, not HTTP request/response copies. |
| [OpenAPI 3.1.1](https://spec.openapis.org/oas/v3.1.1.html), [source Markdown](https://github.com/OAI/OpenAPI-Specification/blob/main/versions/3.1.1.md) | Named nested types, precise field tables, references and examples inform structural precision. Schema metadata alone does not prove default insertion, enforced formats or usable beginner guidance. |
| [GitHub REST getting started](https://docs.github.com/en/rest/using-the-rest-api/getting-started-with-the-rest-api), [authentication](https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api), [best-practices source](https://github.com/github/docs/blob/main/content/rest/using-the-rest-api/best-practices-for-using-the-rest-api.md) | Concepts/guides/reference links belong at decisions, with concrete examples and prerequisites. Website-specific source macros are not portable repository Markdown. |

[Return to contents](#contents)
