# HomeLab documentation standard

This standard governs documentation for **homelab**, the reusable configuration language, component contracts, compiler and deployment capabilities. Documentation is part of the public API: a reader must be able to author a valid declaration, understand its effective meaning and determine the supported execution boundary without reading implementation conversations.

**MUST** is a review requirement. **SHOULD** is the expected approach; a documented reason may justify an alternative that meets the reader's need. **MAY** is optional. These words govern documentation, not permission to change contracts or operate an installation. A proposed documentation improvement never authorizes an implementation change.

This is the canonical framework documentation policy. It defines the acceptance target; adoption does not certify every existing field or native operation. The [documentation assurance record](documentation-assurance.md) identifies the checked scope and remaining review obligations.

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

The framework MUST own the definitions of accepted source, reference resolution, compilation, generated deployment inputs, capability selection and enforced execution limits. It MUST explain these as reusable contracts. It MUST NOT require a consumer to reproduce a particular operator's environment.

| Owner | Canonical documentation | Boundary |
| --- | --- | --- |
| homelab | Authored API, typed components, validators, compiler, diagnostics, deployment protocol, adapter capability and support boundaries | Defines what the framework accepts, produces, executes and refuses |
| [homelab-stack](https://github.com/theaussiepom/homelab-stack) or another compatible library | Reusable guest/app profiles, supplied defaults, software/runtime selections and compositions | Selects and combines framework capabilities; cannot widen their support contract |
| Consumer deployment repository | Concrete allocations, endpoint identities, credential custody, runner/environment selections, approval and operating procedures | Supplies site-specific inputs and authority; must not redefine reusable field meanings |
| Upstream software/platform | Its supported product behavior | Useful contextual authority; does not prove a HomeLab adapter implements or qualifies that behavior |

Public pages MUST exclude private configuration, credentials, actual site allocations, private repository identities, local workstation paths and environmental recovery history. A concrete path required by an API is appropriate when synthetic and clearly explained; an operator's actual path is not. Migration/recovery evidence belongs to its actual owner and task. It MUST NOT become a new ordinary configuration prerequisite unless the accepted contract really requires it.

OpenTofu owns infrastructure/state and Ansible owns configuration/services. Documentation MUST preserve that division and the protected CD maintenance path. It MUST NOT suggest direct imperative edits as ordinary maintenance when those changes would compete with the declared owner.

### 1.2 Reader needs

Every page MUST choose a primary audience and question. The suite MUST support:

- A newcomer learning how a site, library, guest, app and service relate.
- An author composing a valid desired configuration, including nested and conditional cases.
- A reviewer checking effects, continuity, support and compatibility before a change.
- An operator preparing or verifying a supported installation and diagnosing a refused operation.
- A contributor extending a closed component contract without creating duplicate truth.

A reference page may serve several readers through links, but MUST remain a lookup contract. It MUST NOT hide a tutorial inside a property definition or assume a reader has completed a previous conversation.

### 1.3 Version and compatibility

References MUST identify the authored schema and supported contract selection. Cross-repository examples MUST name a compatibility tuple: framework revision, library revision, example revision and relevant fixed catalogue/tooling selection. A library's selected framework revision and an unrelated current framework main are different evidence. Documentation MUST NOT silently update either selection.

Change notes MUST distinguish fields added/removed, defaults changed, accepted shapes changed, diagnostics changed and execution support changed. Link the first relevant release/commit and replacement guidance where known. Do not invent API version numbers or deprecation periods. A dated inspection or passing source test is not an ongoing compatibility guarantee.

## 2. Information architecture and reader journeys

### 2.1 Page responsibilities

Keep the root README concise: purpose, supported scope, repository boundary and clear links to learn, reference, operate and contribute. The documentation index MUST expose those paths. Comprehensive coverage belongs in linked Markdown pages; an HTML platform and an enormous README are not prerequisites.

| Page type | Use it when the reader needs to… | Required contents | Exclude |
| --- | --- | --- | --- |
| Overview/index | Choose a route through the suite | Purpose, audience, scope, ordered entry points and canonical indexes | Exhaustive fields or repeated procedures |
| Concept | Understand a model or relationship | Vocabulary, ownership, relationships, constraints, small explained illustration, links to exact types and tasks | Unsupported architecture proposals stated as fact |
| Tutorial | Learn by completing a bounded result | Starting state, complete files, ordered steps, predicted/observed result, useful change, next stage and evidence boundary | Undefined existing resources or implied deployment from compilation |
| How-to/task | Complete one known task | Outcome, prerequisites, exact steps, verification, failure boundary, relevant fields | General introduction replacing actionable steps |
| Component/type reference | Look up accepted declarations and effects | [Reference page contract](#3-reference-page-contract), [property records](#4-property-records-and-nested-types), variants and examples | Source-code links substituting for field explanation |
| App/adapter reference | Determine the reusable adapter contract | Accepted properties, required bindings/material, generated effects and capability/lifecycle limits | Library defaults represented as framework-wide requirements |
| Composition guide | Combine components correctly | Complete coherent source, relationship explanation, value/readiness/permission distinctions, resolution and lowered effects | Fragments requiring readers to invent missing surroundings |
| Operations | Prepare, run or maintain a supported deployment | Authority/prerequisites, ownership, phases, exact action/verification boundary, supported failure handling | Invented import, HOLD release, retry, rollback or restore |
| Troubleshooting/diagnostic | Explain an actual failure | Code/symptom, stage, causes that evidence supports, bounded diagnostic, actionable correction, safe stopping point | Sensitive-value dumps or generic “check logs” advice |
| Contribution | Change and review the public contract | Owner, templates, inventory delta, tests/evidence, publication and review requirements | A parallel undocumented authoring standard |

A page combining responsibilities MUST separate them with explicit headings and links, and retain one canonical definition of each fact. Split a page when independent lookup targets or long unrelated sections obscure its primary task, not merely to satisfy a page-count goal.

### 2.2 A complete newcomer route

The suite MUST expose four distinct stages, with links in both directions:

1. **Offline synthetic tutorial:** author, validate, resolve and inspect a safe example without target access, credential reads, image pulls or service startup. State deliberate synthetic restrictions.
2. **Deployment preparation:** select a compatible library and supported profile; bind real allocations, trust, custody, capacity, platform and workflow requirements in the consumer's repository. Explain what source checks cannot establish.
3. **First supported installation:** link the real generic deployment contract and profile-specific capability limits. Name externally supplied prerequisites and the consumer-owned procedure that supplies them. Where no supported installation path exists, say so and give the actual supported next boundary.
4. **Service verification and later maintenance:** distinguish successful workflow completion from fresh observations of service, authentication, data or device behavior; describe ordinary declared updates and failure handling.

A safe compiler tutorial is valuable but does not by itself complete this journey. A tutorial MUST finish at its stated outcome and provide the next link without pretending to execute a later stage.

## 3. Reference page contract

### 3.1 Required structure

Every component/type reference MUST use the following reusable structure, adapted by the applicability rules below. These are content requirements, not instructions to publish empty headings.

| Section | Required authoring content |
| --- | --- |
| Purpose and location | Exact contract/type name, schema, owner, placement path, whether root/map value/typed leaf/fragment; what it controls and which owner consumes it |
| Syntax | Exact YAML shape and alternatives; link field names or nearby field index entries to canonical records; mark placeholders as non-executable syntax |
| Properties | Compact linked field index followed by stable per-property records; all nested types and conditional branches covered |
| Resolution and effects | Reference scope and order, inheritance/overrides, computed values, output owner and significant generated effects |
| Worked examples | Minimal valid owned value and a complete composition; nested/conditional case; meaningful invalid variation and diagnostic/correction |
| First installation and later deployments | Actual support, prerequisites, identity/data/material continuity, change effects and refused/unknown behavior |
| Verification and diagnostics | Owning validator/compiler checks, relevant failures and evidence boundary; link operations rather than duplicating execution instructions |
| Navigation | Parent/index, related concepts/tasks/types, compatible change information and complete example |

For a small type, combine sections when all facts remain easy to find. For a large type, split named reusable nested objects into their own anchored sections/pages and link from every use. Field-name search and direct deep links MUST work without requiring a reader to infer the type from prose.

### 3.2 Applicability rules

| Topic | Required when… | Correct handling when inapplicable |
| --- | --- | --- |
| Creation/update/restart/replacement | The object owns or changes execution, persistent identity, runtime configuration or provider resources | A pure value type states that its consumer owns execution, with a direct link to that consumer's lifecycle |
| Secret/material handling | A field selects, transports, derives or exposes credentials or other private data | State that the value contains no material only when the distinction helps; do not add a generic security warning to every scalar |
| Units/ranges/format | The accepted value has such constraints | Do not invent a range for an unconstrained field; name the actual validator limits |
| Null/empty/omitted | They are accepted, rejected or semantically distinct | Group an identical rejection rule at the object/type level and link to it; record exceptions at their fields |
| Inheritance/override | A template/profile/context/source contributes values | Show actual precedence and merge/replace/append behavior; a standalone value may say there is no inheritance |
| Outputs | Compilation or execution produces a meaningful result | For a helper type, name the consumer and resolved value; do not invent a resource or packet |
| External prerequisites | A declaration depends on trust, artifacts, platform capacity, files, services or authority | No imaginary setup steps; scope the type to source acceptance |
| Version/change notes | Availability, behavior or compatibility depends on a revision | Give the known boundary; do not add an empty change-history table |

Authors MUST provide the applicable facts, not repeated “N/A” boilerplate. When an expected topic would otherwise mislead, one sentence explaining its inapplicability is sufficient. An unknown is not inapplicable: label it explicitly and prevent stronger claims.

## 4. Property records and nested types

### 4.1 Reusable property record

Each accepted field MUST have one canonical, directly linkable record containing the following information. A compact table may satisfy simple records; complex fields need prose beneath it.

| Record element | Required precision |
| --- | --- |
| Name and placement | Exact key, full path and enclosing variant, for example `guests.<id>.interfaces.<id>.address.value`; dynamic `<id>` is notation, not a literal key |
| Purpose/effect | What choosing the value does; distinguish authored intent, resolved value and downstream action |
| Type | Exact scalar/container/named union; nested type link; integer versus number/Boolean/string distinctions |
| Presence | Required, optional or conditionally required; express the condition as a testable predicate, not “if needed” |
| Omitted/default | Literal default or derivation, and the layer that applies it; required fields have no invented default |
| Null/empty | Whether null, `""`, `{}` and `[]` are accepted and what they mean where relevant; omission is not assumed equivalent |
| Inheritance | Source of inherited value, precedence and field-level/container behavior; identify append/replace/merge semantics and exceptions |
| Domain | Units, inclusive/exclusive range, enum, pattern, ordering, uniqueness, case sensitivity, size limits and canonicalization actually enforced |
| Relationships | Target kind/scope, resolution phase, prerequisite, dependency/conflict and permitted combinations; link each relevant definition |
| Outputs/security | Resulting values/artifacts, disclosure/custody owner and whether source compilation reads material or only metadata |
| Change behavior | Supported change, consumer action, possible restart/disruption, replacement-triggering provider outcome and whether that outcome is refused; unknown qualification stated plainly |
| Examples/diagnostics | Small meaningful example or link to a named example; relevant failure and practical correction |

“Optional string” is not a complete record. “See schema” is not a substitute. A prose field list without anchors is insufficient for a nested public API.

### 4.2 Nested, alternative and conditional structures

A named object MUST have its own syntax, property inventory and contextual return link to its enclosing type. Tagged unions MUST document every discriminator value and the exact keys accepted/required for each branch. Document mutually exclusive alternatives, shared fields and unknown-key rejection. A single example of one branch is not coverage of the others.

Document acceptance at the correct stage. Structural parsing, component validation, reference resolution, selected profile binding, lowering, admission and native runtime guards may impose different conditions. A structurally accepted value MUST NOT be described as supported for a profile that refuses it later. A default annotation in a schema MUST NOT be described as an inserted runtime value unless the named implementation layer applies it.

Explain actual reuse: a network is referenced by a guest NIC; an app interface binding selects an allowed role/scope; a connection uses endpoints/account/transport; an exposure chooses publication. A reference that carries a value MUST NOT be said to create a wait, grant, route, reservation, DNS record or credential unless its actual named contract does so.

For defaults, give one precedence example with input and effective result. For a conditional rule spanning objects, place the rule at its owning canonical type and link from all affected properties; do not copy divergent versions.

## 5. Contextual linking and navigation

### 5.1 Links where the decision occurs

References MUST link in context. At the property or sentence where the reader encounters a requirement, link to its named type, prerequisite, interacting setting, lifecycle limit, diagnostic and worked example as applicable. A final “related links” section alone does not meet this requirement.

Use descriptive labels such as “guest NIC address variants” or “owned-update plan restrictions”. Avoid “here”, raw implementation filenames as the only explanation, and links to a broad index when a stable field anchor exists. Syntax blocks cannot reliably carry ordinary Markdown links: provide a linked property index immediately alongside them.

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
| Syntax notation | Describes shape; explicit type placeholders/discriminators; clearly non-executable |
| Complete typed value | Valid at one named component/leaf contract, with placement and required surrounding declarations named |
| Explanatory fragment | Demonstrates a relationship or change; cannot be compiled alone; link the complete coherent source |
| Complete offline composition | Every required library/site/catalogue/typed leaf supplied; real parser, resolution and lowering exercised with no target access |
| Deployment procedure | Requires declared compatible source, actual platform/trust/custody/authority and profile support; outcome limited to its real evidence |
| Invalid variation | Deliberately fails at one stated owning boundary with expected diagnostic and correction |

A “minimal” example MUST minimize the owning contract, not omit required context. A useful complete composition MAY contain more than a minimal value. Show how minimal and composed examples relate. Do not imply that independent fragments can be concatenated into a valid site.

Use synthetic coherent names, locally administered MACs, documentation/test addresses and example domains. Synthetic private-material examples MUST contain references or obvious nonfunctional sample metadata, never real credentials. If a value deliberately cannot pass deployment admission, say so next to the example. Do not obscure invalid values with unexplained placeholders in a block claimed to execute.

### 6.2 Required demonstrations

A new component MUST have a minimal valid example, a practical composition and meaningful failure examples for its major semantic boundaries. A union MUST demonstrate each materially different branch somewhere in the maintained suite; repetitive scalar permutations do not require a separate tutorial. Conditional reference/role/credential/default rules need examples that reach the relevant boundary.

A failure example MUST state: input change, failing stage, actual code/message, cause, supported correction and what remains unproved. Reuse an existing tested case when it supplies this evidence. Do not engineer an unrelated earlier error merely to make an example fail. If a diagnostic is generic, document it honestly and add the useful interpretation in prose; do not invent a more descriptive emitted code.

Examples MUST have stable IDs and an inventory of owning validators/integration cases. Use the repository's authored reader and exact accepted source grammar. Tests may select named YAML fences, but MUST NOT create a second documentation grammar. Keep complete compositions readable from source files rather than hiding required declarations in a Python fixture.

### 6.3 Commands

Before a command sequence, define the checkout/revision, starting directory, interpreter/tool versions, locked dependencies, input files, environment and output location. Commands MUST preserve quoting, real newlines and exit status. Define variables before use and avoid common system-variable names. Explain expected output and a concrete inspection/next check.

Use disposable physically resolved temporary roots for confined source checks. Use a new nonexistent output child for create-only packet/report commands, not an existing temporary parent. Keep generated private/runtime results outside committed source and out of logs. Rehearse commands in the stated isolated environment when they are part of an executable tutorial/task. Do not run real deployment as a side effect of documentation validation.

## 7. Installation, maintenance and failure semantics

### 7.1 Required lifecycle language

Use **First installation** and **Later deployments** as reader-facing headings. Explain actual behavior before exposing internal labels:

- `fresh` allows a supported creation path when the genuine owner/backend is absent; the same source continues through ordinary owned updates.
- `retained` requires genuine existing HomeLab ownership; it is not import/adoption and does not create a missing owner.
- Guest and app policies are separate. A new supported app may be created on a genuinely owned guest, subject to that app's actual prerequisites and disjoint ownership.
- A retained-only adapter does not gain a creation path by changing a lifecycle value.

Never tell readers to toggle `fresh` after successful installation. Creation support depends on adapter, selected profile and external prerequisites, not merely accepted YAML. State whether data initialization, account creation, credential bootstrap, image provisioning and commissioning are actually implemented.

### 7.2 Change-effect record

For each execution-owning object/profile, document these situations when applicable:

| Situation | Facts to state |
| --- | --- |
| First installation | Supported platform/path, absent/conflicting backend conditions, trust/files/artifacts/material/traffic prerequisites, create-only behavior |
| Ordinary owned update | Source to retain, ownership/receipt/state/payload requirements, effective changed inputs and affected phases |
| Disruptive change | Actual restart/recreate/process/network effects established by code or qualified evidence; operational uncertainty stated |
| Provider replacement | Which change can produce a replacement and whether the HomeLab policy refuses it; do not equate provider capability with framework permission |
| Persistent identity/material | Immutable names, VMID/node, storage/runtime/service custody, account/device identity and continuity checks |
| Removal/rotation/import/restore | Supported contract or explicit absence/refusal; no inferred cleanup or recovery guarantee |
| Failure | Effects that may already have occurred, evidence/markers to preserve, bounded diagnosis and separate recovery authority |

“Guarded plan” alone is insufficient. Describe the relevant policy and its limits, with source and operation links. The current ordinary LXC saved-plan policy selects exactly the guest and its two firewall resources; creation requires three creates. Existing resources allow update/no-op, preserve selected identity/data fields, and refuse import, move, adoption and replacement. This does not prove that every permitted update is interruption-free. Profile references MUST add their narrower limits.

### 7.3 Deployment and CD

Operations documentation MUST explain the actual workflow owner and phase sequence: infrastructure, preparation, app phases and optional monitoring agent; declared dependencies/readiness control ordering. Define which operation runs OpenTofu and which configures services through Ansible. Values, permission rules and readiness edges remain distinct.

For later maintenance, document how an author changes desired source, validates effective output and selects compatible immutable dependencies; how the consumer's protected CD supplies reviewed environment/runner/secrets/authority; and what receipts plus target checks establish completion. Public docs MUST link the reusable protocol and name consumer-owned setup without publishing a default production site.

Successful compilation does not test configured secret/trust files, real allocations or target services. Successful CD does not itself establish public TLS, authentication, data integrity or device/user behavior unless those checks were actually performed. No generic retry, HOLD deletion, rollback, restore or import procedure may be invented. Failure documentation MUST retain the actual stopping boundary and preserve current evidence.

## 8. Authoring and structural generation

### 8.1 Source-led authoring workflow

Before editing reference text, inspect the accepted contract at the selected revision. Inventory parser/source rules, closed-object validators, nested helper types, resolution/binding conditions, defaults, lowerers, receiver/admission/runtime guards, diagnostics and relevant tests. Follow internal calls and references; a schema alone may not own the effective requirement.

For every contract change:

1. Record the path/variant/layer change and source owner.
2. Establish whether behavior changed or the documentation was wrong. Challenge conflicts rather than copying either side uncritically.
3. Update the canonical record, contextual links, affected examples/concepts/tasks and compatibility/change note.
4. Update inventory/evidence mappings and reuse the meaningful existing checks.
5. Run appropriate source/example/link checks; review rendered Markdown and the full reader path.
6. Report what was inspected/tested and what remains unqualified. Do not turn a failed test green by changing its expectation before deciding whether the contract or test is wrong.

An unrelated implementation defect discovered during documentation work MUST be surfaced separately. Documentation may accurately describe a limit or discrepancy; it MUST NOT silently fix behavior, introduce migration flags or claim unsupported capability.

### 8.2 What may be generated

Structural extraction MAY generate accepted paths, named types, required/optional keys, literal enums/bounds, diagnostic code inventories, source references and traceability skeletons when the source actually encodes them. Every generated record MUST retain path, variant, layer and source provenance. Generated output MUST be reviewable and deterministic.

Authors MUST supply purpose, cross-object conditions, inheritance effects, supported compositions, lifecycle interpretation, operational limits, security ownership and actionable diagnostics unless these are themselves explicit and trustworthy source metadata. Authors MUST check generated defaults against the layer that applies them.

Do not duplicate schema definitions in a generator merely to print tables. Do not publish giant dumps of implementation internals, repeated low-value records or placeholder prose. Preserve authored explanations and canonical nested definitions. Generating field names is assistance, not proof of completeness. Implementing a generator is a separate engineering decision; this standard does not require one before useful documentation can be written.

## 9. Coverage and evidence

### 9.1 Inventory and traceability

Maintain a reviewable inventory with stable row IDs, not a claim of an unmeasured missing-field count. The denominator is the actual accepted public surface at a named revision. Include roots, nested paths, alternatives, conditions, defaults, references, diagnostics, support/lifecycle rules and CLI/output contracts. Distinguish authored active inputs from immutable historical evidence formats.

Each row MUST contain at least:

`ID | owner/source/revision | full path + variant | validating/applying layer | rule/default/effect | canonical page#anchor | example ID(s) | evidence/test ID(s) | evidence level | status/exception`

A cross-object rule may have its own ID linked from affected field rows. Dynamic maps need the key grammar and value type, not one row for every possible user ID. A field accepted in multiple variants needs separate rows when its semantics differ. Output and runtime rules need rows even when absent from an input schema.

Completeness criteria:

- **100% inventoried public paths/variants** map to an explanatory canonical record or a justified named internal-only exclusion.
- **100% inventoried semantic conditions/defaults/reference rules** map to an explanation and relevant evidence; generic field-name occurrence does not count.
- **100% public diagnostic codes** have an owning stage and useful documented handling, either individually or in an explicit shared category that preserves distinctions readers need.
- **100% claimed executable examples** have the right owning validation evidence; complete compositions also have real resolution/lowering evidence.
- **Zero unresolved broken local links/anchors, orphan references, unresolved placeholders or contradictory duplicate definitions** in the changed scope.
- **Zero unsupported operational guarantees**; unknowns and unavailable qualifications are explicit and cannot be counted as verified.

Report covered/total counts and exclusions by category. Record unknown inventory boundaries separately; a percentage with an incomplete denominator is not completeness. Full-suite coverage requires a reconciled full inventory, not extrapolation from sampled pages.

### 9.2 Evidence ladder

| Evidence | Establishes | Does not establish |
| --- | --- | --- |
| Parsed | Accepted YAML/JSON bytes and authored-reader behavior | Component meaning or references |
| Direct component test | Actual field/type/constraint boundary, including negative cases | App/guest orchestration or real deployment |
| App/guest unit with component collaborators mocked | The unit calls/composes contracts as intended | Real collaborator acceptance or integrated lowering |
| Real compiler integration | Names, profiles, bindings, graphs, defaults and useful emitted packet/workflow agree | Target trust/material existence, installation or service health |
| Receiver/controller test with native operations faked | Packet/receipt/state/ownership control flow at its named boundary | Actual platform commands or live service behavior |
| Isolated protocol/native fixture | Named filesystem, command or service protocol under stated fixture conditions | Whole deployment or consumer environment qualification |
| Deployment evidence | Exact source/workflow/run/attempt and relevant phases completed on target | Every service, authentication, data/device/user outcome |
| Service acceptance | Fresh observed named outcome in target environment | Untested future updates, recovery or unrelated services |

Use evidence appropriate to the claim. Reuse existing trustworthy tests instead of adding redundant assertion mirrors. A text-presence test, AST key scan or code-coverage percentage is a regression aid. It does not prove path/branch coverage, field semantics, navigation or beginner usability. The current field-word tripwire is useful, but must not be reported as a semantic coverage audit.

### 9.3 Verification process

Check changed examples through the real authored parser and owning validators. Resolve/lower complete compositions using the real components and compatible library. Verify failure examples reach their intended error and preserve value-free diagnostics. Check changed default/constraint prose against structural and resolved behavior. Rehearse executable shell steps in a disposable environment. Run applicable repository gates defined by the testing guide; do not claim unrun gates.

Review the rendered Markdown on GitHub or an equivalent Markdown renderer: headings, tables, code fences, contextual links, nested navigation and example placement. Walk a newcomer from entry to offline result and onward to real preparation; walk an experienced reader from field to nested constraint to diagnostic and back. Report rendering/navigation inspections separately from automated checks.

## 10. Review rubric and definition of done

### 10.1 Severity and blocking criteria

| Severity | Examples | Disposition |
| --- | --- | --- |
| Blocker | Real secrets/private identity; dangerous operation represented as ordinary maintenance; invented supported import/replacement/rotation/recovery; false deployment/service evidence | Must fix before publication; do not publish a known misleading contract |
| Major | Missing accepted path/variant/conditional rule; wrong default/type/unit/precedence; broken required example; false support or lifecycle limit; missing contextual target preventing correct use | Blocks affected page/contract acceptance |
| Moderate | Missing useful negative case; insufficient diagnostic correction; weak reader transition; orphan page; fragile anchor or incomplete incoming-link update | Fix in scope, or record explicit owner/rationale/follow-up without claiming full completion |
| Minor | Redundant wording/link, inconsistent style, small presentation issue that preserves meaning and navigation | May defer with a specific reason |

Reviewers MUST distinguish an author preference from a contract defect. A requirement can be satisfied in a table or prose if it is complete, directly findable and precise. Review each proposed exception against the actual reader task. An unknown native behavior may be honestly documented; an unsupported positive promise is a blocker/major defect depending on consequence.

### 10.2 Definition of done

A documentation change is complete when its scope and source revisions are explicit; all changed inventory rows resolve to correct canonical records; applicable [page](#3-reference-page-contract), [property](#4-property-records-and-nested-types), [link](#5-contextual-linking-and-navigation), [example](#6-examples-and-reproducible-commands) and [lifecycle](#7-installation-maintenance-and-failure-semantics) requirements pass; meaningful existing checks pass at the stated layers; rendered reading paths are reviewed; privacy/ownership/compatibility are intact; and no blocker or major defect remains.

The review record MUST list evidence actually obtained, tests/checks not run, unresolved facts and accepted exceptions. A self-critique is not independent peer review. Broader gates or native qualification MUST NOT be claimed from a narrower documentation-only review.

## 11. Worked reference specimen: network and guest NIC

This frozen historical specimen illustrates the standard; the maintained current reference is [Networks and guest NICs](../reference/networks.md). It demonstrates the accepted `homelab-components-v1` contract at framework revision [`93ffed7cd5c30b23786e858b1134317b2ccb9118`](https://github.com/theaussiepom/homelab/tree/93ffed7cd5c30b23786e858b1134317b2ccb9118). It is a checked reference specimen, not a proposed API. Its frozen links keep the facts inspectable; adoption authors MUST recheck them against the revision they document.

### 11.1 Purpose and placement

A network is one `networks.<id>` value in a site. It names the bridge, VLAN and IPv4 subnet used by [guest NICs](#114-guest-nic). It describes desired inputs; it does not create a host bridge, configure an external DHCP server or reserve a lease. The guest/infrastructure consumer owns execution. See the complete [offline site](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/examples/first-configuration/site.yaml), [library](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/examples/first-configuration/stack.json) and [image catalogue](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/examples/first-configuration/images.json).

### 11.2 Network syntax and field index

The block below is a **complete network value** placed at `networks.primary`; it needs the surrounding site and context from the linked complete example. It is synthetic and validated offline, not admitted deployment input.

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

Network objects are closed: extra keys refuse with `component.fields`. No fields inherit or merge from a template. Required keys have no defaults; an empty map is invalid. Null is accepted only by `vlan`. No credentials or private material are contained in this value; it references no secret source.

### 11.3 Network property records

<a id="field-network-context"></a>
#### Network context

`networks.<id>.context` is a required identifier matching `[a-z][a-z0-9_-]{0,62}`. Omitted, null and empty strings refuse. It identifies the execution context of a consuming guest. Structural network validation checks the identifier; when a guest consumes the network, resolution requires its context to equal the guest's declared existing context. An unused network's context existence is not unconditionally checked by the inspected resolver; do not infer a stronger validation guarantee. See [context contracts](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/reference/contexts.md) and [guest placement](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/reference/guests.md).

<a id="field-network-cidr"></a>
#### Network CIDR

`networks.<id>.cidr` is a required canonical strict IPv4 network string. `198.18.20.0/24` is valid; `198.18.20.10/24` is not the network address and refuses. IPv6 networks, null and empty values refuse. The resolver uses its prefix length for [static NIC values](#field-guest-nic-address) and tests declared static/DHCP addresses against the subnet. No normalization of a noncanonical authored string is promised.

<a id="field-network-bridge"></a>
#### Network bridge

`networks.<id>.bridge` is required text of 1–4096 characters without NUL. This structural contract does not establish that a real bridge exists. Omitted, null and empty values refuse. The value is copied to the provider-facing NIC declaration. Host-side bridge/VLAN availability is an external [deployment prerequisite](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/operations/deployment.md#prerequisites).

<a id="field-network-vlan"></a>
#### Network VLAN

`networks.<id>.vlan` is required. Null means no VLAN tag. Otherwise it is an integer from 1 through 4094 inclusive; Boolean values, numeric strings, zero and 4095 refuse. There is no implicit VLAN/default inheritance. A network with `vlan: 121` uses the same shape as the untagged example; the linked complete site demonstrates that tagged secondary network. This declaration does not create a VLAN on a physical switch or bridge.

<a id="field-network-gateway"></a>
#### Network gateway

`networks.<id>.gateway` is an optional canonical IPv4 address string. If present it must be a subnet member other than the network or broadcast address. There is no inserted default. Omission supplies no gateway; null and empty values refuse. A static NIC with [`default_route: true`](#field-guest-nic-default-route) requires this field, as does a selected non-default static source-policy-route NIC under its separate [guest rule](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/reference/guests.md). DHCP mode does not use this field to reserve or verify an external lease.

### 11.4 Guest NIC

A NIC is one `guests.<id>.interfaces.<id>` value; it consumes the [network](#112-network-syntax-and-field-index). This **complete NIC value** belongs at `guests.resolver.interfaces.management` in the complete offline site:

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
| `address` | Required closed tagged object | See [address branches](#field-guest-nic-address). No omitted/null/empty default. |
| `default_route` | Optional Boolean | Resolver reads omitted as false; null/numeric/string values refuse. See [route rules](#field-guest-nic-default-route). |
| `ipv6` | Optional string | [IPv6 setting](#field-guest-nic-ipv6) |

The NIC is closed; extra keys refuse. Required keys have no defaults; omitted, null and empty values refuse. Optional exceptions are stated at their records. None of its fields inherits from the network except the explicitly resolved bridge/VLAN/prefix/gateway effects below. The NIC has no credential fields.

<a id="field-guest-nic-network"></a>
#### Guest NIC network

`guests.<id>.interfaces.<id>.network` is a required identifier with the same grammar as [network context](#field-network-context). Resolution selects a site `networks.<id>` object, whose context must match the guest's context. It copies the selected bridge/VLAN and computes address/prefix/gateway effects. No implicit network selection occurs. See the [network field index](#112-network-syntax-and-field-index) and [missing-network failure](#116-failures-and-correction).

<a id="field-guest-nic-slot"></a>
#### Guest NIC slot

`slot` is a required integer 0–31 inclusive. All interfaces on a guest must use exactly contiguous slots starting from zero; duplicates/gaps refuse. Boolean and string values refuse. The resolver orders provider NICs by slot, not by authored map order. Slot changes affect the provider-facing NIC ordering and must meet the [update limits](#117-first-installation-and-later-deployments); no stable hot-plug/reorder guarantee is implied.

<a id="field-guest-nic-mac"></a>
#### Guest NIC MAC

`mac` is a required string matching six hexadecimal octets separated by colons. Uppercase and lowercase hexadecimal are structurally accepted; conflicts are compared case-insensitively within provider-address/node scope. The synthetic example uses a locally administered value. No automatic allocation or discovery of outside MAC use occurs. The value is part of the NIC/control identity consumed by later trust/reachability checks; changing it is not an import or continuity waiver.

<a id="field-guest-nic-ipv6"></a>
#### Guest NIC IPv6

`ipv6` is optional; if supplied it must be exactly the string `manual`. Omission leaves it absent from the resolved provider-facing NIC. Null, empty and other values refuse. No general IPv6 allocation contract is supplied by this field. IPv6 policy literals in other contracts do not widen this accepted shape.

<a id="field-guest-nic-address"></a>
#### Guest NIC address

`address.mode` is required and exactly one of `static`, `dhcp` or `manual`. The discriminator controls the complete accepted object:

| Mode | Exact accepted value shape | Conditions and resolved effect |
| --- | --- | --- |
| `static` | `{mode: static, value: 198.18.20.10}` | `value` is required canonical IPv4; resolution requires a usable member of the selected subnet and constructs address/prefix. No `endpoint` field accepted. |
| `dhcp` | `{mode: dhcp, endpoint: 198.18.20.10}` | `endpoint` is required canonical IPv4 and a usable member; it declares the expected endpoint, not a lease reservation. The environment must supply the lease. No `value` accepted. |
| `manual` | `{mode: manual}` | No `value` or `endpoint` accepted; resolved app address is absent. Cannot be the guest's control interface or supply an app role needing an address. |

The branch columns above are exact accepted syntax. These field meanings belong to this union and do not resolve endpoint-object references.

| Nested field | Presence | Canonical record |
| --- | --- | --- |
| `address.mode` | Required discriminator string | [Address mode](#field-guest-nic-address-mode) |
| `address.value` | Required for static; forbidden otherwise | [Static address value](#field-guest-nic-address-value) |
| `address.endpoint` | Required for DHCP; forbidden otherwise | [DHCP endpoint](#field-guest-nic-address-endpoint) |

Omitted/null/empty discriminator or required branch value refuses. Extra branch keys refuse. Usable means neither the selected subnet's network address nor its broadcast address. Duplicate declared addresses refuse within the same provider-address/node/bridge/VLAN scope. This check does not discover external allocations.

<a id="field-guest-nic-address-mode"></a>
##### Guest NIC address mode

`address.mode` is the required discriminator string with no default: exactly `static`, `dhcp` or `manual`. It chooses the required/forbidden keys and resolved effects in the [branch table](#field-guest-nic-address). Null/empty refuse. Changing mode also changes the [ordinary-route calculation](#field-guest-nic-default-route) and may change reachability; no seamless transition is promised.

<a id="field-guest-nic-address-value"></a>
##### Guest NIC address value

`address.value` is required only when `mode: static`, and forbidden in the other branches. It is a canonical IPv4 address string without prefix/port, with no default; null/empty refuse. Resolution requires a usable member of the selected [network CIDR](#field-network-cidr) and checks conflicts in provider-address/node/bridge/VLAN scope. The resolver appends the network prefix for provider output.

<a id="field-guest-nic-address-endpoint"></a>
##### Guest NIC address endpoint

`address.endpoint` is required only when `mode: dhcp`, and forbidden in the other branches. It has the same canonical IPv4 string and usable-subnet/conflict conditions as [static value](#field-guest-nic-address-value), with no default and rejects null/empty. It records the expected DHCP endpoint; it does not allocate a lease. Actual DHCP/trust admission is a later boundary, distinct from source resolution.

<a id="field-guest-nic-default-route"></a>
#### Guest NIC default route

Only a static NIC may set `default_route: true`, and its network must provide a [gateway](#field-network-gateway). Each guest needs exactly one effective ordinary route: either one DHCP NIC, or one static NIC with the flag true. A DHCP NIC already contributes the ordinary route, so retaining the static-only flag refuses. A manual NIC cannot supply it. Source-policy routing is a separate explicit guest contract, not a second ordinary route.

For a valid DHCP variation, change the management address to `{mode: dhcp, endpoint: 198.18.20.10}` and remove `default_route` or set it false. The other NIC in the complete example remains static and non-default. Real lease/trust qualification is outside this offline variation. These branches demonstrate the exact accepted union; they are not interchangeable ways to bypass ownership or address checks.

### 11.5 Resolution and output

For the static example the resolved provider NIC contains `bridge: example0`, `vlan: null`, the selected MAC, `ipv4: 198.18.20.10/24`, `gateway: 198.18.20.1`, and `ipv6: manual`. The guest's interface-address lookup yields `198.18.20.10`. App roles can refer to that guest interface only through their accepted scope/binding contract; a NIC does not automatically publish an app endpoint, grant traffic or wait for service readiness. See [app bindings](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/reference/apps.md), [connections](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/reference/connections.md) and [exposures](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/reference/exposures.md).

### 11.6 Failures and correction

The following variations were checked through real resolution and lowering against a disposable copy of the linked complete example. Each is a separate change to the valid baseline.

| Change | Actual refusal | Correction and boundary |
| --- | --- | --- |
| Set primary CIDR to `198.18.20.10/24` | `component.invalid at networks.primary` | Use the canonical network address, `198.18.20.0/24`; does not verify host routes. |
| Set VLAN to `4095` | `component.integer at networks.primary` | Select null or an integer 1–4094 according to the actual environment. |
| Set gateway to null | `component.invalid at networks.primary` | Omit it when no consuming static default/source route requires it, or supply a usable subnet member. |
| Change management to DHCP while retaining `default_route: true` | `component.invalid at guests.resolver.interfaces.management` | Remove/false the flag and supply the required DHCP endpoint; check the one-route rule. |
| Change management network to `missing` | `component.invalid` | Declare/select a network in the guest's context; the current diagnostic does not emit a more detailed missing-network code. |

Do not “fix” these by disabling validation or changing a test expectation. For generic failures, compare the named declaration with its canonical field/rule record and preserve the source/revision needed to reproduce the refusal without disclosing values.

### 11.7 First installation and later deployments

The network value has no independent installation action. A supported guest installation consumes it, requires a real compatible host bridge/VLAN/subnet/allocation and trust inputs, and applies the [guest lifecycle](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/reference/lifecycle.md). The linked tutorial is offline-only and deliberately unsuitable for deployment admission.

Later changes affect the desired provider NIC and reachability. The current saved-plan policy refuses replacement, import/move/adoption and changes to its immutable guest fields; an allowed update/no-op is not a promise of online renumbering or uninterrupted management access. MAC/control/address identity and actual reachability checks still apply. The accepted contract provides no automatic bridge provisioning, lease reservation, destructive replacement, arbitrary import or rollback. Review the consumer's actual operation before a potentially disruptive change.

### 11.8 Verification and navigation

The owning structural functions are [`network` and `interface`](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/blueprints/component_types.py), with guest route/layout checks in the same module; consumed references and provider values are resolved by [`guest_values`](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/blueprints/component_plan.py). The maintained [reference example tests](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/blueprints/test_component_reference_examples.py) parse named examples and perform real resolve/lower checks. Their native/network boundaries are faked/refused; they do not install a guest.

The checked source baseline passed all ten tests in that module. The specimen network/NIC fences were parsed with the authored reader and directly validated; complete static, DHCP-management and manual-secondary variants also resolved/lowered. The extra network diagnostic cases above passed their expected source boundaries. This evidence establishes parsing/validation/resolution/lowering only, not deployment/service qualification. To reproduce the complete offline result, follow the pinned [first configuration tutorial](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/guides/first-configuration.md), including its environment preparation and new output path. For actual operation use [deployment prerequisites](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/operations/deployment.md), [support](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/reference/support.md) and [troubleshooting](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/operations/troubleshooting.md).

Return to the [reference index](https://github.com/theaussiepom/homelab/blob/93ffed7cd5c30b23786e858b1134317b2ccb9118/docs/reference/README.md), [network field index](#112-network-syntax-and-field-index), [nested address](#field-guest-nic-address) or [standard contents](#contents).

## 12. Contributor integration

This file is the single normative framework documentation standard. The former
[documentation entry point](documentation.md) remains a compatibility pointer.
The [contributor route](README.md), repository AGENTS and
[reference](../templates/configuration-reference.md),
[task](../templates/task-guide.md) and [tutorial](../templates/tutorial.md)
templates all lead here. Existing security, signing, coverage and review gates
continue to apply.

For a public control/default change, update the canonical property/rule records,
affected complete examples and test-local source/document/evidence pointers in
the same reviewed change. Keep validators and declarations authoritative. A
mapping contains locators, not a parallel catalogue of accepted values.

The [assurance record](documentation-assurance.md) separates the automatically
checked network/NIC pilot from broader authored reference coverage. Expand that
scope only by inspecting the actual owner, preserving path/variant/layer detail,
executing appropriate evidence and reviewing the rendered reader journey. A
passing pilot is not full-repository semantic coverage.

New components still need a closed schema, useful diagnostics, explicit
references, compiler integration, complete examples and appropriate evidence.
Retire duplicate descriptions only after their replacements and incoming links
are established. Do not alter production behavior or dependency selections to
make a documentation assertion pass.

## 13. Design sources

The following are design inputs, not HomeLab support authorities. The requirements above adapt their strengths to a declarative YAML compiler and guarded deployment API.

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
