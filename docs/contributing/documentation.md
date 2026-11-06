# Documentation standard

Documentation is part of the public contract. A field list alone is not a
complete reference, and a compiling fragment is not a runnable installation.
Write for a reader who has not followed the implementation conversation.

## Choose a page and its owner

| Page | Reader's goal | Starting template |
| --- | --- | --- |
| Configuration reference | Know the exact accepted values and effects | [Configuration reference](../templates/configuration-reference.md) |
| Task guide | Complete one bounded task with known prerequisites | [Task guide](../templates/task-guide.md) |
| Tutorial | Learn by finishing a complete, reproducible example | [Tutorial](../templates/tutorial.md) |

The framework owns grammar, resolution, execution and support limits. A library
owns its profile defaults/software/required roles. A consumer owns its concrete
allocations and operating procedure. Link to another owner's versioned contract
rather than copying private facts or inventing a second authority. A library's
app-profile template can extend this standard with its specific bindings and
complete synthetic composition.

Templates deliberately contain placeholders and are not runnable examples.
Finished pages must contain no empty sections, unresolved placeholders or
instructions to fill in an unspecified prerequisite later.

## Make configuration usable

Every configuration reference page needs all of:

1. Explain what the declaration owns and where it belongs. State whether a block
   is a site root, complete typed leaf, one map value or a combination fragment.
2. Show YAML syntax. Mark type placeholders as **non-runnable syntax**; prefer
   actual synthetic values when they can illustrate the same shape.
3. Provide a minimal valid worked example, naming every required surrounding
   declaration. Link a complete tested composition when the page is a fragment.
   Do not imply that unrelated fragments form a runnable site by concatenation.
4. Show a practical combination or a meaningful invalid variation. Explain its
   result: missing reference, wrong role/type, violated bound or unsupported update.
5. Document **every accepted nested field**: type, required/conditional status,
   omission/default/null behavior, bounds, enum/path format and unknown-key rules.
   Describe actual direct-field inheritance before explicit instance overrides.
6. Explain reference lookup and ownership: names, expected target type/scope,
   source confinement, dependency and permission effects. Values, waits and grants
   remain separate unless a named feature explicitly adds behavior.
7. Explain changes: first installation, later deployment, persistent identities,
   material continuity, recreation/import/rotation/deletion/rollback limits.
   Say when interruption or native support is unknown rather than promising it.

Scope this explanation to the declaration. A pure value type does not have its
own installation workflow: say that it only changes a value consumed by a named
owner and link that owner's lifecycle. Mark genuinely inapplicable topics as
such with a reason; do not invent deployment steps or repeat generic warnings.
Application/profile guides still need explicit supported first-installation and
later-deployment requirements.

App property documentation must distinguish structural property acceptance,
resolved conditional requirements, selected profile support and runtime guards.
For example an image catalogue's structural allowance does not override an
adapter's immutable-image floor.

## Explain the lifecycle plainly

Start with **First installation** and **Later deployments**, then explain the
technical proof. `fresh` selects a creation policy when no owner/backend exists;
the same `fresh` source continues through ordinary owned updates. Readers must
not be told to toggle lifecycle after a successful run. `retained` requires
genuine existing HomeLab ownership and is not import. Some adapters have no fresh
path. Link [Lifecycle](../reference/lifecycle.md) and
[Support](../reference/support.md), keeping profile-specific limits explicit.

## Make commands reproducible

Define checkout/revision, interpreter, dependency installation, working directory,
environment variables, file locations and tool prerequisites before using them.
For confined sources, resolve temporary paths physically after `mktemp -d`.
Coverage reports need a **new child** of that disposable parent, never the
already existing directory. Keep generated runtime/private results outside source.

Use real commands, expected output and a concrete next check. Do not leave
an unexplained command fragment or claim source validation exercises native
services. Separate these evidence levels: parsed, validated, compiled/lowered,
controller tested, isolated protocol tested, deployed and service verified.
State any mocks and native/platform limits. An operations guide must state its
authority/prerequisites and failure boundary; it must not invent a retry, HOLD
release, import or rollback procedure.

## Validate before publishing

Use the existing authored reader and owning validators. The maintained examples
in `test_component_reference_examples.py` select named YAML fences, parse them
with `authored_config.parse`, and call real contracts; they do not define a
documentation grammar. Direct component tests prove the value boundary. Real
compiler tests must also resolve the surrounding names and lower a useful
complete composition. Negative examples must reach their intended refusal,
not an earlier unrelated fixture error.

Run maintained tutorial/example tests, link and heading checks, and the normal
source gates required by [Testing](testing.md). Rehearse task/tutorial shell
blocks in a disposable environment. When a complete example depends on a library,
bind a compatible reviewed revision and keep its profile selection testable.
Never refresh a frozen expected hash merely to make changed output pass.

Before calling a page complete, read its full rendered Markdown in context:
syntax and minimal example, practical outcome, every field/condition, defaults,
references, first/later behavior, failure limits and canonical navigation must all
agree with current code. Text-presence checks and coverage percentages alone do
not establish this completeness.

[Contributor index](README.md) · [Testing](testing.md)
