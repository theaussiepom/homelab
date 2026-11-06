# Documentation assurance and maintenance

The [documentation standard](documentation-standard.md) defines the review target.
This page describes the implemented checks and their limits. It is the handoff
for future authors, not a claim that the entire public API has been mechanically
inventoried or qualified on a target.

## Source authority and checked scope

Configuration, validators, resolution and runtime guards remain authoritative.
Test-local mappings store source/document/example/evidence locators; they do not
repeat a schema, default catalogue or runtime configuration. The source baseline
for this adoption is framework `93ffed7cd5c30b23786e858b1134317b2ccb9118`; ongoing
checks inspect the actual checkout, not that frozen tree.

| Checked surface | Denominator / behavior | Limitation |
| --- | --- | --- |
| Network/NIC structural controls | 16 qualified path/variant rows derived from real `network` and `interface` closed declarations | Only the supported concrete extraction patterns in these owners; unclassified patterns fail for review |
| Documentation records | All supported-control rows in the pilot's normal Path/Variant/Presence/Type/Record tables reconciled with source and mapping | Does not infer controls from arbitrary prose or other reference pages |
| Required/optional facts | Presence cells compared with actual closed-object declarations | Type explanations, bounds and lifecycle prose still require review and behavior tests |
| Reviewed procedural rules | Five explicit pointers: consumed network context, ordinary route, contiguous slots, usable addresses and control-interface addressing | Pointers locate owners/evidence; they do not automatically discover every semantic change |
| Examples and refusals | Exact named network/NIC excerpts; complete static/DHCP/manual resolution/lowering; intended negative variations | No target commands, credential reads, lease reservation or service startup |
| Maintained wider reference examples | Existing complete site, template, profile, app, relationship and other named examples remain executed | Useful example coverage is not a full field/variant denominator |
| Local navigation/structure | Root README, AGENTS and Markdown beneath docs; local files/anchors, table/fence structure and inbound reachability | Supported Markdown subset; contextual usefulness and rendering require human review |
| Required test collection | Independent normal CI harness checks named cases/classes are present, discovered and not skipped/expected failures | Local collection checks do not prove a hosted run or branch protection enforcement |

The 16 structural controls include optional `gateway`, `default_route`, `ipv6`,
the address parent, discriminator rows for **each** static/DHCP/manual branch,
and the static `value` and DHCP `endpoint` leaves. They are not 16 bare field words.
No full-suite percentage is claimed from this bounded denominator.

## Implementation map

| Responsibility | Maintained owner |
| --- | --- |
| Actual accepted structural source | [`component_types.py`](../../blueprints/component_types.py), `network` / `interface` / `guest` |
| Actual consumed references/output | [`component_plan.py`](../../blueprints/component_plan.py), `Resolver.guest_values` |
| Current explanatory records | [Network/NIC reference](../reference/networks.md) |
| Pointer records, narrow inventory and table reconciliation | [`test_documentation_contract_helpers.py`](../../blueprints/test_documentation_contract_helpers.py) |
| Live pilot assertion and wider tutorial checks | [`test_component_documentation.py`](../../blueprints/test_component_documentation.py) |
| Existing parser/component/complete example evidence | [`test_component_reference_examples.py`](../../blueprints/test_component_reference_examples.py) |
| Conformance mechanism negative fixtures | [`test_documentation_conformance.py`](../../blueprints/test_documentation_conformance.py) |
| Local navigation checks and mechanism fixtures | [`test_documentation_navigation.py`](../../blueprints/test_documentation_navigation.py) |
| Independent required collection and workflow failure propagation | [Normal coverage-metrics harness](../../.github/scripts/test_coverage_metrics.py) |
| Normal source-suite execution and required aggregator wiring | [CI workflow](../../.github/workflows/ci.yml) |

The literal-field tripwire remains as a broad regression aid. It cannot prove
nested semantics merely because a word appears somewhere in the reference.
The qualified pilot adds forward and reverse checking without changing that
existing evidence boundary or narrowing the wider example checks.

## Reproduce the focused checks

Start at the reviewed framework root in the isolated environment prepared by
[Testing](testing.md), with this checkout's hash-locked requirements installed.
The following run source assertions and disposable local fixtures. They do not
run a deployment or read configured target material.

```sh
python -m unittest discover -s blueprints -p test_component_documentation.py -q
python -m unittest discover -s blueprints -p test_component_reference_examples.py -q
python -m unittest discover -s blueprints -p test_documentation_conformance.py -q
python -m unittest discover -s blueprints -p test_documentation_navigation.py -q
python -m pytest -q .github/scripts/test_coverage_metrics.py -k documentation
```

A successful result requires nonempty discovery and successful assertions.
Mechanism fixtures deliberately introduce missing/stale controls, independent
new documentation rows, source/document presence drift, ambiguous destinations,
wrong examples/refusals and empty scope. The normal harness separately detects
missing or skipped required conformance tests; deleting the new module cannot
make its own in-module presence assertion disappear unnoticed.

These commands are focused development evidence. The complete source/coverage,
security, signing and review gates still follow [Testing](testing.md). A green
local run is not hosted scheduling, required-check or merge evidence.

## Maintain a changed contract

1. Inspect the actual source owner and decide whether behavior or documentation
   is wrong. Never alter accepted values simply to satisfy a stale statement.
2. Update the canonical record's full path, variant, condition and contextual
   destinations. Keep useful old anchors or update maintained inbound links.
3. In the pilot, update the pointer mapping only with the corresponding source,
   page/anchor, example and executable evidence identities. Unclassified source
   extraction is a review failure, not a reason for a blanket exemption.
4. Run the real positive/negative boundary. Start a refusal from a valid example
   and assert its intended code/path; any unrelated failure is insufficient.
5. Read the rendered path from field to nested type, prerequisite, example and
   diagnostic. Walk the [newcomer journey](../README.md) when entry/operation
   pages change. Automation cannot judge whether a link answers the question.
6. Record actual commands/outcomes and unperformed hosted/native checks in the
   change evidence. Preserve failed receipts and separate source, controller,
   deployment and service claims.

For an unpiloted contract, author and review the broader prose against the
standard and existing tests. Expand conformance only with a reviewed source-derived
scope; do not count supplied manifest values as every accepted optional control.

## CI and enforcement boundary

The existing blueprint suite runs these assertions in normal CI for applicable
pull requests and main-branch source validation. Its existing `Repository validation`
aggregator requires the producing job to succeed; failure, cancellation and skip
must not pass. The independent harness tests this wiring and collection.

Actual hosted execution still needs the tested revision/run/attempt and the
required-check relationship to be inspected when publication is authorized.
Workflow YAML and local red fixtures do not establish that result. Documentation
checks need no deployment credentials, new runtime dependency, private site read
or branch-rule weakening.

[Contributor workflow](README.md) · [Standard](documentation-standard.md) ·
[Evidence levels](../concepts/evidence.md) · [Reference index](../reference/README.md)
