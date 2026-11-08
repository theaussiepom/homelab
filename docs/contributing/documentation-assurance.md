# Documentation assurance and maintenance

The [documentation standard](documentation-standard.md) defines what authors and reviewers must check. This page explains the automated checks, their limits and how to maintain them. They do not yet inventory the entire public API or establish that it works on a target.

## Source authority and checked scope

The configuration format, validators, resolver and runtime checks define the actual behavior. Mappings in the tests point to implementation, documentation, examples and evidence; they do not duplicate the schema, defaults or runtime configuration. The documentation standard was adopted against framework `93ffed7cd5c30b23786e858b1134317b2ccb9118`. Ongoing checks inspect the current checkout rather than that historical tree.

| Checked surface | Denominator / behavior | Limitation |
| --- | --- | --- |
| Network/NIC structural controls | 16 checked rows for paths and variants, derived from the accepted fields in `network` and `interface` | Covers the extraction patterns supported for those validators; an unrecognized pattern fails for review |
| Documentation records | Every control row in the pilot's Path/Variant/Presence/Type/Record tables is compared with the implementation and mapping | Does not infer fields or rules from arbitrary prose or other reference pages |
| Required/optional facts | Presence cells are compared with the validator's required and optional field declarations | Type explanations, bounds and lifecycle prose still require review and behavior tests |
| Reviewed procedural rules | Five pointers locate checks for network context, the ordinary route, contiguous slots, usable addresses and control-interface addressing | Pointers locate implementation and tests; they do not automatically discover every behavior change |
| Examples and refusals | Checks exact named network/NIC excerpts, compiles complete static/DHCP/manual variants and tests intended failures | No target commands, credential reads, lease reservation or service startup |
| Maintained wider reference examples | Continues to run the existing complete site, template, profile, app, relationship and other named examples | These useful examples do not inventory every accepted field and variant |
| PBS reference fields and examples | The broad field-name inventory includes the backup validators; five named PBS snippets run through their actual selection, profile, coverage and job validators; a complete PBS composition also resolves management/public-key bindings into a real guest packet, with opt-in and invalid-field cases | These checks do not add PBS to the network/NIC structural-record pilot or prove complete procedural coverage, scheduled capture or restoration |
| Local navigation/structure | Checks the root README, AGENTS and Markdown beneath docs for local files and anchors, table and code-block structure, and incoming links | Handles a supported subset of Markdown; people must still review rendering and whether links are useful in context |
| Required test collection | The normal CI harness independently checks that required test cases and classes exist, are discovered, and are neither skipped nor marked as expected failures | Local collection checks do not prove a hosted run or branch protection enforcement |

The 16 checked rows include optional `gateway`, `default_route` and `ipv6`, the address object, a discriminator row for **each** static/DHCP/manual variant, and the static `value` and DHCP `endpoint` fields. Checks compare these specific paths and variants, not simply 16 words. This limited inventory cannot establish a coverage percentage for the whole suite.

## Implementation map

| Responsibility | Maintained owner |
| --- | --- |
| Validators defining accepted fields | [`component_types.py`](../../blueprints/component_types.py), `network` / `interface` / `guest` |
| Reference resolution and generated values | [`component_plan.py`](../../blueprints/component_plan.py), `Resolver.guest_values` |
| Current explanatory records | [Network/NIC reference](../reference/networks.md) |
| Mappings, the bounded inventory and comparison with documentation tables | [`test_documentation_contract_helpers.py`](../../blueprints/test_documentation_contract_helpers.py) |
| Pilot assertions and wider tutorial checks | [`test_component_documentation.py`](../../blueprints/test_component_documentation.py) |
| Existing parser, component and complete-example tests | [`test_component_reference_examples.py`](../../blueprints/test_component_reference_examples.py) |
| Tests of expected failures in the conformance mechanism | [`test_documentation_conformance.py`](../../blueprints/test_documentation_conformance.py) |
| Local navigation checks and tests of those checks | [`test_documentation_navigation.py`](../../blueprints/test_documentation_navigation.py) |
| Independent checks of required test discovery and workflow failure propagation | [Normal coverage-metrics harness](../../.github/scripts/test_coverage_metrics.py) |
| Normal source tests and the job that combines their required results | [CI workflow](../../.github/workflows/ci.yml) |

The [PBS reference](../reference/backup.md) also has maintained examples for root selection, a backup profile, application coverage and an operational job. Their tests reject unsupported presence values, incomplete storage classification, inconsistent capture types and invalid job fields. The [complete backup example](../examples/backup/README.md) is exercised by [`test_component_backup_documentation.py`](../../blueprints/test_component_backup_documentation.py), including recovery-public-key source digests, management-token isolation, derived client references and disabled membership. Management shape/refusal cases are owned by [`test_component_backup_management.py`](../../blueprints/test_component_backup_management.py), while public-key parsing and confined file resolution have separate component tests. The field-name test includes `component_backup.py`, `component_backup_job.py`, `component_backup_management.py` and `component_backup_key.py`; it remains a basic inventory check, not an independently extracted record for every nested PBS rule.

The same compiler documentation tests read the complete [mixed-client source](../examples/backup/client-limits.yaml): the [client-limit records](../reference/backup.md#backup-client-limits) map to override/inheritance, one group/common timeout, disabled membership and effective four-times staging checks. Direct component negatives are in [`test_component_backup_job.py`](../../blueprints/test_component_backup_job.py). Existing runtime boundaries are exercised by the added capacity case in [`test_backup_worker.py`](../../proxmox/applications/tests/test_backup_worker.py) and the changed-coverage/disabled-member case in [`test_backup_activation.py`](../../proxmox/applications/tests/test_backup_activation.py). These are synthetic source/filesystem/component checks, not native export measurements, host pool reservations or backup acceptance.

The existing field-name test remains useful for detecting broad regressions, but finding a word in the reference does not prove that a nested field is explained correctly. The pilot additionally checks both directions: implementation fields must have records, and documentation records must match the implementation. It preserves the wider example checks and does not increase what the field-name test proves.

## Reproduce the focused checks

Start at the reviewed framework root in the isolated environment prepared by [Testing](testing.md), with this checkout's hash-locked requirements installed. These commands run source checks and disposable local fixtures without deploying or reading configured target credentials and files.

```sh
python -m unittest discover -s blueprints -p test_component_documentation.py -q
python -m unittest discover -s blueprints -p test_component_reference_examples.py -q
python -m unittest discover -s blueprints -p test_documentation_conformance.py -q
python -m unittest discover -s blueprints -p test_documentation_navigation.py -q
python -m pytest -q .github/scripts/test_coverage_metrics.py -k documentation
```

A successful result must discover tests and pass their assertions. Tests of the checking mechanism deliberately introduce missing or outdated controls, extra documentation rows, disagreements about required fields, ambiguous link destinations, incorrect examples or expected failures, and an empty scope. The normal harness separately detects missing or skipped required conformance tests. Deleting the conformance module therefore cannot silently remove the check that requires it.

These focused commands support development. The complete source, coverage, security, signing and review requirements still follow [Testing](testing.md). A passing local run does not show that hosted CI ran, that branch protection requires it, or that a change was merged.

## Maintain a changed contract

1. Inspect the actual source owner and decide whether behavior or documentation is wrong. Never alter accepted values simply to satisfy a stale statement.
2. Update the canonical record's full path, variant, condition and contextual destinations. Keep useful old anchors or update maintained inbound links.
3. For the pilot, update mappings with pointers to the corresponding implementation, page and anchor, example and executable test. If extraction encounters a source pattern it cannot classify, review that failure instead of granting a blanket exemption.
4. Exercise valid inputs and intended failures through the actual implementation. Start each failure case from a valid example and check its intended error code and path; an unrelated failure does not count.
5. Read the rendered path from field to nested type, prerequisite, example and diagnostic. Walk the [newcomer journey](../README.md) when entry/operation pages change. Automation cannot judge whether a link answers the question.
6. Record actual commands/outcomes and unperformed hosted/native checks in the change evidence. Preserve failed receipts and separate source, controller, deployment and service claims.

For types outside the pilot, review the prose against the standard and existing tests. Expand automated checks only after reviewing the inventory derived from the implementation. Values present in a manifest do not represent every optional field the format accepts.

## CI and enforcement boundary

The existing blueprint suite runs these assertions in normal CI for applicable pull requests and main-branch source validation. Its existing `Repository validation` aggregator requires the producing job to succeed; failure, cancellation and skip must not pass. The independent harness tests this wiring and collection.

When publication is authorised, inspect the hosted run and attempt for the tested revision and confirm the required-check relationship. Workflow YAML and local tests of expected failures do not prove hosted execution or enforcement. Documentation checks require no deployment credentials, new runtime dependency, private site access or weakened branch rules.

[Contributor workflow](README.md) · [Standard](documentation-standard.md) · [Evidence levels](../concepts/evidence.md) · [Reference index](../reference/README.md)
