# Troubleshooting

Establish the exact condition that failed before changing code, tests or a target. Keep source errors, test-fixture errors, transport failures and failures in running services distinct.

## Compilation

Component errors show a safe code and validated property path, not source values. For example `component.reference at connections.browser_broker` means inspect the named public relationship, not print its private inputs.

| Code/family or symptom | Check | Safe next step |
| --- | --- | --- |
| component.source / parser refusal | Extension, one file with the requested stem, a regular file within the selected source root, valid JSON-compatible YAML | Correct only authored path/shape; do not fall back to path traversal or symlinks |
| component.fields / type / integer / invalid | Missing/unknown keys, scalar type, null versus omission, bounds | Look up the field in the [reference](../reference/README.md) |
| component.reference / reference-cycle | Missing ID or cyclic external/group references | Follow declared IDs; do not duplicate allocations |
| component.connection-* / account-* | Role, source scope, producer protocol, owner/target/principal | Compare profile and connection/account contract |
| component.readiness* / disabled-dependency | Explicit cycle, self-edge or disabled required guest | Correct intended order/selection; do not infer waits from values |
| component.traffic-ingress / egress / interface | Actual source/target role, protocol, port and both managed guest rules | Correct explicit reviewed policy; do not infer broad access permissions |
| component.address-group-size | Limits on nesting depth, members, aggregate values or combinations | Reduce/restructure the declared values without widening scope |
| component.memory-budget / runtime-* / resource-* | Effective OS reserve, app limits/minimums, required security | Review selected template/runtime and capacity |
| component.runtime-file-conflict / runtime-visibility / sidecar-file-conflict | Duplicate owner or peer-private directory exposure | Give each supported instance separate paths and identities |
| component.monitoring-* | Root server/profile/disabled selection | Check [Zabbix](../reference/zabbix.md) |
| component.origin / authentication / transport | Owned HTTPS exposure, provider type, CA/server name | Check public origin separately from backend trust |
| component.synthetic-binding / ssh-key | Tutorial address/domain/key still selected with admit | Bind real reviewed values; do not disable admission |
| Native namespace refusal | Unit/path/UID/GID collision | Choose supported placement; do not invent a numeric account ID |

Not every defensive refusal has a unique error code. A property path and exact selected source are more useful than guessing from a generic message.

## Generated workflow differs

Use the selected framework generator with the selected site and library. Review the diff; do not hand-patch a generated file, re-pin a hash blindly, weaken its policy or silently use an unpublished dependency. Unknown guest selection or stale disabled dependencies can fail before execution.

## Controller ownership or phase refused

A generic hold message can hide several causes: missing state or state owned by another installation, a changed pointer to the latest success, incomplete history, changed protected inputs, missing immutable inputs, or a HOLD that belongs to another operation. Preserve the evidence and use a read-only diagnostic limited to the information allowed by the installation's operating policy. Do not clear a marker, overwrite a receipt, restore an old backend or change lifecycle to fresh.

The deployment entrypoint keeps that hold message and adds a bounded JSON diagnostic: a recognised Python exception type and up to four public framework source filenames with line numbers. Look up those locations in the exact selected framework revision. Exception messages, arguments, private paths, locals, environment values and request contents are not printed. Unknown exception classes use `Exception`; frames outside the framework application source are omitted. If diagnostic collection itself fails, the original generic hold still applies. This identifies a failure boundary without releasing custody or retrying the operation, and cannot recover details discarded by an earlier source version.

A failure involving file permissions or ownership in a disposable test may be a fixture defect. Establish what the production contract requires before changing the test. Keep the original failed result and preserve meaningful checks of file identity, contents and permissions when correcting a test double.

## Runtime is healthy but a job failed

A pre-existing healthy container does not identify the failed command's cause. Identify the exact phase and command from the logs and selected source. If the command produced no logs, the cause may remain unknown. Do not try restarts, image pulls or container recreation to discover the cause without authority. Distinguish package or registry transfer failures from failures in the application protocol or in preserving existing state.

## CI and review

Read results for the exact current commit. A queued/skipped job or an old green commit is not current acceptance. A review service that cannot run because it lacks capacity leaves a separate review requirement unmet; do not change base, filters or security settings to hide it. Checks of Linux ownership and extended attributes (xattrs) require the real Linux fixture; a macOS mock result cannot establish them.

[Operations index](README.md) · [Testing](../contributing/testing.md)
