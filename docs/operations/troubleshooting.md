# Troubleshooting

Establish the exact failed predicate before changing code, tests or a target.
Keep source errors, fixture errors, transport failures and native service
failures distinct.

## Compilation

Component errors show a safe code and validated property path, not source values.
For example `component.reference at connections.browser_broker` means inspect
the named public relationship, not print its private inputs.

| Code/family or symptom | Check | Safe next step |
| --- | --- | --- |
| component.source / parser refusal | Extension, single sibling, regular confined file, valid JSON-compatible YAML | Correct only authored path/shape; no traversal/symlink fallback |
| component.fields / type / integer / invalid | Missing/unknown keys, scalar type, null versus omission, bounds | Look up the field in the [reference](../reference/README.md) |
| component.reference / reference-cycle | Missing ID or cyclic external/group references | Follow declared IDs; do not duplicate allocations |
| component.connection-* / account-* | Role, source scope, producer protocol, owner/target/principal | Compare profile and connection/account contract |
| component.readiness* / disabled-dependency | Explicit cycle, self-edge or disabled required guest | Correct intended order/selection; do not infer waits from values |
| component.traffic-ingress / egress / interface | Actual source/target role, protocol, port and both managed guest rules | Correct explicit reviewed policy; no broad inferred grant |
| component.address-group-size | Depth/member/aggregate/Cartesian bound | Reduce/restructure the declared values without widening scope |
| component.memory-budget / runtime-* / resource-* | Effective OS reserve, app limits/minimums, required security | Review selected template/runtime and capacity |
| component.runtime-file-conflict / runtime-visibility / sidecar-file-conflict | Duplicate owner or peer-private directory exposure | Give each supported instance disjoint owned namespace |
| component.monitoring-* | Root server/profile/disabled selection | Check [Zabbix](../reference/zabbix.md) |
| component.origin / authentication / transport | Owned HTTPS exposure, provider type, CA/server name | Check public origin separately from backend trust |
| component.synthetic-binding / ssh-key | Tutorial address/domain/key still selected with admit | Bind real reviewed values; do not disable admission |
| Native namespace refusal | Unit/path/UID/GID collision | Choose supported placement; no invented numeric account |

Not every defensive refusal has a unique error code. A property path and exact
selected source are more useful than guessing from a generic message.

## Generated workflow differs

Use the selected framework generator with the selected site and library.
Review the diff; do not hand-patch a generated file, re-pin a hash blindly,
weaken its policy or silently use an unpublished dependency.
Unknown guest selection or stale disabled dependencies can fail before execution.

## Controller ownership or phase refused

A generic hold message can hide several causes: foreign/missing state, changed
canonical pointer, incomplete history, private-material drift, missing immutable
input or exact HOLD ownership mismatch.
Preserve evidence and establish a bounded read-only diagnostic under the
installation's operating policy. Do not clear a marker, overwrite a receipt,
restore an old backend or change lifecycle to fresh.

A file-mode/owner failure in a disposable test can be a fixture defect; prove
the production contract first. Keep the original red result and preserve
meaningful inode/content/mode assertions when correcting a fake.

## Runtime is healthy but a job failed

A pre-existing healthy container does not identify the failed command's cause.
Check exact phase/log boundaries and selected source; no-log output may remain
insufficient. Do not trial restarts/pulls/recreates to discover cause without
authority. Distinguish package/registry transfer failures from application
protocol or preservation failures.

## CI and review

Read exact current-head results. A queued/skipped job or an old green commit is
not current acceptance. Review-service capacity refusal is a separate gate;
do not change base, filters or security settings to hide it.
Linux ownership/xattrs require the real Linux fixture, not a macOS mock result.

[Operations index](README.md) · [Testing](../contributing/testing.md)
