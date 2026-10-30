# Completed commissioning custody and ordinary deployment

A completed database commissioning group continues to own its original records.
Ordinary deployment refuses its members by default. A reviewed private selection
can admit a named member only when the complete existing group provenance and that
member's current backend generation pass the closed reader described here. Public
source tests do not establish private readiness or authorize deployment.

## Source selection

Each configured member carries the same top-level `coordinated_custody` object,
with exactly `schema: "homelab-coordinated-custody-v1"` and `group`. The group has
exactly these fields:

| Field | Required value |
| --- | --- |
| `directory` | Existing `database-network-cutover-<operation>` for both supported schemas, as written by the original producer. |
| `schema` | `homelab-postgresql-cutover-v1` or `homelab-database-server-cutover-v1`. |
| `operation` | Original operation, prefixed `postgresql-` or `mariadb-`. |
| `records` | Exact raw SHA256 values keyed by `request.json`, `claim.json`, `complete.json`. Request and claim must be identical. |
| `catalogue` | `{ "file": "catalogue.json", "sha256": "<raw SHA256>" }`. |
| `acceptance` | `{ "file": "acceptance.json", "sha256": "<raw SHA256>" }`. |
| `recovery` | `{ "mount": "<absolute path>", "directory": "<absolute path below mount>", "source": "<existing NAS source>" }`; equal to the guest's existing backup paths/source. |
| `members` | Exactly `postgresql`, `identity`, `db-tools` for PostgreSQL; exactly `mariadb` for MariaDB. |

Every member entry has exactly `vmid`, `node`, `installed_site`, `overlay`,
`initial_state_sha256`, and `initial_ordinary`. VMIDs remain distinct and retain
protected-guest exclusions. `installed_site` names the original absolute installed
profile path. `overlay` has exactly `directory` and `sha256`, selecting the
existing `database-network-apply-<review SHA256>/overlay.json`.

`initial_state_sha256` binds the independently reviewed starting backend bytes.
`initial_ordinary` is either:

- `null`: the starting canonical ordinary receipt must be absent and the starting
  state must be exactly the accepted network overlay's state; or
- `{ "operation": "ordinary-<run ID>-<attempt>", "sha256": "<raw canonical SHA256>",
  "source_sha256": "<qualified old source SHA256>" }`: require the already existing
  immutable operation copy of the exact reviewed four-field legacy receipt.
  Optional `immutable_sha256` pins that copy's raw bytes separately. When omitted,
  it defaults to `sha256`, preserving the closed same-byte selection format.

The original producer sorts keys in the immutable copy but preserves insertion
order in the canonical pointer; both serializers append a newline. When their
bytes differ, independently pin both raw hashes. After both pins pass, the complete
decoded four-field records must have identical canonical JSON, including nested
values and types; booleans cannot equal integers and integers cannot equal floats.
These reads never normalize or rewrite either file. Later framework receipts
still require exact raw canonical/immutable equality and latest-success custody.

Unknown starting receipt dispositions cannot be represented as accepted facts.
Missing immutable legacy operation copies refuse admission. The reader recognizes
only that selected raw legacy receipt as initial provenance; it does not treat it
as a current workflow success or implement generic legacy compatibility.

The two proof files are ordinary immutable packet files. Existing public profile
`files` templates can select raw proof text from private overlay `values`; ordinary
source resolution selects one complete central value or an exact literal proof.
Proof contents are never interpolated, including literal `${inputs}` or other
central-value tokens; ordinary runtime files retain their normal substitution.
No new runtime loader
or source-file override is required. Before private adoption, require explicit
human review of this proof-integrity control across source resolution, packet
compilation, preparation and admission; public tests provide source evidence and
do not establish deployment acceptance. Their bounded filenames
may differ from the names above, but must be distinct. Set
`paths.coordinated_custody_inputs` to `${inputs}` in the composition source;
preparation requires the exact materialized guest packet directory. The whole
selection excludes this per-guest path, so all copies can remain identical.

All configured member copies and proof bytes must agree, including disabled
members. This does not require all members to run. Existing dependencies, visible
phases, default empty disabled list, prerequisites and exclusive-writer gates
continue to determine the enabled work. No selection grants a custody waiver to
a disabled member or contacts it as a deployment target.

## Read-only evidence and admission

Before target work, the reader verifies exact local/NAS request, claim and full
successful completion bytes, with the original catalogue and retained acceptance
source. PostgreSQL uses the retained accepted network31 group JSON; MariaDB uses
the original cutover selection JSON. Neither is replaced with a new readiness
boolean. Full member proofs preserve the original installed profile, installation
files, source/input bindings, saved network plan and review packet, local/NAS
overlay parity, public CA and recorded guest trust. The own guest's current
known-hosts selector must match its existing trust record; admission never creates
or rewrites trust.

Reads are bounded, reject duplicate JSON and symlink parents, require owned
private files/directories, and recheck parent identity and proof bytes. The NAS
must already be mounted with the selected filesystem/source. The reader never
creates recovery paths or repairs records. Holds, verification markers and hidden
or pending custody in the examined group, overlay, plan and own guest directories
refuse admission. Own continuation requires its exact ordinary hold and completed
infrastructure receipt. Interrupted final receipt publication remains held.

The immutable input binding includes the full proof set and a stable
`coordinated_custody_sha256`. Mutable backend bytes and the canonical ordinary
receipt are deliberately outside that immutable proof set. Under the existing
database shared lock and the own guest's workflow/deployment exclusive locks,
admission checks only this guest's mutable backend. Other members' mutable state
and running ordinary attempts are not frozen.

The first attempt starts from the selected exact anchor. Infrastructure may
advance state serial, hash and mutable attributes while preserving lineage, the
three existing managed resource addresses, VMID, node and each provider resource
ID. Saved plans must preserve those IDs before apply. Its infrastructure receipt
records `state_identity`; the normal immutable operation completion and canonical
ordinary receipt retain it. The ordinary hold binds the preceding canonical
receipt hash through `previous_ordinary_sha256`.

Later attempts require the canonical receipt to match the latest successful
coordinated operation copy and current backend hash/identity. The existing
workflow ownership, monotonic run and private-source ancestry checks still apply.
A missing, altered, failed, foreign or superseded receipt cannot fall back to the
initial overlay or legacy receipt. A valid own continuation instead follows its
exact same-run hold and infrastructure receipt. Successful ordinary generations
advance through the normal receipt protocol without rewriting original records,
repinning overlays or creating handoff markers.

## Separate native prerequisite

The database shared lock cannot fence an older verifier that also takes a shared
lock and writes verification custody. Before any private adoption, the owner must
separately retire or drain old coordinator, writer and verifier entrypoints through
the existing global queue and a reviewed owner/manual/noncooperator window. A
brief exclusive-to-shared lock transition does not establish that window. There is
no `writers_fenced` flag, group release, new controller, all-member lock or global
exclusive serialization in this contract. Missing window or live starting facts
remain prerequisites; synthetic validation cannot supply them.


## Standalone Influx initial ordinary receipt

A standalone Influx guest whose exact original ordinary success lacks the later
workflow fields can explicitly select `initial_ordinary` in its source config.
This is a separate closed contract, mutually exclusive with `coordinated_custody`;
existing coordinated ownership or failure markers still block admission. Only
an `influxdb` profile can select it. No values are inferred, and no receipt,
backend, group or claim is rewritten or released.

The object requires exactly these fields:

| Field | Binding |
| --- | --- |
| `schema` | `homelab-influx-initial-ordinary-v1` |
| `vmid`, `node` | The exact configured and installed Influx identity |
| `installed_site` | Canonical absolute path of the retained original site JSON |
| `installed_site_sha256` | Its exact raw hash, also equal to the old receipt's `binding.site_sha256` |
| `initial_state_sha256` | The independently qualified initial backend raw hash |
| `receipt.operation` | Exact existing `ordinary-<run-id>-<attempt>` directory name |
| `receipt.sha256` | Exact raw canonical `ordinary-complete.json` hash |
| `receipt.immutable_sha256` | Exact raw hash of that operation's `complete.json` |
| `receipt.source_sha256` | Independently qualified original producer source hash |

All digests are required lowercase SHA256 values, and `receipt` permits exactly
its four listed fields. The private owner must independently qualify the selected
success, original source and installed site, complete typed equality of the two
receipt records, current backend, original GitHub run/job evidence and absence of
legacy group ownership and failure holds. A different historical operation is not
an interchangeable initial anchor. This framework does not choose private pins.

The original site must retain the selected guest/node/kind and local/recovery
paths. Its receipt's CA input hash must match current CA bytes; existing guest
host trust is required and read without creating it. Management SSH endpoints and
database listener addresses retain their distinct roles. The immutable site,
operation copy and guest trust are bound into current input hashes; the canonical
pointer and backend remain mutable generation evidence.

After locks and existing hold checks, the first entry requires both selected raw
receipt pins, exact four-field success shape, source/site/VMID/state bindings and
full type-sensitive decoded equality. The current backend must match the initial
hash. This anchor starts a new ordinary run; it is never treated as a completed
current run and receives no fabricated workflow fields.

The new binding includes `initial_ordinary_sha256`. Existing infrastructure and
phase receipt writers record actual current workflow, run sequence, source
revision, backend hash and identity. Later immutable successes outrank the old
anchor; removing or restoring the canonical pointer cannot fall back to it.
Same-run continuation still requires the exact owned hold and completed
infrastructure state/identity. Older runs, source rollback, changed bindings,
failed or pending evidence and dropped selection are refused. Existing historical
records remain byte-for-byte intact; private adoption, continuation and deployment
are separate operations.

## Optional empty provider refresh values

For pinned bpg/proxmox 0.117.0, only the following explicitly present optional
refresh leaves compare `null` as their typed empty value: `tags` as `[]`,
`environment_variables` as `{}`, and each `disk[].mount_options`,
`mount_point[].mount_options` and `features[].mount` as `[]`. Missing fields,
wrong empty types, nonempty values and all other fields retain exact comparison.
This normalization applies only to refresh drift. Desired-plan disk/mount
immutability, configured networking, identity and unknown-value checks are
unchanged. Top-level computed address observation handling remains separate.
