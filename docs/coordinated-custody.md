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
| `directory` | Existing `database-network-cutover-<operation>` for PostgreSQL, or `database-server-cutover-<operation>` for MariaDB. |
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
- `{ "operation": "ordinary-<run ID>-<attempt>", "sha256": "<raw receipt SHA256>",
  "source_sha256": "<qualified old source SHA256>" }`: require the already existing
  immutable operation copy of the exact reviewed four-field legacy receipt.

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
