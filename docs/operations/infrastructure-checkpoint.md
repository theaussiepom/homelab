# Admit completed infrastructure after a failed application phase

Use this narrowly scoped procedure when a managed guest's Infrastructure phase completed, a later phase failed, and an authorised operator has preserved the failed operation and released its hold. The backend can then be newer than the last fully successful ordinary deployment. This procedure admits the genuine infrastructure progress for one fresh successor; it does not declare the failed application successful.

The framework does not archive failures or release holds. Those remain separately reviewed operator actions. Do not edit the backend, move the ordinary-success pointer, manufacture completion files or replay the old run. The [deployment contract](deployment.md#failure-and-recovery) and [lifecycle](../reference/lifecycle.md#later-deployments-and-ownership-checks) continue to apply.

## Prerequisites and evidence

Work from the controller using the reviewed framework selection and the existing deployment UID. Require an independently reviewed failed-operation archive, the current backend and the genuine prior ordinary success, including its immutable receipt and sealed app inputs. The archive must be a real mode-0700 direct child of the guest's existing state directory, named `operator-recovery-<failed-run-id>-<failed-attempt>`. It must contain exactly:

- `ORDINARY-HOLD.json`: the original private hold, including the previous ordinary-success digest, workflow, run number, source revision and binding.
- `ordinary-<failed-run-id>-<failed-attempt>/`: the preserved failed operation, containing its real `infrastructure-complete.json` and partial phase evidence, without an overall `complete.json`.
- `original-evidence-inventory.json`: the reviewed archival inventory, with the original operation/archive paths, original hold identity and hash, and operation evidence identities and hashes.

The inventory is the existing archive item shape: `hold`, `evidence`, `guest_entries`, `operation` and `archive`. Each selected file entry contains `identity` and `sha256`. Identity is the original device, inode, mode, UID, GID, link count, size and modification time in nanoseconds. The reader requires unchanged identities and bytes for the checkpoint, hold and phase evidence; it does not copy, repair or rename them. The reviewed inventory digest is pinned independently in the admission record. Missing, symlinked, foreign, partial or changed evidence refuses.

The current backend must match the checkpoint's exact state hash. Its lineage and complete resource-identity map must equal both the checkpoint and prior ordinary success. Matching IDs alone cannot admit a changed backend. This procedure does not support a new guest, missing prior success, resource replacement or identity extensions.

The reader reuses the sealed static-input verifier and validates ordered partial phase provenance. These partial phase records do not grant application ownership. The archived source must descend from the prior success and be an ancestor of the successor. The workflow and guest/provider identity must remain the same.

## Review and publish one admission record

An explicitly authorised operator prepares the following private controller record at `<state-root>/<vmid>/infrastructure-admission.json`, using exclusive creation under the existing shared database-network lock and exclusive guest workflow/deployment locks. Require the ordinary hold, target operation and `infrastructure-admission-claim.json` to be absent. Review the exact real values before publication; source selection alone does not authorise this record.

This is a **synthetic shape example**, not a runnable recovery request. Zero digests must be replaced with hashes of the genuine named records and the reviewed successor packet. Do not put credentials, resolved models or private payload bodies into the admission file or CI logs.

```json
{
  "schema": "homelab-component-infrastructure-admission-v1",
  "archive_directory": "/var/lib/example-applications/610/operator-recovery-102-1",
  "archive_inventory_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "hold_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "checkpoint_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "previous_ordinary_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "successor": {
    "after_run_id": 103,
    "source_ancestor": "0000000000000000000000000000000000000000",
    "input_identity": "0000000000000000000000000000000000000000000000000000000000000000"
  }
}
```

All listed fields are required, with no defaults. Unknown fields, omitted values, nulls and empty values are refused.

| Field | Accepted value and effect |
| --- | --- |
| `schema` | Exactly `homelab-component-infrastructure-admission-v1`. |
| `archive_directory` | Canonical absolute path to the one reviewed archive described above. No directory search or fallback. |
| `archive_inventory_sha256` | Lowercase 64-hex digest of the exact archival inventory bytes. |
| `hold_sha256` | Lowercase 64-hex digest of the original archived hold bytes. It must also match the inventory. |
| `checkpoint_sha256` | Lowercase 64-hex digest of the original infrastructure checkpoint bytes. It must also match the inventory. |
| `previous_ordinary_sha256` | Lowercase 64-hex digest of the unchanged canonical ordinary-success bytes; must match the archived hold's previous-success binding. |
| `successor.after_run_id` | Positive integer at least the failed archive's run ID. Set it to the latest failed or excluded run. The admitted run ID must be greater, and its attempt must be 1. No old-run or attempt replay. |
| `successor.source_ancestor` | Lowercase 40-hex reviewed private-source commit which must be an ancestor of the admitted source. This allows the normal reviewed source-pin commit without guessing its future merge SHA. Existing ordinary source-ancestry checks still apply. |
| `successor.input_identity` | Lowercase 64-hex identity of the exact reviewed successor deployment packet. Source-pin changes may retain that identity; different desired guest/application/static artifacts are refused. |

Keep the record mode 0600 and owned by the deployment UID. Use the existing private `write_new` helper or an equally reviewed exclusive, no-follow, fsynced file creation; never overwrite a previous record. This change adds no operator CLI, site YAML fields, privileged application credential or hold-release mechanism.

## Execute and verify a fresh successor

After admission publication and the reviewed source pin adoption, the normal protected deployment starts a new operation. Entry validates the prior ordinary success in full and verifies the selected archive and successor binding. It uses the checkpoint's sealed infrastructure configuration for NFS and staging continuity while retaining the prior canonical success as the sole authority for applications, credentials and runtime namespaces.

Before any native infrastructure execution, and under the normal locks, the framework rechecks the bounded evidence snapshot and exact current backend. It copies the admission bytes into the new operation and exclusively creates `<state-root>/<vmid>/infrastructure-admission-claim.json`, binding the admission digest to that new operation. The normal new-operation hold remains in force. The old archive, backend and canonical receipt are not rewritten by admission.

The ordinary infrastructure engine then plans and applies through its existing guards. All required preparation, application, monitoring and backup phases still run. Only their genuine complete success advances `ordinary-complete.json`. The failed original workflow remains failed. An admission claim is evidence of consumption, not infrastructure or application success.

A failure during claim publication leaves the new hold and evidence before any native call. A later failure preserves that operation's normal hold/checkpoint; another run cannot reuse the consumed admission. Any further recovery needs a separate review. Do not remove or replace the claim to force a retry. After a successful ordinary deployment, later ordinary runs use its new canonical backend and do not consume the stale admission again. Preserve the admission, claim and archive as history.

## Source checks and limits

The maintained [checkpoint regressions](../../proxmox/applications/tests/test_component_checkpoint.py) use the real compiler, input publication, ordinary receipts, archive relationships, local Git ancestry and deployment locks. Native provider and Ansible bodies are fakes. They exercise a completed infrastructure change followed by an application failure, exact fresh-successor admission, NFS continuity, prior app ownership, immutable history, normal later deployment, malformed or changed evidence, wrong inputs/source/run, active holds, consumption failure and lock contention. These tests do not perform a production recovery or prove running service acceptance.

[Admission implementation](../../proxmox/applications/component_checkpoint.py) · [ordinary generation](../../proxmox/applications/component_generation.py) · [deployment](deployment.md) · [operations index](README.md)
