# Recover a failed guest deployment

Use the generated CD workflows to recover an update to an existing HomeLab guest. A failed deployment remains **failed**, including when rollback succeeds. Its summary separately reports `failed_rolled_back`, `failed_no_change` or `recovery_required`. Rollback releases only the matching hold after verification so a fresh deployment can proceed. It does not retry the failed forward operation or declare an incomplete phase successful.

## Ordinary update and rollback

Each guest job owns its recovery and completion. After Setup, **Recover pending deployment** checks only that guest's earlier attempts. It closes an already verified but interrupted publication or rolls back a supported interrupted update before starting new changes. **Complete guest deployment** runs after that guest's deployment phases, including Configure backup when selected. Success publishes that guest's completed deployment and releases its hold. Failure restores and verifies only that guest's previous managed configuration. The job stays failed even when rollback succeeds.

Successful guests remain deployed when another guest fails. Declared job dependencies prevent downstream guests starting after a failed prerequisite; they do not trigger rollback of successful providers or independent guests. The shared web-check job reports endpoint failures against completed guests and cannot undo their deployments. There are no global recovery or finish jobs.

Completion runs after a failed phase, but not when Setup or pending recovery failed, the job was cancelled, or its timeout terminated execution. The next run inspects that guest's retained attempt. An uncertain writer or a previous failed rollback still requires engineering reconciliation.

Before an update changes infrastructure, CD saves private copies of the previous deployment's managed configuration leaves, permissions, exact installed package versions and container image identities. OpenTofu plans against the actual backend to restore the previous allowed infrastructure settings; Ansible restores the captured application controls and starts the owned services with their previous image selections. Existing plan guards still reject imports, destructive replacements, changed disks, moved storage, foreign identities and unknown values. No historical OpenTofu state file is copied over the actual backend.

[Root public-key maintenance](../guides/root-ssh-keys.md) includes the exact
shared authorization-file preimage. Recovery admits only that preimage or its
declared additive postimage, preserves unknown prior entries, and refuses
foreign edits. It never copies private SSH keys. Older pending attempts without
this control in their saved inventory require resolution under their previous
qualified framework before adoption; the new owner does not recapture history.

For a mutable container tag, recovery first verifies that the captured image ID still exists locally, then restores the owned Compose reference to that ID. Compose starts with pulling and building disabled. The running container and the local reference must both match the captured ID, so a later service restart retains that selection. Missing images or inconsistent immutable references retain the hold; recovery does not fetch a replacement image.

Recovery verifies the restored configuration, package and image selection, application health, reply routing and previously declared route checks. The restored guest must pass before its rollback hold is released. The canonical `ordinary-complete.json` and failed operation remain historical evidence. A separate `current-state.json` identifies the verified effective owner, current backend and exact resolved failure markers. Deployment and backup readers use that verified state; a reconciliation record is never an ordinary phase success.

An ordinary source change can move prepared monitoring inputs into a new sealed input directory. Recovery requires the exact agent credential and database-password locations, and the selected PostgreSQL storage-password or Zabbix server-payload location when present. It compares their relative application owners, field presence and every other monitoring setting. It verifies the previously installed backup and monitoring settings, credentials and package selections before native reversal and again after restoring controls. Moving a prepared input alone does not authorize credential rotation or a new monitoring owner.

## When an engineer is needed

The MVP restores deployment-managed infrastructure and existing application control files. It does not restore application data, databases, schemas, private account state or external systems. It does not remove newly installed packages. Backup and monitoring ownership must remain unchanged. A newly introduced application control path keeps its supported installation behavior. If that update fails, CD records that the previous control inventory is incomplete and retains its hold instead of claiming a complete rollback. Verify the repaired current-main installation through Reconcile guest; last-good reconciliation cannot erase that missing baseline. New app ownership still needs its supported first-installation recovery. First installation has no last good owner and therefore no automatic rollback baseline.

Changed credentials or trust, a foreign hold, changed resource identity, missing or tampered evidence, an unfinished infrastructure apply, or a configuration writer killed before a known outcome retain their holds. A failed or unverifiable rollback records `recovery_required`; subsequent ordinary CD does not repeatedly run the failed reversal. An interrupted publication that already has a verified current-state pointer can finish its exact hold release without repeating native work.

A returned Ansible process is insufficient evidence after connection loss. Automatic reversal of a failed task requires its complete single-host recap with no unreachable host. A timeout, signal, transport failure or missing recap retains the hold for reconciliation.

## Reconcile guest

After repairing the cause through its supported owner, run **Reconcile guest** from the deployment repository's protected `main` branch. It uses the same deployment concurrency group and the selected guest's literal protected Environment. It does not enable a disabled guest, apply configuration, restart services, import resources or override a mismatch.

| Workflow input | Meaning and limits |
| --- | --- |
| `guest` | Required choice of one guest in the current source. An existing owned guest and its exact ordinary hold are required. Unknown, relocated and first-installation guests cannot be adopted. |
| `baseline` | `last_good` by default: verify the preserved previous owner and its captured controls when available. `current_main`: render expected inputs from protected main and verify the repaired installation against them. No configuration is applied. |
| `reason` | Required engineering recovery note, 1–1024 UTF-8 bytes after trimming. State the repair and disposition of any application data or schema issue. The reason is retained privately with the source revision and GitHub actor. |

For `current_main`, each application prepares only its own declared scalar secret inputs; the final verification step receives no application secret values. Credentials, resource identities, guest storage and existing application ownership must remain continuous. OpenTofu requires a no-op resource plan and may persist refreshed state through its own engine. Ansible performs read-only configuration and health checks. The managed-control inventory follows the selected deployment type: Compose applications include the Compose admission helper; native-only applications verify their declared configuration and services without requiring that helper. A mismatch keeps the hold. A pass records a distinct reconciled owner and releases only that hold, allowing a **new** ordinary deployment.

Reconciliation also checks installed PBS coverage, retained backup credential bytes and source ownership, plus the monitoring configuration, PSK, ownership receipt, selected package versions and active service. It refuses an interrupted monitoring installation. Preparing these payloads locally cannot establish guest readiness. These checks neither enroll a backup client nor rotate credentials, capture a backup or change agent settings.

## Generate and verify the source

Regenerate the Stack and private workflows from the same selected framework revision using the [generation commands](../reference/cli.md#consumer-wrapper-blueprintsprivate_workflowspy). Public Stack output puts recovery and completion steps inside each `guest-*.yml`; private output puts them in each guest job and retains `reconcile-guest.yml`. Remove obsolete generated `pending-recovery.yml` and `finish-deployment.yml` files when adopting this revision. Never edit generated jobs by hand.

Recovery, completion and reconciliation use the selected guest's existing protected Environment. Recovery and completion receive the literal guest name and only that job's result, using already commissioned credential paths without forwarding application secrets. `HOMELAB_CHECK_ENVIRONMENT` remains the shared read-only web-check Environment; remove the obsolete `HOMELAB_RECOVERY_ENVIRONMENT` source setting if present.

Existing deployment records remain immutable. A pending guest can honour its entry in an older global decision without reading or changing other members. New decisions are stored under that guest's recovery directory.

Source tests use real private receipt transactions, local file controls and native fakes to exercise failure, rollback, reconciliation, tampering and future-run admission. A local Ansible integration also runs the production capture, restore and verification playbook against disposable files, including preservation of literal program templates. Passing these tests does not prove recovery on a live guest. A disposable protected-CD failure/rollback exercise and subsequent successful deployment are required to establish native adoption; application data and device acceptance remain separate checks.

[Deployment](deployment.md) · [Lifecycle](../reference/lifecycle.md)
