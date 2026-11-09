# Configure and deploy backups

[Backup setup](README.md) → [API access](access.md) → **Configuration** → [Verify and operate](operations.md)

This step connects the prepared PBS server to your site, enrolls guests and deploys backup services. Work in your deployment repository using the compatible framework and library selected during [initial preparation](../guides/prepare-deployment.md#select-compatible-source).

## Check whether this is a new managed enrollment

This procedure supports first managed enrollment and subsequent deployments using the same managed ownership records. Earlier manually configured backup jobs used different client fields (`auth_id`, `password`, `encryption_key` and `key_password`) and root-wide enrollment; they are not accepted by this contract. New jobs use guest markers, a management credential and a recovery public key instead.

If old backup settings were never commissioned, prepare the new inputs and verify the intended member set before selecting this release. If an old job is running or owns credentials/records, keep its working source, schedule, keys and namespaces intact. There is no automatic conversion or supported in-place import of its keys here. Remain on the previous compatible source until an explicit environmental handover preserves old recovery access and proves replacement protection. Do not clear ownership or generate replacement keys merely to make the new configuration pass. This guide does not authorize retiring an existing backup system.

## Gather the prepared inputs

You need the real PBS HTTPS endpoint and its certificate fingerprint, the existing verified datastore and its filesystem/path, the public recovery PEM, the protected `PBS_API_TOKEN`, and the existing guest interface/staging bindings. Do not paste secrets into YAML. Keep the recovery private key outside the checkout and runners.

Copy the verified public key to a site-relative repository location such as `assets/backup/pbs-recovery-public.pub`. The `.pub` file contains the exact same PEM-encoded RSA public key produced as `master-public.pem`; keep that encoding rather than converting it to SSH public-key format. The repository destination uses `.pub` so it can be staged normally under the existing ignore and private-path rules. Keep the private PEM outside Git; do not force-add a `.pem` file or weaken those rules. Compare the public-key fingerprint with the [generation record](recovery-key.md#generate-the-pair-once). Its public nature does not make changes harmless: review replacement just like a trust-anchor change.

### Prepare storage for an already managed guest

Operational staging currently supports **ZFS-pool subvolumes only**. The authored value remains a storage ID; before any resource apply or creation, CD verifies that the selected storage is a `zfspool`. Other pool/filesystem types are refused rather than using a block-device or root-filesystem fallback. Generic storage-ID syntax alone does not prove runtime support.

A new guest can receive its declared isolated staging subvolume during normal creation; CD verifies its allocated filesystem before proceeding to app configuration. An already managed guest has a separate prerequisite: the pinned bpg 0.117.0 provider marks its entire mount list as requiring replacement, including an appended mount or changed native backup flag. Do not deploy such a change expecting an in-place attachment. `prevent_destroy` remains enforced; changing lifecycle, ignoring mount changes or recreating the guest is not a solution.

Before enrolling an existing guest, obtain a separately reviewed and authorized environmental preparation plan. It must preserve every existing volume identity, mount slot/order, path, size and option, changing only the native backup Booleans to the declared selection. If those flags already match, leave every old mount entry untouched. Allocate and attach exactly the declared empty staging subvolume in the selected storage at the next mount slot, unprotected by native backup. Determine whether that guest needs an authorized stop/start; this guide grants no service interruption and does not assume hot attachment is supported. Record the exact new allocation and preserve existing data and recovery access.

Native protection is a separate prerequisite. In the qualified [pve-container 6.1.10 mount-update path](https://github.com/proxmox/pve-container/blob/5eb5574ee9158ac40a5230de2cf18d7d6345709f/src/PVE/LXC/Config.pm#L1344-L1349), the API checks the guest's protection flag even for a previously unused mount slot. A protected guest therefore needs an explicitly reviewed and authorized temporary **native** protection transition for the attachment. Keep the declared guest protection and OpenTofu `prevent_destroy` unchanged; this is not a new source setting or an ordinary-CD exception. Qualify another installed version before relying on its behavior.

The environmental plan must bind the exact guest and original protected configuration, use fresh configuration digests for its conditional writes, and verify that every old mount remains unchanged and the new allocation matches the declaration. It must read back native protection as enabled again before handing the guest to CD. A cleanup or `finally` block alone does not prove restoration: on any failed or ambiguous step, preserve the original configuration, allocation identity and attempt evidence, stop at the approved boundary, and do not claim successful restoration or proceed to CD. There is no automatic retry or alternate attachment path. The exact write sequence and any failure disposition belong to that separately reviewed plan, not this prerequisite summary.

Do not edit the OpenTofu backend or a successful deployment receipt during that preparation. With the operational job declared, normal CD verifies the old successful ownership, compares the complete active mount sequence and backup flags using `current=1` rather than pending configuration, and binds the prepared volume through the trusted PVE API and guest SSH. It checks the exact ZFS dataset, mounted filesystem, ownership, capacity and an empty first-use root with no descendant mounts. It admits only the declared backup flags and one appended staging mount; a matching pool prefix or directory name alone is insufficient. It then applies the reviewed saved plan, including a state-only reconciliation when native resource actions are already no-op. Only a genuinely completed ordinary deployment records the new backend generation. Later deployments preserve its owned private backup history and client identities. Client preparation without an operational job retains the existing refusal for changed mount drift.

This prerequisite uses existing read permissions: the selected volume-info GET requires storage `Datastore.Audit` and owner-VM `VM.Config.Disk`, or `Datastore.Allocate`; the bounded storage index uses Audit or AllocateSpace. It does not list storage content, activate/import storage or request new grants. Unknown storage formats or an ambiguous API-to-guest filesystem mapping are refused. Consult [the staging contract](../reference/backup.md#backup-client-staging-volume) for the selected shape.

An unresolved deployment HOLD or failed attempt remains a separate environmental decision. Preserve it and its evidence; preparation does not authorize clearing a hold, modifying historical success or resuming a failed operation. Stop before CD until its disposition has been explicitly reviewed. There is no migration flag, imported-success record or ordinary-CD recovery branch.

### Prepare an existing InfluxDB operator token when selected

For an enrolled InfluxDB OSS 2.x producer, identify the exact existing instance and installed versions first. Native full backup requires its existing root/Operator authorization token. An organization's All Access token or a bucket read/write token is a different permission scope; a metrics integration credential is not sufficient evidence. See the [native backup requirements](https://docs.influxdata.com/influxdb/v2/admin/backup-restore/backup/) and [token types](https://docs.influxdata.com/influxdb/v2/admin/tokens/).

Have the authorized credential owner locate that existing token in its protected setup/password-manager record or the exact installed CLI configuration, normally `~/.influxdbv2/configs` unless a different location was selected. The [CLI configuration](https://docs.influxdata.com/influxdb/v2/reference/cli/influx/config/) can contain the URL, organization and token. Verify instance identity and authorization scope privately. Do not print the configuration, dump authorization records, screenshot the token or put it in a logged `--token` argument. If the token is missing, unknown or insufficient, stop: this procedure does not authorize setup, recovery-auth commands, new grants or token creation/rotation.

Through the separately approved credential-transfer procedure, place only the existing raw token in a new canonical controller file outside Git and CI workspaces. Use a private `0700` directory and a `0600` regular file owned by the **actual CD/Backup process account**. A file readable only by root is insufficient when that account is not root. Inspect the exact destination first; do not overwrite, follow a symlink or adopt an uncertain existing file. Then declare a file reference, not the token itself. This is a site fragment for an already declared Influx app named `metrics`; retain the rest of your existing job and capture permissions:

<!-- example: backup-influx-token-reference -->
```yaml
secret_sources:
  influx-operator:
    type: file
    path: /var/lib/homelab-private/influx-operator-token
backup:
  job:
    capture:
      influx_tokens: {metrics: influx-operator}
```

An environment source or the PBS API token cannot replace this file binding. During capture, the worker supplies the token as `INFLUX_TOKEN` only to its native Influx backup child, rather than in argv; sufficiently privileged local processes can inspect runtime environments. Protect both controller and guest accordingly. Keep independent recovery custody: with token hashing enabled, the original token cannot be recovered from its stored hash, and a full restore may require the separately retained operator token and compatible CLI. Do not disable hashing to bypass missing custody. Credential presence and source validation do not prove a successful export or restore.

## Declare shared backup settings

First work through the [complete offline backup example](../examples/backup/README.md). It supplies every library, site, catalogue and public-key file, identifies their compatible source selection, and gives compilation commands with an exact expected result. It cannot be deployed as-is. Return here to substitute your prepared real inputs.

Use the [canonical backup syntax and field reference](../reference/backup.md#syntax), then complete the [operational job](../reference/backup.md#operational-job). That reference is authoritative for accepted fields and limits; this checklist explains where their values come from.

| Configuration | Value source |
| --- | --- |
| `backup.profile` | Compatible library's registered PBS client profile |
| `backup.management.credential` | Environment secret-source reference for `PBS_API_TOKEN` |
| `backup.management.datastore_path` | Expected path of the existing datastore verified during [server setup](server.md#create-and-verify-the-datastore-once); a comparison value, not a request to create storage |
| `backup.recovery_public_key.source` | Site-relative verified public PEM |
| `backup.job.destination` | One declared PBS HTTPS endpoint, datastore, namespace and actual certificate fingerprint |
| `backup.job.schedule` | Your permitted backup interval and jitter; use the reference's UTC semantics |
| `backup.job.clients` | Staging and transport bindings for exactly the enrolled guests; optional client byte/file limits |
| `backup.job.capture` | Explicitly reviewed application pauses, database locking and export inputs |
| `backup.job.limits` | Default byte/file bounds and one shared phase timeout |

Declare the endpoint once and reference it. The management job uses the same destination identity; do not maintain a second address or fingerprint for it. The secret source selects `PBS_API_TOKEN` without containing its value. The [identity/secrets reference](../reference/identity-and-secrets.md#secret-sources) describes the source forms.

## Size each client and review later changes

Use `backup.job.limits` for common defaults. A client's optional [capacity override](../reference/backup.md#backup-client-limits) may contain `max_bytes`, `max_files` or both; omitted fields inherit their root defaults. `timeout_seconds` remains root-only because every member participates in the same coordinated pause window. Work through the complete [mixed-client example](../examples/backup/README.md#size-clients-independently) before selecting real values.

Size each byte bound from that guest's complete native database exports, selected-file archive and metadata, with measured growth allowance. Live database-directory usage is not an export size. The [staging volume](../reference/backup.md#backup-client-staging-volume) must be at least four times the effective byte bound; the worker checks three times that bound free before starting. These are per-filesystem checks, not host thin-pool reservations. Review the combined allocations, other workload growth and pool reserve separately. A successful run releases its verified payload/readback copies but retains operation records and logs; failures preserve remaining artifacts. There is no automatic local history pruning to make an undersized allocation pass.

A limit change is an ordinary configuration update. Enable each affected guest for its matching deployment, then complete the Backup job's whole-group activation before relying on the new configuration. An unchanged disabled member may retain its prior activated coverage; a changed disabled member is refused. Root-default edits affect inheriting clients, and removing an override restores inheritance. Keep existing namespace/token/client-key identities and failed evidence; increasing a bound does not authorize replay or cleanup.

## Enroll guests and select data

Add `backup:` to each guest that needs protection. The following is a **guest-file fragment**, not a complete guest definition:

```yaml
backup:
```

Root shared settings alone do not install clients everywhere. An enrolled guest's apps must have complete recovery classifications in their selected library profiles. For each managed volume whose contents belong in native full-guest backups, add the volume-level marker; keep staging and transient volumes unmarked. See [coverage](../reference/backup.md#application-recovery-declarations) and [volume selection](../reference/backup.md#backup-volume).

The compiler reuses bound app/guest paths. Do not write a second list of the same paths in backup configuration. Files classified as database engine storage are exported with supported database tools rather than copied as live directories. An application's required database-export member must also be enrolled; diagnostics identify missing members rather than silently adding them.

Guests disabled only for a particular CD selection remain enrolled for backup. The Backup job verifies their existing completed deployment and activation without reconfiguring them. A new or changed backup configuration must first be deployed with that guest enabled; disabling it cannot bypass initial setup. A run with every guest disabled performs no activation. Removing a marker from an already protected member requires an explicit retirement procedure; it is not a request to delete snapshots or rotate keys.

## Review the generated change

Use [validate and generate](../guides/validate-and-generate.md) with the exact framework/library/site combination. Inspect the generated management and guest jobs before publication:

- After the selected guest jobs succeed, the **Backup** management job uses the `backup` Environment and receives the named management token. It checks the existing datastore name/path and creates only declared namespaces and client access. A missing or mismatched datastore stops provisioning; the job does not create or relocate it.
- Only enrolled guests receive backup preparation and a **PBS agent** step. Their jobs keep their normal guest names and app deployment dependencies.
- The native client on each newly enrolled guest creates its encryption key once; CD retains a protected controller copy and verifies it on later runs. Each guest receives its own namespace-scoped token and the shared recovery public key. The administrator token and recovery private key are absent from guest inputs.
- Existing key fingerprints, namespaces, account ownership, app inputs and failure records are preserved. Repeated CD does not generate replacement keys.
- The separate Backup job activates the schedule only for a complete, successfully deployed group; ordinary guest jobs prepare coverage without depending on a working PBS server. Review any selected app pauses or database locks before allowing unattended runs.

GitHub secret forwarding must be explicit at every reusable-workflow boundary. Do not use `secrets: inherit` to make management secrets available throughout the guest graph. A missing Environment, denied token or inaccessible mount is a preparation failure, not a reason to broaden permissions during deployment.

## Deploy and check installation

Run the normal [protected deployment procedure](../operations/deployment.md) after the exact source and plan have passed their required checks. CD configures backup services; it does not count as the first successful backup.

Check that the PBS datastore/namespace objects match the source, each guest has the expected private files and client version, and the controller's schedule is installed for the complete group. Verify access using the guest's own token: its namespace must be usable while another guest's namespace and administrative/prune operations are denied.

On a repeated CD, confirm the same identities and key fingerprints remain. If a remote token exists but its saved secret is missing, stop that enrollment and preserve the record for explicit recovery. Do not regenerate encryption keys or replay credential creation to clear the error.

Continue with [the first scheduled backup and isolated restore](operations.md). Only those tests, together with maintenance and alerting, establish readiness for unattended operation.
