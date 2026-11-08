# Configure and deploy backups

[Backup setup](README.md) → [API access](access.md) → **Configuration** → [Verify and operate](operations.md)

This step connects the prepared PBS server to your site, enrolls guests and deploys backup services. Work in your deployment repository using the compatible framework and library selected during [initial preparation](../guides/prepare-deployment.md#select-compatible-source).

## Check whether this is a new managed enrollment

This procedure supports first managed enrollment and subsequent deployments using the same managed ownership records. Earlier manually configured backup jobs used different client fields (`auth_id`, `password`, `encryption_key` and `key_password`) and root-wide enrollment; they are not accepted by this contract. New jobs use guest markers, a management credential and a recovery public key instead.

If old backup settings were never commissioned, prepare the new inputs and verify the intended member set before selecting this release. If an old job is running or owns credentials/records, keep its working source, schedule, keys and namespaces intact. There is no automatic conversion or supported in-place import of its keys here. Remain on the previous compatible source until an explicit environmental handover preserves old recovery access and proves replacement protection. Do not clear ownership or generate replacement keys merely to make the new configuration pass. This guide does not authorize retiring an existing backup system.

## Gather the prepared inputs

You need the real PBS HTTPS endpoint and its certificate fingerprint, the existing verified datastore and its filesystem/path, the public recovery PEM, the protected `PBS_API_TOKEN`, and the existing guest interface/staging bindings. Do not paste secrets into YAML. Keep the recovery private key outside the checkout and runners.

Create a site-relative public-key location, for example `assets/backup/master-public.pem`, and copy only the verified public PEM there. Compare its public-key fingerprint with the [generation record](recovery-key.md#generate-the-pair-once). Its public nature does not make changes harmless: review replacement just like a trust-anchor change.

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
| `backup.job.clients` | Staging and transport bindings for exactly the enrolled guests |
| `backup.job.capture` | Explicitly reviewed application pauses, database locking and export inputs |
| `backup.job.limits` | Bounds sized from the included data, files, temporary staging and expected duration |

Declare the endpoint once and reference it. The management job uses the same destination identity; do not maintain a second address or fingerprint for it. The secret source selects `PBS_API_TOKEN` without containing its value. The [identity/secrets reference](../reference/identity-and-secrets.md#secret-sources) describes the source forms.

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
