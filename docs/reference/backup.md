# PBS backup and recovery coverage

[Reference index](README.md) · [Storage](storage.md) · [Library](library.md) · [Workflow and lifecycle](lifecycle.md)

Define shared settings with site-root `backup`, then add `backup:` to each guest that needs the Proxmox Backup Client. Recovery paths come from existing guest and app bindings. Follow [the complete backup setup guide](../backup/README.md) before your first deployment. Add its `job` object to install a coordinated schedule that encrypts and backs up the selected data. The feature uses the normal continuous deployment (CD) inputs, completion receipts, deployment locks and holds that record failed operations.

There are two recovery tiers. Native Proxmox full-guest backups contain the operating system and selected managed volumes. Guest-client archives contain configuration, application state captured while its writers are paused, and native database exports. This contract implements the guest-client tier and selects volumes for native backup. Install Proxmox Backup Server (PBS), then [create and verify its datastore](../backup/server.md#create-and-verify-the-datastore-once) before CD. CD uses that existing datastore and manages declared namespaces and client access. Proxmox Virtual Environment (PVE) full-guest jobs and server maintenance have separate setup steps in [backup operations](../backup/operations.md). Uploading an archive and reading it back successfully does not prove that an application can be restored.

## Syntax

The following **site fragment** selects the library's only backup profile:

<!-- example: backup-selection -->
```yaml
backup:
```

`backup: null` and `backup: {}` have the same meaning. With multiple profiles, select one explicitly:

<!-- example: backup-profile-selection -->
```yaml
backup:
  profile: pbs-client
```

| Property | Type | Required/default | Meaning and constraints |
| --- | --- | --- | --- |
| <a id="backup-site"></a>Site `backup` | Null or closed object | Optional; omission adds no client phase | Presence defines shared settings; only guests with their own `backup:` marker receive client preparation. Boolean values are rejected. |
| <a id="backup-site-profile"></a>`backup.profile` | [Identifier](supporting-types.md#scalar-and-path-types) | Optional when exactly one profile exists | Reference to `backup_profiles`; omission selects the sole registered profile. |
| <a id="backup-site-job"></a>`backup.job` | Closed [operational job](#operational-job) | Optional; no timer without it | Selects the destination, protected inputs, transport, schedule and permission to capture data. |
| <a id="backup-guest"></a>Guest `backup` | Null or empty object | Optional; omission leaves guest unenrolled | Presence opts the guest into the shared configuration. Root `backup` is required. Booleans and unknown fields are rejected. |
| <a id="backup-volume"></a>Guest `volumes.<id>.backup` | Null or empty object | Optional | On an enrolled guest, presence includes the managed volume in native full-guest backup; omission excludes it. It is not a native database export. |

A bare root `backup` key, null or an empty object selects a shared profile; guest markers select where to install its client software and derive recovery coverage. You can use this form while preparing the server. It selects no destination or credential and grants no permission to interrupt a service. Supply `job` to configure scheduled backups. Validation rejects unknown fields and Boolean values. Compilation does not contact a network service or read secrets. Preparation without a job creates no accounts or keys. An operational job requires the management and recovery-public-key bindings below; its protected CD job creates client credentials once and preserves them on updates.

Without site-root backup, existing provider volume defaults remain unchanged. For an enrolled guest, a protected app storage role cannot bind to a managed volume that lacks `backup`. This includes database engine volumes: native full-guest backup and a coherent database export are separate requirements. A `root_paths` binding uses the root filesystem, which belongs to the native full-guest tier; it does not create another provider mount or native `backup` flag.

For an existing guest, native backup flags may change only to match the compiled selection exactly. All other existing mount attributes and their order must stay unchanged. The only appended mount this contract permits is the declared empty, unprotected staging volume after existing slots. The pinned provider requires replacement for mount-list edits, so existing guests require [separately approved environmental storage preparation](../backup/configure.md#prepare-storage-for-an-already-managed-guest); new guests can allocate their declared mounts during creation. An operational job is required for this desired-drift reconciliation: CD compares all active mount attributes/flags (`current=1`, not pending configuration), binds the allocated ZFS volume to its actual guest mount and proves an empty first-use root with no descendant mounts. Without a job, changed mount drift remains refused. A saved-plan apply persists the refreshed backend even when resource actions are no-op. Later owned private staging history may be nonempty. Unknown flags, changed paths, sizes or old volume identities, replacements, foreign/shared filesystems and undeclared changes remain refused. Backend/canonical ownership and failure holds are not waived.

## Management and recovery inputs

These root objects accompany `job`; neither belongs inside an individual client. Both are required for operational backup and rejected without a job. All objects are closed: unknown fields fail validation.

| Field | Type | Required/default | Meaning and constraints |
| --- | --- | --- | --- |
| <a id="backup-management"></a>`backup.management` | Closed object | Required with `job` | Selects protected PBS API management for namespaces and client access; never provisions the server VM, creates a datastore or formats storage. |
| <a id="backup-management-credential"></a>`backup.management.credential` | Secret-source identifier | Required | Environment source selecting `PBS_API_TOKEN`, whose value is `user@pbs!token:secret`. Only the management job receives it. |
| <a id="backup-management-datastore-path"></a>`backup.management.datastore_path` | Absolute canonical path | Required | Expected path of the existing datastore prepared and verified during server setup. CD compares the API configuration with this value and refuses a missing or mismatched datastore. This field neither creates storage nor proves that its filesystem is mounted; `/` is not an accepted datastore path. |
| <a id="backup-recovery-public-key"></a>`backup.recovery_public_key` | Closed source object | Required with `job` | The shared RSA recovery public key; never a client key or private PEM. |
| <a id="backup-recovery-public-key-source"></a>`backup.recovery_public_key.source` | Confined site-relative file path | Required | A PEM-encoded RSA-4096 public key; use a repository destination such as `assets/backup/pbs-recovery-public.pub` under the normal ignore/private-path rules. The `.pub` suffix does not change the PEM encoding to SSH format. Absolute paths, symlinks/escapes and private-key content are rejected. Its validated bytes are included in the deployment packet. |

The management connection reuses `job.destination.endpoint` and its certificate fingerprint. A second endpoint or trust fallback is not accepted. Define the management source in the site's [secret sources](identity-and-secrets.md#secret-sources):

```yaml
secret_sources:
  pbs-management:
    type: environment
    name: PBS_API_TOKEN
    workflow_secret: PBS_API_TOKEN
```

The secret value belongs in the protected `backup` GitHub Environment, not in YAML. [API setup](../backup/access.md) explains its exact format and permissions. [Recovery-key setup](../backup/recovery-key.md) explains how to create and store the pair. Source compilation validates public inputs; it does not read the API secret or create private keys. Repeated deployment reuses recorded credentials and stops on missing/foreign records rather than generating replacements.

## Backup profiles

Library `backup_profiles.<id>` accepts an inline definition or a confined `{source: relative/file.yaml}` reference, like other [typed sources](sources.md). A referenced document uses `schema: homelab-components-v1` and `kind: backup-profile`.

<!-- example: backup-profile -->
```yaml
schema: homelab-components-v1
kind: backup-profile
type: pbs-client
software: [pbs-client]
configuration:
  ssh:
    path: /etc/ssh
    kind: directory
```

| Property | Type | Required/default | Meaning and constraints |
| --- | --- | --- | --- |
| <a id="backup-profile-type"></a>`type` | String enum | Required | Exactly `pbs-client`. No arbitrary agent or shell command. |
| <a id="backup-profile-software"></a>`software` | Nonempty unique identifier list | Required | Existing [software definitions](supporting-types.md); the effective selection must contain one exact `proxmox-backup-client=<version>` package. Existing repository-key and package-version guards apply. |
| <a id="backup-profile-configuration"></a>`configuration` | Named map of path objects | Required; may be empty | Guest configuration to retain, not a request to read it during compilation. |
| <a id="backup-profile-configuration-path"></a>`configuration.<id>.path` | Absolute canonical path | Required | Names a specific file or directory; `/` is rejected. Listing configuration does not authorise archiving the whole operating system. |
| <a id="backup-profile-configuration-kind"></a>`configuration.<id>.kind` | String enum | Required | `file` or `directory`. |

Compilation resolves the software references and copies their public repository keys into the deployment packet, checking each key against its declared digest. It does not fetch packages, read private configuration, connect to PBS or create credentials. The library selects the client version; the framework does not maintain another copy of that version pin.

When root monitoring is also selected, recovery coverage includes the agent configuration `/etc/zabbix/zabbix_agent2.conf`, existing key `/etc/zabbix/agent.psk` and ownership receipt `/var/lib/homelab-monitoring/agent.json` managed by the framework. Their reserved configuration IDs are `zabbix-agent-configuration`, `zabbix-agent-key` and `zabbix-agent-ownership`; a profile cannot use those IDs for different paths. Package caches and holds from interrupted installations are not normal configuration inputs. Controller credentials and hold records still need their own protected recovery copies.

## Application recovery declarations

For every enrolled guest, each selected app profile must supply a `backup` object that classifies **every storage role**, including optional roles. `include` and `exclude` must not overlap, and together they must cover exactly the profile's `storage` keys. Validation rejects a newly added storage role until the profile says whether to include or exclude it. The object accepts only the fields below.

<!-- example: backup-application -->
```yaml
backup:
  include:
    data:
      category: state
      capture: application-export
  exclude:
    logs: transient
  configuration:
    native_settings:
      path: /etc/example
      kind: directory
```

This is an **app-profile fragment**. The example assumes the profile declares the `data` and `logs` roles. It is not a complete deployable application.

| Property | Type | Required/default | Meaning and constraints |
| --- | --- | --- | --- |
| <a id="backup-application-include"></a>`include` | Named dataset map | Required; may be empty | Storage roles whose recovery material must be retained. |
| <a id="backup-application-include-category"></a>`include.<role>.category` | String enum | Required | `configuration`, `state` or `database`. |
| <a id="backup-application-include-capture"></a>`include.<role>.capture` | String enum | Required | `files`, `application-export` or `database-export`. |
| <a id="backup-application-exclude"></a>`exclude` | Named string map | Required; may be empty | Each excluded role is explicitly `transient` or `rebuildable`. |
| <a id="backup-application-configuration"></a>`configuration` | Named path-object map | Optional; default empty | Native settings outside app storage. Each entry uses the path and kind fields below. |
| <a id="backup-application-configuration-path"></a>`configuration.<id>.path` | Absolute canonical path | Required | Names a specific file or directory under the same [path rules as a backup profile](#backup-profile-configuration-path). |
| <a id="backup-application-configuration-kind"></a>`configuration.<id>.kind` | String enum | Required | `file` or `directory`, as in a [backup profile](#backup-profile-configuration-kind). |

The `state` category requires `application-export`, which captures the app's files while its supported Compose services are paused. The `database` category requires `database-export`, and no other category may use that capture type. The generated file inventory marks live database directories `include: false`: a tar archive, PBS file scan or another app's database connection cannot replace the required native export. Use application export for configuration that contains live SQLite databases or other changing application state.

The compiler derives paths from the actual [app storage binding](storage.md#app-storage-bindings): the guest volume or root path plus its subpath. Profiles do not repeat site paths or addresses. The inventory lists each runtime and supporting file managed by HomeLab individually, preserving app ownership without archiving a shared runtime directory.

Existing [connections](connections.md) identify related PostgreSQL, MariaDB and InfluxDB endpoints. These relationships associate the data needed for recovery; they do not add deployment ordering or prove that the data came from one database transaction. For an operational job, each related database must be a configured app with its own native export command in the backup group. An external database endpoint alone does not meet that requirement.

The library's application-specific coverage guide must explain the contents of each role and its capture requirements. A field named `config` is not evidence that everything within it is static or that it contains no secrets.

## Operational job

For a complete library/site composition and executable offline commands, use the [backup example](../examples/backup/README.md). The fragment below is a field lookup example, not that complete composition.

This is a **site-root fragment**, not a standalone site. Define the referenced HTTPS endpoint, PBS client profile, enrolled `resolver` guest, static `primary` interface and unprotected `backup-stage` volume in the same site/library composition. The staging volume must meet the capacity rule below. Supply the real certificate fingerprint and public PEM rather than the synthetic values shown here. See [configure backups](../backup/configure.md) for the handoff from server setup.

<!-- example: backup-job -->
```yaml
backup:
  management:
    credential: pbs-management
    datastore_path: /mnt/backup/recovery
  recovery_public_key:
    source: assets/backup/pbs-recovery-public.pub
  job:
    name: example-recovery
    destination:
      endpoint: {external: pbs}
      datastore: recovery
      namespace: guests
      fingerprint: ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab
    schedule: {calendar: '02:00', jitter_seconds: 300}
    clients:
      resolver:
        staging_volume: backup-stage
        interface: primary
        limits: {max_bytes: 67108864}
    capture: {pause: [], database_lock: [], influx_tokens: {}}
    limits: {max_bytes: 33554432, max_files: 10000, timeout_seconds: 300}
```

### Job fields

All six top-level job fields are required when `job` is present. Validation rejects null values and unknown keys. The compiler resolves these values once into the versioned deployment packet.

| Field | Type | Required/default | Constraints and effect |
| --- | --- | --- | --- |
| <a id="backup-job-name"></a>`name` | Identifier | Required | Names the shared schedule. Renaming requires explicit retirement or handover of its protection. |
| <a id="backup-job-destination"></a>`destination` | Closed object | Required | Declared destination on an installed PBS server; CD verifies the existing datastore and manages namespaces/client access, not the datastore, VM or storage filesystem. |
| <a id="backup-job-destination-endpoint"></a>`destination.endpoint` | `{external: id}` | Required | Selects an existing HTTPS [external endpoint](networks.md#external-endpoints) for the server and port. No management endpoint is used as a fallback. |
| <a id="backup-job-destination-datastore"></a>`destination.datastore` | String | Required | 3–32 ASCII characters, starting with a letter, digit or underscore; later characters may also be dots or hyphens. `/` is forbidden. |
| <a id="backup-job-destination-namespace"></a>`destination.namespace` | String | Required | Uses the same character/start rules as datastore, with 1–32-character segments separated by `/`. At most 128 characters and six segments; each guest's stable backup ID is appended. The complete ACL path `/datastore/<datastore>/<namespace>/<backup_id>` must also fit PBS's 128-character ACL limit. |
| <a id="backup-job-destination-fingerprint"></a>`destination.fingerprint` | String | Required | Lowercase SHA256 certificate fingerprint, exactly 32 colon-separated hexadecimal bytes. |
| <a id="backup-job-schedule"></a>`schedule` | Closed object | Required | Configures one controller timer for all group members, with no independent guest timers. |
| <a id="backup-job-schedule-calendar"></a>`schedule.calendar` | String | Required | `hourly`, `daily` or quoted 24-hour `HH:MM`. All schedules use UTC. |
| <a id="backup-job-schedule-jitter-seconds"></a>`schedule.jitter_seconds` | Integer | Required | 0–3600; randomized timer delay. Missed runs are not replayed on restart. |
| <a id="backup-job-clients"></a>`clients` | Named map | Required | Must include exactly the enrolled configured guests, including enrolled guests disabled for CD; the group has 1–64 members. |
| <a id="backup-job-capture"></a>`capture` | Closed object | Required | Declares permission to pause apps and the inputs required by native database export commands; see below. |
| <a id="backup-job-limits"></a>`limits` | Closed object | Required | Supplies the default capture-size and entry-count bounds, plus the shared duration of each phase. A client may override only its byte/file bounds below. |
| <a id="backup-job-limits-max-bytes"></a>`limits.max_bytes` | Integer | Required | 1 MiB through 1 PiB. Bounds native command output, the complete recovery files and readback, and the selected source files. Metadata counts toward the budget. |
| <a id="backup-job-limits-max-files"></a>`limits.max_files` | Integer | Required | 1–1,000,000 selected entries or artifacts. |
| <a id="backup-job-limits-timeout-seconds"></a>`limits.timeout_seconds` | Integer | Required | 60–86,400 seconds for each preflight, capture or upload phase. The coordinator also limits the total run duration. |

### Client fields

Each `clients.<guest-id>` selects an enrolled guest. CD creates and preserves its namespace-scoped PBS token and native client encryption key. Do not declare secret values or per-client credential-source fields here.

| Field | Type | Required/default | Constraints and effect |
| --- | --- | --- | --- |
| <a id="backup-client-staging-volume"></a>`staging_volume` | Guest volume identifier | Required | Dedicated managed ZFS-pool subvolume, no app binding and no `backup:` marker. Size must be at least four times this client's effective `max_bytes`. Its path is reused from the volume declaration. CD verifies selected `zfspool` type before any creation/apply; other storage formats are unsupported for this job. |
| <a id="backup-client-interface"></a>`interface` | Guest interface identifier | Required | Selects an existing interface with a resolved static IPv4 address. Before capture, the route check on the guest must report that exact device and source address. |
| <a id="backup-client-backup-id"></a>`backup_id` | String | Optional; `guest-<VMID>` | Uses 1–32 ASCII letters, digits, dots, underscores or hyphens, starting with a letter or digit. The 32-character bound is the PBS namespace-leaf limit. It must be unique in the group. Set it explicitly when contexts reuse a VMID. Changing it requires explicit handover of protection. |
| <a id="backup-client-limits"></a>`limits` | Closed object | Optional; omitted fields inherit `job.limits` | At least one of `max_bytes` or `max_files`; no other fields, null or empty object. Overrides affect this client only and may be above or below the root defaults. |
| <a id="backup-client-limits-max-bytes"></a>`limits.max_bytes` | Integer | Optional; inherit `job.limits.max_bytes` | Same 1 MiB–1 PiB bound. The dedicated staging volume must still be at least four times this effective value; runtime requires three times it free before capture. |
| <a id="backup-client-limits-max-files"></a>`limits.max_files` | Integer | Optional; inherit `job.limits.max_files` | Same 1–1,000,000 bound for this client's selected entries and artifacts. |

The complete [mixed-client source](../examples/backup/client-limits.yaml) and its [compile-and-inspect commands](../examples/backup/README.md#size-clients-independently) exercise both branches: `resolver` overrides its byte/file limits, while `replica` inherits the root defaults. Both retain the same timeout and one coordinated group. Each 1 GiB staging volume exceeds its effective minimum. Omitting `limits` preserves the previous generated values. An unknown field, zero byte bound or undersized staging volume is refused.

Keep `timeout_seconds` only in the root `job.limits`: all members share a coordinated paused capture window, and each worker's existing barrier deadline uses that duration. Per-client timeout overrides are not accepted. This extension does not add schedules, change group membership, reserve host pool space or prune retained staging history. Size from actual complete native exports plus that client's file archive and metadata, with growth and pool reserve; engine-directory usage is not an export measurement.

For later deployments, a root-default change affects only clients inheriting that field; removing an override makes that field inherit again. A changed effective limit requires the affected guest's matching ordinary deployment with that guest enabled, followed by successful whole-group activation. A disabled member's old coverage cannot stand in for a changed limit. Namespace, token and client-key identities stay unchanged by a limit edit; do not recreate credentials or remove failure records. See [capacity preparation and updates](../backup/configure.md#size-each-client-and-review-later-changes).

The final namespace is `<namespace>/<backup_id>` and the snapshot is `host/<backup_id>/<UTC capture time>`. CD creates each namespace and its dedicated user/token with `DatastoreBackup` access there. Both user and token grants are required. The worker can back up and restore its owned archives, but cannot administer PBS or prune snapshots. Its protected controller record and guest files contain the same stable client identity and encryption key. See [API access and permissions](../backup/access.md).

The native client uses the explicitly installed recovery public key on every encrypted upload. The backup includes `rsa-encrypted.key`, an encrypted copy of that client's key; it never includes the recovery private key. Loss of the original client key can therefore be recovered using the independently stored private key and passphrase, plus separate authenticated access to the archive. Follow [recovery-key setup and rehearsal](../backup/recovery-key.md). A public-key change does not make older archives recoverable with the new private key.

### Capture permissions

| Field | Type | Required/default | Meaning |
| --- | --- | --- | --- |
| <a id="backup-job-capture-pause"></a>`capture.pause` | Unique app-ID list | Required; may be empty | Permits stopping and restarting only the listed apps' already-running Compose services. Every `application-export` dataset requires its app in this list. |
| <a id="backup-job-capture-database-lock"></a>`capture.database_lock` | Unique app-ID list | Required; may be empty | Must list exactly the enrolled MariaDB apps. Authorises their all-table read lock while exporting all databases, routines, events and triggers. |
| <a id="backup-job-capture-influx-tokens"></a>`capture.influx_tokens` | App-ID → secret-source map | Required; may be empty | Must include exactly the enrolled InfluxDB apps, each selecting its existing operator-token file. Follow [operator-token custody and file ownership](../backup/configure.md#prepare-an-existing-influxdb-operator-token-when-selected). |

PostgreSQL uses the `pg_dumpall` for its installed major version with local peer authentication. The export includes global objects and roles, with an individual snapshot for each database. MariaDB uses its native logical dump of all databases while holding the explicitly authorised all-table read lock. Influx uses its native full backup command. Raw database engine directories never enter the selected-file archive. These native formats still need a compatible restore environment, including the required extensions and plugins. Producing them does not prove that a restored service works.

For example, a composition with Bitwarden `vault` and MariaDB `database` needs `pause: [vault]` and `database_lock: [database]`. Authentik likewise needs permission to pause its managed app services and must include its PostgreSQL member in the group. A missing pause permission, Influx token, group member or database lock fails compilation or the checks before capture. You cannot supply an arbitrary command hook.

### Coordinated execution and failure behavior

1. The controller attempts to acquire shared database-network locks and exclusive workflow and deployment locks for each guest. It does not wait for busy locks. It verifies the pointer to the latest successful ordinary operation, that operation's immutable receipt, sealed inputs, backend identity and pinned SSH trust. Failed, pending or foreign holds stop the run. Guests need not have participated in the newest CD run: a disabled member uses its last genuinely completed deployment configuration.
2. Each guest worker checks its dedicated mount and available capacity, selected route, PBS reachability, input paths and the exact digests of its deployed Compose control files. The controller creates holds for the backup window and permits the selected pauses only after every member passes these checks.
3. All selected app writers pause before any member captures files or exports a native database. Each worker creates a new private set of recovery files. GNU tar preserves the selected metadata, access-control lists (ACLs), extended attributes and explicit exclusions. Cleanup restarts the original containers even if capture fails, then reads their running state. Once every member has restarted, read-only checks wait for configured container health before upload. These checks never retry a failed start or delay one guest's restart until another guest's applications are ready. Capture does not recreate containers, run `compose up`, restore data, issue radio or nonvolatile-memory commands, or send synthetic device commands.
4. Every member resumes before upload. Each archive contains the same recovery-set manifest, the exact snapshot destinations and the digests of every member's data manifest. The group therefore shares a window in which the selected writers were paused. This is **not a distributed database transaction**, and it does not protect against independent writers outside the declared apps. It adds no deployment scheduling dependencies.
5. Upload always requests client encryption. Each worker downloads and decrypts its exact archive into a separate private readback directory, then compares every artifact hash. The group succeeds only after every member confirms that readback and exits successfully. Temporary capture and readback copies are released only after their exact bytes have been verified; receipts and manifests remain.

After the controller accepts every member's deployment records, a worker may still fail its checks before capture. In that case, the controller preserves evidence under the failed run's UUID and does not open a capture window. A later scheduled run with a new UUID may attempt those checks again. An earlier lock or deployment-record check can stop the run before that UUID directory exists.

Once a window opens, a failed run leaves any remaining controller holds in place. Any pending markers and recovery files still present on failed members remain for investigation. Members that already verified their archives may have released their temporary copies and local pending markers before the group fails. No automatic replay, generic recovery, clearing of remaining markers or retry is provided. A closed coordinator connection or timeout aborts workers and permits only bounded attempts to restart services that were running before capture. If interruption leaves the outcome uncertain, the hold remains. This client does not prune remote snapshots, earlier failures or the last successful recovery generation.

## First installation

Complete [server preparation](../backup/server.md), [recovery-key generation and independent storage](../backup/recovery-key.md), and [management-token setup](../backup/access.md). Then select the shared profile, enroll guests and mark their protected managed volumes. Supply the verified endpoint/fingerprint, public PEM, protected management credential, network policy and dedicated staging volume for each enrolled guest. Review service pauses, database locks and unattended SSH use before rollout.

The protected **Backup** management job uses the `backup` GitHub Environment and explicitly forwarded `PBS_API_TOKEN`. It validates server identity and compares the existing datastore name/path with configuration before creating declared namespaces and client accounts. The operator verifies actual mounted storage during [server setup](../backup/server.md#create-and-verify-the-datastore-once); an API configuration read is not mount verification. CD does not create, move or delete datastores. Private client credentials are created once and handed to their own guest only. The recovery private key is never an input. A conflicting existing identity, unexpected datastore or uncertain token-creation result stops reconciliation; CD cannot silently adopt, rotate or regenerate it.

The ordinary `Prepare` phase installs the selected exact client package. The guest's `PBS agent` step seals and installs its recovery inventory. It does not contact PBS or require newly generated backup credentials to deploy the application.

After the selected guest jobs finish successfully, the separate **Backup** job admits the completed deployments for the whole enrolled group, including the last successful deployment of disabled members. It acquires the existing per-guest deployment locks, validates PBS and the prepared datastore, then provisions the declared namespaces and client access. For a new member, the already-installed native client generates its encryption key on that guest; the job retains a protected copy in its controller ownership record. Existing matching keys are verified, never regenerated. An incomplete or uncertain creation remains held for explicit investigation.

Ansible installs the finite worker, private client inputs and one controller timer only after those ownership checks succeed. Activation records bind the completed deployment, public recovery identity and exact private-input digests. The schedule does not start an immediate backup. Backup activation introduces no new dependency between application jobs, and a PBS outage cannot prevent their configuration from completing; it fails the separate Backup job.

On an existing guest, new staging must be the exact empty allocation appended after existing volumes. Deployment rejects missing or foreign evidence about the path before apply, or ambiguity in the provider plan. Capture starts only after the controller proves that every member completed an ordinary deployment. A version check or installed timer is not a recovery point.

The controller schedule is a standard systemd user service/timer owned by the existing non-root CD account. Controller bootstrap prepares its persistent user manager and root-owned effective `NoNewPrivileges` protection before that manager starts; ordinary CD never uses local `sudo`. The public bundle, user units and private group descriptor are account-owned, versioned and verified, so later source and schedule updates remain CD-managed. This protects expected ownership and hashes, not integrity against a malicious same-UID actor. Root/system-scope namesakes are refused rather than adopted. See [controller preparation](../backup/configure.md#prepare-the-controllers-persistent-user-manager) and [installed paths and user-scope commands](../backup/operations.md#find-the-schedule-and-completion-records).

## Later deployments and retirement

Later CD updates preserve credential bytes, stable group and member identities, previous recovery records, ordinary failure holds and backend ownership. Changes to coverage produce a new sealed input generation. Skipping a guest in CD never removes it from backup membership. Ordinary deployment cannot omit, rename or move an operational job or member: its protection must first be explicitly retired or handed over. This contract provides no automatic retirement procedure.

A configuration without an operational job installs no scheduler. Once a job has installed protection, later configuration must preserve it and cannot downgrade it to client preparation alone. Editing configuration does not change the recorded state identity, migrate databases, clear old holds or invoke historical commissioning controllers.

## Validation and support limits

Validate the named reference snippets using the [reference example suite](../../blueprints/test_component_reference_examples.py), [coverage/profile contracts](../../blueprints/component_backup.py) and [job contract](../../blueprints/component_backup_job.py). Every release must keep these examples and its validators consistent. Representative invalid inputs include:

| Invalid input | Diagnostic and correction |
| --- | --- |
| Set a volume's `backup` to true | `component.backup-presence`; use null or an empty object to include it, or omit the field to exclude it when root backup is enabled. |
| Add a storage role without classifying it | `component.backup-coverage`; include or exclude every role in the app profile. |
| Give a `state` dataset `capture: files` | `component.backup-consistency`; select `application-export` and supply its required pause permission for an operational job. |
| Give management a file credential or another Environment secret | `component.backup-management-credential`; select an Environment source named `PBS_API_TOKEN` for the isolated Backup job. |
| Set the expected datastore path to `/` | `component.backup-datastore-path`; use the prepared datastore directory, never the server filesystem root. |
| Omit management or the recovery public key from an operational job | `component.backup-recovery-key`; supply all three related root objects together. |
| Supply an invalid or private PEM | `component.backup-recovery-key`; supply only the confined RSA-4096 public PEM. |
| Set the calendar to `24:00` | `component.backup-schedule`; use `hourly`, `daily` or a valid quoted 24-hour `HH:MM` value. |

These source checks do not install a worker, read credentials or contact PBS. [Documentation assurance](../contributing/documentation-assurance.md) states their scope.

Component unit tests check accepted fields, references, paths and invalid combinations. App and guest tests mock their collaborators; compiler integration checks the generated packets, explicit volume flags and membership of disabled guests. Local runtime fixtures use real private filesystem records and concurrent pipe messages to test deadlines, preserved failures and service restart paths, while replacing native engines with fakes. Mock provider plans check that permitted allocations match the plan guards. These tests do not verify a real PBS server, Linux guest backup or restore. The feature uses the supported Debian LXC backend and adds no NAS VMM or physical-host provisioning backend.

Before declaring the installation protected, verify a real scheduled capture, native database exports, encrypted transfer and full archive readback on the intended network. Then restore the related apps and databases together in isolation and check their service behavior. PBS installation/storage preparation, PVE full-guest schedules, retention, verification, pruning, garbage collection and offsite copies have their own [setup and acceptance checklist](../backup/operations.md). This client cannot prune remote history.

Product references: [PBS client usage](https://pbs.proxmox.com/docs/backup-client.html), [client commands](https://pbs.proxmox.com/docs/proxmox-backup-client/man1.html), [PostgreSQL dumpall](https://www.postgresql.org/docs/current/app-pg-dumpall.html), [MariaDB dump](https://mariadb.com/docs/server/clients-and-utilities/backup-restore-and-import-clients/mariadb-dump) and [Influx backup](https://docs.influxdata.com/influxdb/v2/reference/cli/influx/backup/).
