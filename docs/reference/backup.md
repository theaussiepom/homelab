# PBS backup and recovery coverage

[Reference index](README.md) · [Storage](storage.md) · [Library](library.md) · [Workflow and lifecycle](lifecycle.md)

Add the site-root `backup` property to select the Proxmox Backup Client and derive recovery paths from your existing guest and app bindings. Add its `job` object to install a coordinated schedule that encrypts and backs up the selected data. The feature uses the normal continuous deployment (CD) inputs, completion receipts, deployment locks and holds that record failed operations.

There are two recovery tiers. Native Proxmox full-guest backups contain the operating system and selected managed volumes. Guest-client archives contain configuration, application state captured while its writers are paused, and native database exports. This contract implements the guest-client tier and selects volumes for native backup. Setting up the NAS-hosted Proxmox Backup Server (PBS), Proxmox Virtual Environment (PVE) full-guest jobs and server maintenance remains separate site integration work. Uploading an archive and reading it back successfully does not prove that an application can be restored.

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
| <a id="backup-site"></a>Site `backup` | Null or closed object | Optional; omission adds no client phase | Presence selects client preparation for every configured guest. Boolean values are rejected. |
| <a id="backup-site-profile"></a>`backup.profile` | [Identifier](supporting-types.md#scalar-and-path-types) | Optional when exactly one profile exists | Reference to `backup_profiles`; omission selects the sole registered profile. |
| <a id="backup-site-job"></a>`backup.job` | Closed [operational job](#operational-job) | Optional; no timer without it | Selects the destination, protected inputs, transport, schedule and permission to capture data. |
| <a id="backup-volume"></a>Guest `volumes.<id>.backup` | Null or empty object | Optional | With root backup selected, presence includes the managed volume in native full-guest backup; omission excludes it. It is not a native database export. |

A bare `backup` key, null or an empty object selects only client software and recovery coverage: the files and data to protect. You can use this form while preparing the server. It selects no destination or credential and grants no permission to interrupt a service. Supply `job` to configure scheduled backups. Validation rejects unknown fields and Boolean values. Compilation does not contact a network service or read secrets. Neither form grants NAS administration or creates accounts or keys.

Without site-root backup, existing provider volume defaults remain unchanged. When you enable it, a protected app storage role cannot bind to a managed volume that lacks `backup`. This includes database engine volumes: native full-guest backup and a coherent database export are separate requirements. A `root_paths` binding uses the root filesystem, which belongs to the native full-guest tier; it does not create another provider mount or native `backup` flag.

For an existing guest, native backup flags may change only to match the compiled selection exactly. All other existing mount attributes and their order must stay unchanged. The only new allocation this contract permits is the declared empty, unprotected staging volume, appended after existing mount slots. Before apply, a read-only check rejects a staging path containing a foreign mount, symlink or existing data. Unknown flags, changed paths, sizes or volume identities, replacements and undeclared changes are still rejected.

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

When the site enables backup, every selected app profile must supply a `backup` object that classifies **every storage role**, including optional roles. `include` and `exclude` must not overlap, and together they must cover exactly the profile's `storage` keys. Validation rejects a newly added storage role until the profile says whether to include or exclude it. The object accepts only the fields below.

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

This is a **site-root fragment**. The library's complete tested [synthetic backup example](https://github.com/theaussiepom/homelab-stack/blob/71fec803d9cd4cf599ab21719ea416da479c670a/site.backup.example.yaml) provides the referenced endpoint, context, file-secret sources, interface, network rule and dedicated guest volume. The fragment alone is not deployable.

<!-- example: backup-job -->
```yaml
backup:
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
        auth_id: resolver@pbs!backup
        password: pbs-password
        encryption_key: pbs-key
        staging_volume: backup-stage
        interface: primary
    capture: {pause: [], database_lock: [], influx_tokens: {}}
    limits: {max_bytes: 33554432, max_files: 10000, timeout_seconds: 300}
```

### Job fields

All six top-level job fields are required when `job` is present. Validation rejects null values and unknown keys. The compiler resolves these values once into the versioned deployment packet.

| Field | Type | Required/default | Constraints and effect |
| --- | --- | --- | --- |
| <a id="backup-job-name"></a>`name` | Identifier | Required | Names the shared schedule. Renaming requires explicit retirement or handover of its protection. |
| <a id="backup-job-destination"></a>`destination` | Closed object | Required | Existing PBS destination; no server provisioning. |
| <a id="backup-job-destination-endpoint"></a>`destination.endpoint` | `{external: id}` | Required | Selects an existing HTTPS [external endpoint](networks.md#external-endpoints) for the server and port. No management endpoint is used as a fallback. |
| <a id="backup-job-destination-datastore"></a>`destination.datastore` | String | Required | A nonempty string of ASCII letters, digits, underscores or hyphens, at most 128 characters; `/` is forbidden. |
| <a id="backup-job-destination-namespace"></a>`destination.namespace` | String | Required | Uses the same character set as datastore, with nonempty segments separated by `/`. At most 128 characters and six segments; each guest's stable backup ID is appended. |
| <a id="backup-job-destination-fingerprint"></a>`destination.fingerprint` | String | Required | Lowercase SHA256 certificate fingerprint, exactly 32 colon-separated hexadecimal bytes. |
| <a id="backup-job-schedule"></a>`schedule` | Closed object | Required | Configures one controller timer for all group members, with no independent guest timers. |
| <a id="backup-job-schedule-calendar"></a>`schedule.calendar` | String | Required | `hourly`, `daily` or quoted 24-hour `HH:MM`. All schedules use UTC. |
| <a id="backup-job-schedule-jitter-seconds"></a>`schedule.jitter_seconds` | Integer | Required | 0–3600; randomized timer delay. Missed runs are not replayed on restart. |
| <a id="backup-job-clients"></a>`clients` | Named map | Required | Must include every configured guest, including guests disabled for CD; the group has 1–64 members. |
| <a id="backup-job-capture"></a>`capture` | Closed object | Required | Declares permission to pause apps and the inputs required by native database export commands; see below. |
| <a id="backup-job-limits"></a>`limits` | Closed object | Required | Bounds capture size, entry count and the duration of each phase. |
| <a id="backup-job-limits-max-bytes"></a>`limits.max_bytes` | Integer | Required | 1 MiB through 1 PiB. Bounds native command output, the complete recovery files and readback, and the selected source files. Metadata counts toward the budget. |
| <a id="backup-job-limits-max-files"></a>`limits.max_files` | Integer | Required | 1–1,000,000 selected entries or artifacts. |
| <a id="backup-job-limits-timeout-seconds"></a>`limits.timeout_seconds` | Integer | Required | 60–86,400 seconds for each preflight, capture or upload phase. The coordinator also limits the total run duration. |

### Client fields

Each `clients.<guest-id>` selects an existing configured guest. Credential inputs refer to [file secret sources](identity-and-secrets.md#secret-sources); they never contain secret values. Compilation validates the references without opening their paths.

| Field | Type | Required/default | Constraints and effect |
| --- | --- | --- | --- |
| <a id="backup-client-auth-id"></a>`auth_id` | String | Required | A unique PBS token identity, `user@pbs!token`, with permissions scoped to that member. Root and PAM logins are not accepted. |
| <a id="backup-client-password"></a>`password` | Secret-source identifier | Required | Protected controller file containing the existing PBS token secret. |
| <a id="backup-client-encryption-key"></a>`encryption_key` | Secret-source identifier | Required | Existing PBS client encryption-key file. No key creation, rotation or default key fallback. |
| <a id="backup-client-key-password"></a>`key_password` | Secret-source identifier | Optional; absent for an unprotected key file | Password for an encrypted key file; passed only through the private process environment. |
| <a id="backup-client-staging-volume"></a>`staging_volume` | Guest volume identifier | Required | Dedicated managed volume, no app binding and no `backup:` marker. Size must be at least four times `max_bytes`. Its path is reused from the volume declaration. |
| <a id="backup-client-interface"></a>`interface` | Guest interface identifier | Required | Selects an existing interface with a resolved static IPv4 address. Before capture, the route check on the guest must report that exact device and source address. |
| <a id="backup-client-backup-id"></a>`backup_id` | String | Optional; `guest-<VMID>` | Uses 1–128 ASCII letters, digits, dots, underscores or hyphens, starting with a letter or digit. It must be unique in the group. Set it explicitly when contexts reuse a VMID. Changing it requires explicit handover of protection. |

The final namespace is `<namespace>/<backup_id>` and the snapshot is `host/<backup_id>/<UTC capture time>`. Create the namespaces beforehand and grant each guest only the permissions needed to upload and read back its own archives. Guest credentials need no server administration, pruning or garbage collection (GC) rights. See [Proxmox access control](https://pbs.proxmox.com/docs/user-management.html). Keep an independently recoverable encryption key outside the encrypted archive; a key stored only inside its own archive cannot recover it.

### Capture permissions

| Field | Type | Required/default | Meaning |
| --- | --- | --- | --- |
| <a id="backup-job-capture-pause"></a>`capture.pause` | Unique app-ID list | Required; may be empty | Permits stopping and restarting only the listed apps' already-running Compose services. Every `application-export` dataset requires its app in this list. |
| <a id="backup-job-capture-database-lock"></a>`capture.database_lock` | Unique app-ID list | Required; may be empty | Must list exactly the configured MariaDB apps. Authorises their all-table read lock while exporting all databases, routines, events and triggers. |
| <a id="backup-job-capture-influx-tokens"></a>`capture.influx_tokens` | App-ID → secret-source map | Required; may be empty | Must include exactly the configured InfluxDB apps, each selecting its existing operator-token file. |

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

Select the backup profile and mark the managed volumes that contain data requiring protection. Before enabling an operational job, supply the existing server and namespaces, certificate fingerprint, separately stored recoverable encryption keys, scoped token files, transport policy and dedicated staging volume for every guest. Review the impact of each service pause and database lock before rollout. Also verify and authorise unattended use of the existing scoped deployment SSH key and the exact staging allocation in the saved plan. Passing public source checks does not authorise live key use, volume allocation or service interruption.

The ordinary `Prepare` phase installs the selected exact client package. The `PBS agent` step seals the recovery inventory and selected private inputs. When `job` is selected, it also uses Ansible to install the guest worker and one timer on the controller; it does not run a backup during CD.

On an existing guest, new staging must be the exact empty allocation appended after existing volumes. Deployment rejects missing or foreign evidence about the path before apply, or ambiguity in the provider plan. The controller schedule runs as the existing CD user from an immutable, verified bundle of public source. Capture starts only after the controller proves that every member completed an ordinary deployment. A version check or installed timer is not a recovery point.

## Later deployments and retirement

Later CD updates preserve credential bytes, stable group and member identities, previous recovery records, ordinary failure holds and backend ownership. Changes to coverage produce a new sealed input generation. Skipping a guest in CD never removes it from backup membership. Ordinary deployment cannot omit, rename or move an operational job or member: its protection must first be explicitly retired or handed over. This contract provides no automatic retirement procedure.

A configuration without an operational job installs no scheduler. Once a job has installed protection, later configuration must preserve it and cannot downgrade it to client preparation alone. Editing configuration does not change the recorded state identity, migrate databases, clear old holds or invoke historical commissioning controllers.

## Validation and support limits

The [reference example tests](../../blueprints/test_component_reference_examples.py) parse the five named snippets on this page and pass them through the [coverage and profile validators](../../blueprints/component_backup.py) and [job validator](../../blueprints/component_backup_job.py). They also check these representative invalid inputs:

| Invalid input | Diagnostic and correction |
| --- | --- |
| Set a volume's `backup` to true | `component.backup-presence`; use null or an empty object to include it, or omit the field to exclude it when root backup is enabled. |
| Add a storage role without classifying it | `component.backup-coverage`; include or exclude every role in the app profile. |
| Give a `state` dataset `capture: files` | `component.backup-consistency`; select `application-export` and supply its required pause permission for an operational job. |
| Set the calendar to `24:00` | `component.backup-schedule`; use `hourly`, `daily` or a valid quoted 24-hour `HH:MM` value. |

These source checks do not install a worker, read credentials or contact PBS. [Documentation assurance](../contributing/documentation-assurance.md) states their scope.

Component unit tests check accepted fields, references, paths and invalid combinations. App and guest tests mock their collaborators; compiler integration checks the generated packets, explicit volume flags and membership of disabled guests. Local runtime fixtures use real private filesystem records and concurrent pipe messages to test deadlines, preserved failures and service restart paths, while replacing native engines with fakes. Mock provider plans check that permitted allocations match the plan guards. These tests do not verify a real PBS server, Linux guest backup or restore. The feature uses the supported Debian LXC backend and adds no NAS VMM or physical-host provisioning backend.

Before declaring the installation protected, verify a real scheduled capture, native database exports, encrypted transfer and full archive readback on the intended network. Then restore the related apps and databases together in isolation and check their service behavior. PVE full-guest schedules, NAS capacity and datastore provisioning, server retention, verification, pruning, garbage collection and offsite copies of complete datastores remain separate server or site work. This client cannot prune remote history.

Product references: [PBS client usage](https://pbs.proxmox.com/docs/backup-client.html), [client commands](https://pbs.proxmox.com/docs/proxmox-backup-client/man1.html), [PostgreSQL dumpall](https://www.postgresql.org/docs/current/app-pg-dumpall.html), [MariaDB dump](https://mariadb.com/docs/server/clients-and-utilities/backup-restore-and-import-clients/mariadb-dump) and [Influx backup](https://docs.influxdata.com/influxdb/v2/reference/cli/influx/backup/).
