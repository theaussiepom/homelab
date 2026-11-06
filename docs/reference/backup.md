# PBS backup and recovery coverage

[Reference index](README.md) · [Storage](storage.md) · [Library](library.md) ·
[Workflow and lifecycle](lifecycle.md)

The site-root `backup` property selects the Proxmox Backup Client and derives
recovery paths from existing guest/app bindings. Add its closed `job` object to
install a coordinated, encrypted selected-recovery schedule. This uses ordinary
CD inputs, completion receipts, deployment locks and failed-operation holds.

There are two recovery tiers: native Proxmox full-guest backups (OS plus selected
managed volumes), and guest-client recovery archives containing configuration,
quiesced application state and native database exports. This contract implements
the client tier and native volume selection. Creating the NAS-hosted PBS server,
configuring PVE full-guest jobs and server maintenance belong to the subsequent
site integration. A successful upload/readback is not an application restore.

## Syntax

The following **site fragment** selects the library's only backup profile:

```yaml
backup:
```

`backup: null` and `backup: {}` have the same meaning. With multiple profiles,
select one explicitly:

```yaml
backup:
  profile: pbs-client
```

| Property | Type | Required/default | Meaning and constraints |
| --- | --- | --- | --- |
| Site `backup` | Null or closed object | Optional; omission adds no client phase | Presence enables client preparation for all configured guests. Boolean values refuse. |
| `backup.profile` | [Identifier](supporting-types.md#scalar-and-path-types) | Optional when exactly one profile exists | Reference to `backup_profiles`; omission selects the sole registered profile. |
| `backup.job` | Closed [operational job](#operational-job) | Optional; no timer without it | Destination, protected input references, transport, schedule and capture permissions. |
| Guest `volumes.<id>.backup` | Null or empty object | Optional | With root backup selected, presence includes the managed volume in native full-guest backup; omission excludes it. It is not a native database export. |

Bare/null/empty `backup` selects client software and coverage only. It is useful
while preparing the server; it never silently assumes a destination, credential
or permission to interrupt a service. A bound `job` is the operational selection.
Unknown fields and booleans refuse. Compilation performs no network or secret
reads. Neither form grants NAS administration or creates accounts/keys.

Without the root feature, the existing provider volume defaults remain unchanged.
With it selected, an application role classified for protection cannot bind to a
managed volume lacking `backup`. This includes a database engine volume: native
full-guest recovery and a coherent database export are separate requirements.
Changes to native backup flags must match the compiled selection exactly; every
existing mount attribute and its order stay immutable in an update. The only
additional allocation permitted by this contract is the exact new, empty,
unprotected staging volume appended after existing mount slots. A read-only
preimage check refuses a foreign mount, symlink or nonempty target before apply. Unknown flags,
changed paths/sizes/volumes, replacements and undeclared changes still refuse.
The root filesystem belongs to the native full-guest tier; a `root_paths` binding
does not create another provider mount or native `backup` flag.

## Backup profiles

Library `backup_profiles.<id>` accepts an inline definition or a confined
`{source: relative/file.yaml}` reference, like other [typed sources](sources.md).
A referenced document uses `schema: homelab-components-v1` and
`kind: backup-profile`.

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
| `type` | String enum | Required | Exactly `pbs-client`. No arbitrary agent or shell command. |
| `software` | Nonempty unique identifier list | Required | Existing [software definitions](supporting-types.md); the effective selection must contain one exact `proxmox-backup-client=<version>` package. Existing repository-key and package-version guards apply. |
| `configuration` | Named map of path objects | Required; may be empty | Guest configuration to retain, not a request to read it during compilation. |
| `configuration.<id>.path` | Absolute canonical path | Required | A specific file or directory; `/` refuses. This is an inventory, not authorization to archive the whole OS. |
| `configuration.<id>.kind` | String enum | Required | `file` or `directory`. |

Compilation follows software references and copies their public, digest-pinned
repository keys into the ordinary packet. It does not fetch packages, read
private configuration, connect to PBS or create credentials. The library owns
the selected client version; the framework does not duplicate its pin.

When root monitoring is also selected, the inventory includes the framework-owned
agent configuration `/etc/zabbix/zabbix_agent2.conf`, retained key
`/etc/zabbix/agent.psk` and ownership receipt
`/var/lib/homelab-monitoring/agent.json`. These use the reserved configuration IDs
`zabbix-agent-configuration`, `zabbix-agent-key` and `zabbix-agent-ownership`;
conflicting profile paths refuse. Package caches and interrupted-installation
holds are not normal configuration inputs. Independent controller credential and
hold records still need their own protected recovery custody.

## Application recovery declarations

An app profile's closed `backup` object classifies **every storage role**, including
optional roles. `include` and `exclude` are disjoint and together cover exactly
the profile's `storage` keys. A newly added storage role without a disposition
refuses rather than silently losing protection.

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

This is an **app-profile fragment**. The example assumes the profile declares
the `data` and `logs` roles. It is not a complete deployable application.

| Property | Type | Required/default | Meaning and constraints |
| --- | --- | --- | --- |
| `include` | Named dataset map | Required; may be empty | Storage roles whose recovery material must be retained. |
| `include.<role>.category` | String enum | Required | `configuration`, `state` or `database`. |
| `include.<role>.capture` | String enum | Required | `files`, `application-export` or `database-export`. |
| `exclude` | Named string map | Required; may be empty | Each excluded role is explicitly `transient` or `rebuildable`. |
| `configuration` | Named path-object map | Optional; default empty | Native settings outside app storage, using the same `path`/`kind` objects as a backup profile. |

`state` requires `application-export`: the profile is declaring that a coherent
capture producer is necessary. `database` requires `database-export`, and that
capture is valid only for a database category. Live database directories are
recorded with `include: false` in the selected-file inventory. Their required
native exports are not replaced by a tar, PBS scan or another app's database
connection. Configuration may require an application export when it contains
live SQLite or other changing application state.

Paths are derived from the actual [app storage binding](storage.md#app-storage-bindings),
including guest volume/root path plus subpath. The profile does not repeat a
site path or address. Compiler-owned runtime leaves and sidecars are listed
individually, preserving app ownership instead of archiving a shared runtime
directory. Related PostgreSQL/MariaDB/InfluxDB endpoints are derived from the
existing [connections](connections.md); these are recovery associations, not
new deployment readiness edges or proof of a common transaction. An operational
job requires each related database to have a configured native producer in the
root group; an external database endpoint alone cannot establish that proof.

The library's application-specific coverage guide must explain the contents of
each role and its capture requirements. A field named `config` is not evidence
that everything within it is static or that it contains no secrets.

## Operational job

This is a **site-root fragment**. The library's complete tested
[synthetic backup example](https://github.com/theaussiepom/homelab-stack/blob/feature/pbs-client-contract/site.backup.example.yaml)
provides the referenced endpoint, context, file-secret sources, interface,
network rule and dedicated guest volume. The fragment alone is not deployable.

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

All six fields are required when `job` is present; null values and unknown keys
refuse. These values are resolved once into the versioned ordinary packet.

| Field | Type | Required/default | Constraints and effect |
| --- | --- | --- | --- |
| `name` | Identifier | Required | Stable root schedule identity. Renaming is a retirement/handover, not an ordinary update. |
| `destination` | Closed object | Required | Existing PBS destination; no server provisioning. |
| `destination.endpoint` | `{external: id}` | Required | Existing HTTPS [external endpoint](networks.md#external-endpoints). Resolves server and port; never a management fallback. |
| `destination.datastore` | String | Required | Literal ASCII letters/digits/underscore/hyphen, at most 128 characters; no `/`. |
| `destination.namespace` | String | Required | Same segments separated by `/`, at most 128 characters and six segments. A stable backup-ID segment is appended for each guest. |
| `destination.fingerprint` | String | Required | Lowercase SHA256 certificate fingerprint, exactly 32 colon-separated hexadecimal bytes. |
| `schedule` | Closed object | Required | One controller timer for the root group, no guest-local independent timers. |
| `schedule.calendar` | String | Required | `hourly`, `daily` or quoted 24-hour `HH:MM`. All schedules use UTC. |
| `schedule.jitter_seconds` | Integer | Required | 0–3600; randomized timer delay. Missed runs are not replayed on restart. |
| `clients` | Named map | Required | Exactly every configured guest, including CD-disabled members; at most 64 members. |
| `capture` | Closed object | Required | Explicit supported interruption and native-producer bindings; see below. |
| `limits` | Closed object | Required | Finite capture capacity, entry count and phase duration. |
| `limits.max_bytes` | Integer | Required | 1 MiB through 1 PiB. Bounds native output, complete payload/readback and selected source intake. Metadata also consumes this budget. |
| `limits.max_files` | Integer | Required | 1–1,000,000 selected entries/artifacts. |
| `limits.timeout_seconds` | Integer | Required | 60–86,400 per bounded preflight/capture/upload phase. The coordinator also enforces a finite total lease. |

### Client fields

Each `clients.<guest-id>` references an existing configured guest. Inputs are
references to [file secret sources](identity-and-secrets.md#secret-sources), never inline secret values.
Public compilation validates references but does not open their paths.

| Field | Type | Required/default | Constraints and effect |
| --- | --- | --- | --- |
| `auth_id` | String | Required | Unique PBS token identity `user@pbs!token`; each member has its own scoped identity. No root/PAM login. |
| `password` | Secret-source identifier | Required | Protected controller file containing the existing PBS token secret. |
| `encryption_key` | Secret-source identifier | Required | Existing PBS client encryption-key file. No key creation, rotation or default key fallback. |
| `key_password` | Secret-source identifier | Optional; absent for an unprotected key file | Password for an encrypted key file; passed only through the private process environment. |
| `staging_volume` | Guest volume identifier | Required | Dedicated managed volume, no app binding and no `backup:` marker. Size must be at least four times `max_bytes`. Its path is reused from the volume declaration. |
| `interface` | Guest interface identifier | Required | Existing interface with resolved static IPv4 address. Native route admission must report that exact device and source address before capture. |
| `backup_id` | String | Optional; `guest-<VMID>` | Stable ASCII letters/digits/dot/underscore/hyphen, first character alphanumeric, 1–128 characters. Must be unique in the root group. Set it explicitly for VMIDs duplicated across contexts. Changing it requires explicit protection handover. |

The final namespace is `<namespace>/<backup_id>` and the snapshot is
`host/<backup_id>/<UTC capture time>`. Pre-create the namespaces and grant only
the permissions needed to upload and read back that member's archives. Guest
credentials need no server administration, pruning or GC rights. See
[Proxmox access control](https://pbs.proxmox.com/docs/user-management.html).
Keep an independently recoverable encryption key outside the encrypted archive;
a key stored only inside its own archive cannot recover that archive.

### Capture permissions

| Field | Type | Required/default | Meaning |
| --- | --- | --- | --- |
| `capture.pause` | Unique app-ID list | Required; may be empty | Explicit permission to stop/start only that app's already-running Compose services. Every `application-export` dataset needs its owning app here. |
| `capture.database_lock` | Unique app-ID list | Required; may be empty | Exactly the configured MariaDB producers. Authorizes their all-table read lock while dumping all databases, routines, events and triggers. |
| `capture.influx_tokens` | App-ID → secret-source map | Required; may be empty | Exactly the configured Influx producers, each bound to its existing operator-token file. |

PostgreSQL uses its installed major's `pg_dumpall` under local peer authentication,
including globals/roles and individual database snapshots. MariaDB uses its
native all-database logical dump with an explicit all-table lock. Influx uses
its native full backup command. Raw database engine directories never enter the
selected-file archive. These are native recovery formats, not restored-service
acceptance; version-compatible restore and extensions/plugin requirements still
need target qualification.

For example, a composition with Bitwarden `vault` and MariaDB `database` needs
`pause: [vault]` and `database_lock: [database]`. Authentik similarly needs its
owned app services paused and its PostgreSQL member included in the group. A
missing pause permission, Influx token, group member or database lock refuses
compilation/admission; no arbitrary command hook is available.

### Coordinated execution and failure behavior

1. The controller acquires existing database-network/shared and per-guest
   workflow/deployment/exclusive locks, nonblocking. It verifies actual canonical
   and immutable ordinary receipts, sealed inputs, backend identity and pinned
   SSH trust. Any failed/pending/foreign hold refuses. It does not require every
   guest to have participated in the newest CD run: disabled members retain
   their genuinely completed deployed configuration.
2. Every worker preflights its dedicated mount/capacity, selected route, PBS
   reachability, input paths and exact deployed Compose control-file digests.
   Only when every member is ready does the controller establish its own backup
   window holds and permit explicitly selected service pauses.
3. All permitted app writers pause before any member captures files or native
   database exports. Each worker creates a new private generation; GNU tar
   preserves selected metadata, ACLs, xattrs and explicit exclusions. Original
   containers are started again in `finally`, with running-service readback.
   No container recreation, `compose up`, restore, radio/NVM command or synthetic
   device command forms part of backup capture.
4. All members resume before upload. Every archive includes the same recovery-set
   manifest, exact snapshot destinations and member data-manifest digests.
   This establishes a coordinated quiescence window, **not a distributed database
   transaction** or protection against independent writers outside the declared
   apps. Deployment does not gain new scheduling edges.
5. Upload always requests client encryption. Each worker downloads/decrypts its
   exact archive into separate private readback and compares every artifact hash.
   The root set succeeds only after all members confirm that readback and exit
   successfully. Successful temporary payload/readback copies are released only
   after their exact-byte verification; receipts/manifests remain.

A partial preflight preserves its failed UUID evidence without opening a capture
window. A new scheduled UUID may attempt a fresh preflight. Once a window opens,
any failure preserves local pending markers, controller holds and failed payloads;
no automatic replay, generic recovery, marker clearing or retry is provided.
EOF/timeouts abort workers and allow only bounded attempts to restart services
that were running before capture. Uncertain interruption keeps the hold. No
remote snapshot, earlier failure or last successful recovery generation is
pruned by this client.

## First installation

Select the profile and explicit authoritative volume markers. For an operational
job, first supply the existing server/namespace, certificate pin, separately
escrowed encryption keys, scoped token files, transport policy and dedicated
staging volume for every guest. Review every service pause/database-lock impact
before a private-site rollout.

Ordinary `Prepare` installs the selected exact client package. The `PBS agent`
step seals the inventory and selected private inputs, installs the guest worker
and one root controller timer through Ansible. It does not run a backup during
CD. New staging on an existing guest is an append-only exact empty allocation;
any missing/foreign preimage or provider-plan ambiguity refuses. The controller
schedule runs as the existing CD actor, from its immutable verified public source
bundle. It starts only after genuine ordinary completion can be proved for every
member. A version check or installed timer is not a recovery point.

## Later deployments and retirement

Owned CD updates preserve credential bytes, stable group/member identity,
previous recovery records, ordinary failure holds and backend ownership. Changed
coverage becomes a new sealed input generation. Merely skipping a guest in CD
never removes it from backup membership. An operational job/member cannot be
omitted, renamed or moved by ordinary deployment: retire/drain its protection
explicitly first. This contract has no automatic retirement executor.

Source without an operational job installs no scheduler. Source with a job must
preserve previously installed operational protection; it cannot downgrade it to
preparation-only. New configuration does not repin state, migrate databases,
clear old holds or invoke historical commissioning controllers.

## Validation and support limits

Component units exercise closed schemas, reference/path resolution and extensive
invalid cases. App/guest tests mock their collaborators; real compiler integration
checks packets, explicit volume flags and disabled membership. Local runtime
fixtures exercise actual private filesystem generations, concurrent pipe framing,
deadlines, failure preservation and worker restart paths with fake native engines.
Provider mock plans test allocation/guard agreement. These are source/integration
checks, not a claim of actual PBS/Linux guest/restore operation. The feature
follows the supported Debian LXC guest backend; it adds no NAS VMM or physical-host
provisioning backend.

Before declaring protection, qualify a real scheduled capture, native database
exports, encrypted transfer and full archive readback on the intended network,
then restore the related app/database set in isolation and verify its service
behavior. Full PVE guest schedules, NAS capacity/datastore provisioning, server
retention/verify/prune/GC and complete-datastore offsite copies remain separate
server/site work. This client deliberately cannot prune remote history.

Product references: [PBS client usage](https://pbs.proxmox.com/docs/backup-client.html),
[client commands](https://pbs.proxmox.com/docs/proxmox-backup-client/man1.html),
[PostgreSQL dumpall](https://www.postgresql.org/docs/current/app-pg-dumpall.html),
[MariaDB dump](https://mariadb.com/docs/server/clients-and-utilities/backup-restore-and-import-clients/mariadb-dump)
and [Influx backup](https://docs.influxdata.com/influxdb/v2/reference/cli/influx/backup/).
