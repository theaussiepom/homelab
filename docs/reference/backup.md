# PBS client preparation and recovery coverage

[Reference index](README.md) · [Storage](storage.md) · [Library](library.md) ·
[Workflow and lifecycle](lifecycle.md)

The root `backup` property prepares the Proxmox Backup Client in every configured
guest and compiles an explicit recovery inventory from the selected application
profiles. It uses the existing guest preparation, deployment locks, owned inputs
and per-guest workflow. It does not create a backup server or activate backup
jobs. A prepared client and an inventory are not a successful recovery point.

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
| `backup.profile` | [Identifier](supporting-types.md#scalar-and-path-types) | Required in a nonempty object | Reference to `backup_profiles`. An empty/null selection requires exactly one registered profile. |
| Guest `volumes.<id>.backup` | Null or empty object | Optional | With root backup selected, presence includes the managed volume in native full-guest backup; omission excludes it. It is not a native database export. |

These are the accepted fields in this release. Repository credentials, endpoint,
schedule, retention and server-creation settings are not accepted as invented
keys. Their private deployment and native scheduling integration is a separate
stage. Selecting this feature grants no NAS access or database administration.

Without the root feature, the existing provider volume defaults remain unchanged.
With it selected, an application role classified for protection cannot bind to a
managed volume lacking `backup`. This includes a database engine volume: native
full-guest recovery and a coherent database export are separate requirements.
Changes to native backup flags must match the compiled selection exactly; every
other mount attribute and its order stay immutable in an update. Unknown flags,
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
new deployment readiness edges or proof of a common transaction.

The library's application-specific coverage guide must explain the contents of
each role and its capture requirements. A field named `config` is not evidence
that everything within it is static or that it contains no secrets.

## First installation

1. Validate the complete source and each profile's recovery classification.
2. Select root `backup`, and mark the authoritative managed volumes with bare
   `backup:`. Review the native full-guest volume flags before deployment.
3. Ordinary `Prepare` installs the selected pinned client through the existing
   package/repository machinery. The later `PBS agent` step validates the guest
   identity and writes root-owned `/etc/homelab-backup/coverage.json` with mode
   `0600` in a `0700` directory, then checks the client executable.
4. Review this inventory alongside the native database and application capture
   producers before the later private-site backup activation.

The feature creates no NAS VM, datastore, export, account, key, timer, prune/GC
job or recovery claim. It does not stop an application, signal a radio, copy
live data or run a database export. Public source tests and a client version
check cannot establish that a later native capture or restore works.

## Later deployments

The phase uses the same sealed ordinary payload and deployment receipts as
other guest work. It validates previous PBS phase ownership on repeat runs.
Changed coverage is a new desired input generation, not a historical rewrite.
Existing failed/pending holds remain enforced.

Coverage includes configured guests even when they are excluded from a CD run;
only selected guests execute the phase. Disabling a guest or omitting the root
property performs no agent removal, job deletion, retention change or history
pruning. Explicit retirement and any future schedule handover need their own
supported procedure. No backup scheduler is installed by this release.

## Validation and examples

The maintained library backup example is a complete synthetic source that can
be compiled without a server. Framework tests exercise source parsing, path
derivation, native volume flags, disabled selection, the actual packet receiver,
workflow steps and sealed ordinary repeats with fake native engines.

Useful invalid cases include `backup: true`, an ambiguous profile selection,
unknown fields, a newly added unclassified storage role, a state role using
`capture: files`, a raw database folder treated as a file export, and an
authoritative volume without its presence marker. Compilation refuses these
without opening private inputs or contacting a target.

## Required later qualification

Before claiming protection, configure a real PBS destination, scoped client
identity, certificate trust, client-side encryption and independently recoverable
keys. Qualify each native producer, completed immutable generation, cross-artifact
association, transfer/readback, successful scheduled cycle and isolated restore.
Keep full-guest and selected-recovery tiers distinct. Database exports need
native metadata/roles and application restore checks; database-only recovery
does not restore attachments, radio keys or app encryption material.

Server retention, verification, prune, GC, NAS capacity and any offsite complete-
datastore copy remain separately owned operations. A failed capture/upload must
not replace the last verified generation. No automatic cleanup is implied here.

Product background: [Proxmox client installation](https://pbs.proxmox.com/docs/installation.html#proxmox-backup-client-only-repository)
and [backup client usage](https://pbs.proxmox.com/docs/backup-client.html).
