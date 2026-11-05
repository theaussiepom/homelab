# Apps

An app is an independent profile instance on one named guest.
Use an inline entry or a complete `kind: app` [source](sources.md).

| Field | Type / requirement / default | Constraint and resolution |
| --- | --- | --- |
| profile | Required ID | Existing library app profile |
| guest | Required ID | Existing site guest |
| lifecycle | Required enum | `fresh` or `retained`, subject to adapter support |
| interfaces | Required named map | Bind only declared roles; required profile roles must be present |
| display_name | Optional text | Default profile display name |
| identity | Optional object for fresh; required fields for retained | Persistent runtime names, below |
| storage | Optional named map, {} | Profile storage role to [binding](storage.md#app-storage-bindings) |
| properties | Optional object, {} | Profile defaults then explicit app keys; [closed per adapter](app-properties.md) |
| software / runtime | Optional unique ID lists, [] | Append to profile selections; conflicts refuse |
| authentication | Optional ID | Named authentication policy; required if profile says so |
| devices | Optional named map, {} | Profile device role to site device ID; one physical owner |
| origin | Optional reference | `{exposure: id, domain?: domain_id}`; selected HTTP exposure must target this app |
| secrets | Optional named map, {} | Declared profile role to secret-source ID |
| resources | Optional object | Exactly `containers`, a nonempty service-role map of numeric allocation overrides |

## Interface roles

Each role is exactly one of `{interface: guest_nic_id}`,
`{scope: guest-loopback}`, `{scope: app-network, network: adapter_network_role}`.
The profile must accept the selected scope. Physical roles resolve a guest IPv4
address; loopback resolves 127.0.0.1. App-network roles do not invent host addresses.
A connection source must be physical, or the supported same-guest loopback case.

## Runtime identity

| Identity field | Type / default | Retained requirement |
| --- | --- | --- |
| phase | ID, default app key | Required, unique per guest, not reserved stage |
| runtime_id | ID, default app key | Required |
| project | ID of guest compose_projects | Required for container adapters |
| services | Map adapter service role → runtime name | Exact complete adapter role set |
| networks | Map adapter network role → runtime name | Exact complete adapter role set |
| runtime_directory | Absolute path under `/opt/homelab-app/runtime` | Required for adapters owning runtime leaves |
| custody_directory | Adapter-specific absolute path | Required for CloudBeaver/Explorer, under their owned custody roots; forbidden for other adapters |

Fresh identities derive missing phase/runtime/service/project names.
Generated project name is `homelab-<guest-key>-<app-key>`; service name is
`<app-key>_<service-role>`. Explicit project references must exist.
Generated defaults establish new ownership; they are not a way to rename an
existing app. Service names used in execution match
`[a-z0-9][a-z0-9_-]{0,127}` and are unique in their project.
Runtime/custody leaf collisions and whole-directory exposure to peer inputs refuse.

## Allocations

A container allocation contains one or more of `memory_mib` (positive integer),
`pids_limit` (positive integer), `cpu_limit` (number >0 and ≤256).
Only selected runtime service roles can be overridden. Profile/runtime minimums
still apply. Boolean is not accepted as a numeric allocation.

Changing placement or any persistent identity is not an automatic move.
Storage/private role ownership must match genuine prior receipts.
Removing a sealed private role or changing material refuses; additions are
checked through that role's normal parser. [Lifecycle](lifecycle.md) describes
the effect boundary and unsupported deletion/rotation cases.

## Worked app and combination

This is the complete value of `apps.recursive_a` in the
[offline tutorial](../examples/first-configuration/site.yaml). It compiles with
that tutorial's `recursive` profile and `resolver` guest; it is not a standalone
site or deployment-ready configuration.

<!-- example: app-minimal -->
```yaml
profile: recursive
guest: resolver
lifecycle: fresh
interfaces:
  private: {scope: app-network, network: default}
  local: {scope: guest-loopback}
```

For a practical override, add the following fields to this app. The `unbound`
role comes from its selected runtime; 256 MiB remains within the tutorial guest's
budget. The display label is independent of its persistent identity.

<!-- example: app-overrides -->
```yaml
display_name: Example recursive resolver
resources:
  containers:
    unbound: {memory_mib: 256, cpu_limit: 1, pids_limit: 128}
```

**Invalid variation:** change `interfaces.local` to `{scope: app-network,
network: default}`. This is a valid scope generally, but this profile accepts
only guest loopback for that role, so real resolution refuses it.
Keep `lifecycle: fresh` for later ordinary deployments of this owned app; do not
toggle it after installation. See [First installation and later deployments](lifecycle.md).

[Reference index](README.md) · [Properties](app-properties.md)
