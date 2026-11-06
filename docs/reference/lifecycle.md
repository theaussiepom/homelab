# Lifecycle and supported updates

First installation creates a supported guest/app. Later deployments update the
same owned installation. You do **not** change `fresh` to `retained` after each
successful run: the same `fresh` source continues through ordinary owned updates.

| Policy | Meaning |
| --- | --- |
| `lifecycle: fresh` | HomeLab may create it if absent; later deployments update that same instance. |
| `lifecycle: retained` | It must already exist and be managed by HomeLab; creation is refused. |

**Both allow ordinary updates.** Creation still requires a supported path and
absence of conflicting existing state. `retained` is not an import switch for a
manually created guest. Neither value permits resetting data, rotating a key or
removing a HOLD. Some adapters have no fresh installation path.
Check the [support matrix](support.md) and the selected library profile first.

## Worked first installation and later deployment

This is the tutorial's complete app value. Its guest also uses `fresh`.

<!-- example: lifecycle-fresh -->
```yaml
profile: recursive
guest: resolver
lifecycle: fresh
interfaces:
  private: {scope: app-network, network: default}
  local: {scope: guest-loopback}
```

| Situation | Source and behavior |
| --- | --- |
| First installation, no backend/owner | The supported `fresh` path may create the selected guest/app after every real prerequisite passes. The tutorial is offline-only and deliberately cannot be deployed. |
| Later deployment of that installation | Keep this same source. Current genuine receipts/state/payloads establish continuity; supported changes such as a display label are checked as updates. |
| Existing HomeLab-owned installation selected as retained | `retained` requires explicit persistent identities and genuine prior ownership. It cannot create or adopt a missing owner. |
| Existing manually created installation without those proofs | Neither changing the lifecycle label nor a successful compile imports it. No general import procedure is provided. |

A retained-only app such as Bitwarden cannot become installable by changing its
label to `fresh`. **Invalid variation:** `lifecycle: update` is not an enum value.
Do not rewrite VMID, paths or service names to make a later deployment appear new.

Guest and app policies are independent. A genuinely already owned guest may keep
`lifecycle: retained` while a **new** supported app on it uses `lifecycle: fresh`.
For example, another Unbound instance needs its own free listener/publication,
service/project namespace and sufficient capacity. The guest is updated; that
app is created. On the next deployment keep both policies unchanged. This does
not permit an app to adopt an existing unowned data directory or service.

## First installation

A genuinely fresh guest has no prior ordinary owner or existing backend,
and all selected apps use their supported fresh path. Fresh storage
initialization is create-only under an explicitly supported owned directory.
A valid vendor image or successful compile alone does not establish fresh
commissioning support. Use the [support matrix](support.md) and selected library
profile.

## Later deployments and ownership checks

The controller checks the genuine current canonical and immutable ordinary
success, sealed static configuration, every phase and AppPayload proof, current
backend and stable guest/app identity. Prior API authority, node, VMID, hostname,
storage/runtime/service ownership and workflow ancestry remain bound.
A newly selected retained app cannot adopt an unowned namespace.

Later ordinary runs advance their own receipts and backend generations.
An earlier inactive record remains historical bytes. It does not become a
baseline allowlist or import authority. Active/pending markers, unresolved newer
or foreign component history, changed state or canonical rollback refuse.
An exact owned checkpoint can be used only through its existing guarded contract;
the workflow is not an automatic retry/release system.

Historical sealed v1 component configurations may contain retired fields.
They are read as immutable proof, not parsed as new active source.
Historical proof does not add an authored migration waiver, bootstrap adapter
or release hook to the current contract.

## Infrastructure plan policy

The ordinary [saved-plan guard](../../proxmox/applications/plan_policy.py) admits
exactly the selected guest and its two firewall resources. Fresh creation needs
three creates with absent prior resources. Existing resources allow only update
or no-op, preserving node, VMID, disk, mount points, operating system,
unprivileged/protection flags and purge-on-destroy policy. The planned guest
must be active. Import, move, adoption and replacement are refused.

The complete disk and mount-point blocks are immutable for an existing guest;
this refuses growth as well as shrink. An accepted numeric resource value or a
provider-proposed action does not bypass that restriction. Device attachment
has its separate host-capability owner. These are execution constraints beyond
structural validation and packet lowering; an admitted update does not establish
that every permitted change is interruption-free.

## Change effects

| Change | Expected contract / update limit |
| --- | --- |
| Display name | Cosmetic; must not rename persistent resources |
| CPU/memory/startup | Changes desired infrastructure; planned guest must be active; permitted updates still need actual native and service verification |
| Disk/mount-point block | Immutable on an existing guest, including size increases; no ordinary resize or move |
| NIC/address/gateway | Changes reachability and desired infrastructure; management/identity/traffic checks apply |
| Template/profile default | Affects inheriting instances; compare effective output before adoption |
| Software/image/runtime | Changes selected packages or services; health, process identity and owned data guards remain |
| Connection/exposure/policy | Revalidates target, account, transport, readiness and traffic; may change app config or route |
| Source extraction | Effective entry unchanged; new source pins, same packet/graph semantics |
| Persistent path/VMID/project/service owner | No automatic move/rename/adoption; unsupported continuity changes refuse |
| Private role addition | Normal role parser/owner/create-once requirements apply |
| Private role removal/material change | Refuses; source rename cannot permit implicit rotation |
| App removal | No automatic data/container cleanup; undeclared existing project services refuse preflight |
| DNS alias removal | Exact prior-owned native record retirement only; conflicts refuse |
| Backend rollback/foreign edit | Refuses before new native work |
| Failure | Preserve HOLD, markers, prior canonical/immutable receipt and evidence; diagnose before any separately authorised recovery |

No general rollback, import, destructive replacement, native restore or arbitrary
delete contract is provided. The separate [recovery subsystems](../framework-reference.md)
have their own qualification and authority.

## Failure boundaries

Existing locks serialize cooperating deployment work. Exact own-HOLD checks
precede phase/final success publication and the original pre-unlink boundary.
They do not make arbitrary external/manual writers atomic or safe.
An app's private-material comparison happens before its payload/credential/service
effects once material is available; earlier infrastructure/preparation may have
completed. A generic redacted failure message is not enough to identify cause.

Compilation, controller proof tests, isolated Docker protocols, protected CD and
real service acceptance are distinct evidence. Read [Deployment](../operations/deployment.md)
and [Troubleshooting](../operations/troubleshooting.md) before acting.

[Reference index](README.md)
