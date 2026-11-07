# Lifecycle and supported updates

First installation creates a supported guest or app. Later deployments update that same HomeLab-managed installation. Keep `fresh` after a successful run; you do **not** need to change it to `retained` for ordinary updates.

| Policy | Meaning |
| --- | --- |
| `lifecycle: fresh` | HomeLab may create it if absent; later deployments update that same instance. |
| `lifecycle: retained` | It must already exist and be managed by HomeLab; creation is refused. |

**Both allow ordinary updates.** Creation still requires a supported path and absence of conflicting existing state. `retained` is not an import switch for a manually created guest. Neither value permits resetting data, rotating a key or removing a HOLD. Some adapters have no fresh installation path. Check the [support matrix](support.md) and the selected library profile first.

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
| Later deployment of that installation | Keep this same source. Current receipts, state and recorded app inputs prove existing ownership; supported changes such as a display label are checked as updates. |
| Existing HomeLab-owned installation selected as retained | `retained` requires explicit persistent identities and genuine prior ownership. It cannot create or adopt a missing owner. |
| Existing manually created installation without those proofs | Neither changing the lifecycle label nor a successful compile imports it. No general import procedure is provided. |

A retained-only app such as Bitwarden cannot become installable by changing its label to `fresh`. **Invalid variation:** `lifecycle: update` is not an enum value. Do not rewrite VMID, paths or service names to make a later deployment appear new.

Guest and app policies are independent. A guest already managed by HomeLab may keep `lifecycle: retained` while a **new** supported app on it uses `lifecycle: fresh`. For example, another Unbound instance needs unused listening and published sockets, distinct service and project names, and sufficient capacity. Deployment updates the guest and creates the app. Keep both policies unchanged on the next run. This does not permit the app to take over an existing data directory or service that HomeLab does not own.

## First installation

A fresh guest must have neither a prior ordinary HomeLab owner nor an existing backend, and every selected app must support first installation. Storage initialization may only create new data in an explicitly supported HomeLab-managed directory. A valid vendor image or successful compilation does not prove that HomeLab can commission the service. Check the [support matrix](support.md) and selected library profile.

## Later deployments and ownership checks

The controller checks the current pointer to the last successful ordinary operation (the canonical record) and the immutable receipt for that operation. It also verifies the sealed static configuration, completion evidence for each phase, and each AppPayload—the recorded inputs for an app—against the current backend and guest and app identities. These checks preserve the previous API provider, node, VMID, hostname, and ownership of storage and runtime services. They also check that workflow history continues from the previous run. A newly selected retained app cannot take over names or paths that HomeLab does not already own.

Each later ordinary run records new receipts and a new backend generation. Earlier inactive records remain unchanged historical evidence; they do not permit importing resources. Execution stops when checks find active or pending markers, unresolved records from a newer or different component operation, changed state, or a pointer moved back to an older successful operation. A checkpoint records progress within an operation and can be reused only through the existing procedure that verifies it belongs to that exact operation. The workflow does not automatically retry operations or release holds.

Historical sealed v1 component configurations may contain retired fields. HomeLab reads them as immutable evidence rather than parsing them as new configuration. Their contents do not add migration exceptions, bootstrap adapters or release hooks to the current configuration format.

## Infrastructure plan policy

The ordinary [saved-plan guard](../../proxmox/applications/plan_policy.py) admits exactly the selected guest and its two firewall resources. Fresh creation needs three creates with absent prior resources. Existing resources allow only update or no-op, preserving node, VMID, disk, mount points, operating system, unprivileged/protection flags and purge-on-destroy policy. The planned guest must be active. Import, move, adoption and replacement are refused.

For an existing guest, the complete disk and mount-point blocks must remain unchanged, including size increases and decreases. A valid numeric resource value or an action proposed by the provider does not bypass this restriction. Device attachment follows its separate host-capability procedure. These execution checks apply after the compiler validates the configuration and generates a packet. Passing them does not guarantee that an allowed update will be uninterrupted.

## Change effects

| Change | Expected contract / update limit |
| --- | --- |
| Display name | Cosmetic; must not rename persistent resources |
| CPU/memory/startup | Changes desired infrastructure; planned guest must be active; permitted updates still need actual native and service verification |
| Disk/mount-point block | Immutable on an existing guest, including size increases; no ordinary resize or move |
| NIC/address/gateway | Changes reachability and desired infrastructure; management/identity/traffic checks apply |
| Template/profile default | Affects inheriting instances; compare effective output before adoption |
| Software/image/runtime | Changes selected packages or services; checks still protect health, process identity and managed data |
| Connection/exposure/policy | Revalidates target, account, transport, readiness and traffic; may change app config or route |
| Source extraction | Keeps the effective declaration unchanged; source pins change, but generated deployment inputs and dependencies stay the same |
| Persistent path/VMID/project/service owner | Does not move, rename or adopt resources automatically; unsupported ownership changes are rejected |
| Private role addition | The role's normal parser, ownership and create-once requirements apply |
| Private role removal/material change | Rejected; renaming the source cannot permit implicit rotation |
| App removal | Does not delete data or containers automatically; preflight rejects existing project services absent from configuration |
| DNS alias removal | Removes only a record with its exact previously managed value; conflicts are rejected |
| Backend rollback/foreign edit | Refuses before new native work |
| Failure | Preserve HOLD, markers, the prior canonical pointer, immutable receipt and other evidence. Diagnose before separately authorised recovery. |

No general rollback, import, destructive replacement, native restore or arbitrary delete contract is provided. The separate [recovery subsystems](../framework-reference.md) have their own qualification and authority.

## Failure boundaries

Locks prevent cooperating deployments from running conflicting work at the same time. Before publishing phase or final success, and at the existing check before unlinking the HOLD, HomeLab verifies that the exact HOLD still belongs to the operation. These checks do not protect against arbitrary external or manual writers. Once an app's private inputs are available, they are compared before its payload is published, credentials are written or services are changed. Infrastructure and preparation may already have completed. A generic redacted failure message alone does not identify the cause.

Compilation, controller tests, isolated Docker protocol tests, protected CD runs and observations of real services establish different things. Read [Deployment](../operations/deployment.md) and [Troubleshooting](../operations/troubleshooting.md) before acting.

[Reference index](README.md)
