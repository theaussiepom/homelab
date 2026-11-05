# Component configuration

The component API separates a reusable library from a site's allocations and
execution policy. Both accept authored JSON or YAML with schema
`homelab-components-v1` and kind `library`, `site`, or a referenced definition.
Use one source representation for each logical file. Duplicate keys, aliases,
unsafe tags, unsupported values, ambiguous siblings and escaping source paths
refuse with redacted diagnostics.

This version replaces the fixed guest-bundle authored API. Existing deployments
can keep their immutable older framework/library pins until they adopt component
source. The new compiler does not translate old authored shapes or migrate
receipts, state, data, credentials or holds.

## Use a library

A library declares guest templates, independent app profiles, software, runtime,
health, authentication and monitoring requirements, assets and policy fragments.
It has no implicit guest set. A site selects profiles, places stable app instances
on explicit guests and binds their interface roles, endpoints, connections,
storage, private input sources and policies. Instances of the same
profile can use distinct projects, services, endpoints and storage.

Support remains adapter-specific. Unbound and the namespace-aware proxy helpers
support independent instances on one guest. Pi-hole currently owns one fixed
DNS-record sidecar per guest, and Zigbee2MQTT supports one coordinator and fixed
receipt per guest; a second instance refuses during source validation. Native
database adapters retain their supported package service and data layout.
Fresh HA and Node-RED use declared create-only data initialization; retained-only
adapters refuse unsupported fresh commissioning. A rendered service or vendor
startup test alone does not qualify its complete deployment lifecycle.

Keep allocations and credentials in the consuming site. Store references to
private inputs rather than values. Public raw assets and ongoing identity-callback declarations retain their
declared type and hash. Historical adoption records are not active source
requirements. Value references do not
create deployment waits or firewall access. Declare genuine readiness edges and
ordered network grants separately.

From this framework checkout, validate or compile a selected source:

```sh
python3 blueprints/compile.py --stack /path/to/library --site /path/to/site.yaml --check
python3 blueprints/compile.py --stack /path/to/library --site-root /path/to/site --guest resolver --output /path/to/new-packet.json
python3 blueprints/workflows.py --stack /path/to/library --site /path/to/site.yaml --check
```

`--site` reads that exact file. `--site-root` discovers its single logical site
source. Packet output is create-only and private. `--admit` additionally validates
the selected source's deployment admission requirements; it is not a native
deployment, authorization grant or service verification.

The Python API is `compile.resolve_plan(...)`, `compile.lower_plan(plan)` and
`compile.compile_site(...)`. Workflow generation consumes the same sealed plan.
OpenTofu owns infrastructure and Ansible owns reconciliation through the
protected deployment workflow. Directly invoking helpers is not a recovery or
hold-clearing interface.

## Add or extend a component

First reuse an existing contract. When another capability is needed:

1. Add a closed typed schema, defaults and useful safe error code/property path.
   Reject unknown keys, unsupported combinations and unsafe bounds before I/O.
2. Resolve typed references centrally. Validate component contracts before the
   global placement, resource, identity and readiness graph checks.
3. Add only adapter-owned rendering and preparation. Register every runtime leaf
   in `application_contract.runtime_files`; never expose authored commands,
   Compose overrides, arbitrary mounts or generic property bags.
4. Preserve stable storage, credential and receipt ownership. Fresh creation
   needs its supported create-only path and exact owned repeat; retained data
   does not become fresh through a flag change.
5. Add the tests described in [testing.md](testing.md), document supported and
   refused behavior, then remove superseded callers and tests after replacement
   evidence exists.

Adapters own their helpers and narrow protocols. Changing a display name must not
rename a Compose project, NIC slot, data path, credential owner or custody
directory. Changes to those identities require an explicit supported contract;
the compiler does not silently adopt or relocate existing resources.

Selected private inputs are sealed by app role in the existing protected app
payload. An ordinary source update may add a role, but cannot remove a sealed
role or change its credential material. Renaming a source ID or workflow key
does not permit rotation. Compound WiNet/MQTT/provider records compare their
credential fields; public endpoint/options/permission metadata can evolve.
Bitwarden's sealed private environment role and opaque keys retain their
exact-byte contract. This check runs in the selected app phase before
its input publication, credential preparation or service execution; earlier
infrastructure/preparation phases may already have completed.

## Ordinary ownership

A retained deployment requires a genuine current component ordinary success:
its canonical and immutable receipts, sealed static configuration, every phase
and AppPayload proof, current backend and stable guest/app ownership must agree.
The prior API authority, node, VMID and hostname remain bound. A fresh guest with
only supported fresh apps may start without prior ownership; it cannot adopt an
existing backend. A new retained app cannot adopt an unowned namespace.

Later ordinary runs advance their own receipts and backend generations. Earlier
inactive records remain historical bytes, rather than a source of ownership.
Active or pending markers, newer or foreign unresolved component history,
canonical rollback, changed backend identity and a replaced HOLD refuse before
native mutation. Locks and the existing protected workflow remain authoritative;
there is no authored migration waiver, baseline allowlist or release hook.

Prior sealed component v1 configurations can contain retired fields. They are
read only as immutable history, never reinterpreted as active new configuration.
New input bindings have the seven permanent fields. Historical optional receipt
proofs remain readable without requiring their old source files or granting
adoption. Generated monitoring/account credentials retain their separate
existing owner/create-once checks. Private role continuity still prevents
implicit credential rotation.

## Split site sources

A site's `guests` and `apps` entries may be complete inline values or exactly one
confined source reference:

```yaml
guests:
  resolver: {source: guests/resolver.yaml}
apps:
  recursive: {source: apps/recursive.yaml}
```

Each referenced document has `schema: homelab-components-v1`, the matching
`kind: guest` or `kind: app`, and the complete typed entry at its root. There are
no overlays, recursive includes or partial configuration bags. Paths remain
relative to that site's source root; escapes, symlinks, wrong kinds and ambiguous
JSON/YAML siblings refuse. Every consumed leaf joins the source pin set.

## Reuse ordered address values

A site can name repeated CIDR facts and compose them with existing network CIDRs:

```yaml
address_groups:
  vpn_clients:
    members: [198.18.10.0/28]
  home_and_vpn:
    members:
      - {network: home}
      - {address_group: vpn_clients}
```

An HTTP `ip-allow-list` uses `ranges: {address_group: home_and_vpn}`. A network
policy's source or destination can use `{address_group: clients}`; the guest's
policy binding explicitly maps `address_groups: {clients: home_and_vpn}`.
Unused or missing bindings refuse.

Expansion keeps exact order and duplicates, with no union or sorting. A policy
with both grouped source and destination emits source-outer/destination-inner
rows in that order. Unknown references, cycles, wrong types and bounds refuse
before allocating the full Cartesian result. Limits are 256 authored members,
4,096 expanded values per group, depth 64, 65,536 aggregate expanded values and
4,096 rendered policy rows per guest. These are values only: they create no
firewall permission, service endpoint or readiness dependency.

## Managed DNS changes

The Pi-hole app derives its previous managed record selection from its genuine
prior ordinary receipt and sealed AppPayload. Removing a selected alias retires
only that previously owned name with its exact prior native address. A changed
or ambiguous old value refuses; unrelated aliases and their order remain.
There is no authored retired-name list or generic pruning. New sidecars use the
closed v2 current/previous document; a sealed older flat map is historical input
only. An unchanged-source repeat reuses its immutable document.

## Lifecycle qualification

| Case | Required contract and source evidence |
| --- | --- |
| Fresh guest | No existing backend or prior ordinary owner; every selected app supports fresh creation. |
| Fresh Unbound/Pi-hole | Compiler, packet and real local ordinary-payload fixtures cover creation and owned repeats. |
| Fresh HA/Node-RED and proxy workspaces | Declared create-only directory initialization and exact ownership proof; helper and caller tests cover the boundary. |
| Retained app/update | Genuine current component success, sealed app/private-material continuity and unchanged persistent identity. |
| Retained-only adapters | Unsupported fresh commissioning refuses; no data or installation identity is invented. |

These tests establish source and controller/helper behavior. Actual native
creation and service acceptance require protected CD and target verification.

## Ordinary Bitwarden inputs

Bitwarden properties are `issuer`, `database_name`, `data_uid` and `data_gid`.
Its software selection supplies an immutable official
`ghcr.io/bitwarden/lite[:tag]@sha256:...` reference, rendered literally with the
common Compose pull policy. Local image IDs, archive mappings and duplicate
source checksums or runtime file locators are not active instance properties.
Keep the selected `runtime_environment` private file role; its protected
AppPayload proof enforces exact-byte continuity before app input publication.
The closed compiled runtime/settings DTOs use `homelab-bitwarden-runtime-v2`.
Historical sealed v1 payloads remain readable as prior ownership/material proof;
they are not new runtime inputs. Database, installation identity, numeric data
ownership and health predicates remain in force. Fresh commissioning remains
unsupported.
