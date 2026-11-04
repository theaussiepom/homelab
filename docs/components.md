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
storage, secret sources, admission evidence and policies. Instances of the same
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
private inputs rather than values. Evidence files retain their declared type and
hash; raw custody documents preserve their exact bytes. Value references do not
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
Bitwarden's existing authoritative environment digest and opaque keys retain
their exact-byte contract. This check runs in the selected app phase before
its input publication, credential preparation or service execution; earlier
infrastructure/preparation phases may already have completed.

The first retained transition needs genuine prior immutable material proof.
The reader accepts only known hash-bound compiled legacy input slots, without
recompiling old authored source. Missing proof refuses that selected role;
there is no inferred baseline, rotation override or adoption of unpublished
component prototypes. Generated monitoring/account credentials retain their
separate existing owner/create-once checks.
