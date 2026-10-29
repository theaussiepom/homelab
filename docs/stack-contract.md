# Guest deployment contract

A stack provides `stack.json`, `common.json`, `images.json`, and one declarative
`guests/<name>/profile.json` per prepared guest. Profiles contain `config`, text
`files` and a nullable `stack`. The framework catalogue owns the supported platform,
preparation capabilities and application phase names. `blueprints/compile.py`
merges the site overlay and substitutes explicit `${central.value}` slots. It is
a pure compiler, not a controller: it never reads credentials or invokes targets.

Compilation resolves every guest through `compile_stack`, checks that VMIDs are
unique across the composition, and validates readiness for all enabled guests
before returning an admitted packet. The phase workflow selects one guest from
that validated result. There is no weaker guest-only admission API.

All declared guests participate by default. The optional `disabled` workflow
input is a JSON list, defaulting to `[]`; the compiler's `--disabled` option has
the same meaning. Exclusions must name unique known guests, and cannot disable
a prerequisite while a consumer stays active. Newly declared guests therefore
participate without updating a second list. There is no `enabled` input or alias.
Packet `enabled` is derived from this selection, not another configuration source.
A generated hosted validation job checks the disabled list before any guest job
can be skipped. Every guest also depends on that job, so disabling a root
prerequisite cannot turn invalid selection into an all-skipped successful run.
This gate uses only the public dependency map and input names, with no private
Environment, Secrets, checkout or target access.

A private overlay has `schema: homelab-site-v3`, central `values`, `common`, per-guest
`guests`, `images` overrides, `routes` and `accepted` prerequisites. Guest overrides may
contain `config` and `stack`. Lists replace whole lists, so NICs, rules and mounts
must be reviewed together. No implicit deep merge of list items occurs.

Each profile compiles to a `homelab-guest-deployment-v2` packet consumed directly by
`deploy.py`. Its `site.json` and bounded text files are placed into a private,
immutable directory identified by their effective non-secret inputs. `${inputs}`
binds that directory only after hashing. Runtime Secret injection stays out of the
packet and must match on repeats. Changed secret material cannot overwrite an
already prepared input directory. Keep actual Secrets outside Git, including
private Git. Existing credentials are compared; they are never implicitly rotated.

## Version authorities

The stack's `.github/workflows/phase.yml` has one literal external framework
workflow reference. That SHA is the framework version and checkout selection.
The private site's `.github/workflows/deploy.yml` has one literal external stack
workflow reference. That SHA is the adopted stack version. There are no competing
JSON pins. Image entries have a repository, recorded tag (or null), and digest;
a retained local image instead has a local ID, archive path and archive hash.
The existing Bitwarden operator-selected `latest` policy is a documented exception
with a separate observed image ID checked at runtime; this work does not change it.

GitHub requires literal reusable workflow references. The stack uses static guest
workflows and explicit `needs`, and the reusable phase runner explicitly checks out
the caller site, selected stack and selected framework. Workflow nesting stays
within GitHub's supported limits. References: [reuse workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows),
[caller checkout behavior](https://docs.github.com/en/actions/concepts/workflows-and-actions/reusing-workflow-configurations).
`blueprints/workflows.py` generates the checked-in stack entry workflow and one
permanent workflow per guest. Application phases and display names come from the
blueprint catalogue; cross-guest dependencies come from `stack.json`. Source CI
runs the same generator with `--check` and rejects missing, changed or obsolete
generated paths without rewriting them. Generation happens during development;
GitHub executes the explicit checked-in graph. There is no runtime DAG executor.
The framework selection in `phase.yml`, source CI and private exclusions/version
selection remain explicit controls outside the generator.

## Custody and phase behavior

`Infrastructure -> Preparation -> Application(s)` uses one run identity across jobs.
The private parent keeps `homelab-private-deployment`, cancel-in-progress false.
All admitted runner slots must share the same durable state/input/trust paths.
Do not enable this graph on runners with isolated local state. Independent guests
can run concurrently only within the existing slots; no extra runner is created.

The state root and VMID directory, OpenTofu backend, workflow/deployment/database
network locks and original receipts retain their existing identities. The current contract records a
Preparation completion record to the existing ordinary attempt directory. Package
repositories, retained accounts and exact packages run there once. Applications
reuse existing tasks without importing data or bootstrapping initial accounts.

Preparation refreshes the declared repository indexes before exact package
installation, with one bounded refresh attempt. Common Compose reconciliation
receives a derived map of image archives from the guest contract. Application
renderers retain their own input formats; Ansible does not inspect those formats
to locate images. Every rendered preserved data bind requires a prepared-path
declaration, including the additional HA startup and Node-RED configuration files.
DNS starts Unbound then Pi-hole with `--no-deps`; Automation starts MQTT, Home
Assistant, Node-RED. Authentik deploys server/worker/Redis as one app.

A matching completed input/source/state binding returns without target contact.
A partial/failed phase retains `ORDINARY-HOLD.json` and its started marker. A rerun
cannot replay it, clear it or advance another run. Existing migration/verification
holds still block. Infrastructure plans reject drift, deletion, replacement,
import/adoption, guest identity changes and data-volume changes. There is no restore
or automatic rollback path. Only `homelab-guest-deployment-v2` packets are accepted;
previous request formats are rejected before input materialization or target access.

The saved-plan policy is owned by `plan_policy.py`; the adapter supplies its
explicit creation/reconciliation decision from backend custody. A weaker standalone
plan checker is not retained. Both modes reject import, move, unknown target
identity, incomplete/deferred plans and drift. Installed guest identity/data fields
are immutable. A genuine no-change plan remains valid without an apply step.

A framework update changes the source binding and can cause a guarded reconciliation;
it does not migrate installed data or state. Do not convert an old receipt by hand.
Adoption must compare the final desired NICs, disks, identities and state first.

## Configuration and retained applications

Ordinary CD never applies HA HTTP/trusted-proxy conversion, Node-RED wrapper
conversion, frontend route migration, Zigbee configuration or radio identity.
These are separate prepared operator actions over SSH. Preparation checks required
paths before packages change; missing prerequisites hold the run. Central network
and domain values and narrow Secret delivery remain explicit deployment inputs.

MariaDB package-account admission requires the current account mode and preserves
its recorded package-created UID/GID; an installer `new_target` flag is refused.
Node-RED uses native Authentik OIDC. Optional route middleware is defined centrally.
HA startup requires the
explicit `HOMELAB_HA_IPV4` input; the prefix-based address fallback is removed.
Separately prepared configuration must satisfy these current contracts.

Bitwarden v2 reads an existing mode-600 runtime JSON file with its own hash. That
file must already contain the final commissioned database endpoint and identity;
ordinary deployment performs no endpoint conversion and reads no restore receipts.
Its app job retains the pre-start schema query and observed image ID check.
PegaProx requires the existing database key and initial account; it verifies the
retained key and runs its bounded health helper without replaying bootstrap.

## One current architecture

The application source has one deployment entrypoint and one current packet
contract. Service-specific controllers, old profile/workflow templates, historical
installation/restore/cutover orchestrators, v1 adapters and migration-only Ansible
branches have been removed. They are preserved in Git history, not relocated under
an inactive source directory.

[The application guide](../proxmox/applications/README.md) describes the owning
modules. Common behavior is extracted by responsibility: private I/O, runtime
bindings, immutable inputs, pure guest validation, durable custody and the PVE/
Ansible adapters. There is no generic controller or plugin registry. The blueprint
catalogue is the authority for capabilities, phases and mandatory retained paths.

`blueprints/connections.py` projects required internal IPv4 connections from the
resolved routes and guest DNS selections. Compilation checks the
initiator's outbound policy and receiver's inbound policy, including source
interface selection, protocol and port. Endpoint changes and private firewall
overrides must remain consistent. HTTP endpoints belong to named apps; the stack
routes map resolves them and external origins before validation. No implicit
firewall allowances are added. These source checks do not establish
router reachability, NAT behavior or actual host enforcement.

The composition also rejects duplicate IPv4 or MAC identities on the same declared
endpoint, node, bridge and VLAN before admission. Separate declared links retain
their own address spaces; this is a source check rather than topology discovery.

Credential binding derives the public key from the retained private SSH key and
checks it against the approved guest keys before writing either persistent
credential. An invalid, encrypted or mismatched key holds the binding step.
Key comments are metadata rather than part of that identity. Credential and trust
inputs require distinct declared paths, and existing credential drift is refused.
When foundation runtime files change, their application job explicitly recreates
the bundle so file bind mounts and startup-only settings use the new contents.
An unchanged copy does not force recreation. Existing data mounts are retained.

`secret_contract.py` owns foundation secret names, required/optional status,
environment sources and runtime filenames. Injection and rendering consume the
same definition. `private_io.py` owns bounded no-follow reads and durable guarded
writes. Renderers and evidence logs share those guarantees. Reads preserve accepted
read-only private source modes; writes refuse unexpected ownership/permissions
before truncation, and rendering checks all existing artifacts before rewriting.

Recovery copies pin the verified NAS directory and open each destination component
without following symlinks. Nested filesystems and directory identity changes are
refused. Copies, hash readback and durable receipts use those open directory
handles. Existing directory metadata is preserved; drift never triggers path
replacement, permission repair or a local backup fallback.

Existing state paths and HOLD/receipt names remain part of durable custody. Their
continued enforcement does not accept historical requests or replay old operations.
Before selecting an attempt, custody rejects symlinked or non-regular backends and
refuses a missing backend when prior attempts, trust records, installation evidence
or backend backups exist. Changed inputs cannot turn missing state into permission
to recreate a guest. The check belongs to custody, before either executor runs.
Fresh creation records the saved plan and exact apply window before the identity
verifier may pin a key through the trusted PVE creation evidence. Existing guests
retain their backend and pinned identity.

Every new reviewed merge reconciles infrastructure and application health, even
when its desired configuration is unchanged. A completion receipt can skip only
the same completed run and attempt. Receipts bind the private workflow, run
sequence and source commit; older runs, other workflows and commits that are not
descendants of the last completed deployment are refused before target work.
The caller checkout retains history for the local ancestry check. A guest that
was stopped externally is planned active again; other unexpected drift remains
subject to review.

Configuration preparation and data import remain external operator prerequisites.
Runtime helpers and the existing monitoring/host-bootstrap components remain where
they have current consumers. Native VM/application and physical-device acceptance
remain unverified.

Hardware attachment is a separate host infrastructure capability. Proxmox rejects
`devN` updates authenticated by API tokens, including root-owned tokens. The BPG
module therefore leaves `device_passthrough` to its registered host owner; it
never asks the token-authenticated API to add, remove or replace devices.
Infrastructure checks the capability before planning, reconciles the active guest,
then invokes it before Linux/Docker preparation and the Zigbee application.

Zigbee's Compose renderer registers the device at its identical by-id path inside
Docker and explicitly binds that same node to the preserved `/dev/ttyACM0`
application path. This keeps runc's source path available inside an unprivileged
LXC. Both sources must already exist; no guest tty alias or additional device
permission is introduced. The prepared data bind and application configuration
remain unchanged.

`host_device_helper.py` runs through a dedicated forced-command SSH key. The
root-owned policy fixes the node, guest ID, hostname, MAC and one persistent device
path, with UID 0, GID 20 and mode 0660. Registration of the current site binds that
key to guest 209 and the selected coordinator. Only `check` and `attach` are
accepted; the request must equal the installed policy. Existing attachments must
match exactly, and pending device changes are preserved for review. New attachment
uses the current configuration digest, verifies the
live configuration and checks the character device inside the running guest. No
replacement, removal, shutdown, restart, shell command or automatic retry exists.
The runner pins host SSH trust separately and records the policy hash and result.
The two capability files participate in deployment input identity.

Register the capability explicitly before enabling the guest. From the operator's
trusted workstation, create a fresh private policy from the compiled packet:

```sh
umask 077
python3 blueprints/compile.py --stack ../homelab-stack --site ../homelab-site/site.json --guest zigbee2mqtt --output /private/reviewed-packet.json
python3 proxmox/applications/host_devices.py --packet /private/reviewed-packet.json --output /private/209.json
ansible-playbook -i /private/operator-inventory.yml proxmox/bootstrap/ansible/host-device.yml -e host_device_policy_file=/private/209.json
```

The operator inventory has exactly one `pve` host and one `deploy` host with their
already pinned SSH trust. Registration creates a separate runner key, preserves
existing key pairs, refuses changed code/policy/trust, backs up host authorizations
and grants only the policy's forced command from the runner address. It performs a
read-only check; it does not attach a device or deploy a guest. Ordinary CD never
runs this registration play. API saved-plan checks admit only the expected
host-owned attachment entering refreshed state and active-state reconciliation,
while refusing other drift.

Registration also installs two comment-owned firewall allowances: runner IPv4 `/32`
to the PVE IPv4 `/32` on TCP 22, in the runner's outbound and the node's inbound
scope. Existing rules with that ownership comment must match exactly. Other rules
and global firewall enablement remain under their existing owners. Registration
binds the runner firewall scope to its protected, unprivileged `deploy` guest
(default VMID 900, explicitly selectable with `host_device_runner_vmid`). Every
hardware guest gets a dedicated key named `proxmox-host-device-VMID`.

Both the policy hash and the installed helper's source hash must match the selected
framework. Stale helper implementations fail preflight. Capability stdout/stderr,
including failed connections and timeouts, are retained in owned private operation
logs; an existing invocation cannot replay automatically. Registration refuses a
second key or changed caller address for an already owned policy, including after
loss of the runner-side key pair. Credential replacement requires explicit review.

HTTP routing has one runtime-independent model in `proxmox/applications/discovery.py`, resolved globally by `blueprints/routes.py`. App endpoints own
backend URLs; stack/site routes own unique hostnames, aliases and ordered middleware
references. Managed routes render to guest Notes, external routes to the file
provider. Shared middleware definitions and verified TLS transports belong to
ingress. All route DNS names point to its frontend; MQTT service DNS stays separate.
The stack/site source schemas are v2/v3, with no old per-app route adapter.


## Retired source and retained preparation obligations

The removed `ansible/` roles, `src/homelab` CLI and four encrypted draft roots
belonged to the superseded draft engine. They are not alternate deployment
paths. The current application's `proxmox/applications/tofu/versions.tf` retains
the same local backend and exact OpenTofu/provider versions as pre-replacement
main `d77b6bf5e417c371839d2e61c32c8d6f0fb0df36`.
Private state files, private plans, locks and verified NAS recovery copies are
its existing protection model; this does not claim OpenTofu state/plan encryption
or qualify encryption of the underlying storage. No backend conversion or
passphrase change occurs during ordinary deployment.

Guest readiness checks prepared application paths for type and symlinks; it does
not reproduce the retired draft role's generic UID/GID/mode manifest. Separate
`data-prepared` and `configuration-prepared` qualification must establish numeric
ownership and modes for every retained data/configuration path. Ordinary CD must
preserve that prepared metadata and must not repair it by recursive chown, restore
or initialization. Specific current owners still enforce native database account
IDs/receipts, the PegaProx key's UID/GID/mode/hash, Bitwarden's retained PUID/PGID
and private runtime-file hash, controller private-file ownership/modes and the
restricted radio device's exact metadata. These checks do not establish generic
metadata equivalence for every application path; that remains native preparation
evidence, not a successful source test.

Ordinary deployment selects an active guest. A newly created container can start
before its dependent guest-firewall options/rules are applied; the per-NIC firewall
flag alone does not close that initial-start interval. Before accepting
`state-and-trust-reviewed` for fresh creation, independently qualify the selected
network and host/datacenter firewall protection for that interval. Without that
qualification, fresh native creation remains held. The retired stopped-creation
migration path is not restored to ordinary CD, and this source does not assert
that any current guest is exposed or that native protection has been qualified.

The removed fixture files are not all equivalent to successor tests:

| Earlier guarantee | Current scope and evidence |
| --- | --- |
| Bitwarden startup, restart and attachment persistence | Retained: `bitwarden_runtime_fixture.py` exercises the current renderer, real synthetic Lite/MariaDB startup, restart and recreation, and a volume attachment sentinel. Required hosted CI runs it. This does not verify real vault rows, user authentication or native migration. |
| Installed browser-helper drift refusal during a maintenance transition | The transition controller is retired. Current ordinary routing consumes endpoint/route definitions; `frontend-ready.yml` verifies separately prepared reply-routing policy without changing it. No equivalent historical helper-adoption protocol is claimed. |
| Selective Unbound ACME configuration edits and metadata preservation | Automatic conversion is retired. The separately prepared Unbound configuration remains an existing read-only mount; source compilation does not rewrite it. Actual resolver/ACME configuration and ownership require separate preparation acceptance. Owned Pi-hole record reconciliation has its own current behavioral fixture. |
| Manually stopped clients survive a disposable Docker-daemon cycle | That maintenance-specific behavior is retired. The requested ordinary deployment maintains active services and defaults containers to `restart: always`; it must not preserve a manual stop as desired state. |
| Watched-file Influx routing, source gating and native auth headers | Managed Influx routing now belongs to guest Notes. The pinned provider fixture exercises managed Influx routing, direct-peer denial despite spoofed headers, and native Authorization/cookie preservation. The former file-migration protocol is retired; external routes remain the separate file-provider map. |

The stack/site owners must verify adopted identifiers, endpoints, middleware,
metadata preparation and prerequisite records against their exact published
versions. Framework source tests do not qualify native firewall enforcement,
TLS trust, browser/SQL acceptance, physical devices or restore capability. Missing
acceptance must remain a visible preflight failure, never an implicit exclusion.


Additional current behavioral coverage uses only disposable synthetic resources:
`package_install_fixture.py` exercises both real shared APT tasks against a stale
local index, exact version selection, no vendor start, unchanged repeat and absent
pin refusal. `pegaprox_runtime_fixture.py` exercises the pinned current renderer,
separate key, encrypted database row and restart through the current passwordless
health verifier. Its initial synthetic account exists only in a fresh isolated
fixture volume; no setup helper is restored to ordinary CD.
`pgadmin_runtime_fixture.py` starts the selected immutable image from an existing
synthetic profile without default credentials, preserves the complete profile
projection and verifies trusted OIDC discovery and the selected callback. Its old
registration-replacement migration assertions remain retired. Required hosted CI
runs these fixtures; they do not qualify native applications or private state.


## DHCP allocation and qualified endpoints

`guest.interfaces[].ipv4` remains the provider allocation: a static IPv4 CIDR or
`"dhcp"`. A DHCP interface must additionally declare `ipv4_endpoint` as its
independently qualified assigned IPv4 CIDR and must have no static gateway.
Static interfaces derive their endpoint from `ipv4` and reject `ipv4_endpoint`;
there is no second static authority, runtime discovery or guessed prefix. For
example, a synthetic reviewed interface can declare `"ipv4": "dhcp"`,
`"ipv4_endpoint": "198.18.40.2/27"`, `"gateway": null`. The real private assigned
prefix requires site evidence; this example is not acceptance for any live guest.

The shared endpoint helper feeds SSH binding, health/backend interface ownership,
service publication, routing, DNS resolver ownership, source selection and network
identity collision checks. Connected destinations select the longest qualified
prefix; a DHCP NIC supplies its own default route. Ambiguous source choices fail.
The qualified endpoint participates in packet identity, while the provider input
strips `ipv4_endpoint` and preserves `ipv4: "dhcp"` and the null gateway. No
provider, network allocation or tool choice is changed.

Before an existing DHCP guest's infrastructure reconciliation and every guest SSH
phase, read-only admission checks the trusted PVE guest identity, configured DHCP,
MAC, bridge and VLAN against reviewed inputs. It also requires one observed
interface with that exact MAC and assigned IPv4 address/prefix. New-guest SSH key
pinning uses the same network admission before its existing creation-task proof.
All reviewed DHCP interfaces are checked even when SSH uses a different static
NIC. A missing or ambiguous interface, changed lease/prefix or static conversion
holds execution before SSH; it never rewrites trust, adopts a lease, converts the
NIC or clears failed evidence. Existing locks, state custody and no-replay behavior
remain in force. Hosted synthetic checks do not qualify the private endpoint or
provide native execution authority.
