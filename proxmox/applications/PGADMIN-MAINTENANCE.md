# PostgreSQL network maintenance for an existing pgAdmin guest

This is a component contract and runtime playbook for the shared maintenance
controller. It is not a new deployment, restore recipe or separate workflow. An existing pgAdmin
profile must stay in place. Do not regenerate the commissioned guest's foundation
inputs, change its source pin, or rewrite its install/plan/completion receipts to
make a maintenance run look like the original installation.

## Network and startup request

Root's private `networks/databases.json` with schema
`homelab-database-networks-v1` is authoritative. The shared
`database_networks.read`/`validate`, `interface`, `endpoint`, `rules` and `attach`
functions own network values; this component does not carry another catalogue.
The shared helper must be pinned by Root before integration. No private catalogue
or shared workflow is changed by this proposal.

For the selected `db-tools` guest, Root's maintenance packet needs to:

1. Bind the commissioned VMID/hostname, management address/MAC, original source,
   private-input hashes, Terraform state and successful installation receipts.
   Hold on unexplained drift or another maintenance operation.
2. Use `database_network_maintenance.candidate_guest` with `engine='postgresql'`,
   `phase='cutover'`, the selected client VMIDs and observed legacy server address.
   It composes the shared catalogue interface/rules into an exact candidate.
   Preserve existing
   management/backend NIC ordering, addresses, MACs, gateway and HTTP listener.
   Append only the selected PostgreSQL NIC: untagged private bridge, manual IPv6,
   no gateway. Keep guest autostart enabled. Never join another database network.
3. Replace the old PostgreSQL egress allowance with
   `rules(catalogue, 'postgresql', vmid)` for the exact client-source `/32`
   to PostgreSQL-server `/32` TCP 5432 allowance, with the matching server rule
   owned by Root. Removal of the old PostgreSQL allowance is mandatory in the
   same coordinated cutover; bind its observed-before/exact-after replacement in
   the shared packet. Activation requires human approval of the observed old
   allowance and exact replacement rules; packet hashes alone grant no authority.
   Existing valid approval remains valid within its exact scope. The common
   cutover compiler removes the old rule; bare `attach` only appends and is
   insufficient. Do not leave a database-specific route, SQL allowance or fallback.
   Retain SSH, DNS,
   Authentik HTTPS and Traefik HTTP access.
4. Keep the existing shared network-ready implementation. Docker must require
   successful IPv4 readiness on the existing management/backend NICs and the
   appended PostgreSQL NIC (normally `eth0`, `eth1`, `eth2`; bind actual order).
   Select `docker.service`, not the PostgreSQL unit. Retain the current image,
   service user, volume, `unless-stopped` policy and HTTP bind address. Editing
   startup ordering must not restart Docker or unrelated containers. Root must
   decide how its mechanism activates a newly appended NIC; this proposal does
   not assume that a running LXC hotplug is qualified.

## Common source checkpoint and remaining activation gap

The [common source proposal](https://github.com/theaussiepom/homelab/pull/42)
supplies `database_network_maintenance.plan/check_plan` and
`ansible/network-update.yml`. These are separate from the original installation:

- `plan` uses the original installer, authoritative state/backend and existing
  workflow/deployment locks, writes separate private evidence and retains failed
  or interrupted-plan holds. Calling it contacts the pinned Proxmox API. It is
  not an offline compiler and has not been run against a target by this component.
- `check_plan` checks a supplied provider plan against the exact existing guest,
  firewall and permitted NIC/SQL-rule delta. A passing result still reports
  `apply_supported=False` and `lifecycle_effects_verified=False`. The common
  planner has no apply entry point.
- `network-update.yml` accepts the existing `app` identity,
  `network_ready_interfaces`, `network_ready_gate_sha256` and
  `network_ready_dependency_sha256`. For pgAdmin it selects `docker.service`,
  matches the current gate/dependency files and guest identity, waits for all
  selected IPv4 interfaces and verifies that the service process is unchanged.
  It needs the new NICs already active; it does not apply the provider plan or
  activate a saved-connection change.

The remaining common activation gap is finite: actual provider saved plans and
their lifecycle behavior; exact current startup/runtime/profile/receipt bindings;
the authoritative server/user selector and old endpoint; and Root's admitted
coordinated activation/verification packet. Root owns binding those observations
to the reviewed source and catalogue, applying the exact network/rule changes,
sequencing the two quiesced clients and resuming/verifying their retained services.
Do not invent a private executor, infer that a source plan grants activation, or
replace missing native evidence with synthetic results. No additional live read
or action is requested by this document.

## Runtime caller API

[pgadmin-database-network.yml](ansible/pgadmin-database-network.yml) is called by
the common coordinator with `app` (the original app identity),
`database_network_action`, `database_network_request` and
`database_network_result_path` (a new private controller result file). Trusted
source bytes from `pgadmin_database_runtime.py` and `pgadmin_endpoint.py` are sent
with `python3 -c`; the inspect/verify phases do not install a guest helper. No packet field can
choose commands, source files, guest paths, SQL or a different image.

The pure controller sequence is:

```python
target = database_networks.endpoint(catalogue, 'postgresql')
request = pgadmin_database_runtime.prepare(target, inspected, selector, legacy_address)
pgadmin_database_runtime.validate_binding(request, catalogue, client_vmids, legacy_address)
```

This normalized-endpoint `prepare` is the equivalent of a catalogue-based
compiler; `validate_binding` reuses the shared catalogue validator and checks
membership/group, exact endpoints and every component-packet field. `inspected`
is the complete structured inspect result, not a caller-invented profile row.
`legacy_address` is the observed old network IP, independently of the saved
hostname. Preserve the exact observed saved `before.host` literal without DNS
resolution or an inferred substitution. The inspect request contains original
`compose_sha256`, `identity_sha256`, `config_sha256`, immutable `image`, unchanged
backend `http_address`, `selector` and the shared catalogue `target`.

| Action | Behavior and result |
| --- | --- |
| `inspect` | Read only: match the commissioned identity, original Compose/config/image, exact container and retained mounts/policy. Return lifecycle identity, profile inode/owner/mode/xattr digest, coherent logical SQLite fingerprint, selected OAuth owner/server host/port and complete safe registration inventory. Bind a fresh-ID replacement proposal. No credentials or private rows are returned. |
| `preflight` | Read only: validate the whole prepared request and current running state/profile before either client stops. Existing/failed component backup evidence is preserved. |
| `quiesce` | Stop only the exact admitted container; require `unless-stopped`. Make a coherent SQLite backup using SQLite's backup API, including committed WAL, without checkpointing or restoring the source. Return `quiesced` with request/profile/backup hashes, profile metadata and stopped StartedAt/FinishedAt/restart-count bindings. A failure never implicitly resumes the app. |
| `activate` | Add the returned receipt as `request.quiesced`. Require the same container stayed stopped across the provider cycle. Verify backup and all original bindings; atomically replace the bound registrations using the approved OAuth owner’s retained settings and a pre-commit whole-profile guard; start the same container ID without pulling, recreating or Compose-up. Check the existing HTTP listener. |
| `verify` | Read only: same runtime/image/config, exact fresh registration and expected complete profile, metadata and HTTP liveness. Report SQL acceptance separately as described below. |

Every successful action returns JSON `status: passed` and its `action`. That
status means the selected phase passed, not that browser/SQL acceptance passed.
The fixed guest backup location is derived from the prepared request hash;
`backup_location(request)` exposes that pure location for common NAS custody.
Backup files are root-private and never overwritten. No component approval,
workflow, locks, state-owner, NAS, one-use or failed-hold manager is introduced.
Those remain with the common coordinator. Original installation files/receipts
and all pgAdmin users, OAuth configuration and file metadata stay unchanged.
The registration replacement is explicit: bind the complete observed old
server/owner/host/port inventory; create one fresh ID named `PostgreSQL` using the
selected OAuth owner’s original row settings, except ID/name/host/port; delete
exactly those old registrations. The selected database role, TLS policy, encrypted
saved password and other connection settings remain byte-for-byte unchanged in
SQLite. Query history for the removed registrations is cleared, matching pgAdmin’s
server-delete behavior; the coherent backup retains it. The selected registration's
per-database `schema_res` settings follow the fresh registration: only
`database.server` changes, preserving every database ID and stored value. The
pinned application's model and database-view code use these rows for schema
visibility restrictions. Reparent them before deleting old registrations so an
`ON DELETE CASCADE` cannot discard them. Their exact count and contents digest
are bound in the proposal. Rows belonging to another removed registration,
unrelated rows already attached to the fresh ID, shared registrations, unknown
foreign-key dependents and debugger state hold for separate review. A drifted
inventory cannot silently expand the removal scope. The backup is copied into
disposable memory to calculate the complete expected profile before any real
write; the guard checks that exact fingerprint before committing all changes.

The common order is both client preflights, quiesce211+202, saved provider plans
for208/211/202, startup-gate updates, PostgreSQL activation, Authentik activation,
pgAdmin activation and read-only verification. A provider-required guest restart
is allowed only by the common exact packet. The component checks that pgAdmin
retained its stopped timestamps/restart count across that cycle; Docker itself
is never restarted by a component phase.

### Same-profile SQL acceptance

The pinned pgAdmin password handler can require an authenticated user's session
or master-password unlock key. A new maintenance Python process does not inherit
that context. The runtime result therefore reports `profile_verified: true`,
`database_verified: false` and
`database_verification_reason: existing_authenticated_profile_session_required`.
It never decrypts/exports passwords, invents a login model, or opens an unrelated
administrator connection and labels it same-profile proof.

The common deployment may record the endpoint/config result separately, leaving
human SQL acceptance unverified. From the actual authenticated browser profile,
connect through the new registration under the same authenticated owner and run:

```sql
SELECT 1;
SELECT current_database(), current_user, inet_server_addr(),
       inet_server_port(), current_setting('server_version'), inet_client_addr();
```

Bind that observation to the selected server/user and admitted endpoint. Until
that happens, no successful same-profile SQL result is claimed.

## Registration adapter

`pgadmin_endpoint.py` has no file-opening code, CLI, service control, SSH,
networking or receipt management. Root supplies an admitted SQLite connection.
The runtime uses its explicit replacement API:

```python
target = database_networks.endpoint(catalogue, 'postgresql')
proposal = pgadmin_endpoint.replacement_plan(connection, selector, before, target)
# Only after common admission, writer quiescence and coherent backup:
changed = pgadmin_endpoint.replacement_apply(connection, proposal,
                                            validate_update=trusted_profile_guard)
```

`selector` is exactly `{'server_id': <int>, 'user_id': <int>}` and selects the
approved existing OAuth user's settings template. `before` is exactly
`{'host': <observed literal>, 'port': <int>}`; `target` is
`{'address': <IPv4>, 'port': 5432}`. Never infer an owner from a display name.
The safe proposal binds the complete old inventory, selected template, OAuth
authentication source, fresh ID/sequence, name, target, selected per-database row
count and a digest of registration/history/database settings. Credentials stay
inside SQLite. The write transaction rechecks the
proposal and rolls back every insert/delete if the expected-profile guard fails.
Replay holds instead of deleting the new registration.

The smaller `plan`/`apply` endpoint-only API remains available for callers whose
explicit scope is only one row's host/port. It does not remove registrations; the
runtime replacement phase does not silently fall back to it. Both APIs refuse
service-file transport, SSH tunnelling, shared registrations/copies, selected
endpoint overrides in `connection_params`, server triggers and unfamiliar schema.
The pinned-image fixture exercises the actual pgAdmin schema, not an invented
replacement profile. Retain the master-password policy and do not import a new
`servers.json`, recreate users, rotate secrets or restore an old profile.

## Acceptance after Root integrates and admits the pair

Root owns one coordinated PostgreSQL + Authentik + pgAdmin cutover. The PostgreSQL
server replaces its former backend database NIC/listener/HBA/firewall with the
selected private database network; there is no period of dual PostgreSQL network
service. The clients retain their backend NICs for HTTP/OAuth, and replace their
old SQL allowance and application endpoint with the new private path. Root must
sequence the quiesced clients, exact network/rule changes, server acceptance and
registration replacement before resuming clients. Do not leave a fallback SQL path or
wait for unrelated application migrations.

- Check the append-only NIC delta and exact firewall rule replacement; confirm
  the old management/default route and backend HTTP listener remain unchanged.
  Check host and container routing and the effective NAT source. The eventual
  PostgreSQL query should observe the selected client's database-network IP.
  Also prove the former PostgreSQL backend endpoint is unreachable and no old
  TCP 5432 allowance remains; HTTP/OAuth on the client's backend must still work.
- Verify the exact approved registration delta and all remaining SQLite content
  and original file metadata against the coherent backup, without exposing credentials. Verify the original installation
  inputs/state/receipts remain unchanged; record maintenance separately.
- From the existing browser profile, complete the retained HTTPS/Authentik login
  and connect using the **fresh registration under the same approved OAuth owner** and retained role/TLS policy.
  Run the [read-only acceptance queries](PGADMIN.md#native-acceptance-performed-by-the-deployment-owner),
  also checking `SELECT inet_client_addr();`. A TCP probe alone does not prove
  pgAdmin's saved-credential connection, and OAuth success does not prove DB access.
- Confirm startup ordering from effective units. A service readback does not
  prove a future reboot; leave cold-start acceptance open until Root/Ben perform
  it. Preserve failed evidence/holds instead of replaying installation or restore.

The unit tests use synthetic SQLite profiles and an exact Docker double. The pinned-image fixture replaces
two synthetic registrations with one fresh OAuth-owned registration while stopped
and compares retained connection settings and every non-registration profile
value through the existing OAuth redirect test. Neither test proves a real
PostgreSQL connection, native login, network attachment or startup behavior.
The additional isolated Docker26.1.4 daemon/container-cycle fixture proves that
an explicitly stopped `unless-stopped` workload retains its stopped identity and
timestamps while a control restarts. It has a dedicated synthetic volume, no
external network, no published ports, no host socket or private bind mounts.
Its nested daemon needs test-only privilege. This is not a restart of the host
Docker service, a native Proxmox test or complete qualification of the separately
pinned Debian26.1.5 package/provider lifecycle.
The generic profile fixture never invokes this privileged fixture. Its separate
CI step explicitly opts in only on a disposable GitHub-hosted Linux runner. The
fixture refuses remote/ambiguous Docker environment overrides or a non-default
effective context; it requires the exact local root-owned socket and matching
daemon hostname. Every outer command then uses that fixed endpoint and isolated
CLI config, including cleanup and image streaming. It is default-deny outside
that admission and must not be run against a shared or production daemon.
