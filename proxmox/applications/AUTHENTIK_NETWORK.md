# Move a commissioned Authentik guest to its PostgreSQL network

This is source preparation for maintenance of an existing installation. Do not
replay foundation creation, staging, restore, secret generation or the initial
application deployment. Keep the commissioned site/stack inputs, source pin,
installation receipts and current application data unchanged. A maintenance
receipt records the update separately.

## Small service interface

`identity_database.candidate(original_compose_bytes, before, after)` returns a
candidate Compose document as bytes. It performs no file, SSH, Proxmox, Docker
or service operations. `before` and `after` each contain only `address` and
numeric `port`.

The shared maintenance caller must bind the exact private
`networks/databases.json` bytes by SHA256 and validate the
`homelab-database-networks-v1` contract. It derives `after` through
`database_networks.endpoint(contract, 'postgresql')`. Do not add a separate
Authentik address catalogue or rewrite the installed foundation bundle.
`before` binds the existing commissioned connection, including a hostname if
that was the installed setting. Both Authentik modes must match it; absent port
means the installed default PostgreSQL port, 5432. `after` must be a literal
private IPv4 endpoint from the network contract. The firewall adapter requires
the exact old private IPv4 endpoint rather than resolving an old hostname.

The candidate changes only `AUTHENTIK_POSTGRESQL__HOST` and
`AUTHENTIK_POSTGRESQL__PORT` in both `server` and `worker`. It preserves every
other Compose field, including secret file references, database role/name,
SMTP, image/version, process users, restart policies, local Redis, capture
mounts, server HTTP publication and worker settings. A partial change, wrong
stack, wrong modes or changed original endpoint is a hold, not an invitation to
repair or replay it automatically.

## Requirements for the shared maintenance packet

`identity_database.rules_candidate(original_guest_rules, legacy_sql_endpoint,
after_rule)`
replaces the sole exact legacy Authentik PostgreSQL egress rule with
`database_networks.rules(contract, 'postgresql', vmid)[0]`. It retains HTTP and
all non-SQL rules in their original order. Duplicate, changed, unbounded or
additional TCP rules allowing SQL are held for review; no fallback SQL allowance
is retained. The new rule has one client `/32`, one server `/32` and the selected
PostgreSQL port. Bind `legacy_sql_endpoint` separately from the installed Compose
`before`: its `address` is the exact admitted old private IPv4 from the server
NIC/firewall evidence, and its numeric `port` is the installed SQL port. Validate
that literal IPv4 binding without resolving or guessing from a Compose hostname.
`before['address']` remains the original Compose setting and may be a hostname.

The common database-network mechanism owns the packet schema and source pin.
This service helper does not define a second packet or execution engine.
The common packet needs to bind:

- The commissioned guest identity, original installed source, original
  site/stack/Compose bytes and installation-completion evidence.
- The exact database contract hash and the PostgreSQL server/client identities.
- The saved plan and exact appended NIC and PostgreSQL client firewall rule.
- The before/after Compose hashes and the existing PostgreSQL endpoint.
- The persistent startup requirement, read-only acceptance probes and failure
  custody. A completed update must verify on later runs without recreating it.
- A durable authorization record retained through the existing reviewed CD
  path, bound to the exact contract, selected clients, saved-plan hashes,
  candidate rule order and endpoint data. Activation stays blocked if that
  record is absent or any binding differs. This source-only work grants no
  activation authority and adds no separate approval workflow.

The shared contract helpers still derive the endpoint, interface and exact SQL
rule. For maintenance, use
`database_network_maintenance.candidate_guest(original_guest, contract,
'postgresql', phase='cutover', client_vmids=selected_clients,
legacy_server_address=legacy_sql_endpoint['address'])` as the authoritative guest candidate.
It keeps the existing management/backend NICs and appends the untagged database
NIC without a gateway. Select only the Authentik and pgAdmin clients for this coordinated PostgreSQL
cutover, not every future client in the catalogue.

Run `rules_candidate()` against the original guest rules with the separately
bound `legacy_sql_endpoint` as a service preflight.
Require its sole new SQL rule and unchanged non-SQL rule order to match the
common candidate. Keep the common candidate's exact rule order for
`check_plan()`: the common planner appends the replacement SQL rule, whereas the
service helper replaces it at the old position. Do not substitute that different
list ordering into the saved plan. A mismatch in membership or non-SQL rules is
a hold. In particular, keep the service guard for additional broad SQL egress;
an exact native resource-change check is not a substitute for that guard.

Preserve management/default routing, HTTP ingress and storage. The old SQL
allowance is removed with no period of dual PostgreSQL access or unrelated
firewall cleanup. The backend interface remains for HTTP/OAuth, even though
database traffic leaves it.

## Available common source and the activation gap

The common checkpoint exposes `database_network_maintenance.plan()` and
`check_plan()`. Planning uses the original installed module, authoritative
state/backend and workflow/deployment locks. It binds the contract and original
installation evidence in a separate maintenance directory and holds failed or
interrupted attempts. `plan()` contacts the pinned Proxmox API; it has not been
called by this source work. The planner returns `apply_supported=false` and
`lifecycle_effects_verified=false`, and has no apply entry point.

The common `ansible/network-update.yml` startup playbook accepts the original
`app` identity, `network_ready_interfaces` and exact current
`network_ready_gate_sha256` / `network_ready_dependency_sha256`. Derive the
interface names from all IPv4 NIC positions in the common candidate. Authentik
uses the fixed `docker.service` dependency. Both existing startup files must
match their admitted hashes and metadata. The playbook requires active IPv4
interfaces, updates the shared gate/dependency and checks Docker's PID and
activation timestamps stay unchanged. It does not recreate Authentik containers.

The remaining coordinated activation packet must supply:

- Real saved plans for all three commissioned guests, their exact hashes and
  provider lifecycle effects, including whether the new client NIC is usable
  without an unapproved guest restart. Keep original state, inputs and receipts.
- Exact current startup-file hashes, runtime Compose/image/secret-reference
  bindings, existing source/profile/installation receipts and current holds.
- A reviewed common apply/activation path for those exact plans, PostgreSQL's
  listener/HBA cutover and both Authentik modes, with failure custody and no
  implicit retry or fallback SQL access. No such executor is added here.
- New-network verification and the current verification-profile binding after
  retiring the old database address; historic installation receipts must not
  cause later CD to probe the retired SQL endpoint.
- pgAdmin's exact saved-server/user selector and profile/runtime bindings from
  its service owner, plus separate OAuth and authenticated database checks.

The committed prepared selection is source preparation. Neither a green plan
nor the startup playbook fills these activation gaps or admits a native target.

## Ordering and target evidence

This is the Authentik/pgAdmin next update group. It does not depend on migrating
other application clients. The selected order is:

1. Coordinate PostgreSQL, Authentik and pgAdmin as one cutover group. Root's
   common database/bootstrap maintenance prepares the private bridge and
   replaces PostgreSQL's old database NIC/listener/HBA/firewall with the selected
   private network and exact client access. Do not retain the old SQL network or
   use an additive listener transition.
2. Through that mechanism, verify the existing Authentik identity, installation
   bindings and original runtime; append its contract-selected NIC/rules and
   read back the exact guest state. Require its persistent PostgreSQL interface
   and route before application startup, without changing the default route.
3. Generate the Authentik candidate from the bound Compose bytes and derived
   endpoint. Validate Compose privately. Apply both modes together through the
   common service-maintenance hook. Recreate only the affected server/worker
   containers if needed; do not restart Docker, Redis or the guest or import a
   database/capture as part of this service patch.
4. Verify the effective settings in both modes, local Redis, worker health,
   existing backend HTTP readiness and database reachability over the new NIC.
   A running container alone is insufficient. Confirm no other service was
   recreated and preserve private failure evidence on any error.
5. Verify the unchanged Authentik login and pgAdmin OAuth path separately from
   pgAdmin's saved PostgreSQL connection update/query. OAuth success alone does
   not prove the database path. Keep Node-RED forward-auth acceptance distinct.

No live read, restart, native plan, apply or migration is performed by this
source helper. The common planning/startup APIs are known; the finite native
plan/lifecycle, binding and activation gaps above remain. Source tests do not
establish native readiness.
