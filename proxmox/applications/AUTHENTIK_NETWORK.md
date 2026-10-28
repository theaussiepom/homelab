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

## Runtime interface for the common caller

`identity_database_runtime.py` supplies only the existing guest's finite service
phases. `ansible/identity-database-network.yml` accepts the original `app`,
`database_network_action`, `database_network_request` and
`database_network_result_path`. The caller owns the authoritative packet,
authorization, source pin, locks, saved plans, one-shot execution, private evidence
and failure/interruption holds. Before quiescing either client, the caller must
retain a private copy of the exact original Compose bytes and verify its SHA256
against `compose_sha256`. Hold activation if that recovery material is absent or
differs; a hash alone cannot recover the file. This helper adds none of those mechanisms.

The first native `inspect` must pass the commissioned hostname, IPv4 and interface
MAC fact checks on the selected Debian LXC. CI source-delivery compilation does
not validate that target fact shape; the common owner retains this native result
before preparing or admitting the packet.

The playbook executes the pinned Python source bytes with `python3 -c`; it does
not install a helper on the guest. Requests cannot supply a command or source
path. Results go to a fresh file beneath an existing private controller-owned
`/var/lib/homelab-applications/<vmid>/database-network-*/` directory. Input/output
and Docker diagnostics stay private. No Compose text or environment/secret values
are emitted in the inspection or runtime packet.

1. `inspect` accepts exactly `{'after': <contract-derived endpoint>}`. It reads
   the existing private Compose and identity files, both Authentik containers,
   local Redis, image defaults and bind sources. It derives the candidate locally
   and returns before/after hashes, endpoints, container/configuration/image/data
   fingerprints and states. It changes no guest files or services.
2. On the controller, call
   `prepare(catalogue, inspected, client_vmids, legacy_address, *, allow_guest_restart=True)`.
   It returns the closed runtime packet. `validate_binding(packet, catalogue,
   client_vmids, legacy_address)` returns `True` or raises. Both functions are
   pure. The common caller must first validate and hash the entire catalogue.
   These guards require exactly the selected two catalogue clients, this
   Authentik VMID/hostname, the admitted literal old address on port 5432 and the
   catalogue PostgreSQL address on port 5432. A hostname-based installed endpoint
   supported by the pure candidate helper is deliberately held by this coordinated
   runtime path until separately admitted.
3. `preflight` checks the exact original Compose, image/configuration/data/secret
   references, persistent `unless-stopped` policies, all three container health
   states, both `ak healthcheck` probes and Redis PONG. Run both client preflights
   before either client is stopped. This phase is read-only.
4. `quiesce` stops exactly `server` and `worker` and confirms both original
   containers remain stopped. It preserves Compose and Redis. For an explicitly
   admitted provider-required guest restart between quiesce and activate, both
   Authentik containers must remain stopped with their original `StartedAt`.
   Redis may restart with the same container, image, configuration and data
   bindings. `allow_guest_restart=False` also rejects Redis timestamp changes.
5. `activate` requires the original two clients still stopped. It validates the
   locally regenerated candidate, writes only both SQL HOST/PORT settings into
   the existing Compose inode, then recreates exactly `server` and `worker` using
   `--no-deps --no-build --force-recreate --pull never --wait`. It checks both
   new container identities, unchanged image/configuration/data fingerprints,
   health and unchanged Redis process during this phase. A failed or interrupted
   activation stays in caller custody; there is no automatic retry or rollback.
   For manual recovery, keep the clients stopped and use the caller-held,
   hash-verified original bytes to rewrite the existing private Compose inode.
   Recheck ownership, mode and hash, then follow the common recovery procedure
   for network/service state; restoring the file alone does not admit startup.
6. `verify` receives the same original runtime packet, checks the candidate hash,
   both new client identities/endpoints and original stable bindings, and repeats
   the health probes. Generated hostnames, endpoint config hashes and replacement
   history are checked separately from application configuration fingerprints.
   It changes no files or services and supports later read-only
   verification. The caller retains successful result identities for its receipt.

The common worker also owns native saved-plan application, PostgreSQL listener/HBA
cutover, startup gates and current verification profiles. The shared
`ansible/network-update.yml` accepts original `app`, `network_ready_interfaces`
and exact existing gate/dependency hashes. Derive interface names from the common
candidate; Authentik uses the fixed `docker.service` dependency. Preserve original
installation receipts and bind the current verification profile separately so
later CD does not probe the retired SQL endpoint.

The isolated Docker lifecycle fixture
(`python3 proxmox/applications/tests/identity_lifecycle_fixture.py`, after
preloading its two pinned images) proves the manual-stop policy with a synthetic
three-container stack and disposable daemon. It needs permission to launch a
resource-bounded privileged test container on a disposable Docker test host; it
uses no host socket, network, deployment credentials or application data. It does not establish
Debian/LXC/provider behavior. The common execution must admit actual saved plans,
provider lifecycle effects, current runtime/startup/profile evidence and holds,
then verify native readiness. Source tests alone grant no activation authority.

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
   containers once. The service helper does not restart Docker, Redis or the
   guest, or import a database/capture. An admitted provider-required restart is
   performed only by the common caller while both clients remain quiesced.
4. Verify the effective settings in both modes, local Redis, worker health,
   existing backend HTTP readiness and database reachability over the new NIC.
   A running container alone is insufficient. Confirm no other service was
   recreated and preserve private failure evidence on any error.
5. Verify the unchanged Authentik login and pgAdmin OAuth path separately from
   pgAdmin's saved PostgreSQL connection update/query. OAuth success alone does
   not prove the database path. Keep Node-RED forward-auth acceptance distinct.

This source-preparation work performed no native inspection, plan, apply or
migration. The runtime phases are executed only through the common caller under
its admitted packet. Native lifecycle, SQL connectivity, HTTP/OAuth and physical
service acceptance remain target-environment evidence.
