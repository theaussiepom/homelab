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
`before` binds the existing commissioned connection. Both Authentik modes must
match it; absent port means the installed default PostgreSQL port, 5432.

The candidate changes only `AUTHENTIK_POSTGRESQL__HOST` and
`AUTHENTIK_POSTGRESQL__PORT` in both `server` and `worker`. It preserves every
other Compose field, including secret file references, database role/name,
SMTP, image/version, process users, restart policies, local Redis, capture
mounts, server HTTP publication and worker settings. A partial change, wrong
stack, wrong modes or changed original endpoint is a hold, not an invitation to
repair or replay it automatically.

## Requirements for the shared maintenance packet

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

Derive the guest overlay with
`database_networks.attach(original_guest, contract, ['postgresql'])`; use its
`interface`/`rules` output rather than repeating NIC or rule literals. The new
NIC is untagged, has no gateway and is appended after the existing management
and application backend NICs. Preserve their order, addresses, MACs, gateway,
HTTP ingress, storage and existing rules. Do not remove a legacy database rule
implicitly: its exact retirement requires the common mechanism's reviewed
policy and a working new connection. There is no unrelated firewall cleanup.

## Ordering and target evidence

This is the Authentik/pgAdmin next update group. It does not depend on migrating
other application clients. The selected order is:

1. Commission the PostgreSQL private bridge, PG server NIC/listener and exact
   client access through Root's common database/bootstrap maintenance.
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
source helper. The exact common maintenance API/pin and its admitted native
evidence are integration prerequisites; source tests do not establish them.
