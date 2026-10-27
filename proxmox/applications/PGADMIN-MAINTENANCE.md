# PostgreSQL network maintenance for an existing pgAdmin guest

This is a component contract for the shared maintenance controller. It is not a
new deployment, restore recipe or executable CD entry point. An existing pgAdmin
profile must stay in place. Do not regenerate the commissioned guest's foundation
inputs, change its source pin, or rewrite its install/plan/completion receipts to
make a maintenance run look like the original installation.

## Network and startup request

Root's private `networks/databases.json` with schema
`homelab-database-networks-v1` is authoritative. The shared
`database_networks.read`/`validate`, `interface`, `endpoint`, `rules` and `attach`
functions own network values; this component does not carry another catalogue.
The shared helper is being prepared separately and must be pinned by Root before
integration. No private catalogue or shared workflow is changed by this proposal.

For the selected `db-tools` guest, Root's maintenance packet needs to:

1. Bind the commissioned VMID/hostname, management address/MAC, original source,
   private-input hashes, Terraform state and successful installation receipts.
   Hold on unexplained drift or another maintenance operation.
2. Derive `attach(installed_guest, catalogue, ['postgresql'])`. Preserve existing
   management/backend NIC ordering, addresses, MACs, gateway and HTTP listener.
   Append only the selected PostgreSQL NIC: untagged private bridge, manual IPv6,
   no gateway. Keep guest autostart enabled. Never join another database network.
3. Use `rules(catalogue, 'postgresql', vmid)` for the exact client-source `/32`
   to PostgreSQL-server `/32` TCP 5432 allowance, with the matching server rule
   owned by Root. Any obsolete PostgreSQL allowance on the former backend needs
   an explicit observed-before/exact-after replacement in the shared packet;
   `attach` only appends and does not retire the old rule. Retain SSH, DNS,
   Authentik HTTPS and Traefik HTTP access.
4. Keep the existing shared network-ready implementation. Docker must require
   successful IPv4 readiness on the existing management/backend NICs and the
   appended PostgreSQL NIC (normally `eth0`, `eth1`, `eth2`; bind actual order).
   Select `docker.service`, not the PostgreSQL unit. Retain the current image,
   service user, volume, `unless-stopped` policy and HTTP bind address. Editing
   startup ordering must not restart Docker or unrelated containers. Root must
   decide how its mechanism activates a newly appended NIC; this proposal does
   not assume that a running LXC hotplug is qualified.

## Saved connection adapter

`pgadmin_endpoint.py` is a small SQLite adapter, with no file-opening code,
CLI, service control, SSH, networking or receipt management. Root passes its
already admitted SQLite connection; the adapter never creates a new profile.

```python
target = database_networks.endpoint(catalogue, 'postgresql')
# selector and before come from a private observation of the existing profile.
proposal = pgadmin_endpoint.plan(connection, selector, before, target)
# Later, only under Root's reviewed maintenance transaction/lifecycle:
changed = pgadmin_endpoint.apply(connection, proposal)
```

The selector is exactly `{'server_id': <int>, 'user_id': <int>}`. `before` is
exactly `{'host': <observed>, 'port': <int>}`. `target` is the shared endpoint
shape `{'address': <IPv4>, 'port': 5432}`. These IDs and the current endpoint
must be observed; do not select by display name, guess a user, create a server
entry or bulk-rewrite matching hosts across profiles.

Planning reads only transport columns for the exact server/owner. Applying
opens an immediate transaction, repeats those checks under the SQLite lock and
compares the expected old host/port before changing only `server.host` and
`server.port`. Stale/replayed proposals hold. An already-open caller transaction
is refused rather than committed or rolled back. No usernames, credentials,
maintenance database, TLS settings, users, groups, preferences or other rows are
rewritten. Service-file transport, SSH tunnelling, shared registrations/copies,
server update triggers or endpoint overrides in `connection_params` hold for
separate review. An unfamiliar schema also holds; do not adapt a live database
merely to make the adapter accept it. The relevant model is documented in the
[pgAdmin server/profile source](https://github.com/pgadmin-org/pgadmin4/blob/REL-9_15/web/pgadmin/model/__init__.py).

Root's mechanism must bind this proposal to guest identity, the private catalogue
hash, reviewed source and offline profile-backup hash. Before `apply`, it must
quiesce the selected pgAdmin writer and active UI sessions, obtain a coherent
SQLite backup including WAL state and preserve numeric ownership, modes, ACLs
and xattrs. Use the admitted existing database in read/write-existing mode;
never SQLite's default create-if-absent fallback. Root owns the exact stop/start
action and its approval. This component performs none of those native actions.
Do not import `servers.json`, recreate users, rotate secrets, change the master
password policy or restore an old profile. Keep Authentik/provider/callback and
HTTP/TLS routing configuration unchanged.

## Acceptance after Root integrates and admits the pair

Root owns the order: private bridge/access and PostgreSQL server acceptance,
then commissioned Authentik and pgAdmin maintenance as the next update group.
Do not wait for unrelated application migrations.

- Check the append-only NIC delta and exact firewall rule replacement; confirm
  the old management/default route and backend HTTP listener remain unchanged.
  Check host and container routing and the effective NAT source. The eventual
  PostgreSQL query should observe the selected client's database-network IP.
- Verify all non-endpoint SQLite content and original file metadata against the
  coherent backup, without exposing credentials. Verify the original install
  inputs/state/receipts remain unchanged; record maintenance separately.
- From the existing browser profile, complete the retained HTTPS/Authentik login
  and connect using the **same saved server entry** and retained role/TLS policy.
  Run the [read-only acceptance queries](PGADMIN.md#native-acceptance-performed-by-the-deployment-owner),
  also checking `SELECT inet_client_addr();`. A TCP probe alone does not prove
  pgAdmin's saved-credential connection, and OAuth success does not prove DB access.
- Confirm startup ordering from effective units. A service readback does not
  prove a future reboot; leave cold-start acceptance open until Root/Ben perform
  it. Preserve failed evidence/holds instead of replaying installation or restore.

The unit tests use synthetic SQLite profiles. The pinned-image fixture changes
one disposable saved endpoint while stopped and compares every other profile
value through the existing OAuth redirect test. Neither test proves a real
PostgreSQL connection, native login, network attachment or startup behavior.
