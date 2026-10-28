# pgAdmin in the db-tools guest

For a commissioned guest changing PostgreSQL networks, use the
[maintenance contract](PGADMIN-MAINTENANCE.md). Do not replay this installation
or restore path to change its saved connection.

The `db-tools` application kind runs one pinned pgAdmin container through the
existing guest module, capture restore, Ansible and CD steps. PostgreSQL remains
in its own native database guest. The deployment runner stays dedicated to CD.

This is source preparation. A rendered stack or successful synthetic test does
not establish a migrated profile, working OAuth callback or database connection.

## Private inputs

Start with [db-tools.stack.example.json](examples/db-tools.stack.example.json).
Its addresses, credentials and digest are invented test inputs. Supply the actual
values outside Git, under the runner's existing private input directory.

- Select `app.kind: db-tools` in the usual private site file. Keep the existing
  guest identity, saved-plan limits, NAS state backup and failure holds. Select
  autostart for the guest and the accepted ongoing container restart policy.
- Set `pgadmin_bind_address` to the selected guest's fixed backend IPv4 address.
  Management can continue to use DHCP. The container publishes HTTP port 80 only
  on that backend address. Root must verify that the address belongs to this guest.
- Use the existing image's registry digest or its exact local image ID with a
  SHA256-verified image archive. A local image ID is not a registry digest. Retain
  the installed version; do not choose a new version from the example.
- Capture the stopped pgAdmin data coherently with numeric ownership, modes,
  ACLs and xattrs. The archive must contain `pgadmin/` at its root, so restore
  places the profile at `/srv/homelab/data/pgadmin`, mounted at `/var/lib/pgadmin`.
  Verify the existing profile database and saved server definitions before start.
  No owner normalization is part of this addition. The bind refuses to create a
  missing source directory; archive completeness still needs operator inspection.
- Preserve the existing `PGADMIN_CONFIG_AUTHENTICATION_SOURCES=['oauth2']` and
  full `PGADMIN_CONFIG_OAUTH2_CONFIG` Python-literal string, including provider
  name, client ID/secret, endpoints, scopes and any claim restrictions. The
  renderer checks the OAuth2-only list and the confidential client fields; it
  does not validate the client against Authentik. It escapes literal dollar signs
  for Compose without rewriting the provider. Additional config mounts and an
  alternate config-distro path are deliberately unsupported by this narrow kind.
- Retain the container's required bootstrap environment, SMTP settings and proxy
  settings from the source. Do not interpret the default bootstrap password as
  an enabled local login: `internal` remains absent from authentication sources.
  Keep the existing master-password policy and saved-password handling.

The [pgAdmin container documentation](https://www.pgadmin.org/docs/pgadmin4/latest/container_deployment.html)
describes environment syntax, persistent profile storage and proxy header counts.
Check those details against the retained image version; current documentation
does not prove compatibility with an unidentified older image.

## Component contracts

| Owner | Contract for this path |
| --- | --- |
| db-tools | One pgAdmin service at `http://<backend-ip>:80`; no Docker labels or cross-guest Docker socket. |
| Traefik | File-provider route for every retained pgAdmin hostname, TLS and Host preservation, with the existing LAN middleware chain. Do not attach Authentik forward-auth to pgAdmin. Forward the correct external scheme and host using the retained proxy settings. |
| Authentik | Restore the existing OAuth provider/application, client ID/secret, bindings, flows, signing material and redirect allowlist. Keep identity routes accessible without their own forward-auth loop. No provider creation or credential rotation is required by this source change. |
| PostgreSQL | Admit the intended endpoint/database/role and network access separately. pgAdmin's OAuth identity does not grant PostgreSQL privileges. |
| Private CD | Add `db-tools` to the existing guest selector and merge-trigger mapping, and pin the reviewed public revision after integration. Use `/var/lib/homelab-inputs/db-tools.json` and the existing stack input, plan/start/verify path; no separate executor. |

The [Authentik pgAdmin integration](https://integrations.goauthentik.io/infrastructure/pgadmin/)
uses `https://<pgadmin-host>/oauth2/authorize` as the authorization callback.
Preserve each existing callback exactly. In Authentik versions before 2026.5,
retain the old redirect representation; do not import newer logout-URI semantics.
This change does not modify the ingress renderer or Authentik implementation.

## Native acceptance, performed by the deployment owner

Prerequisites: PostgreSQL server, separate Authentik database restore, retained
Authentik/Redis and Traefik have each reached their own acceptance gate. Confirm
the pgAdmin image identity, profile capture, owner IDs and private inputs above.
Keep original data and failed evidence. No production action is authorized by
this document.

1. Review the selected guest plan, backend address and access rules. Permit
   Traefik to reach pgAdmin on TCP 80, pgAdmin to reach the admitted PostgreSQL
   endpoint on TCP 5432 and Authentik's retained HTTPS endpoint, plus the already
   approved DNS, package and image access. Check actual bridge/container traffic;
   these access paths are proposed inputs until admitted by the deployment owner.
2. Retire the old pgAdmin writer, confirm the coherent capture and use the shared
   `plan`, `deploy` (or staged `apply`, `stage`, `start`) path. Record the source
   revision, plan/capture/image hashes and guest identity privately. Confirm the
   restored profile is present and the backend listener responds. A private
   `health_checks` probe can use `curl --fail --silent --max-time 10
   http://<backend-ip>/misc/ping` expecting `PING`; check that route on the pinned
   image. This is HTTP liveness only.
3. From the permitted client network, open a fresh browser session at each
   retained HTTPS hostname. Check TLS and the existing LAN access restrictions.
   A client outside the allowed network must remain denied. Observe the pgAdmin
   OAuth button or existing automatic OAuth redirect and absence of local login.
4. Sign in as an existing allowed Authentik user. Confirm the same client/provider
   is used and the authorization request's `redirect_uri` matches the retained
   HTTPS hostname plus `/oauth2/authorize`. Confirm return to that pgAdmin origin,
   the expected pgAdmin user and existing profile/server tree, with no callback
   loop or forwarded-header error. Repeat for the other hostname if it is a
   supported entry point; do not widen callbacks to make an unapproved alias work.
5. In the pgAdmin browser, connect to the admitted PostgreSQL server using the
   intended existing role and the retained TLS policy. If a saved endpoint must
   change, let the owner explicitly approve that profile edit. Open Query Tool
   against the approved database and run only:

   ```sql
   SELECT current_database(), current_user, inet_server_addr(),
          inet_server_port(), current_setting('server_version');
   SELECT 1 AS connection_ok;
   ```

   Match the database, role, address/port and expected server version to the
   owner's admission record. Do not infer this from container liveness or a
   successful OAuth login. Enter credentials privately; do not export a password
   or change the master-password policy to bypass a saved-password problem.
6. Log out, then verify a new unauthenticated visit cannot access the pgAdmin
   browser or saved server details. Confirm a separately selected Authentik user
   outside the existing provider policy is denied, without altering bindings.
   Record whether logout also ended the IdP session; retain existing SSO semantics.
7. Record separately: source checks, backend HTTP, each hostname's TLS/callback,
   allowed/denied users, profile preservation and PostgreSQL query result. Use
   timestamps and redacted observations; never store client secrets, cookies,
   authorization codes, tokens or raw HAR exports in the evidence. Leave any
   missing observation unverified. Failure holds remain in place for owner review.

These observations qualify the native pgAdmin OAuth path and one database
connection. Node-RED's forward-auth flow requires separate acceptance.
