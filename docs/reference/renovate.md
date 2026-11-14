# Mend Renovate Community Edition

The `renovate` adapter runs Mend's self-hosted Community Edition server and worker in one container. It schedules scans of explicitly selected GitHub repositories. Repository configuration selects the dependencies and update policy. The adapter disables automatic merging, admin APIs and startup job enqueueing. It publishes no port; its health check runs inside the container against `/health`. The Enterprise Web UI and inbound webhooks are outside this profile.

Mend CE is distinct from the open-source Renovate CLI. Read [Mend's setup requirements](https://github.com/mend/renovate-ce-ee/blob/main/docs/setup-for-github.md) and [terms](https://www.mend.io/terms-of-service/) before activation. This framework never supplies acceptance or a licence on your behalf. Upstream offers an unregistered CE licence for up to ten repositories; the configured allowlist is bounded to that size.

## Properties and bindings

| Field | Contract and effect |
| --- | --- |
| `apps.<id>.properties.database` | Required object containing `name` and `user`; no extra fields. Both are strings of 1–63 lowercase letters, digits or underscores, beginning with a letter. System names and the `pg_` prefix are refused. These identify the dedicated PostgreSQL database and its restricted owner. |
| `apps.<id>.properties.repositories` | Required list of 1–10 distinct exact `owner/repository` strings. Wildcards, duplicates ignoring case, newlines and extra path segments are refused. These become the server discovery filter. GitHub App installation must separately grant access to exactly the selected repositories. |
| `connections.<id>` | The `database` role must target the declared PostgreSQL app, port 5432, with an explicit guest source interface and `readiness: start`. Both guests must share a context. PostgreSQL is a service dependency; Traefik is not. The connection does not grant firewall access. |
| `apps.<postgresql>.properties.application_database` | Optional closed object `{app: <renovate-id>}`. Omission manages no application database. Presence expressly selects one Renovate consumer on this server; no implicit creation follows from a connection alone. Its database name, user, password source and client address come from that consumer. No arbitrary SQL or administrator account is accepted. |

Each Renovate instance needs its own PostgreSQL-owner selection. The initial contract supports one explicitly managed application database per PostgreSQL app. It does not change the ownership or credentials of Authentik, monitoring or existing databases. The new client receives only its own database/user HBA entry; a conflicting broad client allowance is refused.

## Protected inputs

The Renovate profile requires `accept_terms`, `license_key`, `github_app_id`, `github_app_key` and `database_password`. Bind each through the existing [secret-source contract](identity-and-secrets.md). GitHub environment secrets are delivered only to the selected deployment process, then to its private Compose overlay. The PEM must be one `base64://` scalar; raw multiline values are refused. `accept_terms` must equal `y` at activation, and the App ID must be a positive decimal ID. No real values belong in Git or chat.

The database owner's derived `application_database_password` slot reads the same named source as Renovate's `database_password`. Do not author a second source or put the secret in the PostgreSQL properties. Existing sealed-input continuity rejects ordinary credential changes; this is not a rotation mechanism.

## First installation and updates

Use an unprivileged Docker guest with at least 2560 MiB RAM for the supplied 2048 MiB container limit and operating-system reserve. Bind fresh writable scratch and cache subdirectories owned by UID/GID 12021. The container runs without added capabilities or Docker socket access. Its image must be an immutable `ghcr.io/mend/renovate-ce` tag and digest.

The PostgreSQL phase first checks that both the database and role are absent, or both have the exact retained ownership receipt. Foreign or partial resources refuse installation. It creates a LOGIN/NOINHERIT role without superuser, database-creation, role-creation, replication or RLS-bypass rights, owns only the new database, revokes PUBLIC database access and verifies authentication. The prior sealed app record also refuses replacement of an already owned database/role/consumer or relocation of the Renovate database connection. The first explicit binding on an already owned PostgreSQL app is supported. Repeated deployment verifies ownership, privileges, memberships and the unchanged credential. It never adopts, drops, repairs privileges or resets an existing role. Ordinary phase locks and failure holds remain in effect; preserve failed evidence before recovery.

The ownership receipt under `/var/lib/homelab-databases/` is included in the PostgreSQL backup configuration. The existing native PostgreSQL export covers the new database and role. Renovate's secret overlay is protected configuration; scratch repositories and containerbase caches are rebuildable. Recover the matching PostgreSQL state, ownership record and independently held GitHub inputs. No restore has been established by source tests.

## Verification and limits

The [stack example](https://github.com/theaussiepom/homelab-stack/blob/main/examples/catalogue/renovate.yaml) compiles a complete synthetic server/database pair. Tests cover source refusals, runtime restrictions, secret scope and create-once task wiring. After approved CD, verify `/health`, the database login, a scheduled scan and a real reviewable image PR. Source compilation, mocked native boundaries and a healthy HTTP process do not establish successful repository scanning or recovery.
