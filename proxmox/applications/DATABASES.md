# Prepare database servers, then bring the data across

[Application guide](README.md) · [Technical reference](OPERATIONS.md#native-databases)

When Home Assistant uses MariaDB for its history, that server must be ready
before HA starts. Authentik needs PostgreSQL; that login service is used by Node-RED. InfluxDB holds time-series history and metrics.
Each database gets its own small LXC. These are native database services inside
the guest, rather than more containers in the deployment guest.

The same GitHub deployment workflow creates and configures one database guest
at a time. **Database CD installs, configures, starts and checks an empty server.
It does not restore backups or create application databases, logins or grants.**
There is no extra bootstrap script and no need to reinstall Proxmox.
The deployment guest needs access to each new guest through the existing
[bootstrap application setup](../bootstrap/README.md#8-prepare-the-runner-to-deploy-your-applications).

## What is ready?

The install and restore scripts exist for all three databases. Preparation uses
matching database versions, rather than upgrading the database during migration:

| Database | Selected version | Preparation and test boundary |
| --- | --- | --- |
| MariaDB | 12.3.3 | Matching signed Debian packages found; synthetic full SQL restore fixture checks rows, restored accounts/grants and an application login |
| PostgreSQL | 16.10 | Matching signed Debian packages found; synthetic clean SQL restore checks rows, ownership, grants and removal of its temporary restore account |
| InfluxDB | Server 2.7.12, CLI 2.7.5 | Synthetic full backup restore/query passed with exact matching binaries; current official package/key retrieval is blocked. Do not substitute a newer version silently |

These Docker fixtures are useful confidence checks. **They do not mean a database
LXC has passed a full GitHub deployment or that household data has migrated.**
They do not test systemd startup or a real application's connection to its new
server. Keep that distinction when reporting a successful test.

## Two separate steps

| Step | What it does | What a successful result means |
| --- | --- | --- |
| Database CD | Creates the LXC, installs the selected database version and configuration, starts it and checks server health | The server is ready for the separate restore; the application's data has not migrated |
| Manual migration | Restores the existing databases, accounts and grants, then checks an application login and known data | The selected application can use its restored database |

Keep the old database working while preparing the empty server. Stop its writers
at the migration window before taking the final coherent backup and restoring
it. Deploy the application only after the restore has been checked. Applications
may then perform their usual schema upgrades; do not assume every application
can create its own database and login.

Database CD does not receive `app.capture`, `app.database.capture` or restore
credentials. Old capture inputs are refused rather than silently ignored. Its
health probes check the server itself, without requiring restored household rows.
It never runs the restore helpers. Subsequent verification is read-only; the
installer refuses to redeploy an already applied guest.

## What happens next?

1. Finish the DNS deployment so the next guests have working name resolution.
2. Choose one unused database guest ID/address, its resource budget and the
   permitted client addresses. Add its access through bootstrap, then review the
   OpenTofu plan. Start with MariaDB because Home Assistant uses it.
3. Run **Plan**, review its fingerprint, then **Deploy** through the existing
   application workflow. It creates and checks the empty database server.
4. Separately practise a restore with synthetic data and query it using a restored
   application account. That restore is not part of CD.
5. Near the real migration, stop the old writers, take a coherent current backup
   and confirm its recovery copies. Manually restore the database, users and
   grants, then check the application's login and known data before starting it.

The existing one-time restore helpers remain available for the separate migration;
see the [manual restore reference](OPERATIONS.md#manual-database-restore).
Fresh household backups can wait until the migration window. The isolated test
needs no private household rows. It still needs a real admitted LXC to prove the
full deployment and startup path.

## Preserve file owners

The database account must retain the selected numeric user and group IDs.
The scripts refuse numeric identity changes and ID collisions before creating
anything. A reused account can still receive the configured home and shell;
review those private settings before deployment. For example, if a template already uses the required MariaDB group ID
for `systemd-journal`, stop and choose a compatible fresh template. Do not
renumber the template's existing account to make the test pass.

## Repeat the local confidence checks

This section is for contributors checking the scripts. It is not an installation
step for your Proxmox host. You need Python 3 and Docker on your development
computer, an internet connection and roughly 2 GiB available for one fixture.
Run the following from the repository's top folder, one after the other:

```sh
python3 proxmox/applications/tests/native_package_fixture.py mariadb --evidence .work/db-mariadb
python3 proxmox/applications/tests/native_package_fixture.py postgresql --evidence .work/db-postgresql
```

Use a new evidence folder for each run; existing evidence is never replaced.
The fixture installs exact packages in a limited disposable Debian container,
checks its pinned vendor signing key, then disconnects networking before
starting synthetic databases. It exposes no ports and mounts no host folders or
devices. It removes only the container it created and retains the result/logs.

A pass checks the real restore helper with native database binaries. Its systemd
calls are intercepted because ordinary Docker cannot prove LXC service startup.
For InfluxDB, retain the package retrieval failure and resolve it before adding
a similar installation claim. Do not bypass signature checks or use an
unreviewed mirror.
