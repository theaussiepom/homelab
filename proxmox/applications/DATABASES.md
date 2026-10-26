# Bring the databases across safely

[Application guide](README.md) · [Technical reference](OPERATIONS.md#native-databases)

Home Assistant needs MariaDB for its history. Authentik needs PostgreSQL; that
login service is used by Node-RED. InfluxDB holds time-series history and metrics.
Each database gets its own small LXC. These are native database services inside
the guest, rather than more containers in the deployment guest.

The same GitHub deployment workflow creates and configures one database guest
at a time. There is no extra bootstrap script and no need to reinstall Proxmox.
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

## What happens next?

1. Finish the DNS deployment so the next guests have working name resolution.
2. Choose one unused database guest ID/address, its resource budget and the
   permitted client addresses. Add its access through bootstrap, then review the
   OpenTofu plan. Start with MariaDB because Home Assistant uses it.
3. Test the new LXC with synthetic data first: install the exact packages, restore
   the test backup, and query it using a restored application account.
4. Near the real migration, take a coherent current backup, stop the old writers
   for that database and confirm its recovery copies. Restore and check the
   application before relying on the new database.

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
