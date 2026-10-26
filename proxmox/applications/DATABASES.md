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
| MariaDB | 12.3.3 | Exact signed packages installed; unchanged full synthetic SQL dump restored from Unix999:999 into the package-created account, with restored users/grants and password login/query passing |
| PostgreSQL | 16.10 | Native LXC/systemd install and local SQL check passed; synthetic clean SQL restore checks rows, ownership, grants and temporary-account removal |
| InfluxDB | Server 2.7.12, CLI 2.7.5 | Exact signed packages installed and empty daemon health/CLI checks passed; synthetic full backup restore/query also passed. Native LXC/systemd startup and backend health also passed |

The Docker fixtures check package and logical-restore behaviour. In addition,
on 26 October 2026 the matching versions of all three empty servers passed a real
private GitHub CD installation on protected, unprivileged Debian 13 LXCs. Native
checks covered systemd active/enabled status, database readiness, local SQL
queries where applicable and each backend TCP listener. InfluxDB remained
uninitialised, ready for its separate restore/setup. No household data or
application accounts were restored.

The initial creation stopped at SSH identity admission because Proxmox reported
a systemd compatibility warning. The approved correction retained the guests,
verified their original SSH fingerprints and completed their installations.
Failed evidence was preserved. This is a successful corrected deployment; a
fresh uninterrupted deployment from the corrected baseline has not been
retested. Autostart is configured and read back; a host reboot after database
installation remains untested.

For this Debian13 base, use `nesting: true`, `keyctl: false` and unprivileged
LXCs. Use fixed management IPv4 plus the fixed private backend address. The
initial management DHCP setup waited for DHCPv6 and delayed the backend
interface on two guests; the tested fixed-address setup avoids that wait.

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
   OpenTofu plan. PostgreSQL comes first when preparing Authentik; MariaDB
   underpins HA history. InfluxDB can be prepared independently.
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
needs no private household rows. The empty-server native checks above do not replace the later restore and
application-connection checks.

## Preserve file owners

The default fixed-account setup retains the selected numeric user/group IDs
and refuses collisions. For a new empty MariaDB guest, explicitly selecting
`account_mode: package` lets the native package create its own `mysql` account.
The script records its actual IDs and refuses later changes. This avoids the
old Docker999 conflict with Debian's journal group without renumbering either
old data or an existing account. It does not permit attaching old raw data.
Database users/grants restored from SQL are separate from those Linux file IDs. A reused account can still receive the configured home and shell;
review those private settings before deployment. If fixed mode's required ID
belongs to another account, stop and select compatible inputs. Do not renumber
the template's existing account to make the test pass.

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
InfluxDB's earlier package retrieval failure has been preserved. Its exact signed
packages and empty daemon have since passed an isolated check. That slim Docker
root produced service-install script warnings; the subsequent native LXC test
separately verified real systemd startup. Do not bypass signature checks or use
an unreviewed mirror.
