# Application deployment: technical reference

[Beginner walkthrough](README.md) · [Proxmox overview](../README.md)

## One guest, standard tools

`tofu/` manages one protected, unprivileged Debian LXC and its guest firewall,
using OpenTofu 1.13.1 and bpg/proxmox 0.117.0. The local backend locks active
state on the sole private runner. No PostgreSQL backend is needed. GitHub jobs
share bootstrap's global deployment concurrency group; a process lock also
prevents competing application jobs. Never run another active state copy.

The guest starts so Ansible can reach SSH; this does not start the restored
applications. On initial creation the provider starts it before the following
guest-firewall resources are installed. Admit that initial SSH window only on
the selected trusted network, after checking the datacenter firewall. If that
window is unacceptable, select `started: false`; the guest then needs a separate
reviewed start plan after firewall creation. Do not bypass this with a manual
boot or treat interface `firewall: true` as proof the full firewall is active.
Use `start_on_boot: false` for rehearsal until boot behaviour is
accepted. Proxmox protection, `prevent_destroy` and the saved-plan checker reject
replacement/deletion. The old staging framework and bootstrap guard are unchanged.

## Private inputs

Copy [site.example.json](examples/site.example.json) into the runner's private
input directory. Replace invented values. Secrets/captures stay outside Git,
files mode 0600 and directories 0700.

| Input | Meaning |
| --- | --- |
| `site` | Verified Proxmox node and trusted HTTPS API endpoint |
| `guest` | One ID, hostname, resources, template/storage, NICs and firewall allowances |
| `ssh_public_keys` | Deployment public key; private key stays on the runner |
| `paths` | Existing token, CA, deployment key, verified known_hosts, state, NAS recovery paths and exact `backup_source` mount identity |
| `app` | Same guest identity, selected kind, exact packages, health probes and an application capture where required |

Kinds: `dns`, `mariadb`, `postgresql`, `influxdb`, `identity`, `ingress`,
`automation`. Final IDs/addresses/VLANs are private site choices, not reserved
by examples. Declare all required traffic: runner SSH, DNS/time, downloads,
database clients, proxy, MQTT, callbacks and device/discovery traffic. The guest
firewall drops everything else. Host/router rules are not changed. Select IPv6
explicitly where needed; IPv4-only tests do not prove Matter/HomeKit.

For the API-token deployment route, use `nesting: true` and `keyctl: false`
for a Docker application guest. Proxmox permits a token to enable nesting on an
unprivileged container; enabling other feature flags requires a root session.
The isolated rehearsal has proved guest creation with nesting alone. Docker
runtime qualification is still separate; do not add root credentials to the
runner to work around a rejected feature flag.

Review actual guest lifecycle, API access and network changes before a native
run. A valid plan alone does not authorize them. Bootstrap must first declare
the selected application's token access through its normal configuration
command. Deploy grants no additional permissions. NAS recovery and strict guest SSH trust must be in
place first; there is no local-backup or insecure-SSH fallback.

### Application captures and images

`app.capture` contains `path`, `sha256`, `coherent`. The tar archive is rooted at
the contents of `/srv/homelab/data` on the new guest: `homeassistant/config`,
`node-red/data`, `node-red/config`, `mqtt/config`, `mqtt/data`, `mqtt/log`, or
equivalent DNS/identity/proxy directories. Include private settings, HACS,
custom components and preserved helpers. Capture coherent frozen files; these
scripts do not capture or stop the old system automatically.

The data disk is mounted at `/srv/homelab`; restored applications use its
`data` subdirectory. A new formatted disk can already contain a filesystem
recovery directory such as `lost+found`. Leave that directory untouched;
restore still requires the application destination itself to be empty.
Use `/srv/homelab/data` for an explicit stack `data_root` and captured extra
mounts. Do not move an already restored installation by changing this setting.
This release accepts only the child-directory layout. An older experimental
restore at the disk root needs a separately reviewed migration; changing the
renderer setting cannot move its data or update its restore receipt.

Restore checks hashes, paths/links, empty destination and the prior receipt.
GNU tar restores numeric owners, modes, ACLs and xattrs. **Any tar warning holds
the restore**, including unsupported metadata. Do not strip ACLs or recursively
chown data merely to make it pass.

The stack examples pin images by registry digest. For a custom HA/Node-RED image
without a registry digest, supply its exact `sha256:…` image ID, `archive` and
`archive_sha256`. Ansible hashes the frozen `docker save` archive, loads it and
checks that exact ID. It never replaces it with a vendor tag. Automation inputs
can preserve `command`, `entrypoint`, `user` and selected helper mounts.

New stacks default to `restart: no` during qualification, so a failed first
start does not become an automatic retry loop. Select `restart: unless-stopped`
explicitly in the reviewed private service inputs after accepting its ongoing
restart/boot behaviour. That change follows a fresh plan and explicit start.

The renderer does not grant privileged mode, expose Docker control sockets,
restore the broken Avahi socket mount or move radios. Bluetooth/DBus hardware
access is not covered by this initial guest definition.

For an existing HA image whose entrypoint runs `/startup/mdns-route.sh`, retain
its helper mount at `/srv/homelab/data/ha-startup:/startup:ro` and set the selected
guest address in `HOMELAB_HA_IPV4`. Ansible backs up that helper and installs the
parameterised equivalent, retaining its IPv4/IPv6 multicast routes. Its only
supported optional capability is an explicit `cap_add: [NET_ADMIN]` for HA,
confined to this new automation guest's network namespace. Review that network
administration grant in the concrete native guest/start decision. It is not
enabled by the example or granted to other services. The address must belong
to a declared guest interface; missing IPv4/IPv6 routing fails startup.

### Existing-version Authentik

Use the `identity` stack for the existing Authentik server, worker and Redis.
Server and worker must select the same pinned image. Retain the installed version;
this path does not upgrade Authentik or create OAuth/proxy providers. The restored
PostgreSQL database retains users, flows, provider/client secrets and outpost
configuration. Restore it separately before starting this guest, and keep its
original `AUTHENTIK_SECRET_KEY` in the private `authentik_secret_key` input.

Supply the existing database credentials in the top-level PostgreSQL inputs.
The renderer sets both modes to that database and the stack's internal `redis`
host. Preserve other private `AUTHENTIK_*` settings, including SMTP, in each
service's `environment`. Dollar signs are escaped for Compose and arrive intact
inside the containers. Do not copy a new-install bootstrap password/token into a
restored deployment. Keep existing external hostnames, callbacks and proxy
settings; login acceptance belongs to the restored integrations.

The capture archive must contain `authentik/media`, `authentik/templates`
(the original custom-templates contents), `authentik/certs` and `redis` at its
root. Server and worker share media/templates; only worker mounts certs. Preserve
numeric owners, modes, ACLs and xattrs. Identity services accept an explicit
captured `user`; no permission repair or Docker socket is added. Redis accepts
its captured `command` as a string, argv list or null, so its persistence mode
can match the capture; omission retains the previous append-only default. Record
its exact image and persistence command before binding real private inputs.

Server/worker wait for Redis to answer `PING` with `PONG` on its default local
port without authentication, matching the [2025.2.1 upstream Compose
contract](https://github.com/goauthentik/authentik/blob/version/2025.2.1/docker-compose.yml).
A Redis setup with a different port or authentication needs a reviewed matching
probe before use. Redis has no published guest port. Authentik retains the
image's mode-aware `ak healthcheck`; Compose `up --wait` checks both modes, rather
than considering a running container sufficient. PostgreSQL is external to this
stack: it is neither created nor restored by Compose.

Require private read-only probes for server readiness and worker/Redis health.
Then check a real existing login, the embedded outpost/Node-RED forward-auth
path, and pgAdmin's OAuth callback separately. Startup/config tests do not prove
those integrations, TLS, SMTP delivery, Docker inside the native LXC, or restored
file access. No test email is sent by this path.

### Native databases

`app.database` supplies `user`, `group`, `uid`, `gid`, `home`,
`version_command` (argv), `version_pattern` (required literal substring),
`config_files` (`source`, `destination`). Database CD does not take `app.capture`,
`app.database.capture` or restore credentials; legacy capture inputs are refused.
It uses the same plan/deploy/identity/stage/start/verify pipeline as other guests.
Stage installs the configuration without starting the server. Start enables and
starts the selected native systemd service; Verify runs the private server health
probes. No application database, login, grant or backup is imported by CD.
Exact vendor packages/clients belong
in `app.packages`. Supply reviewed deb822 sources with ASCII-armoured key files
and SHA256s in `app.repositories` when Debian packages do not match. Each source
must name its explicit Signed-By path. There is no silent database downgrade.

Use server-only probes in `app.health_checks`: for example MariaDB's local
administrative `SELECT 1`, PostgreSQL's `pg_isready` plus a local `SELECT 1`, and
InfluxDB's `/health` endpoint. An uninitialised InfluxDB server is not proof of
restored organisations, buckets or tokens. Real client access is accepted after
the separate restore. Configure the selected data directory and its persistent
guest storage before deployment; do not assume a backup is active merely because
OpenTofu state has NAS recovery copies.

For a **new empty MariaDB guest only**, `account_mode: package` uses the `mysql`
user/group created by the signed native package. Supply `user: mysql` and
`group: mysql`, and omit `uid`/`gid`; the script never guesses new numeric IDs or
renumbers an existing account. It records the actual IDs and refuses drift on
repeat. The default `account_mode: fixed` retains the existing numeric-identity
guards, including for PostgreSQL and InfluxDB. This exception does not admit a
raw old-data bind or filesystem-level restore. The later logical SQL restore
preserves database usernames/passwords/grants separately from Linux file owners.

### Manual database restore

This is a separate, deliberate migration action inside the selected guest,
**never a CD step**. Keep the old writers stopped for the final coherent capture
and restore. Preserve its original recovery copy and checksum. Verify the
restored users, grants, known data and application login before application CD.

The existing `database.py`, `pg_clean.py` and `restore.py` helpers remain in this
repository for that step; server CD neither installs nor invokes them. If using
the helper, copy these three files from the same reviewed source revision into
`/opt/homelab-app` in the selected guest (root-owned, directory/files mode `0700`).
Privately copy the checked input to `/opt/homelab-app/database.capture`, mode `0600`.
Prepare a root-owned mode `0600` `database-restore.json` with `kind`,
`exclusive_writer_confirmed: true` and `capture` containing `sha256` and `format`,
plus the engine-specific settings below. Then, from that guest's trusted
administrator session, run:

```sh
python3 /opt/homelab-app/database.py --config /opt/homelab-app/database-restore.json
```

The helper retains its persistent incomplete-attempt hold and exact capture
receipt. Do not remove a failed receipt or repeat a partial restore automatically.
Restore approval, final backup and application acceptance remain operator tasks.

MariaDB uses `kind: mariadb`, `format: sql` and restores SQL through its local root socket. PostgreSQL uses
`kind: postgresql`, `user: postgres`, `format: pg-dumpall-clean` and the
[existing clean restore contract](../../services/database-backup/POSTGRESQL-CLEAN-RECOVERY.md).
Provide unchanged uncompressed SQL from that selected archive, retaining the
original archive separately. A unique local maintenance superuser/database
imports it without rewriting SQL. Only the exact ordered protected-bootstrap
DROP/duplicate-CREATE diagnostics are accepted; all other errors/client failure
hold the target. Bootstrap OID 10 is checked, then only those temporary objects
are removed. Native confirmation still needs the retained account/grant/data
comparisons and real credential checks. A raw Docker data directory is not an input.

InfluxDB uses `kind: influxdb` and expects a tarred **v2 native backup directory**, `format: influx-v2`.
Supply the source `influx_operator_token` and private setup
`influx_username`, `influx_password`, `influx_org`, `influx_bucket`.
The original token is used for setup and full restore, following
[InfluxDB's procedure](https://docs.influxdata.com/influxdb/v2/admin/backup-restore/restore/).
Setup credentials go through the local HTTP setup API body; the restore token
uses the CLI's supported environment variable, never argv. Supply the captured
`source_version` as well; this helper admits only pre-2.9 v2 backups. A 2.9+ hashed-token
backup needs its exact supported CLI/token procedure and is not automatically
admitted by this initial helper.

Vendor package post-install behaviour, cluster layout and native recovery
remain **unqualified until exercised on the selected LXC**. Source tests do not
certify a real dump. Failed restore receipts and partial targets stay held.

### Proxy and login

Restore Traefik static configuration/certificates under `traefik/`. Its file
provider must watch `/etc/traefik/dynamic`, with a `websecure` entrypoint and the
restored certificate. Generated routes go into `dynamic/homelab-applications.yml`.
Prepare that directory and remove conflicting routes in the private capture.
No certificate or Cloudflare credential is requested/copied implicitly.

HA uses its own login. Node-RED gets Authentik forward auth and an unprotected
outpost callback route following the
[Authentik pattern](https://docs.goauthentik.io/add-secure-apps/providers/proxy/server_traefik/).
Restrict Node-RED's backend port to the proxy/explicit administration; SSO does
not protect a separately exposed backend. Restore its existing provider/outpost
and verify login. The installed Authentik version's PostgreSQL and Redis
dependencies are retained. Restore HA's exact trusted proxy settings using
the [HA HTTP guidance](https://www.home-assistant.io/integrations/http/).

## Workflow commands

Run on the selected private runner using its pinned tools, not as workstation
failover commands:

```sh
python3 proxmox/applications/deploy.py plan --site /var/lib/homelab-inputs/automation.json
python3 proxmox/applications/deploy.py deploy --site /var/lib/homelab-inputs/automation.json --plan-sha256 REVIEWED_PLAN_SHA256
python3 proxmox/applications/deploy.py verify --site /var/lib/homelab-inputs/automation.json
```

`deploy` is for a new, unapplied guest. It runs apply, identity, stage, start and
verify under one workflow lock. For application guests it first checks coherent
capture hashes and archive safety; select the migration window and set
`exclusive_writer_confirmed: true`. Database-server deployment needs neither a
capture nor retirement of the original database: it prepares an empty server.
The saved plan must create the database guest: updates, no-ops and older plans
without that creation evidence are refused by database Deploy. The manual
restore and application cutover come later. Individual
apply/stage/start commands remain available for separately reviewed qualification
and partial-installation recovery. They do not bypass an interrupted rollout's
`ROLLOUT-HOLD.json`. Existing installations use verify; Deploy does not reinstall
them or replay a saved plan.

Source/site hashes and private configuration/CA-file hashes bind the saved
plan; changes require a fresh plan. Starting an application guest
requires `exclusive_writer_confirmed: true` after the selected cutover decision
and retirement of old writers. Stage does not need it. HA can operate real
devices even if its data is a copy: do not start it casually for rehearsal.

`app.health_checks` contains reviewed read-only argv arrays, names and expected
output. Define real DNS/database/MQTT/HTTP probes. Success is service evidence,
not physical household acceptance. Plans, logs and state stay private; the
driver prints compact results. Missing NAS recovery blocks execution. A failed
mutation leaves `HOLD.json`; review closure/state before any corrected attempt.

Deploy verifies guest SSH keys **after creation**, before the first Ansible step.
The current token reads its own successful `vzcreate` task over the pinned
Proxmox TLS route. Its node, guest ID, creator and time must match the reviewed
apply window. The Ed25519 fingerprint in that task must match the key scanned
from the address assigned to the selected guest MAC. Missing, ambiguous or changed
evidence holds the run; it never falls back to trusting the scan alone. No new
host permission or Proxmox root SSH key is required.

Only the verified guest entry is appended to the private known_hosts file;
existing pins are preserved. Adding an unrelated guest does not invalidate an
earlier plan. Legacy separately staged guests can still receive their exact key
through the trusted Proxmox administrator route. SSH uses only the declared
key/trust file and direct route, without agent, global trust, DNS-trust or proxy
fallback. Automatic first-creation verification requires the Proxmox creation
log format above; an incompatible or expired log needs review.

## Offline source tests

From the repository root, with Docker running:

```sh
docker build --platform linux/amd64 -t homelab-app-test -f proxmox/bootstrap/docker/Dockerfile proxmox/bootstrap/docker
docker run --rm --platform linux/amd64 --network none --cpus 2 --memory 2g --tmpfs /tmp:rw,exec,nosuid,nodev,size=768m,mode=1777 -v "$PWD:/src:ro" -e HOME=/tmp homelab-app-test sh /src/proxmox/applications/tests/check.sh
```

Tests use invented inputs, the real provider schema/mock plans, Ansible syntax
and GNU tar with UID/GID/mode/ACL/xattr readback. CI also runs Docker Compose's
parser for all four stacks. Public jobs receive no deployment credentials and
never reach private runners or a Proxmox host.
