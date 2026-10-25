# Application deployment: technical reference

[Beginner walkthrough](README.md) · [Proxmox overview](../README.md)

## One guest, standard tools

`tofu/` manages one protected, unprivileged Debian LXC and its guest firewall,
using OpenTofu 1.13.1 and bpg/proxmox 0.117.0. The local backend locks active
state on the sole private runner. No PostgreSQL backend is needed. GitHub jobs
share bootstrap's global deployment concurrency group; a process lock also
prevents competing application jobs. Never run another active state copy.

The guest starts so Ansible can reach SSH; this does not start the restored
applications. Use `start_on_boot: false` for rehearsal until boot behaviour is
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
| `app` | Same guest identity, selected kind, exact packages, coherent capture and health probes |

Kinds: `dns`, `mariadb`, `postgresql`, `influxdb`, `identity`, `ingress`,
`automation`. Final IDs/addresses/VLANs are private site choices, not reserved
by examples. Declare all required traffic: runner SSH, DNS/time, downloads,
database clients, proxy, MQTT, callbacks and device/discovery traffic. The guest
firewall drops everything else. Host/router rules are not changed. Select IPv6
explicitly where needed; IPv4-only tests do not prove Matter/HomeKit.

Review actual guest lifecycle, API access and network changes before a native
run. A valid plan alone does not authorize them. The existing bootstrap token
cannot create these guests. NAS recovery and strict guest SSH trust must be in
place first; there is no local-backup or insecure-SSH fallback.

### Application captures and images

`app.capture` contains `path`, `sha256`, `coherent`. The tar archive is rooted at
the contents of `/srv/homelab` on the new guest: `homeassistant/config`,
`node-red/data`, `node-red/config`, `mqtt/config`, `mqtt/data`, `mqtt/log`, or
equivalent DNS/identity/proxy directories. Include private settings, HACS,
custom components and preserved helpers. Capture coherent frozen files; these
scripts do not capture or stop the old system automatically.

Restore checks hashes, paths/links, empty destination and the prior receipt.
GNU tar restores numeric owners, modes, ACLs and xattrs. **Any tar warning holds
the restore**, including unsupported metadata. Do not strip ACLs or recursively
chown data merely to make it pass.

The stack examples pin images by registry digest. For a custom HA/Node-RED image
without a registry digest, supply its exact `sha256:…` image ID, `archive` and
`archive_sha256`. Ansible hashes the frozen `docker save` archive, loads it and
checks that exact ID. It never replaces it with a vendor tag. Automation inputs
can preserve `command`, `entrypoint`, `user` and selected helper mounts.

The renderer does not grant privileged mode, expose Docker control sockets,
restore the broken Avahi socket mount or move radios. Bluetooth/DBus hardware
access is not covered by this initial guest definition.

### Native databases

`app.database` supplies `user`, `group`, `uid`, `gid`, `home`,
`version_command` (argv), `version_pattern` (required literal substring),
`config_files` (`source`, `destination`) and coherent `capture`
(`path`, `sha256`, `format`, `coherent`). Exact vendor packages/clients belong
in `app.packages`. Supply reviewed deb822 sources with ASCII-armoured key files
and SHA256s in `app.repositories` when Debian packages do not match. Each source
must name its explicit Signed-By path. There is no silent database downgrade.

MariaDB restores SQL through its local root socket. PostgreSQL restores plain
SQL through its native postgres peer account with `ON_ERROR_STOP`. Prepare SQL
that creates required roles/databases/grants without recreating built-in
postgres/template objects. A raw Docker data directory is not this input.

InfluxDB expects a tarred **v2 native backup directory**, `format: influx-v2`.
Supply the source `influx_operator_token` and private setup
`influx_username`, `influx_password`, `influx_org`, `influx_bucket`.
The original token is used for setup and full restore, following
[InfluxDB's procedure](https://docs.influxdata.com/influxdb/v2/admin/backup-restore/restore/).
Credentials go through environment variables, not argv. A 2.9+ hashed-token
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
python3 proxmox/applications/deploy.py apply --site /var/lib/homelab-inputs/automation.json --plan-sha256 REVIEWED_PLAN_SHA256
python3 proxmox/applications/deploy.py stage --site /var/lib/homelab-inputs/automation.json
python3 proxmox/applications/deploy.py start --site /var/lib/homelab-inputs/automation.json
python3 proxmox/applications/deploy.py verify --site /var/lib/homelab-inputs/automation.json
```

Source/site hashes and private configuration/trust-file hashes bind the saved
plan; changes require a fresh plan. Starting
requires `exclusive_writer_confirmed: true` after the selected cutover decision
and retirement of old writers. Stage does not need it. HA can operate real
devices even if its data is a copy: do not start it casually for rehearsal.

`app.health_checks` contains reviewed read-only argv arrays, names and expected
output. Define real DNS/database/MQTT/HTTP probes. Success is service evidence,
not physical household acceptance. Plans, logs and state stay private; the
driver prints compact results. Missing NAS recovery blocks execution. A failed
mutation leaves `HOLD.json`; review closure/state before any corrected attempt.

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
