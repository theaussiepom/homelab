# Move an existing Bitwarden Lite installation

[Application guide](README.md)

Use the existing application OpenTofu module, saved-plan approval, Ansible
capture restore, NAS recovery copies, SSH trust and failure holds. Bitwarden's
adapter supplies private inputs to that installer; it never restores MariaDB.
The database runs separately on the existing shared native MariaDB service.

## Latest image and preserved installation

Use `ghcr.io/bitwarden/lite:latest` without a version or digest pin. Update the
existing installation first, check web vault and client sync, and record its
resolved image ID. The move must use that checked image: Ansible pulls the
selected reference and checks its actual image ID before startup. Compose then
uses the checked local image without another pull. If `latest` has advanced
since the source was verified, stop and review it rather than combining another
upgrade with the move. The image ID records the migration evidence; the image
reference remains `latest`.

Preserve the effective `BW_*`, `globalSettings*`, `adminSettings*`, PUID/PGID and
any existing TZ values. The private runtime JSON file supplied with `--runtime-file` must match the
reviewed source-environment hash. The environment binding
`BITWARDEN_RUNTIME_JSON` is also supported, but only one input source may be
selected. The private workflow uses the existing recovery file and creates no
new GitHub runtime Secret. Only `BW_DB_SERVER` changes to the
reviewed private native MariaDB endpoint. Preserve installation ID/key, schema,
database credentials, certificate password, optional integration keys, SMTP,
feature switches, internal URLs and the current public hostname.

Set PUID/PGID explicitly to the source data's numeric owner. Image defaults can
change across upgrades. The adapter refuses an absent or mismatched UID/GID so
startup cannot silently change restored ownership. Keep the image's default
entrypoint; do not add a Docker `user` override.

The generated private stack and Compose files are mode 0600. The source runtime
file must also be owned by the runner and mode 0600. A selected shared network
contract is fingerprinted in the expanded site input and the common saved-plan
input set; every phase refuses raw contract drift. Values are passed
as an environment mapping with literal dollar escaping, which works with the
selected Compose 2.26 package. No dotenv reparsing is needed. Never print resolved
Compose, runtime JSON, captures, database dumps, private keys or application logs
in GitHub jobs or upload them as Actions artifacts.

## Concrete packet and admission

Copy [the disabled synthetic packet](examples/bitwarden.deployment.example.json)
to private source. The packet has the complete common-installer site and stack,
an `enabled` flag and an exact `approved_plan_sha256`. An ordinary source check
can inspect missing inputs without credentials or native access:

```sh
python3 public-source/proxmox/applications/bitwarden_configuration.py \
  --config bitwarden/deployment.json
```

Before enabling native preflight, review these inputs together:

| Input | Required evidence |
| --- | --- |
| New separate guest | Unused VMID/MAC/addresses, exact resource/disks, existing trusted API/SSH credentials and NAS recovery destination |
| Final database checkpoint | Writer-fenced consistent selected-schema dump, verified hashes/table coverage and isolated restore proof; no unrelated schemas or server data directory |
| Complete file capture | All of `/etc/bitwarden` and `/var/log/bitwarden`, including attachments/Send, keys, certificates and licenses; hashes and numeric ownership, modes, ACLs and xattrs |
| Private environment | Exact retained source values and reviewed database endpoint delta; no secret rotation |
| Native restore receipt | Reviewed restore on the shared MariaDB, schema/data validation and retained account definition (v2); exact capture, environment, image and backup bindings |
| Access/route receipt | Bootstrap grant, discovery scope, ingress backend allowance and reviewed DNS/TLS plan for this exact guest/backend/public origin |

A live backup checkpoint is not the final coherent cutover capture. Fence the
old writer for the final database/filesystem recovery set, restore and new
application start. An application start can migrate the schema or write state.
The DB restore is a separate authorized operation; ordinary CD never executes it.
The adapter reads exact private restore/access receipts and identical NAS copies,
with their hashes bound into the saved plan. It does not manufacture their checks.
The receipt formats are closed contracts in `bitwarden_migration.py`.

The source-restricted account cannot be tested from an absent guest. The v2
restore receipt therefore attests the account definition before creation.
After creation, staging uses the reviewed Debian MariaDB client to run a bounded
read-only `LIMIT 0` query against the restored Cipher table from the actual guest
with its retained account. No vault rows are returned. Failure stops the rollout
before Bitwarden starts. A successful private query proof is bound into the
completion receipt and mirrored to NAS; verification repeats the actual query.
Never broaden the account host restriction to the runner to bypass this gate.

After the inputs and prerequisites are reviewed, the adapter calls the common
installer. First select `plan` with no old approval. Review its exact new-guest
saved plan, then supply that fingerprint for `deploy`:

Use `bitwarden_cd.py` for every Bitwarden phase. The public `deploy.py` CLI
rejects Bitwarden to preserve the adapter's hold, proof and completion records.
The adapter still calls the same internal installer; other application CLI
entry points retain their existing behavior.

```sh
python3 public-source/proxmox/applications/bitwarden_cd.py \
  --phase plan --config bitwarden/deployment.json
# After reviewing and admitting that saved plan in the private packet:
python3 public-source/proxmox/applications/bitwarden_cd.py \
  --phase deploy --config bitwarden/deployment.json
```

The adapter refuses incomplete/different existing runtime inputs, old saved
state, adoption and failure holds. A failed or interrupted operation retains its
hold and evidence; it must not be automatically replayed. Completed deployment
receipts are mirrored to NAS. Subsequent runs verify that exact installation
rather than restoring/recreating it. A rollback after target writes requires
reviewed reverse-data treatment; restarting the old container can lose writes.

## Startup policy after migration

Admitted deployments default to `unless-stopped`. The disabled preparation
preview retains `no`, and explicit legacy `no` inputs remain readable so an
existing installation's saved plan and receipts need not be rewritten.

For an already completed installation with `no`, use a separately reviewed
`homelab-bitwarden-startup-v1` packet through `foundation_maintenance.py` in the
same permanent Bitwarden job. Bind the reviewed helper revision, original
deployment revision, VMID, saved-plan and completion hashes, retained public
origin, and observed full container ID, image ID and configuration/mount
fingerprint. The image ID is observation evidence; keep the configured image
reference at `ghcr.io/bitwarden/lite:latest`.

The driver requires the original committed deployment configuration, private
inputs, completed receipts, database-query proof, existing SSH trust and matching
NAS custody. It refuses every existing operation/verification hold. Hold
disposition requires separate review; this packet cannot clear one. The sole
guest mutation is `docker update --restart unless-stopped` on that exact running
container. It never starts, restarts, pulls, recreates, stages or restores it.
Configuration, environment, mounts and all original migration records remain
unchanged. A stopped container or identity/configuration drift stops admission.

Exclusive local/NAS claims and the shared continuation hold preserve interrupted
or failed attempts without automatic retry. After completion, the same packet
only observes the desired policy and exact identity. Later pushes continue
through the original installation's normal read-only verification. Keep this
maintenance selection inside its existing job rather than adding a second
deployment path or retiring the normal job.

```sh
python3 reviewed-helper/proxmox/applications/foundation_maintenance.py \
  --packet bitwarden/startup.json --source original-deployment-source \
  --config bitwarden/deployment.json
```

The policy fixes automatic startup after Docker/host restart; it does not prove a
reboot, public routing or authenticated client acceptance. See Docker's
[restart policy documentation](https://docs.docker.com/engine/containers/start-containers-automatically/).

## Exposure and acceptance

Publish HTTP 8080 only on the selected private backend. The bind mounts refuse to
create missing source directories. Existing Traefik terminates HTTPS and uses
Proxmox Notes discovery. Keep the selected current hostname during the move;
a domain cutover is a separate plan. Bitwarden authenticates its own clients.
Review API and notification/WebSocket routing without adding an Authentik gate.
The existing service-discovery scope and ingress firewall must admit this new
guest before its job can run; a synthetic test cannot supply that authority.

The bounded health helper sends GET requests only to `/api/alive`, `/api/config`
and `/identity/.well-known/openid-configuration`. It requires HTTP 200, an observed
API version and the explicitly retained issuer. Public probes use verified TLS
and refuse redirects. A native guest probe may explicitly use its private HTTP
backend with `--backend`. These checks do not establish web assets, client login,
sync, notifications, attachments, organizations, licensing or SMTP delivery.
Verify the web vault through the real hostname and obtain client acceptance.
Record an existing localhost issuer; do not silently change authentication.

The older [latest preview example](examples/bitwarden.stack.example.json) remains
a source-only rendering contract. It references a future private env file and
cannot enter the native installer without the complete migration admission.
The Docker fixture uses synthetic data only; its health/restart/attachment-file
checks prove neither a real vault restore nor a Proxmox cutover.

See Bitwarden's [Lite guide](https://bitwarden.com/help/install-and-deploy-lite/)
and [database options](https://bitwarden.com/help/database-options/).
