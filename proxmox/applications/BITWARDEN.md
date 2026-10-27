# Prepare an existing Bitwarden Lite installation

[Application guide](README.md)

This prepares the **official Bitwarden Lite** application for a later migration.
It renders a reviewable Compose preview and checks three unauthenticated health
responses. Deployment is deliberately disabled. The generic installer refuses
the Bitwarden kind before reading host or credential inputs.

Keep the existing application version and immutable image digest. A migration
is not an upgrade, a new installation, a vault export/import or a move to
Vaultwarden. Bitwarden Lite supports an external MariaDB database through its
`mysql` provider; reuse the matching commissioned native database service.
See the vendor's [Lite guide](https://bitwarden.com/help/install-and-deploy-lite/)
and [database options](https://bitwarden.com/help/database-options/).

## Preview the application

Copy [the synthetic example](examples/bitwarden.stack.example.json) into your
private site repository. Select the exact observed image digest and a proposed
backend address. The example digest is invented and cannot be pulled.

```sh
python3 public-source/proxmox/applications/render.py \
  --config bitwarden/stack.json --output /tmp/bitwarden-preview
```

The preview does not read environment files, contact a server or create a guest.
It reuses the existing renderer's CPU/memory/PID limits and log caps. It publishes
HTTP8080 only on the selected private guest address. Traefik will terminate HTTPS
and discover the future backend from the existing Proxmox Notes mechanism.
Bitwarden keeps its own authentication; review API and notification/WebSocket
paths without adding an Authentik login gate in front of native clients.

The two bind mounts refuse to create missing source directories. The exact image
keeps its own default entrypoint, process identity and healthcheck. Do not add
PUID/PGID, a `user`, alternate image or new security/runtime defaults during this
move without separately proving compatibility with the retained filesystem.

The only credential binding in Compose is the file path
`/opt/homelab-app/runtime/bitwarden.env`. Its future installation must be private
and mode0600. This PR does not install it. Preserve the effective existing
`BW_*`, `globalSettings*` and `adminSettings*` settings, including installation
ID/key, database credentials, certificate password, optional integration keys,
SMTP sender and credentials, feature switches and internal service URLs. Review
only the required target database endpoint change. Never print resolved Compose
or upload that file, logs, private keys or captures to source/Actions artifacts.
Validate dotenv quoting with the target Compose version so `$`, quotes and
backslashes survive exactly. Do not depend on newer `env_file.format: raw`:
the current application package proposal uses Compose2.26.

## Restore inputs to review together

Before any future start, obtain one coherent, privately retained recovery set:

| Input | Required evidence |
| --- | --- |
| Existing `bitwarden_vault` MariaDB database | Reviewed consistent logical dump, schema/table coverage, version, charset/collation, users/grants and checksums; synthetic restore rehearsal first |
| Entire `/etc/bitwarden` tree | Attachments and Send blobs, data-protection keys, identity certificates, licenses and other existing files; file hashes and numeric UID/GID/modes/ACLs/xattrs |
| `/var/log/bitwarden` | Retained privately with metadata; logs may contain personal data |
| Effective runtime configuration | Existing installation/license identity, secrets, SMTP and non-secret settings; safe private custody and an exact before/after comparison |
| Exact image and tools | Immutable registry digest or separately verified archive, matching API version and architecture, selected Docker/Compose package locks |
| New target and recovery destination | Unused VMID/MAC/addresses, NAS protection, empty target paths, approved disk/resource limits and available space |

A recent archive's presence is not proof of consistency or restore usability.
Never replace the server database with a personal vault export: that would not
preserve the full organization, user, settings and installation state.

Database restore is a **separate explicitly reviewed migration operation** to
the selected schema and retained user/grants on the shared native MariaDB
server. It must not drop other schemas or replace MariaDB's entire data directory.
Keep the old writer fenced during the final coherent capture, restore and
cutover. An application startup can write schema or runtime state, so it needs
its own approval after restoration and recovery checks. Repeated ordinary CD
must never replay a restore.

## Proposed CD admission

Use the existing application OpenTofu module, Ansible roles, saved-plan digest,
NAS state recovery, captured SSH host key and failure-hold patterns. Add a
service-specific input/secret adapter only after the inputs above are reviewed;
do not create a parallel deployment controller. That adapter still needs to
bind the runtime environment and capture fingerprints into the retained plan
and receipt, install the env file without logging it, refuse a missing restore
receipt and require the explicit exclusive-writer/start decision.

The future job would depend on the commissioned MariaDB and Traefik services.
Its private proposal stays disabled, outside the existing deployment graph.
Enabling it requires a separate source review and live approval. Commissioned
DNS, database, foundation and automation source pins remain independent.

Failures must retain evidence and stop. No automatic import/adoption, overwrite,
failed native-operation replay, credential rotation or weakened TLS/SSH checks.
If the target accepts writes, switching back requires a reviewed reverse-data
plan; simply restarting the old container would risk losing those writes.

## Health and acceptance

The source helper sends only GET requests to `/api/alive`, `/api/config`, and
`/identity/.well-known/openid-configuration`. It requires HTTP200, the retained
API version and the explicitly selected existing issuer. TLS verification stays
enabled and redirects are refused. It does not unlock, list or sync a vault,
send mail, or authenticate a client.

```sh
python3 public-source/proxmox/applications/bitwarden.py \
  --origin https://vault.example.invalid --version EXISTING_API_VERSION \
  --issuer EXISTING_DISCOVERY_ISSUER
```

An existing localhost issuer must be recorded and reviewed separately; silently
fixing it would change authentication behavior. A health pass does not prove
client login/sync, notification delivery, attachments, organization membership,
settings, licensing, SMTP delivery, physical reboot or Proxmox readiness.
Those remain later supervised acceptance tasks with separate authorization.

The Docker fixture starts only the pinned Lite2026.4.1 and MariaDB12.3.3 images,
on an internal network with disposable volumes, no published ports and synthetic
credentials. It checks initial health, a synthetic attachment across restart and
health after restart. It uses no personal vault data and proves no native
database restoration or live cutover.
