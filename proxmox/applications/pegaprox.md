# PegaProx in its own LXC

[Back to application deployment](README.md)

PegaProx gives you another web interface for Proxmox. It does not replace
Proxmox, move your applications, or prove that the house has migrated.
The selected home here is a **separate unprivileged Debian LXC**, independent
of the deployment runner. An LXC is a Linux container managed by Proxmox.
The separate-guest decision was made on 26 October 2026.

**This change prepares a proposal and a Compose preview. It is not an admitted
installer.** No PegaProx guest or credentials are created. `deploy.py` refuses
`app.kind=pegaprox` before reading target or credential inputs. Keep the paired
private PR draft and unmerged until the missing inputs have been reviewed.

## Smallest practical starting point

Propose one LXC, 2 CPU cores, 2 GiB RAM and an 8 GiB root disk. The application
container has a 1536 MiB limit, leaving 512 MiB for Debian and Docker. This is
an initial test budget, not a measured capacity guarantee. Configuration,
plugins and bounded logs fit on the guest disk initially; monitor growth.
There is no shared PostgreSQL, Redis, NAS runtime mount or extra backend NIC.

The [official requirements](https://docs.pegaprox.com/getting-started/requirements/)
are not a single minimum: they give 1 core/1 GB for 1–5 clusters, but recommend
4 cores/8 GB/20 GB for a comfortable production deployment. The official
[LXC example](https://docs.pegaprox.com/getting-started/deploy-premade/) uses
2 cores/2 GB/8 GB. Our smaller starting point still needs real measurements,
a host-capacity check and Ben's acceptance before activation.

Use the official Docker image **inside this separate LXC**. This follows the
existing application Compose path and bundles Python dependencies. It requires
qualification of Docker nesting on the actual unprivileged LXC. Keep keyctl
disabled unless an observed requirement receives separate review.

Other supported options exist:

| Upstream installation | Tradeoff for this home |
| --- | --- |
| Docker in a Debian LXC (proposal) | Reuses our stack format and image policy; needs Docker/LXC qualification. |
| Native Debian package | Avoids nested Docker; adds a package repository, signing key and package/version qualification. Upstream README recommends this for production. |
| Tagged source + virtual environment | Needs Python and dependency qualification; requirements contain version ranges. |
| Official prebuilt LXC template | Supported upstream, but brings a different template lifecycle and documented default OS credentials that must be retired before use. |
| Automated `deploy.sh` | Fetches moving main and can configure dependencies, systemd and firewall. Do not run it through this preparation. |

A VM is not needed by the official installation instructions. If native tests
find an LXC conflict, present that concrete evidence before proposing a VM.

## Version and dependencies checked

Checked 28 October 2026. The latest published stable release was
[1.4.1](https://github.com/PegaProx/project-pegaprox/releases/tag/v1.4.1), from
source commit `ea40c362c78b8d16f869f07a4d00d3f1a2028e71`.
The preview pins the official multi-platform image index:

`ghcr.io/pegaprox/pegaprox@sha256:8d295a524a52f0b923616a3eb415ff6422fe62beba5bb441f35c75d8985f1add`

The observed amd64 manifest is
`sha256:849b1cbad1a8bc3ba54be4f1965c0b9bc37734c6cf8a1d9616403e343190ccf7`.
The image reports version 1.4.1 and the same source revision in its labels.
Upstream publishes provenance attestations; their cryptographic verification
remains an activation input, not a claim made by resolving a digest.

The [release Dockerfile](https://github.com/PegaProx/project-pegaprox/blob/ea40c362c78b8d16f869f07a4d00d3f1a2028e71/Dockerfile)
uses Python 3.12, Flask/gevent, cryptography/Argon2, requests, Paramiko and
SQLCipher on Linux amd64; the [requirements](https://github.com/PegaProx/project-pegaprox/blob/ea40c362c78b8d16f869f07a4d00d3f1a2028e71/requirements.txt)
also include optional integration libraries. Upstream documents Python
3.10–3.13 and PVE 8+ or 9+. No extra database server is required. The pinned
image bundles its dependencies; it does not freeze the LXC's Debian packages.

## Access starts small

Use a stable management-network address. Allow the named management client(s)
to **TCP5000** only and the deployment runner to the guest's SSH port. The
preview binds 5000 to that one address, uses Docker bridge networking, drops
Linux capabilities and keeps the container root filesystem read-only.

For the first Proxmox connection, propose a separate, privilege-separated
**audit-only API token**, with reviewed user and token ACLs. Starting privilege
candidates are `Sys.Audit`, `VM.Audit`, `Datastore.Audit`, plus the version-specific
guest-agent read privilege only if needed. Scope paths and propagation to the
selected node/guests/storage; review the effective permissions before minting.
The source does not create an account, token, role or ACL. Confirm inventory
works with this restricted account; missing management features are expected.

The upstream [permission guide](https://github.com/PegaProx/project-pegaprox/blob/ea40c362c78b8d16f869f07a4d00d3f1a2028e71/docs/proxmox-permissions.md)
explains token login and how features lose access without their privileges.
Its generated “least-privilege” recipe still includes power, creation,
migration and hardware changes. **Do not copy that broad role for this initial
inventory proposal.** Do not use a root password or reuse the deployment,
Traefik discovery or monitoring token. Even audit permissions reveal inventory;
Ben must approve their exact scope and expiry/revocation plan.

Initial outbound application access is only the reviewed PVE endpoint on
TCP8006, with certificate and hostname verification explicitly enabled. Verify
the installed version and its CA loading path; the upstream cluster default
for SSL verification is false. A successful local health check says nothing
about trust of the real PVE endpoint. Package/image downloads, DNS and time
services need their own finite reviewed allowances during installation.

Do not admit host SSH22, console5001/5002, SPICE3128, direct VNC5900+, PBS8007,
HA/witness5005, syslog1514 or another management network for this first scope.
The upstream [port guide](https://docs.pegaprox.com/configuration/ports/) describes
these features. Syslog is enabled by default inside the app: it is unpublished
here, should be switched off at setup, and needs explicit approval before use.
Set cluster SSH off; supplying no SSH credential is an additional constraint.
No WAN route, shared Traefik route, OIDC client or device access is added.

Only the selected management client should reach the **first-run setup wizard**.
There is no default web administrator. Complete setup, configure 2FA and verify
TLS before opening access further. Initial TLS is self-signed; select a trusted
certificate/CA plan before native use, rather than disabling browser validation.

## Configuration, key and updates

Persist `/app/config` (encrypted database, plugins/settings, branding and TLS)
and `/app/logs`. Supply a separately protected 32-byte database key through
`PEGAPROX_KEY_FILE`, not a literal environment value. The preview references
`/opt/homelab-app/runtime/pegaprox-db-key`, mounted read-only at
`/run/secrets/pegaprox-db-key`; missing bind sources cannot be silently created.
The native installer must preflight the file's ownership/mode/readability and
create the config/log directories for the image's actual numeric UID/GID before
startup (the tested image runs as UID999/GID999). No key is generated or read by the preview renderer.

Back up a coherent config/database plus the separate key, preserving numeric
metadata. The key needs independent encrypted recovery custody. A config-only
backup is insufficient. Keep logs according to a reviewed retention policy;
Docker's own logs are bounded in the preview, application logs need a separate
retention decision. Test an isolated restore before depending on recovery.
This is proposed as a clean install; any existing PegaProx data must be identified
and preserved before changing that assumption.

For Docker, updates mean a reviewed **new digest and container recreation**.
Upstream [update code](https://github.com/PegaProx/project-pegaprox/blob/ea40c362c78b8d16f869f07a4d00d3f1a2028e71/pegaprox/api/settings.py)
detects Docker and normally refuses the file updater (it has an explicit override).
`update.sh` also detects managed installs. Do not use that override, Watchtower,
a moving `latest` tag, a new scheduler, or apt inside this container. Review
release behaviour changes and protect config/key before each update; 1.4's
history conversion means an image downgrade is not a complete state rollback.

## What the prepared source can do

Preview using the invented example (this prints JSON; it does not install):

```sh
python3 proxmox/applications/pegaprox.py proxmox/applications/examples/pegaprox.preparation.example.json
```

Do not run the output against a real host. The two false flags are enforced
preparation markers; setting them true does not enable deployment.
`tests/test_pegaprox.py` checks listener, image, resource and refusal boundaries.
`tests/pegaprox_fixture.py` exercises the actual image with invented data,
disposable volumes, no network and no published ports. It checks local health,
encrypted database/key separation and restart persistence. It does not log in
to Proxmox or establish LXC, firewall, browser, native TLS or restore readiness.

Activation is a later scoped source change to the **existing** single-guest
OpenTofu/Ansible path: add clean directory/key preflight and installation,
then the private disabled-to-reviewed CD selection. Reuse `deploy.py`,
`plan.py`, `guest_identity.py`, NAS-backed state recovery, saved-plan hashes,
original SSH identity, shared queue and failure holds. Do not invent a second
engine or replace a failed guest. The current restore-oriented Ansible path
has no PegaProx clean-install support; no fake capture is supplied to bypass it.

Before that change: confirm allocation and free resources, exact Debian image
and package versions, key/CA custody, finite client/API access and effective
privileges. Review an exact saved plan and native packet with Ben. A failed
native attempt stops under the existing hold and is never replayed automatically.
