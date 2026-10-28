# PegaProx in its own LXC

[Back to application deployment](README.md)

PegaProx gives you another web interface for Proxmox. It does not replace
Proxmox, move your applications, or prove that the house has migrated.
The selected home here is a **separate unprivileged Debian LXC**, independent
of the deployment runner. An LXC is a Linux container managed by Proxmox.
The separate-guest decision was made on 26 October 2026.

**CD source is prepared; native deployment is disabled.** The private selection
and both deployment jobs remain off. The profile refuses missing allocation,
client or clean-install admission. No PegaProx guest or Proxmox credentials have
been created by this work. Review the native packet before enabling the jobs.

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
Initial testing uses PegaProx directly, without Authentik or forward-auth.
The selected 1.4.1 release has no documented anonymous management-UI mode: its
[cluster API requires authentication](https://github.com/PegaProx/project-pegaprox/blob/ea40c362c78b8d16f869f07a4d00d3f1a2028e71/pegaprox/api/clusters.py#L41-L43),
and the [authentication guard](https://github.com/PegaProx/project-pegaprox/blob/ea40c362c78b8d16f869f07a4d00d3f1a2028e71/pegaprox/utils/auth.py#L1369-L1401)
returns 401 without a valid session/token. Public health or optional metrics
access does not remove the UI login. Use its native account for this release;
review a future upstream anonymous mode or Authentik integration separately.

No management client can reach the **first-run setup wizard** during CD.
The bootstrap stack publishes no host ports; CD creates the administrator and
proves login before publishing TCP5000 to the selected clients. Sign in with
the configured initial credentials and verify TLS before opening access further. Initial TLS is self-signed; select a trusted
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

## Follow the CD path

The private parent graph has a **PegaProx** branch after DNS. It does not depend
on Authentik or Traefik for the first test. The called job selects its own exact
public source revision; existing services retain their commissioned revisions.
The private parent job, called job and `deployment.json` are all disabled until
a separate native review. Missing MAC or individual HTTPS client allowances
also stop the profile before planning or reading deployment secrets.

Once admitted, `pegaprox_cd.py` prepares this guest's private inputs and passes
them into the **existing foundation CD protocol**. It creates one saved plan,
checks the three fresh guest/firewall resources, deploys that exact binary plan,
pins the new guest's original SSH identity, stages the stack, starts it and
checks readiness. The same `deploy.py`, `plan.py`, guest identity, NAS state
recovery, shared queue and failure holds remain in charge. This adds a closed
profile to that protocol, not another provisioning engine.

Ansible requires empty image-owned configuration/log directories, refuses key
or ownership drift, installs the separate database key and starts the pinned
image. A clean install has no restore capture. Failed or interrupted work stays
held; a later job never adopts a partial guest, resets its password or replays it.
Completed runs only verify the original installation.

### The temporary administrator password

The initial username is a private setting. Supply its password through the
GitHub Environment secret **`PEGAPROX_ADMIN_PASSWORD`**. Do not put its value in
site JSON, a stack environment variable, commands, a capture or Git.
Supply **`PEGAPROX_DB_KEY`** as a base64-encoded value that decodes to exactly
32 random bytes. Retain it separately for recovery.

The profile requires the password before the first rollout, but does not write
it into the runner's permanent input bundle, manifest or saved-plan inputs.
During first startup, Ansible stages it in a newly allocated root-only file in
volatile guest `/run`. The helper sends it on stdin to a Python process inside
the container. That process uses only the fixed loopback endpoint to create
the account, sign in, confirm its administrator role and log out. It prints a
fixed result, never a password or session token. Ansible removes the temporary
file in its `always` block. A killed job retains its normal failure hold; any
unconfirmed remote cleanup must be reviewed before continuation.

First startup uses `compose-bootstrap.yml`, which publishes no host ports.
Only after account creation and successful login does Ansible recreate the same
service with the selected management listener, then verify the persisted account.
A failed bootstrap leaves remote access closed and retains its failure hold.
The helper polls health for up to 65 seconds before reading authentication state
or sending credentials. It verifies TLS using only `/app/config/ssl/cert.pem` as
its local trust anchor. Hostname matching is omitted because the generated
self-signed certificate has no loopback SAN; proxies and redirects are refused,
and the endpoint is fixed at `https://127.0.0.1:5000`. Browser, Proxmox and IdP
certificate trust remain separate acceptance checks.
A second bootstrap is refused, even with a different password. Readiness after
completion needs no administrator password, so deleting that GitHub Secret
later will not break ordinary CD verification.

### Move to Authentik after testing

Use PegaProx's native OIDC support when the first installation is proven. Verify
an Authentik administrator sign-in and the required roles before retiring the
local test account. Upstream refuses to overwrite a local account with an OIDC
identity of the same name, so use a separate SSO identity or a separately reviewed
account migration. Decide whether to retain an independently protected recovery
account. Retire the test password/account and its sessions deliberately, then
delete `PEGAPROX_ADMIN_PASSWORD` from the GitHub Environment. **Deleting the
Secret alone does not disable the existing local account.** Keep the database
key and its independent recovery custody after the Authentik switch.

No OIDC provider, Authentik application, proxy middleware or automatic secret
removal is created by this initial CD preparation.

### Preview and synthetic tests

The original invented preview remains available and prints JSON only:

```sh
python3 proxmox/applications/pegaprox.py proxmox/applications/examples/pegaprox.preparation.example.json
```

Its two false markers describe that preview. The CD stack is a separate plain
runtime document; actual admission is controlled by the private CD selection
and disabled jobs. Do not run an unreviewed Compose preview on a real host.

The tests cover the shared saved-plan/hold protocol, password-free completed
repeats, stdin-only bootstrap, key drift, empty-directory metadata and private
job gates. `tests/pegaprox_fixture.py` uses the actual pinned image with invented
credentials, disposable volumes, no network and no published ports. It creates
and signs in to the first account, refuses bootstrap replay, verifies readiness
without the password after restart, and checks encrypted data/key persistence.
Fetch the image explicitly first; every fixture run uses `--pull=never`.

These are synthetic checks. Native unprivileged LXC/Docker, package availability,
real API trust/permissions, browser login and coherent backup/restore still need
qualification. Review the unused ID/address, MAC, resources, exact Debian
packages/template, approved client allowance, scoped runner grant and separate
key custody. CD does not yet connect PegaProx to a Proxmox cluster or grant it
API/SSH authority; that follows the separately reviewed runtime-access decision.
