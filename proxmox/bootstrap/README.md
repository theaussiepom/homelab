# Start the first deployment guest

[Back to the combined Proxmox guide](../README.md) ·
[Installation USB guide](../iso/README.md) ·
[Bootstrap verification](verification.md)

This is the small step between installing Proxmox and letting GitHub manage
your homelab:

**Your workstation → one Debian deployment guest → its private GitHub runner.**

OpenTofu creates and starts the guest. Ansible installs its deployment tools and
runner. Other guests and applications are later work. No database is required.

**Current status (25 October 2026):** the selected route passed a complete
fresh-host test in an isolated Proxmox 9.2 lab: guest creation, automatic API
firewall setup, state handover, new runner registration and a successful real
GitHub verification job. No manual repairs were made between script stages.
Subsequent publication-review fixes passed 67 unit tests and offline
OpenTofu/Ansible integration checks; the live rehearsal was not repeated for
those corrections. Physical-target and later application rollout remain separate. See the
[verification record](verification.md) for the exact scope and limits.

## The steps at a glance

| Step | What you do | What the scripts do |
| --- | --- | --- |
| Prepare | Supply private site settings and verify the host's SSH fingerprint. | Build the local Docker tools image, validate settings and create a private working bundle. |
| Create | Run `access`, review `plan`, then run `apply` and `verify`. | Upload a selected cached template, create scoped API access, and create and check one guest. |
| Hand over | Save a private backup and run `runner`. | Add the required host API allowance, install tools, transfer state and register the GitHub runner. |
| Confirm | Run the reviewed workflow in your private GitHub repository. | Prove that the new runner can use the transferred state for a no-change plan. |

The following sections give the commands in that order. No separate base-guest
creation script or manual Proxmox token/firewall setup is needed.

## What you need

- A Mac or Linux workstation with Git, Python 3, Docker, and GitHub CLI (`gh`).
- A newly installed, reachable x86-64 Proxmox host.
- An existing storage location and management bridge on that host.
- A checksum-pinned Debian 13 amd64 template archive, or an existing template
  on the host. Bootstrap can upload a cached archive over pinned SSH.
- A private GitHub deployment repository that you administer. The source code
  can be public; the self-hosted runner is registered to your private repository.
- The SSH key installed on the host by your ISO. Bootstrap creates its own
  separated Proxmox API token through that trusted SSH connection.

Run the commands below from the root of your source checkout. Docker must be
running. The deployment tools run inside Docker; do not install them on Proxmox.

```sh
python3 --version
docker version
gh auth status
```

If GitHub CLI is not signed in, run `gh auth login` on the workstation. The
bootstrap reuses that login; no additional GitHub personal access token is needed.

## 1. Practise without touching Proxmox

```sh
./proxmox/bootstrap/bootstrap test
./proxmox/bootstrap/bootstrap test-backend
```

The first command runs unit checks, real OpenTofu/provider-schema checks with
mocked Proxmox calls, and Ansible with a synthetic runner. The second runs real
OpenTofu against disposable local state, tests competing-writer refusal, and
copies that state to a second workspace for a fresh no-change plan. Neither
test contacts Proxmox, your NAS, or GitHub. There is no database container.

These checks cannot prove that your physical host, guest, networking or real
GitHub registration works. That final check is described below.

## 2. Make your private settings

Keep your real host details, credentials, state and plans outside the public
checkout. The examples contain invented addresses and placeholders.

```sh
umask 077
bootstrap_private="$HOME/.config/homelab-bootstrap"
mkdir -p "$bootstrap_private"
cp -n proxmox/bootstrap/site.example.json "$bootstrap_private/site.json"
cp -n proxmox/bootstrap/settings.example.json "$bootstrap_private/settings.json"
```

Edit the two copied files:

| File | Replace |
| --- | --- |
| `site.json` | Proxmox hostname/API address and node name; your SSH public key; an unused guest ID; existing storage and bridge; an unused MAC address; your IP settings. |
| `settings.json` | Your private `owner/repository`, runner name, administration subnet, DNS and gateway settings. |

The small `site.example.json` contains only the deployment guest. You do not
need the full homelab catalogue. Its hostname inside the guest is `deploy`;
its default size is 1 CPU, 1 GiB RAM and an 8 GiB disk. Check that those values
fit your host. Guest IDs 4914, 4915 and 4920 remain excluded for this project's
protected rehearsal machines.

For DHCP, leave the guest's `ipv4` as `"dhcp"`; the gateway is obtained by
DHCP. Replace the example DNS servers with your own, or use an empty list to
inherit the host's DNS configuration. For a static address, provide its actual
address, subnet prefix, gateway and DNS.

Set `template_file_id` to an existing Debian 13 LXC template. Alternatively,
add a `template` object to `settings.json`. For a cached vendor archive:

```json
{
  "file": "/YOUR/CACHED/debian-template.tar.zst",
  "sha256": "EXACT_TRUSTED_VENDOR_SHA256",
  "file_name": "debian-template.tar.zst",
  "datastore_id": "local"
}
```

Set the guest's `template_file_id` to the matching
`local:vztmpl/debian-template.tar.zst`. Preparation verifies and privately copies
the archive. The `access` step automatically uploads it over pinned SSH to the
selected template storage, checks its size/hash again, and refuses to overwrite
a different file. No manual Proxmox template upload is needed. Retain the
vendor's signed-index/checksum provenance for the archive you choose.

Download the archive to your workstation from the vendor and retain its trusted
checksum before preparing the bundle. This MVP accepts a cached file or an
existing host template; it does not download templates through the Proxmox API
or grant template-administration permissions. Storage and bridges must already
exist; this bootstrap does not reconfigure host networking or disks.

## 3. Establish SSH trust for the fresh host

Use the SSH key you included when preparing the ISO. You also need a known-hosts
file whose SSH fingerprint you have compared with the host's console. Do not
accept an unknown host key without comparing it. Substitute your private paths:

```sh
export HOMELAB_SSH_KEY="$bootstrap_private/bootstrap-key"
export HOMELAB_KNOWN_HOSTS="$bootstrap_private/known_hosts"
```

No Proxmox web-interface setup is needed for the API token or the runner's
host firewall allowance. The scripted steps below use the verified SSH key.

## 4. Prepare, establish API access and create one guest

```sh
./proxmox/bootstrap/bootstrap prepare \
  --catalog "$bootstrap_private/site.json" \
  --settings "$bootstrap_private/settings.json" \
  --out "$bootstrap_private/first-run"

bootstrap_bundle="$bootstrap_private/first-run/bundle"
./proxmox/bootstrap/bootstrap access "$bootstrap_bundle" --expires-in 21600
./proxmox/bootstrap/bootstrap plan "$bootstrap_bundle"
```

Preparation builds its AMD64 tools image on your selected local Docker engine,
then creates the private bundle with networking disabled. A prebuilt tools image
is not required. Apple Silicon workstations use Docker's AMD64 emulation.
The build has a 30-minute limit and offline preparation a five-minute limit.
A timeout stops the local CLI; Docker may still be running the build or
container. Inspect Docker and preserve partial output before another attempt.
Preparation prints the actual bundle directory. Note the final `/bundle` in
subsequent commands. An existing output directory is preserved; preparation
refuses to overwrite it.

The `access` step checks the selected host and unused guest ID, retrieves the
public Proxmox CA, and creates one separated `root@pam!homelab-deploy-VMID`
token. It grants access only to the selected guest, storage, bridge and node;
existing accounts, tokens and permissions remain intact. A cached archive uses
the existing root SSH connection for the exact file transfer, so the API token
needs only audit access to its template storage.
It adds no permissions to other guests. HTTPS certificate checks stay enabled.

The token and CA are saved privately in the bundle. Later commands load them
automatically; no token copy/paste or credential export is needed. The example
lifetime is six hours, suitable for a rehearsal. For an ongoing CD installation,
choose the intended lifetime explicitly. Use `--expires-in 0` only after the
operator explicitly approves a credential without automatic expiry; this is
not the rehearsal default. Expired or partially created credentials are held
for inspection rather than silently replaced. Keep durable credentials in your
password manager and keep this bundle outside Git.

For revocation, an administrator removes the exact `homelab-deploy-VMID` token
from Proxmox's API Tokens panel; an exposed token should be revoked immediately.
For planned rotation, approve and issue a replacement separated token with the
same reviewed resource grants. Update the token in the private workstation
`access.json` and the guest's root-owned `/etc/homelab-bootstrap.env`, then
restart `homelab-deploy.service` and verify a no-change deployment job before
revoking the old token. Keep both tokens private and preserve the active state.
The bootstrap does not automate rotation or replace an existing token.

Read the plan log and confirm the correct host, unused guest ID, template,
storage and network. Then apply those same saved plan bytes:

```sh
./proxmox/bootstrap/bootstrap apply "$bootstrap_bundle"
./proxmox/bootstrap/bootstrap verify "$bootstrap_bundle"
```

The guest starts automatically and is configured to start after a host reboot.
It is unprivileged and protected against deletion. SSH is allowed from the
administration subnet; outbound traffic is allowed. The bootstrap accepts only
creation of its own guest/template or a no-op. It refuses replacement, deletion
and unrelated resource changes.

A timed-out apply first interrupts OpenTofu and gives it up to five minutes to
save partial state. Only then does it force-stop the local process if necessary.
The result remains `UNKNOWN`: local process exit does not prove the remote
resource outcome. A failed apply leaves `HOLD.json` and private logs. Inspect the actual outcome
before another attempt. Do not delete state or clear a hold to make a retry run.

## 5. Back up the initial state, then hand over to GitHub

State is the file `tofu/terraform.tfstate` inside the private bundle.
There is no PostgreSQL dependency. Keep this file private and available for
recovery. Use one bootstrap workstation and the documented launcher: it holds
a workstation lock across each Docker operation. Docker Desktop bind-mount
locking alone did not exclude competing containers in our test. Inside the
Linux deployment guest, OpenTofu also uses its standard local state lock.
Do not run raw OpenTofu or another active state copy alongside the launcher.

Use an already-mounted private NAS directory as the backup destination. The
parent directory must exist; the final backup directory must be new:

```sh
./proxmox/bootstrap/bootstrap backup "$bootstrap_bundle" \
  /YOUR/MOUNTED/NAS/private/bootstrap-before-handover
```

This copies the state and configuration without cached tools, plans, or SSH
keys. It checks the copied state hash and records its lineage/serial. It does
not mount the NAS or prove that a supplied path is actually NAS-backed.

The runner step automatically permits **the selected guest address → this
Proxmox host on TCP port 8006**, using the already verified host SSH connection.
It prepends one enabled host rule, or reuses the exact first rule, and checks
that all existing rules and host firewall settings were preserved. An equivalent
rule with a different owner comment is a conflict and is not silently adopted. It does not
enable/disable the host firewall or change your router, NAS firewall or VLANs.
The API hostname must resolve to one IPv4 address assigned to this host.

After installing the trusted CA in the guest, Ansible checks HTTPS access to
the API before copying state and registering the runner. A failed allowance or
connection check stops setup and preserves its private evidence; there is no
automatic retry. Before leaving this allowance in place for ongoing CD, the
operator must confirm a static address or DHCP reservation and prevent another
device from taking that address. This firewall rule trusts the `/32` address,
not the guest's identity; it does not reserve or follow a changing DHCP lease.

Now install the runner:

```sh
./proxmox/bootstrap/bootstrap runner "$bootstrap_bundle"
```

Runner registration includes both `homelab-private-deploy` and your configured
runner name as labels. Target the unique name label when testing alongside
another retained runner, so GitHub cannot choose the older machine.

The workstation checks that your GitHub repository is private and your account
has administration access. It obtains a fresh one-hour registration token
automatically. Only that temporary token is passed to Docker for registration;
your personal GitHub credentials remain on the workstation. The token is not
printed or saved in the bootstrap configuration.

The installer verifies the guest, reads its SSH public host key through the
trusted Proxmox connection, and copies the exact state/configuration into
`/var/lib/homelab-bootstrap` on the guest. It checks the state hash and runs a
fresh no-change provider plan there before registering and starting the runner.
The guest receives only the scoped Proxmox API token; username/password
credentials and a missing API token are refused before handover. The token is
stored in a root-readable service environment file. The service loads it into
its process environment, so **every workflow job on this runner can read it**.
Only protected, reviewed workflows may run here. Restrict repository and
workflow-change access, and do not send untrusted pull-request jobs to this
runner. Runner labels route jobs; they are not an access control. The operator's SSH
private key and personal GitHub token are not installed as deployment credentials.

**Handover is one-way.** A local `HANDOVER.json` disables further workstation
plans/applies once state transfer begins. A workspace lock prevents handover
from racing a local operation. If setup fails halfway, preserve the marker and
logs and reconcile the guest's actual state. There is no automatic retry or
automatic return to the workstation copy.

After handover, the guest's copy is active. The workstation and NAS copies are
recovery snapshots; they are not automatically kept current. Any future CD
workflow that changes infrastructure must back up the current runner state to
your private NAS before its state can be discarded or the runner rebuilt.
The installed helper supports that without needing database or API access:

```sh
python3 /opt/homelab-bootstrap/bootstrap.py backup \
  --work /var/lib/homelab-bootstrap \
  --out /YOUR/MOUNTED/NAS/private/NEW-STATE-BACKUP
```

Run that command as the deployment account (or an administrator) on the guest.
Providing the NAS mount and scheduling ongoing state backups are subsequent
site configuration; this MVP does not silently install them.

## 6. Confirm GitHub has taken over

Enable the reviewed manual workflow from
`templates/private-bootstrap-preview.yml.example` in your private deployment
repository's `.github/workflows/` folder with a `.yml` filename. Replace the
example `homelab-deploy` label in `runs-on` with your configured `runner_name`.
Check that GitHub shows that runner online, then run the workflow.
It must finish with a no-change OpenTofu plan using the transferred state.
An existing registered runner is preserved rather than replaced on a repeat run.

The MVP is accepted only when **guest running, SSH working, private runner
online, and GitHub job successful with the same state** have been observed.
Docker tests alone do not establish that. Physical disk installation and later
application rollout remain separate operations.
