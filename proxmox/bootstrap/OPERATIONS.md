# Bootstrap operating reference

[Back to the step-by-step guide](README.md)

Read this when choosing ongoing credential/address policy, investigating a failure,
or maintaining the runner. The README links the relevant sections at each step.

## Credential lifetime and rotation

The `access` step checks the selected host and unused guest ID, retrieves the
public Proxmox CA, and creates one separated `root@pam!homelab-deploy-VMID`
token. It grants access only to the selected guest, storage, bridge and node;
existing accounts, tokens and permissions remain intact. A cached archive uses
the existing root SSH connection for the exact file transfer, so the API token
needs only audit access to its template storage.
It adds no permissions to other guests. HTTPS certificate checks stay enabled.
For a tagged guest, it also grants `SDN.Use` at the exact bridge/VLAN path
(for example `vmbr0/25`). Neither the bridge nor VLAN grant propagates to other
VLANs. An untagged rehearsal does not exercise this additional permission.

### Physical-run access review: 25 October 2026

Before the physical bootstrap, the operator explicitly approved the selected
guest, storage and bridge access. After the missing tagged-VLAN permission was
identified, a separate approval covered one corrected attempt adding only the
selected bridge/VLAN grant, with the other grants and lifetime preserved. This
was human approval of both network scopes, separate from test results and the
successful retry. The exact private approval/readback receipts are retained.
For another installation, review both paths for that site's intended network;
this record grants no permission for a different target or VLAN.

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

## Timeouts and uncertain outcomes

Docker tools-image builds have a 30-minute limit, and offline preparation has a
five-minute limit. A timed-out CLI does not prove the Docker build/container has
finished. Inspect Docker and keep partial output before another attempt.

A timed-out apply first interrupts OpenTofu and gives it up to five minutes to
save partial state. Only then does it force-stop the local process if necessary.
The result remains `UNKNOWN`: local process exit does not prove the remote
resource outcome. A failed apply leaves `HOLD.json` and private logs. Inspect the actual outcome
before another attempt. Do not delete state or clear a hold to make a retry run.

## State locking

### Reconfiguring a completed bootstrap

`bootstrap configure BUNDLE DEPLOYMENT.json` uses the existing pinned operator
SSH route to plan application ACLs and the NFS connection. Apply requires the
printed plan SHA256 and unchanged source/inputs/live plan. The separate
configuration lock permits this operation after handover, but never unlocks
workstation OpenTofu writes or copies stale workstation state back to the guest.
The existing runner must be idle. An attempt-owned maintenance marker blocks
application jobs until configuration and the NAS readback/backup finish.

The API token keeps its identity, secret and separated-privilege setting.
Permissions are nonpropagating and limited to the listed guest/storage/bridge
and VLAN paths. Existing grants must match the saved receipt exactly. No
permission removal, automatic token replacement or adoption of occupied guest
IDs is performed. The token expiry stays unchanged unless `expires_at` is
explicitly provided as a future Unix timestamp (or deliberately `0`). An expired
token requires this explicit decision; there is no implicit renewal.

The host owns `mnt-homelab_backups.mount` and its automount, using one selected
NFS version, `hard,nosuid,nodev,noexec`. The automount does not make NAS
availability a Proxmox boot requirement. One newly created directory is owned
by the mapped runner UID/GID under the existing default unprivileged map.
Existing directory ownership, export permissions and user maps are never
rewritten. Only that directory is bound as `mp0`; unexpected mounts cause a hold.
OpenTofu ignores the deployment guest's `mount_point` field because the
host-side bootstrap owns and verifies it; the runner gets no arbitrary host-path
mount permission. Application managed data volumes remain OpenTofu-owned.

If activation requires a restart, `restart_deploy: true` allows one graceful
shutdown/start of the deployment guest only. Failure to stop has no forced
fallback. After a timeout, preserve the local hold and remote marker: local
process exit does not establish remote closure. Bind-mount contents are not
included in Proxmox container backups; retain the NAS recovery files themselves.

The automount avoids a **host** boot dependency, but the guest's `mp0` source
creates a **deployment-guest** startup dependency on NAS availability. A hard
NFS operation can remain blocked during an outage. Restore NAS connectivity
before retrying a guest start. If an administrator deliberately chooses to
remove the exact `mp0` mapping for recovery, app jobs must remain held until the
NAS bind and write/readback are restored; there is no automatic local fallback.
No stopped-NAS guest-start test has been performed. Do not interrupt the NAS
or other household services just to test this scenario.

### Active state

State is the file `tofu/terraform.tfstate` inside the private bundle.
There is no PostgreSQL dependency. Keep this file private and available for
recovery. Use one bootstrap workstation and the documented launcher: it holds
a workstation lock across each Docker operation. Docker Desktop bind-mount
locking alone did not exclude competing containers in our test. Inside the
Linux deployment guest, OpenTofu also uses its standard local state lock.
Do not run raw OpenTofu or another active state copy alongside the launcher.

## The host firewall allowance

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

## Runner trust and one-way handover

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

Before registering the runner, the repository owner must check:

- Repository access and branch/ruleset protection prevent untrusted people from
  changing a workflow that can use the runner. Check who can bypass those rules.
- Pull requests, including private forks, cannot run untrusted code on this
  runner. Inspect triggers and checkout behaviour, including any
  `pull_request_target` workflow; the private-repository flag alone is not enough.
- This script registers a repository-level runner, not an organisation runner
  group. Confirm its repository scope. If additional organisation runners/groups
  are available, review their repository/workflow access separately rather than
  treating a group or label name as protection for this runner.

**Do not register or accept jobs if untrusted code can reach the runner.** This
is an operator acceptance check; the script verifies repository privacy/admin
access, but does not audit branch protection, workflow code or fork policy.

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
