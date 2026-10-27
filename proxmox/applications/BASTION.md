# Reach one management endpoint through a restricted bastion

The bastion is a small, separate unprivileged LXC. An existing authorized VPN
client connects to its entry address over SSH. SSH then opens a **new** connection
from the bastion's management interface to one exact permitted address and port.
The workstation retains the downstream SSH keys and performs downstream login or
MFA. The bastion stores only selected public authentication keys and its own SSH
host keys. It is not a VPN server, router, proxy discovery target or backup system.

This is source preparation. It has not created or qualified a native guest.
The private CD selection must stay disabled until its admission inputs are bound.

## What the installer does

Use `app.kind: bastion` in the existing single-guest site file. The existing
OpenTofu module creates the protected LXC and DROP-by-default guest firewall;
Ansible installs exact native OpenSSH/nftables packages. There is no Docker stack,
application capture or restore. Plan, reviewed saved-plan SHA256, creation-log SSH
identity, state/NAS copies, locks, completion receipts and failure holds use the
same `deploy.py` path as the other guests. Existing or interrupted guests are held,
not adopted or retried automatically. Later completed runs use read-only Verify.

`bastion.py` validates and renders `app.bastion`. Its fields are:

| Input | Required binding |
| --- | --- |
| `entry_address`, `management_address` | Two distinct static guest IPv4 addresses on non-overlapping networks, /24 or narrower |
| `runner_source` | One existing machine deployment identity as a literal /32 |
| `roles` | Finite records with `name`, exact `uid`/`gid`, `sources` (/32 peers), `public_key_file` and `permit_open` |
| `permit_open` | Exact literal management-interface IP:port pairs; no host wildcard, CIDR, range or arbitrary SOCKS target |
| `public_key_file` | Existing comment-free Ed25519 public key on the private runner; bytes are saved-plan inputs |
| `maintenance` | Exact `address`, numeric `port`, `proto` and assigned `source_address` for package/DNS reads; no blanket egress |

The guest uses **one default gateway on entry** for replies to routed VPN clients.
Management targets stay directly attached, with the management source address.
Maintenance on that management subnet uses management; other selected package/DNS
endpoints use entry. Bind the actual gateway, routes and return enforcement before
admission. The installer does not add policy routing, a new gateway or UDM rules.
The source test's invented addresses and keys are examples, never deployable input.

Guest firewall rules must equal `bastion.access_rules(policy)` exactly. Existing
firewall default DROP remains mandatory. UDM VPN entry rules and management-target
ingress rules are separate operator inputs; same-subnet traffic may bypass UDM.
Source /32 checks supplement the existing authenticated VPN identity; they do not
establish which real peer owns an address.

SSH listens only on the two selected addresses. On entry, only named roles from
selected peers can authenticate; on management, only the existing runner's root
key path is allowed. Root never authenticates on entry. Roles have no session,
shell, command, PTY, SFTP, agent/X11 forwarding, Unix-socket forwarding, remote
forwarding, user RC or IP tunnel. Local TCP forwarding is limited by each role's
PermitOpen. The native accounts are created only after collision checks; a repeat
requires the original exact account receipt. Existing names, UID/GID membership or
account drift stop the run. In particular, Debian can already have an `operator`
group: its existence is a hold, never permission to renumber it.

Stage prepares the checked candidate. Start applies no-transit sysctls, backs up
the original SSH configuration, validates the new file, and reloads **SSH only**.
The existing deployment root key and host key files remain in their original
locations. An active `ssh.socket` or unreviewed daemon command override is a hold;
qualify service activation on the exact template first. Network readiness reuses
the shared guest startup gate. No host/UDM network setting is changed by this code.

## Keep downstream verification on the workstation

For downstream SSH, use a local SSH config selecting the literal permitted
management IP, existing downstream user and existing client key. Set `ProxyJump`
to the restricted entry role. Keep `StrictHostKeyChecking yes`, `ForwardAgent no`
and the independently verified host-key identity for **both** hosts. The downstream
private key never goes onto the bastion. A tunnel alone does not authenticate the
target or prove that its host key is correct.

For HTTPS, an exact local forward can carry TLS unchanged:

```sh
ssh -N -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=yes \
  -o ForwardAgent=no -L 127.0.0.1:18443:198.18.25.10:8006 tunneladmin@bastion.example.invalid
curl --fail --connect-to admin.example.invalid:8006:127.0.0.1:18443 \
  https://admin.example.invalid:8006/
```

These are invented endpoints. Supply the independently trusted CA where needed;
never disable TLS or host-key checks. The URL remains the target's actual hostname
and port, preserving SNI, HTTP Host and certificate validation. A browser needs an
explicit, reviewed local hostname/port mapping through the same tunnel; visiting
a loopback URL is not a certificate workaround. Redirects, login, MFA and console
WebSockets require native acceptance with the selected real hostname/trust.
The backend owns its native login and MFA; this code does not alter them.

If an existing Traefik listener is on a different service network, this source
**refuses it as a management destination**. Bind the actual bastion-to-proxy
transport, observed connected peer and target ingress rules before proposing a
separate integration. Do not infer a management HTTPS listener, add a new listener,
copy a Services-to-management grant or route around the bastion. Direct native
HTTPS is a reviewable transport choice, not an automatic Traefik cutover.

## Before one native admission

1. Read back collisions, VMID/IP/MAC ownership, host resources, template, storage,
   normal machine API authority, VLAN carriage and exact guest/target firewall
   rules. Preserve a denied normal read; do not change account or privilege.
2. Bind existing VPN peers, public operator key files, preserved UID/GIDs, package
   versions and finite package/DNS endpoints. Missing inputs stay missing.
3. Independently pin bastion/downstream host keys and backend CA/SAN/SNI, exact
   human destinations and browser transport. Retain physical recovery access and
   credentials independent of DNS, UDM, VPN, bastion and the Proxmox host's guests.
4. Prepare one normal shared Plan, before-state/identity/source hashes, NAS
   recovery readback and its SHA256. Inspect the exact create/firewall delta with
   the operator. Do not enable private CD or supply the plan fingerprint merely
   because synthetic tests passed. A later scoped decision admits that action.
5. After approval, one existing Deploy run completes apply/identity/stage/start/
   verify with holds and receipts. A failure stops, preserves evidence and needs
   separate review. No automatic recovery, failed-target replay or schedule.
6. Test actual allowed/denied peers and ports, no IPv4/IPv6 transit, the existing
   deployment SSH path, downstream host-key rejection, trusted HTTPS, native MFA,
   redirects and console access. Record household acceptance separately.

A bastion hosted on Proxmox cannot recover a down Proxmox host by itself. Local
physical management recovery must remain independently documented and usable.

## Evidence and limits

The unit tests exercise exact policy/refusal and input binding. The disposable
OpenSSH fixture tests permitted local forwarding and runner SSH; it rejects wrong
source/destination, command, PTY, SFTP, entry-root, management-role, remote forwarding
and wrong host key. Effective daemon checks also cover agent/Unix forwarding.
The fixture uses generated disposable keys and loopback only, with no published
ports or production credentials. It does not prove native LXC service activation,
namespace sysctl permissions, PVE firewall/UDM enforcement, MFA, TLS or resources.

OpenSSH behavior follows its official [server configuration manual](https://man.openbsd.org/sshd_config)
(`Match`, `MaxSessions`, `PermitOpen`, forwarding restrictions) and
[client configuration manual](https://man.openbsd.org/ssh_config) (host-key checks,
ProxyJump). Restricted forwarding requires denying shell/session access as well.
