# Prepare your SSH key and check the installed host

[Back to the Proxmox guide](README.md) · [ISO guide](iso/README.md) ·
[Bootstrap guide](bootstrap/README.md)

SSH lets your workstation sign in to Proxmox securely. A key has two parts:
the **public key** goes in the ISO; the **private key** stays on your workstation
and in your password manager. Never publish the private part.

## 1. Have a key ready before building the ISO

**Current bootstrap limitation:** its Docker SSH calls are non-interactive and
do not forward your workstation's SSH agent. The supplied private key must be
usable without a passphrase. **Before creating or using one, review and accept
that a stolen copy can authenticate as root on the host and guest.** File mode
`0600` and a password-manager backup do not protect a copy already stolen.

Confirm your access restrictions and a usable revocation route first: an
administrator must be able to remove this exact public key from the host and
guest while retaining independent recovery access. This version accepts only a
bare public key; it does not install per-key source-address or forced-command
restrictions. Do not assume those controls exist. If that scope is unacceptable,
stop before making the key; agent/passphrase support is not implemented here.

For a new dedicated key, leave the passphrase prompts empty only after accepting
that scope. Keep its file private with mode `0600` and store a recovery copy in
your password manager. Do not remove a passphrase from an existing personal key
to work around the limitation.

If you already have a suitable dedicated Ed25519 key, use it. Otherwise run this
on your **workstation**, using a new filename:

```sh
umask 077
mkdir -p "$HOME/.ssh"
ssh-keygen -t ed25519 -f "$HOME/.ssh/homelab-proxmox" -C homelab-proxmox
```

If asked to overwrite an existing file, answer **no** and choose a different
filename. This creates `homelab-proxmox` (private) and `homelab-proxmox.pub`
(public).

Show the public key:

```sh
cat "$HOME/.ssh/homelab-proxmox.pub"
```

**Expected result:** one line beginning `ssh-ed25519`. When copying it into
the ISO settings and bootstrap `ssh_public_keys`, use its first two parts
(the key type and long value); omit the trailing `homelab-proxmox` comment.
Return to [ISO sign-in details](iso/README.md#sign-in-details).

## 2. Check the fresh host at its own screen

After installation, use the host's local keyboard/screen to sign in as `root`
with the recovery password you saved. Run these **read-only** commands there:

```sh
hostname -s
pveversion
pvesm status
zpool status
lsblk -d -b -o NAME,SIZE,MODEL,SERIAL
ip -br link
ip -br address
ip route
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

| Check | What you need to see |
| --- | --- |
| Host name/version | Your chosen short hostname and the intended Proxmox release. Use this short hostname for bootstrap's `site.node`. |
| Storage | The intended guest storage is active. For the ISO's ZFS mirror, normally `local-zfs`; record the actual name from `pvesm status`. |
| Mirror | The pool is `ONLINE` with the two intended new drives in a mirror and no reported errors. Compare member identities with your disk inventory. |
| Original disk | Its original serial is still present and it is not a member of the new mirror. This check alone does not prove all of its files are intact. |
| Physical ports | `mgmt0` and `fast0` have the MAC addresses you selected, and connected links are up. |
| Addresses/routing | Your management address is on `vmbr0.YOUR_VLAN`, storage is on `vmbr1.YOUR_VLAN`, and the default route uses your management gateway. |
| SSH fingerprint | Record the `SHA256:…` value from the final command for comparison in the next step. |

If storage, disks or networking differ, stop and inspect at the console.
Do not rerun the first-start network script or change switch settings by guesswork.

## 3. Compare and save the host's SSH identity

Back on the **workstation**, set your actual reachable host name. It must be the
same name you will use in bootstrap's `api_endpoint`. That name must resolve
to the host's management IPv4 address.

```sh
umask 077
bootstrap_private="$HOME/.config/homelab-bootstrap"
mkdir -p "$bootstrap_private"
pve_host='REPLACE_WITH_YOUR_PROXMOX_HOSTNAME'
```

Collect the public host key into a **new candidate file**. This is an observation,
not yet a trusted key. The subshell refuses to overwrite an earlier candidate:

```sh
( set -C; ssh-keyscan -T 10 -t ed25519 "$pve_host" > "$bootstrap_private/known_hosts.candidate" )
ssh-keygen -lf "$bootstrap_private/known_hosts.candidate"
```

Compare its `SHA256:…` value with the value you recorded at the host's own screen.
**They must match exactly.** If they differ or there is no key, stop. Do not
disable host checking or accept a new key merely because a connection answers.

Only after a match and an explained host-key change, save the candidate. On a
first installation there is no previous file. If one exists, the command below
preserves it under a new timestamped name before replacing the active file:

```sh
if [ -e "$bootstrap_private/known_hosts" ]; then
  trust_backup="$bootstrap_private/known_hosts.before-$(date -u +%Y%m%dT%H%M%SZ)"
  ( set -C; cat "$bootstrap_private/known_hosts" > "$trust_backup" ) &&
    cp "$bootstrap_private/known_hosts.candidate" "$bootstrap_private/known_hosts"
else
  cp "$bootstrap_private/known_hosts.candidate" "$bootstrap_private/known_hosts"
fi &&
export HOMELAB_SSH_KEY="$HOME/.ssh/homelab-proxmox" &&
export HOMELAB_KNOWN_HOSTS="$bootstrap_private/known_hosts" &&
chmod 600 "$HOMELAB_SSH_KEY" "$HOMELAB_KNOWN_HOSTS"
```

Use the actual key filename if you chose a different one. If preserving the old
file fails, stop; do not proceed with SSH or delete the backup to force a retry.
A reinstall can legitimately change a host key, but needs this fresh console
comparison and deliberate replacement. Never remove old trust merely to silence
an SSH warning.

## 4. Confirm workstation access

Run this on your workstation:

```sh
ssh -i "$HOMELAB_SSH_KEY" -o BatchMode=yes \
  -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$HOMELAB_KNOWN_HOSTS" \
  "root@$pve_host" 'hostname -s; pveversion'
```

**Expected result:** the same host name and Proxmox version as the console,
without a password prompt or a host-key question. Check the web interface at
`https://YOUR_PROXMOX_HOSTNAME:8006` as well. Its browser certificate warning is
separate from SSH trust; the bootstrap retrieves the Proxmox CA over the verified
SSH connection and keeps API certificate checking enabled.

Your workstation must later be able to reach both the host and the new guest.
Return to [bootstrap](bootstrap/README.md#2-fill-in-your-private-settings).

## When something goes wrong

| What you see | What to do |
| --- | --- |
| Hostname cannot be resolved | Check your chosen local DNS record or name resolution. Use the same verified name consistently. |
| Connection timed out | Check cables, VLAN membership, management address and access from the workstation's network. |
| Permission denied | Check the public key in the ISO matches your selected private key and that root SSH works at the host. |
| Key needs a passphrase | The current Docker launcher cannot forward your SSH agent. Review the dedicated-key limitation above. |
| Host identification changed | Compare the actual host's console fingerprint again. Preserve the previous entry until the change is explained. |
