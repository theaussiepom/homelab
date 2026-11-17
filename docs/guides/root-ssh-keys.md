# Maintain root SSH public keys through CD

Use the existing `ssh_public_keys` list in a
[context](../reference/contexts.md#context-ssh-public-keys) or
[guest override](../reference/guests.md#guest-ssh-public-keys) to add an Ed25519
public key to a managed Debian LXC guest. The context list is inherited by guests
without an override. Keep the deployment key in every selected list; protected
input admission verifies that the controller's retained private key matches a
declared public key.

A key declaration and a network grant are separate. Bind an explicit TCP22
[network policy](../reference/policies.md) to the guest's actual control
interface and the approved administrative source group. Compilation cannot
establish gateway reachability or successful authentication.

## First installation

OpenTofu supplies the initial root keys when creating the container. The pinned
provider treats its account initialization block as
[creation-only](https://github.com/bpg/terraform-provider-proxmox/blob/v0.117.0/proxmoxtf/resource/container/container.go#L652).
HomeLab keeps that block out of ordinary resource updates and maintains later
public-key additions in the existing Ansible preparation phase.

The supported image must provide root's existing `/root/.ssh/authorized_keys`.
Preparation verifies its custody before adding anything. An absent file or
unclassified authentication layout needs explicit installation preparation;
the key maintainer does not create another account or rewrite sshd settings.

## Later deployments

From the consuming deployment repository root:

1. Append the public key's `ssh-ed25519` type and encoded body to the context or
   guest list. Omit its workstation comment and retain the deployment public key.
   Private keys remain with their existing owners.
2. Select the administrative source group and interface-bound SSH policy.
   Keep deployment-runner groups separate when they also authorize other traffic.
3. Complete the normal [source gates](../contributing/testing.md) and immutable
   upstream adoption, then use the deployment repository's protected CD.
4. Check that a key-only update preserves the guest resource and adds the key
   during preparation. Repetition is a no-op. Adding a key requires no guest
   replacement, reboot or sshd configuration change.
5. Verify a new connection using the personal identity and trusted public host
   metadata through the approved route. Keep deployment credentials on the
   controller. File checks, CI and a successful CD do not prove that connection.

Preparation preserves all existing lines, including unknown keys, comments,
non-UTF8 comment bytes and options on an already-present key. Matching uses the
Ed25519 wire identity, so an existing constrained key retains its options.
Trailing comments remain opaque, including unmatched quotes and non-UTF8 bytes.
Omitting a key from a later list does not revoke it. Key removal and rotation
need their own reviewed configuration operation.

## Custody and recovery

The existing file must be a single regular file owned by root:root, with mode
0600, 0640, 0644 or 0700, beneath a root-owned SSH directory without group/other write
access. Links, unmodelled extended attributes and conflicting custody are
refused. The bounded control writer preserves the original file's owner, mode
and every pre-existing byte while atomically appending missing keys.

Before an ordinary update changes infrastructure, recovery captures this shared
file with the other controls. A failed update may restore only its exact
preimage or the exact append postimage computed from that preimage and the
admitted key list. Foreign content or permission changes retain the hold.
Recovery checks the captured owner and mode before restoring any controls.
The existing file writer checks them again before replacing the shared file,
so a permission change after preflight also stops restoration.
Each capture checks ownership, mode and change time again after reading.
Read-only reconciliation
checks declared key presence while retaining unrelated authorizations.
Private SSH keys, passwords and application data are outside this operation.

Keep key maintenance within protected CD, whose existing guest deployment lock
serializes supported writers. Finish CD before making an out-of-band root edit
to this shared file. The final comparison and atomic replacement do not form a
transaction with a concurrent administrator's commands.

Resolve pending attempts from older framework versions before adopting this
capability. Their saved inventories may lack the key-file preimage; recovery
refuses that mismatch before infrastructure reversal or control writes rather
than inventing historical evidence. Follow the
[CD recovery contract](../operations/cd-recovery.md).

Source tests exercise the packed operation on temporary files and genuine
receipt transactions with fake native transport. They cover additive/idempotent
updates, constrained and unknown keys, custody failures, exact rollback,
foreign edits, legacy inventory refusal and a fresh ordinary deployment.
Linux-only metadata cases require the actual Linux test environment. Native
plan, connection and route acceptance remain separate deployment evidence.

[Deployment](../operations/deployment.md) · [Documentation index](../README.md)
