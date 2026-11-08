# Install and prepare PBS

[Backup setup](README.md) → **Server** → [Recovery key](recovery-key.md) → [API access](access.md)

This first-installation task prepares the server that will receive backups. It works for a dedicated machine or a VM on a suitable hypervisor; it does not depend on a particular NAS vendor. A VM does not make its backing storage independent of the machine hosting it, so choose its failure boundary deliberately.

## Before you install

Choose and record these facts in your private installation plan:

| Choice | What to establish |
| --- | --- |
| Compute | Supported x86-64 hardware or a VM with sufficient CPU/RAM for your data volume and verification workload; size from the [PBS requirements](https://pbs.proxmox.com/docs/installation.html#system-requirements), not evaluation minima |
| OS disk | An explicitly identified installation disk that may be erased |
| Backup storage | A separate, persistent filesystem with capacity for your retention period, change rate and free-space reserve |
| Network | Stable address, hostname, gateway, DNS and management/client routes to TCP8007 |
| Trust | A way to obtain the server's certificate identity from its trusted console before giving clients credentials |
| Emergency access | Administrator credentials and hypervisor/physical console access available without the applications being backed up |
| Power and lifecycle | Host power protection and VM autostart, if applicable; a planned reboot must preserve the storage mount |

Do not assume compression or deduplication will achieve a particular capacity saving. Document which underlying disks or storage system hold the datastore and how to restore access to them if this server is lost.

## Install the operating system

1. Download the official PBS installer and verify its published checksum using the [installation instructions](https://pbs.proxmox.com/docs/installation.html#installation-medium).
2. Boot the intended machine or VM from that media. Check the disk identity and capacity before accepting installation: the selected installation disk is erased.
3. Complete the installer with your timezone, administrator password, notification email and stable management network settings. Protect the administrator credentials outside the server.
4. Remove the installation media from the next boot path and boot the installed server. Check that your address and route are correct.
5. Open `https://<your-pbs-address>:8007` from your management client. Compare the presented identity with the trusted console before signing in as `root` using Linux PAM. Do not make disabled certificate verification a permanent client setting.

On the **trusted PBS console**, these read-only commands report the installed version and certificate:

```bash
dpkg-query -W proxmox-backup-server proxmox-backup-client
proxmox-backup-manager cert info
```

Record the SHA-256 certificate fingerprint for the [backup destination](../reference/backup.md#backup-job-destination-fingerprint). It is a different value from the recovery public-key fingerprint. A reverse proxy may serve a different browser certificate; backup clients must trust the certificate at the endpoint they actually connect to.

## Finish the base server setup

In the PBS interface:

1. Confirm hostname, DNS, routing, timezone and synchronized time. Time errors affect certificate checks and schedules.
2. Configure the package repository appropriate to your subscription and installed release using the [PBS repository instructions](https://pbs.proxmox.com/docs/installation.html#debian-package-repositories). Apply available updates and handle a required reboot before enrolling clients.
3. Confirm administrator login works after a normal restart. Enable your chosen administrator authentication controls and preserve an independent emergency-access route.
4. Permit the management runner and selected backup clients to reach the PBS API on TCP8007. Grant no additional client-to-client access merely because backups are enabled. Use your site's network owner for firewall changes.

A proxy and browser FQDN are optional conveniences. Keep a verified direct PBS route for backup and recovery that does not require a working guest DNS, SSO or proxy deployment.

## Prepare the backup filesystem

PBS stores backups in a **datastore**, a named directory on a suitable filesystem. Preparing the filesystem and creating and verifying the datastore are **one-time server setup steps completed before CD**. CD uses that existing datastore and manages the declared namespaces and client access; it does not create, relocate or reformat the datastore.

1. Attach or allocate the storage through its owner: the hypervisor, physical storage configuration or existing storage service.
2. Use the [PBS disk/filesystem guide](https://pbs.proxmox.com/docs/storage.html#disk-management) for a new local disk or ZFS pool. Formatting is destructive: positively identify the intended empty device first. For remotely backed storage, qualify its durability, mount semantics and performance before using it for a production datastore.
3. Mount the filesystem persistently. For the synthetic example in this section, the mount is `/mnt/backup` and the datastore will be the new child `/mnt/backup/recovery`.
4. Check the mounted source, capacity and options, then verify that the same mount returns after a planned restart. An ordinary empty directory on the OS disk must not masquerade as an absent backup disk.

The following are **read-only Linux checks**, from any directory on PBS. Replace the example mount with your reviewed mount before running:

```bash
PBS_DATA_MOUNT=/mnt/backup
findmnt --mountpoint "$PBS_DATA_MOUNT"
df -h -- "$PBS_DATA_MOUNT"
df -i -- "$PBS_DATA_MOUNT"
```

`findmnt` must identify the expected filesystem source, not merely an ancestor mount. Confirm capacity and free space against your installation plan. Do not fix a failed permission check by making the filesystem world-writable. The PBS backup service needs access through the supported storage setup. A configured mount entry or datastore path returned by the API does not prove that the filesystem is currently mounted.

Record the mount source, datastore child path and ownership in your protected installation notes. Capacity, mount persistence and write access are real prerequisites; source validation cannot establish them.

## Create and verify the datastore once

Complete the filesystem checks above first. In this synthetic example the datastore name is `recovery` and its backing path is `/mnt/backup/recovery`. Substitute the name and path from your installation plan. These values must later match [the backup destination and expected datastore path](../reference/backup.md#management-and-recovery-inputs).

1. Inspect the PBS datastore list. The disk/filesystem setup may already have created a datastore. If the intended datastore exists, verify its name, path, storage and ownership instead of creating it again. Stop if either the name or path belongs to something else; do not delete it or reuse its contents.
2. For a new datastore, use **Datastore → Add Datastore** in the PBS web interface. Enter the selected **Name** and **Backing Path** on the verified filesystem. Review any offered prune or garbage-collection schedules before saving; those are separate [maintenance decisions](operations.md#configure-server-maintenance).
3. Wait for the creation task to finish with **OK**. Open the datastore and check that its name, path and reported capacity match the intended storage. A task that is merely running is not completion.
4. On the trusted PBS console, repeat `findmnt --mountpoint /mnt/backup` using your actual mount. Check `findmnt --target /mnt/backup/recovery` and `df -h -- /mnt/backup/recovery`: the datastore must resolve to the same expected backup filesystem, not the OS disk.
5. During the planned setup restart, verify that the mount and datastore return with the same identities and capacity. Complete this before scheduling production backups. Preserve the results in your installation notes.

For administrators using the trusted PBS console, the following is an **alternative to UI creation**, not an additional step. First inspect `proxmox-backup-manager datastore list` and confirm the selected name is unused. Run this once only for a new, absent child path on the already verified mount:

```bash
(
  set -eu
  PBS_DATA_MOUNT=/mnt/backup
  PBS_DATASTORE_NAME=recovery
  PBS_DATASTORE_PATH="$PBS_DATA_MOUNT/recovery"
  findmnt --mountpoint "$PBS_DATA_MOUNT"
  test ! -e "$PBS_DATASTORE_PATH"
  test ! -L "$PBS_DATASTORE_PATH"
  proxmox-backup-manager datastore create "$PBS_DATASTORE_NAME" "$PBS_DATASTORE_PATH"
  proxmox-backup-manager datastore show "$PBS_DATASTORE_NAME"
)
```

The subshell stops on an error. It does not format a disk or establish mount identity for you. Check the task result and complete steps 3–5 regardless of which creation route you use. If creation fails or its outcome is uncertain, inspect the task and retained configuration before doing anything else; do not blindly repeat creation or remove the directory. See the [native datastore commands](https://pbs.proxmox.com/docs/proxmox-backup-manager/man1.html) and [PBS storage guide](https://pbs.proxmox.com/docs/storage.html).

CD checks the existing datastore name and path against configuration. A missing datastore or a different path stops backup provisioning; CD does not repair it by creating a directory on whatever filesystem is available. Ongoing mount availability and storage health remain server-operation responsibilities.

## Server preparation is complete when

- The normal installed server boots without installer media and you can log in through verified TLS.
- Network, DNS and time are correct, and authorized runners/clients have the intended path.
- The backup filesystem is persistent, correctly identified and adequately sized.
- The datastore creation task succeeded, its path is on that filesystem, and both remain correct after the planned setup restart.
- Administrator access and the underlying storage can be recovered independently of the guests.

No successful backup is claimed yet. Continue with [creating and storing the recovery pair](recovery-key.md), then [API access and GitHub secrets](access.md). Schedules, notifications and real restores are checked in [the final operating checklist](operations.md).
