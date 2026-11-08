# Prepare remote backup storage

[Backup setup](README.md) · [Server setup](server.md#prepare-the-backup-filesystem) · [Operate and restore](operations.md)

Use this procedure when your installation plan places the PBS datastore on an NFS export. It is an operator setup task, before datastore creation and CD. It does not change the storage backend selected in your plan. PBS recommends fast local storage; a remote filesystem needs its own durability, permissions, availability and workload qualification. See [PBS storage requirements](https://pbs.proxmox.com/docs/storage.html#datastore).

## Before you start

Have a working PBS console, administrator access to the storage owner and an approved storage network. Record the following for **each** mount and datastore in your private installation plan:

| Fact | What must be known |
| --- | --- |
| Source | Exact storage-server address and export path; backing filesystem and failure boundary |
| Client | Stable PBS source address, interface and route used for storage traffic |
| Destination | PBS mountpoint and datastore child path; no existing unrelated contents |
| Identity | Actual numeric `backup` UID/GID on PBS and their effective mapping on the server |
| Capacity | Combined quota, free reserve, retention, staging and snapshot overhead in explicit units |
| Recovery | How the export, mount and datastore are recovered without guest DNS, SSO or the controller |

If the planned storage VLAN or route is absent, establish it through its network owner before mounting. Do not silently use a management or former test network. Verify address ownership before assignment; a failed ping alone does not establish that an address is free. If full-guest and selected recovery data need different retention or offsite handling, keep their datastore directories distinct; a combined budget must cover both.

This page's complete mount example uses the documentation address `192.0.2.20`, export `/exports/pbs`, PBS storage address `192.0.2.21` on `nic1`, mount `/mnt/backup` and datastore children `full` and `recovery`. These are placeholders, not deployable site allocations. Substitute the reviewed values consistently. Do not copy an old qualification export or its access policy into production without inspecting it.

## Prepare the export through its owner

On the storage server, using its supported administration tools:

1. Create the dedicated empty backing directory/share on the intended persistent filesystem. Set the admitted capacity/quota; preserve other shares and their snapshots, permissions and backup jobs.
2. Grant the verified PBS backup-service numeric identity access to this directory, with only the traversal needed through its parents. Retain restrictive directory/file permissions. Do not assume a NAS account with the same name has the same numeric ID.
3. Export only this path to the exact PBS storage client address, using NFSv4 over TCP and synchronous writes. Select and record the identity-mapping policy explicitly. Prefer root squashing where the native datastore operations support the resulting non-admin mapping; do not map all clients to administrator or grant Everyone access to solve a permission failure. Preserve reserved-port restrictions when the client supports them.
4. Record the exact resulting export and access policy. Confirm other clients have not gained access. Network grants, account mapping and export administration are security changes requiring the installation owner's authority.

NAS products differ in their path syntax, ACLs, UID mapping and quota units. Use the vendor's documented controls for those steps and record the actual results; the Linux client commands below do not configure a NAS. If the required numeric service access cannot be expressed, stop and resolve that constraint before creating a datastore. The privileged PBS datastore-creation operation must also be able to create directories with the backup identity and set their ownership. A successful write as `backup` alone does not establish that this operation can work through root squashing. Qualify the supported server-side identity mapping for your installed PBS release; mapping root to an unrelated anonymous account can prevent ownership changes. Some NFS servers support a non-admin anonymous UID/GID mapping matching `backup`, but do not assume a NAS exposes it. If supported controls cannot express the required root-squashed mapping, record the constraint and obtain an explicit storage/access decision. A native-ID policy (often called “No mapping” or `no_root_squash`) allows root on the admitted PBS client to act as root within the export. It is a broader trust decision, not an equivalent spelling of root squashing: only use it after the owner approves that exact client/export scope. It must not grant other clients or unrelated shares access. Do not hand-edit vendor-managed exports, map all users to administrator, or manually fabricate a PBS chunk tree.

## Configure the PBS mount

Use the trusted PBS root console. First inspect `id backup`, `ip route get <storage-address>`, `findmnt` and the existing mount configuration. Confirm the expected source interface/address and that the intended mountpoint and unit are unused. The following first-installation commands assume `/mnt/backup` and `mnt-backup.mount` do not exist. Existing paths require inspection, not deletion or replacement.

Install the official Debian NFS client tooling using the [configured repositories](server.md#configure-the-update-repository):

```bash
apt install nfs-common
```

Create the **unmounted** directory with no access for unprivileged services. Run these commands individually, checking each result; stop on any failure:

```bash
test ! -e /mnt/backup
test ! -L /mnt/backup
mkdir -m 000 /mnt/backup
test ! -e /etc/systemd/system/mnt-backup.mount
```

Using your root editor, create `/etc/systemd/system/mnt-backup.mount` with the following complete unit after substituting the source. Do not also add the same mount to `/etc/fstab` or an automount unit. Unit names must correspond to their mount path; for another path, derive the name with `systemd-escape --path --suffix=mount <path>` and use it throughout this procedure.

```ini
[Unit]
Description=PBS backup storage
Wants=network-online.target
After=network-online.target

[Mount]
What=192.0.2.20:/exports/pbs
Where=/mnt/backup
Type=nfs4
Options=rw,hard,vers=4.1,proto=tcp
TimeoutSec=90

[Install]
WantedBy=remote-fs.target
```

NFS `hard` behavior can make I/O wait during an outage; it avoids treating a storage timeout as permission to continue on a local directory. Do not switch to `soft`, `noatime`, asynchronous server writes or a different source to make qualification pass. Select and qualify a supported NFSv4 minor version for both ends. See the [Linux NFS options](https://man7.org/linux/man-pages/man5/nfs.5.html) and [systemd mount units](https://www.freedesktop.org/software/systemd/man/latest/systemd.mount.html).

```bash
systemd-analyze verify /etc/systemd/system/mnt-backup.mount
systemctl daemon-reload
systemctl enable --now mnt-backup.mount
findmnt --mountpoint /mnt/backup -o SOURCE,TARGET,FSTYPE,OPTIONS
df -h -- /mnt/backup
df -i -- /mnt/backup
```

Verify the exact source, path, NFS version, writable/hard options and available capacity. A successful mount is not yet permission or durability acceptance.

## Refuse a missing or wrong mount

Both PBS services must depend on the mount and check its identity before starting. Otherwise an absent export can leave an ordinary directory on the OS disk that looks like usable backup storage.

Create `/usr/local/sbin/pbs-storage-ready` as a root-owned, non-writable-by-others executable (`0755`). This complete example must use the same source/path as the mount unit:

```sh
#!/bin/sh
set -eu
mountpoint=/mnt/backup
expected_source=192.0.2.20:/exports/pbs
python3 - <<'PY_ROUTE'
import json
import subprocess
route = json.loads(subprocess.check_output(['ip', '-j', '-4', 'route', 'get', '192.0.2.20']))
if len(route) != 1 or route[0].get('dev') != 'nic1' or route[0].get('prefsrc') != '192.0.2.21':
    raise SystemExit('PBS storage route does not match the approved interface and source')
PY_ROUTE
[ "$(findmnt -rn --mountpoint "$mountpoint" -o SOURCE)" = "$expected_source" ]
[ "$(findmnt -rn --mountpoint "$mountpoint" -o FSTYPE)" = nfs4 ]
options=$(findmnt -rn --mountpoint "$mountpoint" -o OPTIONS)
case ",$options," in *,rw,*) ;; *) exit 1 ;; esac
case ",$options," in *,hard,*) ;; *) exit 1 ;; esac
case ",$options," in *,noatime,*) exit 1 ;; esac
```

Inspect `systemctl cat proxmox-backup.service proxmox-backup-proxy.service` first. Do not replace vendor units or existing drop-ins. Add the following complete drop-in named `storage.conf` in **each** corresponding `/etc/systemd/system/<service>.d/` directory:

```ini
[Unit]
Requires=mnt-backup.mount
After=mnt-backup.mount
BindsTo=mnt-backup.mount

[Service]
ExecStartPre=/usr/local/sbin/pbs-storage-ready
```

`After` plus `BindsTo` ties service availability to the mount; the additional check rejects a wrong source at the same path or a route using the wrong interface/source address. It does not configure routes or provide network isolation; establish those through the network owner before mounting. This example makes both services unavailable if this mount is absent, including the web UI. Preserve independent console access. For multiple required mounts, name every mount in the dependencies and check every exact source in the helper. See [systemd dependency behavior](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html#BindsTo=).

From the console, validate the helper with `sh -n`, run it once, reload systemd and inspect the effective units. On this new server with **no active clients or backups**, restart both services and verify the web interface returns. Do not perform a disruption test on an active backup system without its maintenance procedure.

## Qualify the actual filesystem before reliance

These procedures require the verified empty export, the approved identity mapping and no active clients or backup jobs. They are first-installation checks, not a production outage procedure. Preserve failed results and partially created objects for inspection; do not rerun into an existing directory.

### Check service-identity file operations

Run this complete command from the trusted PBS root console. It creates only one new `qualification-` directory and two small, non-sensitive test files under the verified mount. It performs the file operations as the actual `backup` account and prints the disposable directory to inventory for later cleanup. No live datastore is opened.

```bash
/usr/local/sbin/pbs-storage-ready &&
runuser -u backup -- python3 - <<'PY_FILES'
import fcntl
import os
from pathlib import Path
import tempfile
import time

os.umask(0o077)
root = Path(tempfile.mkdtemp(prefix='qualification-', dir='/mnt/backup'))
first = root / 'first'
renamed = root / 'renamed'
with first.open('xb') as stream:
    stream.write(b'PBS filesystem qualification\n')
    stream.flush()
    os.fsync(stream.fileno())
parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(parent)
    first.rename(renamed)
    os.fsync(parent)
finally:
    os.close(parent)
# Make the old atime unambiguously older than mtime for relatime filesystems.
old = time.time_ns() - 2 * 86400 * 10**9
os.utime(renamed, ns=(old, time.time_ns()))
assert renamed.read_bytes() == b'PBS filesystem qualification\n'
metadata = renamed.stat()
assert metadata.st_uid == os.getuid() and metadata.st_gid == os.getgid()
assert metadata.st_mode & 0o777 == 0o600 and metadata.st_atime_ns > old
with (root / 'lock').open('xb') as one, (root / 'lock').open('r+b') as two:
    fcntl.flock(one, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        fcntl.flock(two, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        pass
    else:
        raise SystemExit('Independent lock acquisition unexpectedly succeeded')
print('File-operation checks passed; preserve for reviewed cleanup:', root)
PY_FILES
```

Expected: one success line naming the new directory. An exception is a failed check. This tests client-visible fsync, rename, readback, atime and lock behavior, not power-loss durability or cross-client locking. Synchronous export configuration, storage power protection and native PBS datastore creation, verification and garbage collection remain separate requirements. The native creation task tests the actual chunk-directory creation workload; do not manufacture chunks with this script.

### Prove an absent mount cannot receive backups

Use the trusted console, which remains available while both PBS services and their web interface are stopped. Run each block only after the preceding result matches its description. Never force or lazily unmount a busy datastore.

```bash
systemctl stop proxmox-backup-proxy.service proxmox-backup.service
systemctl is-active proxmox-backup-proxy.service proxmox-backup.service
systemctl stop mnt-backup.mount
findmnt --mountpoint /mnt/backup
runuser -u backup -- test -w /mnt/backup
/usr/local/sbin/pbs-storage-ready
```

Expected: both services are `inactive`; `findmnt` finds no mount; the write-access test and helper both return nonzero. Stop if any check disagrees. Record the return status immediately after each command with `echo "$?"`.

Prevent automatic mounting only during this negative check using a new runtime condition drop-in. A runtime whole-unit mask is unsuitable here because the mount unit in `/etc` takes precedence over `/run`. In the **same root Bash session**, use these exact commands:

```bash
PBS_MOUNT_TEST=$(mktemp -d /run/pbs-storage-test.XXXXXX)
test ! -e "$PBS_MOUNT_TEST/allow" && test ! -L "$PBS_MOUNT_TEST/allow"
install -d -m 0755 /run/systemd/system/mnt-backup.mount.d
PBS_MOUNT_DROPIN="/run/systemd/system/mnt-backup.mount.d/$(basename "$PBS_MOUNT_TEST").conf"
( set -C; printf '[Unit]\nConditionPathExists=%s/allow\n' "$PBS_MOUNT_TEST" > "$PBS_MOUNT_DROPIN" )
systemctl daemon-reload
systemctl cat mnt-backup.mount
systemctl show mnt-backup.mount -p DropInPaths -p Conditions
```

Inspect the effective condition: it must reference the absent marker in the recorded test directory, with no later reset or override. Record these two exact paths for cleanup. Then attempt each service start and inspect its resulting state, regardless of the command's exit status:

```bash
systemctl start proxmox-backup.service
systemctl is-active proxmox-backup.service
systemctl start proxmox-backup-proxy.service
systemctl is-active proxmox-backup-proxy.service
findmnt --mountpoint /mnt/backup
```

Expected: neither service is active and no mount appears. A failed start is the intended result; a command exit code alone is insufficient. Once verified, remove **only this test's drop-in and empty marker directory**, then restore the declared mount:

```bash
rm -- "$PBS_MOUNT_DROPIN"
rmdir -- "$PBS_MOUNT_TEST"
systemctl daemon-reload
systemctl start mnt-backup.mount
/usr/local/sbin/pbs-storage-ready
systemctl start proxmox-backup.service proxmox-backup-proxy.service
systemctl is-active proxmox-backup.service proxmox-backup-proxy.service
```

Expected: the helper succeeds and both services are `active`; the web interface returns. Do not delete another drop-in or change the expected source to make the checks pass.

### Verify persistence

Perform the [planned PBS setup reboot](server.md#configure-the-update-repository). After normal login, run the identity helper and inspect both service states and the datastore's backing filesystem. Confirm the expected network, exact mount, service ordering and datastore identity all return. A mount entry in a file is not evidence of successful reboot behavior.

Keep the qualification directory until its evidence and cleanup scope are reviewed. Never delete existing data to repeat a test. Only explicitly inventoried disposable test objects may be reset for the [clean rehearsal](operations.md#rehearse-an-amended-guide-from-a-clean-setup).

When these checks pass, return to [create and verify the datastore](server.md#create-and-verify-the-datastore-once). Create separate `full` and `recovery` child directories through the supported datastore operation where your plan requires them, then complete [encrypted backup and independent restore verification](operations.md). Neither successful NFS mounting nor a green CD run establishes recoverability.
