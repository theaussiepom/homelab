# Prepare remote backup storage

[Backup setup](README.md) · [Server setup](server.md#prepare-the-backup-filesystem) · [Operate and restore](operations.md)

Use this procedure when your installation plan places the PBS datastore on an NFS export. It is an operator setup task, before datastore creation and CD. It does not change the storage backend selected in your plan. PBS recommends fast local storage; a remote filesystem needs its own durability, permissions, availability and workload qualification. See [PBS storage requirements](https://pbs.proxmox.com/docs/storage.html#datastore).

## Before you start

Have administrator access to the storage owner, an approved storage network and a verified access route that survives stopping both PBS services. Use a hypervisor/physical console, or separately authorized and verified SSH access that does not depend on the PBS web services. **The PBS web Shell is not an independent console:** stopping its services can disconnect it. Establish and test the independent route before the service-stop, restart or missing-mount checks below. Record the following for **each** mount and datastore in your private installation plan:

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
2. Select the supported way to give the verified PBS backup-service numeric UID/GID access, with only the traversal needed through its parents. A NAS named-account UI may not support that numeric identity. Where supported, set **only this new empty directory** to the approved UID/GID and mode `0700` through storage-owner tools. Otherwise, the owner may approve that same nonrecursive change through the exact mounted PBS client after export and mount qualification, using the procedure below. Do not change unrelated parents, use recursive ownership/permission changes or alter an existing datastore. A NAS account with the same name is not sufficient identity proof.
3. Export only this path to the exact PBS storage client address, using NFSv4 over TCP and synchronous writes. Select and record the identity-mapping policy explicitly. Prefer root squashing where the native datastore operations support the resulting non-admin mapping; do not map all clients to administrator or grant Everyone access to solve a permission failure. Preserve reserved-port restrictions when the client supports them.
4. Record the exact resulting export and access policy. Confirm other clients have not gained access. Network grants, account mapping and export administration are security changes requiring the installation owner's authority.

NAS products differ in their path syntax, ACLs, UID mapping and quota units. Do not assume that a quota UI value is in GiB: confirm its documented units and verify the resulting byte limit through a supported storage-owner readback. For example, `512 GiB` is `549755813888` bytes; `512 GB` in decimal units is `512000000000` bytes. Record the effective limit and free space, rather than the entered number alone. The Linux client commands below do not configure a NAS.

If the required numeric service access cannot be expressed, stop and resolve that constraint before creating a datastore. The privileged PBS datastore-creation operation must also be able to create directories with the backup identity and set their ownership. A successful write as `backup` alone does not establish that this operation can work through root squashing. Qualify the supported server-side identity mapping for your installed PBS release; mapping root to an unrelated anonymous account can prevent ownership changes. Some NFS servers support a non-admin anonymous UID/GID mapping matching `backup`, but do not assume a NAS exposes it. If supported controls cannot express the required root-squashed mapping, record the constraint and obtain an explicit storage/access decision. A native-ID policy (often called “No mapping” or `no_root_squash`) allows root on the admitted PBS client to act as root within the export. It is a broader trust decision, not an equivalent spelling of root squashing: only use it after the owner approves that exact client/export scope. It must not grant other clients or unrelated shares access. Do not hand-edit vendor-managed exports, map all users to administrator, or manually fabricate a PBS chunk tree.

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
case ",$options," in *,vers=4.1,*) ;; *) exit 1 ;; esac
case ",$options," in *,proto=tcp,*) ;; *) exit 1 ;; esac
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

`After` plus `BindsTo` ties service availability to the mount; the additional check rejects a wrong source, NFS minor version or transport at the same path, or a route using the wrong interface/source address. It does not configure routes or provide network isolation; establish those through the network owner before mounting. This example makes both services unavailable if this mount is absent, including the web UI and its Shell. Preserve the independent access route established above. For multiple required mounts, name every mount in the dependencies and check every exact source in the helper. See [systemd dependency behavior](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html#BindsTo=).

From the console, validate the helper with `sh -n`, run it once, reload systemd and inspect the effective units. On this new server with **no active clients or backups**, restart both services and verify the web interface returns. Do not perform a disruption test on an active backup system without its maintenance procedure.

## Qualify the actual filesystem before reliance

These procedures require the verified empty export, the approved identity mapping and no active clients or backup jobs. They are first-installation checks, not a production outage procedure. Preserve failed results and partially created objects for inspection; do not rerun into an existing directory.

### Set the new empty export's numeric ownership when needed

Skip this change if storage-owner tools already established and verified the intended numeric ownership and mode. If they cannot express it, use this route **only after the storage owner approves the exact client/export and numeric ownership change**. It depends on the admitted mapping allowing the PBS root client to perform ownership changes; do not broaden mapping or permissions merely to make it work. The mount and readiness helper above must already pass. No datastore, qualification files or other contents may exist yet.

In this example the reviewed service identity is `34:34`. Substitute both numbers only from the recorded `id backup` result and approved mapping; do not assume those IDs on another installation. Run from the independently verified PBS root access route:

```bash
/usr/local/sbin/pbs-storage-ready &&
PBS_OWNER_UID=34 PBS_OWNER_GID=34 python3 - <<'PY_OWNER'
import os
import pwd
import stat

owner = pwd.getpwnam('backup')
expected = (int(os.environ['PBS_OWNER_UID']), int(os.environ['PBS_OWNER_GID']))
if (owner.pw_uid, owner.pw_gid) != expected:
    raise SystemExit('Backup numeric identity differs from the approved mapping')
path = '/mnt/backup'
fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    before = os.fstat(fd)
    if os.listdir(fd):
        raise SystemExit('Export is not empty; ownership change refused')
    os.fchown(fd, *expected)
    os.fchmod(fd, 0o700)
    after = os.fstat(fd)
    current = os.stat(path, follow_symlinks=False)
    if not (stat.S_ISDIR(current.st_mode)
            and (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
            == (current.st_dev, current.st_ino)
            and (after.st_uid, after.st_gid) == expected
            and stat.S_IMODE(after.st_mode) == 0o700):
        raise SystemExit('Export ownership readback failed; preserve and inspect')
finally:
    os.close(fd)
print('Verified numeric ownership and 0700 on the empty export root only')
PY_OWNER
```

This changes only the opened export root, with no recursion. A failure or uncertain outcome requires inspection, not repetition. Next verify the service-identity file operations below and confirm an unrelated anonymous identity cannot traverse the export through the storage owner's supported access check. These access checks do not grant permission to create a datastore until its other prerequisites pass.

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

Use the verified hypervisor/physical console or separately authorized SSH session that remains available while both PBS services and their web interface are stopped. Do not use the PBS web Shell for this test. Run the commands below **individually**, checking each expected result and recording its status immediately with `echo "$?"` before entering the next command. Some commands intentionally return nonzero: do not paste the whole negative-test sequence into a shell with `set -e`, or join it with `&&`. Never force or lazily unmount a busy datastore.

```bash
systemctl stop proxmox-backup-proxy.service proxmox-backup.service
systemctl is-active proxmox-backup-proxy.service proxmox-backup.service
systemctl stop mnt-backup.mount
findmnt --mountpoint /mnt/backup
runuser -u backup -- test -w /mnt/backup
/usr/local/sbin/pbs-storage-ready
```

Expected: both stop commands succeed; both services are `inactive` (`is-active` returns nonzero); `findmnt` finds no mount and returns nonzero; the write-access test and helper both return nonzero. Stop if any check disagrees.

Prevent automatic mounting only during this negative check using a new runtime condition drop-in. A runtime whole-unit mask is unsuitable here because the mount unit in `/etc` takes precedence over `/run`. In the **same root Bash session**, use these exact commands:

```bash
PBS_MOUNT_TEST=$(mktemp -d /run/pbs-storage-test.XXXXXX)
test ! -e "$PBS_MOUNT_TEST/allow" && test ! -L "$PBS_MOUNT_TEST/allow"
install -d -m 0755 /run/systemd/system/mnt-backup.mount.d
PBS_MOUNT_DROPIN="/run/systemd/system/mnt-backup.mount.d/$(basename "$PBS_MOUNT_TEST").conf"
( set -C; printf '[Unit]\nConditionPathExists=%s/allow\n' "$PBS_MOUNT_TEST" > "$PBS_MOUNT_DROPIN" )
systemctl daemon-reload
systemctl cat mnt-backup.mount
systemctl show mnt-backup.mount -p DropInPaths
```

`systemctl show` can render `Conditions=[unprintable]`; that is not proof that a condition is absent or correct. Inspect the typed systemd D-Bus values instead. In the same session, run this complete read-only check before attempting either service start:

```bash
PBS_MOUNT_TEST="$PBS_MOUNT_TEST" PBS_MOUNT_DROPIN="$PBS_MOUNT_DROPIN" python3 - <<'PY_CONDITION'
import json
import os
import subprocess

def bus(*args):
    return json.loads(subprocess.check_output(
        ['busctl', '--system', '--json=short', *args], text=True))

marker = os.environ['PBS_MOUNT_TEST'] + '/allow'
dropin = os.environ['PBS_MOUNT_DROPIN']
unit = bus('call', 'org.freedesktop.systemd1', '/org/freedesktop/systemd1',
           'org.freedesktop.systemd1.Manager', 'GetUnit', 's', 'mnt-backup.mount')
if not (unit.get('type') == 'o' and isinstance(unit.get('data'), list)
        and len(unit['data']) == 1 and isinstance(unit['data'][0], str)
        and unit['data'][0].startswith('/org/freedesktop/systemd1/unit/')):
    raise SystemExit('Unexpected mount unit object')

def prop(name):
    return bus('get-property', 'org.freedesktop.systemd1', unit['data'][0],
               'org.freedesktop.systemd1.Unit', name)

paths = prop('DropInPaths')
if not (paths.get('type') == 'as' and isinstance(paths.get('data'), list)
        and all(isinstance(path, str) for path in paths['data'])
        and paths['data'].count(dropin) == 1):
    raise SystemExit('Test drop-in is not loaded exactly once')
conditions = prop('Conditions')
rows = conditions.get('data')
if not (conditions.get('type') == 'a(sbbsi)' and isinstance(rows, list)
        and all(isinstance(row, list) and len(row) == 5
                and isinstance(row[0], str) and type(row[1]) is bool
                and type(row[2]) is bool and isinstance(row[3], str)
                and type(row[4]) is int for row in rows)):
    raise SystemExit('Unexpected typed condition data')
selected = [row for row in rows if row[3] == marker]
if not (len(selected) == 1
        and selected[0][:4] == ['ConditionPathExists', False, False, marker]
        and not os.path.lexists(marker)):
    raise SystemExit('Required absent-marker condition is missing or optional')
print('Loaded mandatory, non-trigger, non-negated absent-marker condition')
PY_CONDITION
```

The last integer is the condition's evaluation result; it may still be untested before a start attempt. The check requires the exact loaded drop-in and one matching **mandatory, non-trigger, non-negated** condition, with the marker still absent. If it refuses or `busctl` is unavailable, stop; do not proceed using the rendered string alone. Record the two exact test paths for cleanup. Then run each command below individually, record its status immediately and inspect each service's resulting state regardless of the start command's exit status:

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

First return to [create and verify the datastore](server.md#create-and-verify-the-datastore-once). Create separate `full` and `recovery` child directories through the supported datastore operation where your plan requires them, and wait for each creation task to finish successfully. Record their identities before rebooting; there is no datastore identity to verify before creation.

Then perform the [one planned persistence reboot](server.md#verify-the-completed-storage-setup-after-reboot), after mount/service qualification and datastore creation. After normal login through your independent access route, run the identity helper and inspect both service states and each datastore's backing filesystem. Confirm the expected network, exact mount, service ordering and datastore identities all return. A mount entry in a file is not evidence of successful reboot behavior.

Keep the qualification directory until its evidence and cleanup scope are reviewed. Never delete existing data to repeat a test. Only explicitly inventoried disposable test objects may be reset for the [clean rehearsal](operations.md#rehearse-an-amended-guide-from-a-clean-setup).

When these checks pass, continue with [encrypted backup and independent restore verification](operations.md). Neither successful NFS mounting nor a green CD run establishes recoverability.
