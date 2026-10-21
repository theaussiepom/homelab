# Local network recovery installation

The installer is restricted to root on host `ben-beast`. It installs a fixed payload from its own staged directory, not from arbitrary command-line paths. Run the dry-run first:

```sh
/usr/bin/python3 /path/to/staged/candidate/install.py
```

After the candidate and dry-run have been reviewed, the authorized deployment command is:

```sh
/usr/bin/python3 /path/to/staged/candidate/install.py --apply
```

Required staged files are `recovery.py`, `fdb.py`, `macvlan.py`, `probe.py`, `network-recovery.json`, and both `homelab-network-recovery` systemd units. The installer copies only those files. It compiles Python in memory, verifies the installed systemd units, and runs the default audit with the installed configuration. Only an exit code of 0 with JSON `healthy: true` permits enabling and starting the timer. It never invokes the recovery CLI with `--apply` itself.

| Destination | Ownership / mode |
|---|---|
| `/usr/local/lib/homelab-network-recovery/*.py` | root:root / 0755 |
| `/etc/homelab/network-recovery.json` | root:root / 0644 |
| `/etc/systemd/system/homelab-network-recovery.{service,timer}` | root:root / 0644 |
| `/var/lib/homelab-network-recovery` | root:root / 0755 when created |
| `/var/lib/homelab-network-recovery/installations` | root:root / 0700 |

The installer reads `findmnt` metadata before traversing the destinations and requires runtime, configuration, units and state to be on a local block-backed ext4, XFS or Btrfs filesystem. NFS, autofs, tmpfs and overlay destinations are rejected. The state directory is therefore independent of NAS/network availability. Its public status can be read by a future Zabbix check; non-root processes cannot modify configuration or runtime state. Installations neither delete nor replace runtime state files, including interrupted-attempt safety records. The pre-enable audit may update the core's normal observation/status records.

The timer starts its first check 30 seconds after activation and schedules subsequent checks 30 seconds after the service finishes. The root oneshot is bounded by 900 seconds and kills its process group on timeout. Exit 2 is an expected degraded/settling observation, represented in JSON status; internal errors use exit 1. `After=network.target docker.service` sets ordering only; there is no `Requires`, `Wants`, or network-online gate that prevents invocation when Docker or the network is unavailable. Host namespace entry requires retaining the host mount namespace and root capabilities; do not add `PrivateMounts`, `NoNewPrivileges`, or restrictive capability settings without validating `nsenter`/`setns` behavior.

The installer refuses symlinked destinations, non-root-owned or group/world-writable path components, hardlinked managed files, unexpected unit drop-ins, externally managed unit files, and masked/runtime-only timer enablement. A separate nonblocking installation lock prevents concurrent installers. It stops only the managed timer during an update, refuses to replace files while the recovery service is active, and holds the same `state/lock` used by the recovery core during payload replacement. It releases the core lock before running the audit. It does not restart Docker or any application container.

Every applied installation preserves exact previous managed file bytes, modes and ownership under a timestamped private installation directory, alongside a durable `receipt.json`. On failure it stops/disables the managed timer, checks the service is inactive and acquires the core lock before restoring previous managed files (or removing newly introduced managed files), then reloads systemd and restores the previous timer enablement and active state. If a manual or scheduled repair has become active, it does not kill it or overwrite its payload: rollback is marked incomplete and requires review. Runtime state is preserved. If rollback itself fails, the receipt records the failure and the timer stays stopped and disabled rather than resuming with an uncertain installation. Empty installation directories and failure evidence are retained.

Local offline tests:

```sh
python3 -m unittest discover -p 'test_install.py' -v
```

These tests exercise filesystem guards and install/rollback ordering using temporary files and a fake systemd adapter. Target-host `systemd-analyze verify`, healthy audit, actual root ownership and live timer acceptance must still be established during the separately authorized installation.
