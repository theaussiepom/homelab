# Local network recovery on BenBeast

[Back to the main README](../../README.md)

This service watches for two specific Docker network faults after an adapter
interruption and can repair them within strict limits. It runs locally on the
existing BenBeast Linux host, even when NAS monitoring is unavailable.

**This is not a generic network fixer or a Proxmox setup step.** Its installer
is restricted to the host named `ben-beast`. It needs reviewed private settings
for that host. Publishing these files does not install or enable the service.

## What can it repair?

| Fault | What it can do | What it will not do |
| --- | --- | --- |
| Missing overlay forwarding entry | Add one verified missing destination for the configured `underground` overlay. | Replace/delete/flush forwarding entries or guess peer identities. |
| Missing macvlan address | Restart the same enrolled container when its configured static LAN address is absent from its actual network namespace. | Restart stopped containers, pull images, recreate containers or restart for ordinary application errors. |

An **overlay** connects containers across Docker hosts. **Macvlan** gives a
container its own address on your LAN. Only the existing enrolled containers
`hass`, `mass`, `nodered`, `pgadmin` and `traefik` can be restarted by this code.

The service runs as root because these repairs inspect network namespaces and
kernel forwarding entries. It exposes no inbound listener/API or remote shell,
stores no passwords and needs no NAS/Zabbix connection to start or record status.
Zabbix enrollment is separate work.

## 1. Try the source checks safely

You can run the tests on your workstation without installing the service.
From the **repository root**:

```sh
cd services/network-recovery
python3 -m unittest discover -s . -p 'test_*.py' -v
```

**Expected result:** the test summary ends with `OK`. The checks use synthetic
faults and local loopback test servers; they do not disconnect an adapter or
repair a real Docker network.

## 2. Prepare the intended Linux host

Installation is for an administrator making a reviewed change on `ben-beast`.
Use the [installation reference](INSTALLATION.md) to stage the fixed payload,
both systemd unit files and the private `network-recovery.json`.

The public synthetic fixture is test data, not a ready-made live configuration.
The installed files/state must be root-owned on a supported local block-backed
ext4, XFS or Btrfs filesystem, independent of the NAS. The installer checks these
conditions and refuses unsupported destinations.

On the **intended Linux host**, from the reviewed staging folder, run the dry run:

```sh
sudo /usr/bin/python3 ./install.py
```

**Expected result:** JSON with `"status": "dry_run"` and the proposed file list.
It does not install/enable the service. It still requires root and the correct
host. A refusal is a reason to inspect the prerequisite, not remove the guard.

## 3. Install only after reviewing the dry run

The following command **changes the host and enables automatic repairs**.
Run it only for the intended, reviewed deployment:

```sh
sudo /usr/bin/python3 ./install.py --apply
systemctl status homelab-network-recovery.timer --no-pager
cat /var/lib/homelab-network-recovery/status.json
```

**Expected result:** installation reports `"status": "installed"` with
`"audit_healthy": true`; the timer is enabled, and the status is healthy/fresh.
The installer validates units and requires a healthy audit before enabling the
timer. The timer's first check starts 30 seconds after activation.

A timer being active does **not** mean the network is healthy. Read the JSON
health and its observation time too. Installation receipts and previous managed
files are retained under `/var/lib/homelab-network-recovery/installations/`.
The installer preserves runtime safety state; see [rollback details](INSTALLATION.md).

## 4. Read health without requesting a repair

On the host, run a manual audit:

```sh
sudo python3 /usr/local/lib/homelab-network-recovery/recovery.py
```

This observes the network and updates local status/observation records without
requesting repairs. Its exit codes are:

| Exit | Meaning |
| --- | --- |
| `0` | Configured network/readiness checks are healthy. |
| `2` | Degraded, settling or waiting; inspect the JSON reason. |
| `1` | Unexpected failure. |

Checks include Home Assistant's Z-Wave WebSocket path, the configured Zigbee2
listener and Node-RED's path to the HA frontend. These establish network
readiness, not authenticated application state, every HA entity, a physical
smoke detector or music playback. HA handles its own integration reconnection.

## When something goes wrong

| What you see | What to do |
| --- | --- |
| Wrong host, missing config or unsafe destination | Recheck the [installation prerequisites](INSTALLATION.md). Do not substitute the synthetic fixture for live settings. |
| `healthy: false` or stale status | Read the reason, current timestamp and service journal; timer state alone is insufficient. |
| NAS prerequisite unavailable | Let the repair defer. A NAS-dependent container cannot safely restart without its required access check. |
| Interrupted or uncertain operation | Preserve the receipt and investigate the exact container/network state. The halt survives restarts. |
| Node-RED left stopped after an interrupted HA repair | The receipt identifies the dependency and ownership. Inspect it before deliberately resuming that same container. |
| Failed installation/rollback | Read its installation receipt. An incomplete rollback needs review before resuming the schedule. |

After investigating and resolving an interrupted operation, an administrator can
explicitly acknowledge the halt with a healthy audit. This does not request a repair:

```sh
sudo python3 /usr/local/lib/homelab-network-recovery/recovery.py --acknowledge
```

To stop future scheduled runs:

```sh
sudo systemctl disable --now homelab-network-recovery.timer
```

This does not kill an in-flight transaction. Inspect the service before changing
its files. Never delete `state.json` to bypass a halt/cooldown or restore old
safety state from an installation backup.

## How the repair limits work

The timer runs 30 seconds after the previous check finishes. The adapter/VLAN
must be up and stable for at least 60 seconds, and an unchanged fault must persist
for 60 seconds. Each run permits at most one transaction, with at most six per
hour and a 15-minute same-target cooldown. Boots, config changes and observation
gaps over 120 seconds reset settling.

Before an overlay add, current task/peer, namespace, VXLAN, neighbour and
forwarding identities must agree; the peer must be reachable. Identities are
checked again before and after the add. Conflicts stop repair.

Before a container restart, NAS-dependent apps need fresh bounded NAS
metadata/read access. Unreaped I/O halts the operation. The same container's ID,
image, configuration, mounts, restart policy, network options and static
addresses must be preserved; dynamic leases may change.

For HA, only its configured running Node-RED dependency is stopped first.
Ownership and exact identity are recorded; that dependency resumes after HA is
ready. A container already stopped is never started by this repair.

## Where to find results

| Location under `/var/lib/homelab-network-recovery/` | Contents |
| --- | --- |
| `status.json` | Readable health, timestamp, issues, probes and last repair/success. |
| `state.json` | Root-only settling, rate limits and interrupted-operation bookkeeping. |
| `receipts/` | Root-only intent, changes and acceptance records. |
| `installations/` | Private managed-file backups and installation/rollback receipts. |

The journal records transitions without repeating unchanged healthy reports.
Synthetic tests do not establish a fresh real fault/recovery cycle. Target-host
audit, timer acceptance and any actual recovery need their own observations.
Underlying Docker/NIC defects are separate from these bounded repairs.
