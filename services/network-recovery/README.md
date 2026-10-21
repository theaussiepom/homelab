# BenBeast local network recovery

Host-local recovery for missing overlay forwarding entries and missing macvlan
addresses after an adapter interruption. Reusable source is maintained here;
private configuration, runtime state and installation receipts remain on the host.
Zabbix enrollment is a separate deployment step.

The root service performs narrowly guarded network repairs. Publishing this source
does not authorize installation or changes to its privileges. Review the unit,
private configuration, target identities and dry-run evidence before deployment.

## Operation

`homelab-network-recovery.timer` runs 30 seconds after the previous check completes.
The host service requires root to inspect Docker network namespaces and repair the
kernel forwarding table. It has no inbound API, listener, remote shell facility,
stored passwords, or dependency on the NAS/Zabbix for starting and recording status.

The configured adapter identity and VLAN must be up, with recent stable observations
for at least 60 seconds. Each unchanged fault must also persist for 60 seconds.
The process locks its local state; it makes at most one repair transaction per run,
at most six per hour, and waits at least 15 minutes before repeating the same target.
Configuration changes, host boots and observation gaps longer than 120 seconds reset
settling. An interrupted operation remains halted across restarts and host boots.

### Missing overlay forwarding entry

For the configured `underground` overlay, read current Docker task/peer identities,
network namespace, VXLAN device/VNI, permanent ARP neighbour and bridge forwarding
record. Add a VXLAN `self` destination only when that destination is absent and all
other evidence agrees. Confirm the peer is reachable first. Recheck identities
immediately before and after the add. No hard-coded Z-Wave MAC, IP or endpoint ID;
no replace/delete/flush operation is available. Conflicts require inspection.

### Missing macvlan address

Only these enrolled existing containers can be restarted: `hass`, `mass`, `nodered`,
`pgadmin`, `traefik`. A repair requires a declared static LAN address that is actually
absent from the container's kernel namespace. Ordinary application errors, listener
failures, stopped containers or unavailable entities do not authorize a restart.

Require the expected NAS export plus fresh bounded NAS metadata/read access before
restarting a NAS-dependent application. An offline prerequisite defers the repair;
an unreaped I/O process halts it for review. Restart the same container without image
pulls, recreation or detach/attach. Verify ID, image, configuration, mounts, restart
policy, network options and static addresses are preserved; dynamic leases may change.

For HA, stop only its configured running Node-RED dependency first. Record that
ownership and exact container identity. After HA is ready, resume that same dependency;
never start a container that was already stopped. If interrupted or uncertain, preserve
the receipt and halt rather than replaying a stop/restart. Node-RED may require manual
resumption in this exceptional case; the receipt identifies it explicitly.

Readiness checks include the rebuilt namespace, actual LAN address, Docker stats,
listener on its configured network, default route and configured discovery multicast
memberships/routes. They establish transport/readiness, not authenticated application
state, physical smoke-detector function, or successful music playback.

## Monitoring

- `/var/lib/homelab-network-recovery/status.json`: root-owned, readable current status,
  health, observation timestamp, issues, configured connection probes, last repair and
  last success. Suitable for a future read-only Zabbix item. Monitor freshness too.
- `state.json`: root-only settling, rate-limit and interrupted-operation bookkeeping.
- `receipts/*.json`: root-only durable intent, individual mutations and acceptance.
- `installations/*`: exact managed-file backups and installation/rollback receipts.
- Journal: state transitions; unchanged healthy checks do not emit repeated reports.

Configured service checks currently verify HA to Z-Wave via a WebSocket handshake,
HA to Zigbee2's listener, and Node-RED to the HA frontend. Names and probe types are
configuration, not device-specific repair code. The daemon does not use HA credentials
or reload integrations; HA's own connection retry remains responsible after transport
recovery. `healthy` means these network/readiness checks passed, not every HA entity
or household function is healthy.

Audit exit codes: 0 healthy, 2 degraded/waiting, 1 unexpected failure. systemd accepts
exit2 as an expected observation; its unit state is not a substitute for JSON health.

## Install and verify

See `INSTALLATION.md`. The root-only installer defaults to a dry run. `--apply`
installs fixed root-owned files, validates the unit files, runs a full non-mutating
audit and enables the timer only if the audit explicitly reports healthy. It preserves
runtime safety state and restores prior managed files/schedule state on safe rollback.

```sh
sudo python3 ./install.py --apply
systemctl status homelab-network-recovery.timer --no-pager
cat /var/lib/homelab-network-recovery/status.json
```

Run a manual audit:

```sh
sudo python3 /usr/local/lib/homelab-network-recovery/recovery.py
```

After investigating and resolving an interrupted/failed operation, a healthy audit
can explicitly acknowledge the halt. This does not perform a repair:

```sh
sudo python3 /usr/local/lib/homelab-network-recovery/recovery.py --acknowledge
```

Disable future runs with `sudo systemctl disable --now homelab-network-recovery.timer`.
This does not kill an in-flight transaction; inspect the service before changing its
files. Never delete `state.json` to bypass a halt or cooldown. Do not restore old safety
state from an installation backup.

## Validation and limits

Tests use synthetic failure scenarios and loopback protocol servers. Run
`python3 -m unittest discover -s . -p 'test_*.py' -v`. Target-host audit and timer
acceptance are recorded separately by the installing operator. No physical adapter
disconnection is part of installation, and a fresh real failure/recovery cycle is not
claimed without observing one. Underlying Docker/NIC defects remain separate from
repairing the verified inconsistent network state.
