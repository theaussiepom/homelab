# Supported scope

The implemented application platform is Debian13 LXC on Proxmox.
VM guests, arbitrary physical fleet targets and universal hardware support are
not implied. Host bootstrap/ISO/network recovery are separate subsystems.

## Adapter capability matrix

This is the framework adapter boundary, not a promise that every library profile
or private installation has completed native commissioning.

| Adapter | Execution | Fresh behavior / important limits |
| --- | --- | --- |
| unbound | Compose | Fresh packaged config without empty storage binds; retained explicit config; distinct loopback publication permits instances |
| pihole | Compose host network | Supported fresh/owned helper path with declared upstream/storage; fixed DNS sidecar means one per guest |
| homeassistant | Compose | Create-only supported directory path; retained custom mDNS/startup path requires its existing capability and files |
| node_red | Compose host network | Fresh supported directory path; retained exact OIDC/settings/health wrapper and process identity |
| mqtt | Compose | Explicit probe/password/storage contract; existing broker/account identities preserved; no general credential bootstrap |
| mqtt_explorer | Compose gateway + app | Fresh/retained workspace with owned broker account or explicit existing credential and outpost/origin |
| cloudbeaver | Compose gateway + app | Fresh/retained owned workspace, OIDC/recovery identity and selected DB accounts |
| authentik | Compose server/worker/Redis | Existing database/private roles and optional exact callback update contract; source does not commission an IdP merely by selecting it |
| traefik | Compose | Declared ACME/provider/runtime contracts; trust/token prerequisites required |
| zabbix | Compose server/web | Selected database/auth/monitoring-owner prerequisites; root expansion does not invent placement |
| postgresql | Native packages/systemd | Exact version/data/listener/account ownership; current ordinary owned updates; source native render is not fresh database commissioning proof |
| mariadb | Native packages/systemd | Package-account and existing data/credential guards; no automatic import/rotation |
| influxdb | Native packages/systemd | Fixed native account/data/config ownership; no automatic organisation/bucket commissioning |
| bitwarden | Compose | Retained only; genuine environment/install/DB/data identity; normal declared image |
| zigbee2mqtt | Compose | Retained only; one owned serial coordinator; fresh commissioning refused |
| music_assistant | Compose host network | Retained only; existing /data and exact process/listener contract |
| pegaprox | Compose | Existing DB key/data and trusted private proxy; no arbitrary backend publication |
| winet | Compose | Single inverter, closed existing options/credential contract; no arbitrary vendor options |

Each library profile specifies actual required interfaces, storage, resource
minimums and software versions. A profile can be more restrictive than this
adapter matrix. Source-only acceptance is deliberately weaker than target
qualification; no unnamed fresh path is promised by this table.

## Placement and repeat instances

Repeated profiles must have disjoint owned listeners, data/runtime/custody files,
service/project namespaces and numeric/native account identities.
Unbound and namespace-capable proxy instances have source/packet tests for this.
Fixed Pi-hole/Zigbee sidecars and native unit names impose one-per-guest limits.
PostgreSQL plus InfluxDB can conflict in declared numeric group identities;
namespace checks refuse before packet emission. Co-location never permits
sharing another app's private leaf directory.

## Evidence levels

- Component units check contracts and negative boundaries.
- Real compiler/receiver tests check source composition and exact packets.
- Controller tests use genuine local receipts/state/payloads with native bodies faked.
- Docker/native fixtures verify their named isolated protocols or filesystem
  behavior only.
- Protected CD and real service/user/device verification establish an installation.

No source test creates deployment authority. See [Lifecycle](lifecycle.md) and
the selected library's profile-specific support page.

[Reference index](README.md)
