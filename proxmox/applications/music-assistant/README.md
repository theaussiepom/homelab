# Bring Music Assistant across without losing its library

This profile prepares **one unprivileged Debian LXC running the requested latest Music
Assistant image in Docker**. OpenTofu creates the guest through the existing
[application module](../tofu/guest/main.tf); Ansible installs the selected packages,
restores the capture and runs bounded checks through the existing
[deployment workflow](../README.md). There is no separate deployment engine.

The public profile is reusable. Your private site supplies the image selection, guest addresses, package pins and capture references. Nothing
here contains a provider token, a library or a real player identity. This is
source preparation; native LXC operation and real provider/player acceptance
remain unverified.

## What stays with the server

Capture the **whole `/data` directory**: settings and their backup, server ID,
provider credentials, player IDs/groups, playlists, library and authentication
SQLite databases, WebRTC keys/certificate and cache. Keep a protected original.
A copy of a live SQLite main file can omit committed WAL data; arrange an approved
writer stop and coherent capture before migration. Preserve numeric UID/GID,
modes, ACLs and extended attributes using the existing capture/restore contract.
The archive must contain a `music-assistant/` directory, restored as
`/srv/homelab/data/music-assistant` and mounted at `/data`.

Keep the selected image's default process identity. Root **inside an unprivileged
LXC** does not map to host root. Do not convert owners to a new service user or
add PUID/PGID variables. Restoring a missing directory must fail rather than
creating an empty library.

## Choose listeners before the first start

A saved Docker bridge IP will not exist in the new LXC. On a separate candidate
copy of the stopped capture, review only these settings in `settings.json`:

- `core.webserver.values.bind_ip`: the assigned player-facing guest IPv4.
- `core.streams.values.bind_ip` and `publish_ip`: that same IPv4, explicitly.
- UI `bind_port` 8095 and stream `bind_port` 8097, or omit those port keys to
  retain these defaults. Keep the existing public `base_url` and credentials.

Preserve the untouched original and verify the semantic diff contains only the
approved listener changes before hashing the candidate archive. This profile
**does not rewrite settings**. `profile.py` reads the restored settings and holds
startup for stale listeners, missing library/auth files or additional enabled
providers. It permits the provider set inspected for this migration; a newly
configured provider needs review, even if it is disabled elsewhere in your UI.
Database header checks identify required files; they do not prove database
integrity, row counts, credential validity or complete preservation.

Set `music_bind_address` in the stack and `app.music_address`
in the site input. Deployment validates that the selected address belongs to the
guest. Use the explicitly requested `ghcr.io/music-assistant/server:latest`, `restart: no` and `start_on_boot: false`
while qualifying the guest. `latest` uses `pull_policy: always`, so each explicit
start may select a newer stable image; no updater or schedule is added. Record
the actual image ID/version from that run. Keep the untouched pre-upgrade capture
and original image for rollback; never point the old server at state migrated by
a newer release. Retain the normal Docker entrypoint and image user.

## Networking and privileges

Docker uses the **guest's host network namespace**, not the Proxmox host's.
No host devices, control sockets, NAS mounts, extra capabilities or unconfined
AppArmor are added. Nesting enables Docker within the unprivileged guest;
`keyctl: false` follows the existing guest base and still needs native testing
for this service.

The inspected provider set uses streaming services and network players, with no
filesystem/share provider. Upstream documents mount capabilities as necessary
only when Music Assistant mounts a share itself. Their presence in an old
Compose file alone does not prove a requirement. If a share provider appears,
hold and review its exact mount requirement; do not silently add SYS_ADMIN,
DAC_READ_SEARCH, privileged LXC, a VM or a new NAS library.

| Path | Why it is needed | Admission before live start |
| --- | --- | --- |
| Runner → guest SSH22 | Existing deployment path | Pinned CA/host key, selected guest/storage/network access |
| Existing proxy/approved clients → UI8095 | Local info, web UI and WebSocket API | Preserve the existing TLS and local/tablet access policy |
| Enabled players → TCP8097 | Players fetch streams from the published address | Exact enabled player identities and return path |
| Home segment mDNS UDP5353, IPv4 224.0.0.251 | AirPlay, Chromecast and Sendspin discovery | Confirm selected Home interface and multicast route; no reflector introduced |
| Home segment SSDP UDP1900, IPv4 239.255.255.250 | Enabled DLNA discovery | Scope to the existing Home segment; confirm interface and replies |
| Sendspin clients → TCP8927 | Installed Sendspin listener | Exact admitted clients; keep WebSocket proxy behavior |
| Server ↔ enabled devices | AirPlay/Cast/DLNA control, callbacks and negotiated media | Exact device/port requirements, including dynamic ports, remain commissioning inputs |
| Server → existing HA HTTPS endpoint | Retained HA integration | Preserve URL/token and trusted TLS; no test commands to HA |
| Server → existing DNS and provider HTTPS | Apple Music, Spotify and metadata | Preserve credentials; no provider login/sync test during preparation |

A multihomed guest needs explicit bind/publish choices and observation of
multicast interface selection. Merely allowing multicast in a firewall does not
prove discovery. Do not use a broad device port range or publish the UI through
new discovery labels that omit the old access policy. Default-deny proposal
rules deliberately omit unadmitted device allowances and must not be enabled
as a completed network policy. IPv6 multicast is an additional input if IPv6
players are required; the current candidate does not enable guest IPv6.

## What a passing check means

The Compose healthcheck performs an HTTP GET to this server's `/info` endpoint
and opens/closes its own stream8097 TCP listener without requesting any audio. Use the existing `plan → apply → stage → start → verify` path, exact saved-plan fingerprint, host-key check, capture
checksum, NAS state protection and failure holds. Retire old writers before
`deploy`/`start`; never put the old and new server on the same LAN identity.

The [synthetic fixture](../tests/music_assistant_fixture.py) starts the requested latest
image with invented state in disposable, resource-limited Docker using
a unique Docker `--internal` network with no peers, no published ports and
no real mounts or credentials. A real virtual interface is needed for discovery
initialization; loopback-only `--network none` fails multicast membership. The
internal network has no external route and is removed with the fixture. It
records the actual image ID/version and checks local HTTP and stream-listener readiness only. Its result does not qualify
Proxmox nesting, systemd boot, household routing, cloud providers or speakers.
Ben performs real provider, library, browser and speaker acceptance after a
separately authorized rollout. No playback, volume, queue or player commands
are part of preparation or service checks.

Upstream references: [installation and mount privileges](https://www.music-assistant.io/installation/),
[network troubleshooting](https://www.music-assistant.io/faq/troubleshooting/),
[system settings](https://www.music-assistant.io/settings/core/).
