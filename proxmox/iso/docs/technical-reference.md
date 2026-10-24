# Technical reference

The main README is the operator walkthrough. This page explains implementation details and change boundaries.

## Supported vendor inputs

The build is intentionally tied to these exact x86-64 artifacts:

| Artifact | Version / SHA-256 |
| --- | --- |
| Proxmox VE source ISO | 9.2-1; `4e88fe416df9b527624a175f24c9aa07c714d3332afb1ee3dbf3879573ef2c6c` |
| Auto-install assistant | 9.2.8; `19c786bf633e9c10631932cc8bcf1920153776995a25002c5c2fa818e405183e` |
| Native auto-installer executable | `e0c76415d3511ad018c0949c7a9e5df4a5e1751ba729a37472264904c971b03e` |
| Original vendor startup script | `7a5be4ff18f286b9216811a6216e3ddd098d49206d4c900192c75b3c89b74d7c` |
| Debian container base | trixie-slim manifest digest `62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad` |

[Official ISO download/checksum page](https://www.proxmox.com/en/downloads/proxmox-virtual-environment/iso).

The assistant fetch checks release-key fingerprint `24B30F06ECC1836A4E5EFECBA7BCD1420BFE778E`, the signed InRelease, package-index digest, package digest and extracted executable digest. The signing key comes from the HTTPS vendor endpoint. The public APT endpoint uses HTTP, with content authenticated through that signed chain. No TLS verification is disabled. Derived vendor build inputs also receive a digest receipt; partial or altered cached inputs are refused. If the pinned helper is no longer in the repository, fetching stops; there is no upgrade fallback.

The base container digest is pinned. Debian package versions installed into it are not all individually locked, so this workflow does not assert byte-reproducible Docker or ISO builds. Each build pins the resulting native artifacts and records its own final image digest.

## Build and launch sequence

1. Verify source ISO/helper/runtime/startup pins and validate the closed site/hardware inputs.
2. Generate an answer with two nonresolving disk placeholders and a first-start network payload. Native assistant validation must succeed.
3. Prepare the vendor ISO, preserving its BIOS/UEFI hybrid boot records.
4. Export/rebuild SquashFS using pseudo metadata so vendor ownership, modes, timestamps, links and extended attributes are preserved. The root directory mode, UID, GID and timestamp are retained explicitly, including when the build runs as an ordinary user. Only the selected startup file changes. The native installer executable remains byte-identical.
5. Bind the embedded members to a manifest digest pinned in startup. Replace the sole automatic native launch with the attended guard, and bound the initial DHCP wait. The menu offers CHECK ONLY and guarded INSTALL, with normal and serial-console entries.
6. At boot, validate mounted read-only media, embedded member hashes, machine UUID, UEFI, boot ID, live/vendor disk inventory and capacity agreement, exact serial/alias pairs, protected original, both NIC identities and runtime hash.
7. CHECK ONLY holds. INSTALL requires the exact two-target phrase, then repeats the media and same-boot observation checks. Only then does it replace placeholders with current device paths in RAM and exec the unchanged native installer.
8. Successful installation powers off. A later first start validates pinned NIC identities and writes the tagged two-bridge configuration, preserving the vendor interfaces file and refusing repeats.

The observer, live guard and shared core originated in the qualified local installer. Review subsequently updated the guard's runtime-failure handling and the retained core's legacy helpers; the observer remains unchanged. Build configuration, first-start rendering, CLI packaging and USB selection were adapted for this package. Earlier target-specific receipts are not treated as proof of the revised package's complete workflow. Current qualification results are recorded separately in `verification/README.md`.

Vendor trust checks use explicit exceptions and remain enabled under Python optimisation. Media qualification requires successful metadata verification bound to the current build receipt's SquashFS SHA-256, so an earlier build's metadata receipt cannot admit a replacement image.

The retained core module includes older compiler helpers; they are not exposed by this package's commands. The legacy separately signed, installer-session-bound compiler contract was not loosened or relabelled as this static-media contract. Its unavailable mirror path explicitly refuses; the static ISO builder owns this package's two-disk mirror. Legacy signature verification returns the captured verified signature together with the request, for callers to pass directly into bundle compilation. Rendering and manifest validation finish before a bundle directory is created, and the manifest hashes the single rendered answer.

The generated `/etc/network/interfaces` is root-owned with mode `0644`: root can modify it, and local users can read it. This follows [Proxmox's network configuration writer](https://github.com/proxmox/pve-common/blob/master/src/PVE/INotify.pm), which registers that file without a permission override and defaults to `0644`. The generated content contains interface names, addresses, VLANs and a gateway; it contains no passwords, private keys or password hashes. The CodeQL world-readable-file report is reviewed as an intentional permission choice for this specific payload. Credential inputs retain their separate restrictive permissions.

## Disposable tests

Unit tests cover identity conflicts, observed/native inventory agreement, answer transport framing, confirmation timeout, template replacement, profile validation, network rendering and preservation, and bounded USB selection/receipt behavior.

QEMU uses new sparse NVMe disks with separate subsystem identifiers, an emulated UEFI machine and a read-only USB image. It receives no host block device or production route. Cases run serially under container CPU/memory limits. Each receipt records the exact image digest and QMP target-disk write counters; each VM is stopped and reaped. Linux rejecting a duplicate controller before it is visible is not credited as a guard duplicate-identity pass.

The practice image has a no-op first-start payload and unusable synthetic password hash. It is for guard tests, not a successful native installation rehearsal. Physical install/boot/ZFS, actual first-start hook execution and network/SSH acceptance remain separate.

The selected ZFS profile uses a two-disk RAID1 mirror, ashift12, LZ4 compression, one copy and a 2048MiB ARC maximum. These are fixed profile choices in this version, not automatically sized hardware recommendations.

## Updating the supported release

Changing a version or checksum alone is insufficient. Inspect the new vendor startup/answer transport, native device-inventory representation, disk-list matching, interface pinning, filesystem metadata and boot records. Update the pins and affected source only after that review, then run the affected source and disposable boot tests. Preserve failed results. There is no automatic latest-version substitution or failed-target replay.

## USB helper

Only an explicitly selected external physical USB whole disk is supported, and other external physical disks must be disconnected. The saved model/capacity/port identity and original partition layout are rechecked before opening its raw device. Real-image digest and current acceptance are required; fixture images are refused. An existing operation receipt prevents replay.

Write mode records progress before writes, removes the old backup partition table only at the selected USB's tail, writes the image, syncs, reads the full image back, checks its SHA-256 and ejects. Partial failure is recorded. The helper does not boot a target, write its internal SSDs or grant Mac administrator privileges; the operator authenticates normally.
