# What the installer tests establish

[Back to the installation USB guide](../README.md) ·
[Whole Proxmox sequence](../../README.md)

The installer has passed source checks, image builds and guarded virtual boot
tests. A later installation on the maintainer's physical host is recorded below.
**Your computer still needs its own installation and checks.**

A **receipt** is a saved result identifying the exact files/image checked.
A **checksum** identifies file contents; changed contents produce a different
checksum. A result for an earlier image does not qualify a new image.

## Read the results at a glance

The packaged checks were reverified on **25 October 2026**, using Docker Desktop
on an Apple Silicon Mac. A later code correction was checked separately:

| Check | Result | What that means for you |
| --- | --- | --- |
| Docker tool images and vendor inputs | Passed. Existing public downloads were rechecked, including signed verification; the full download was not repeated. | The documented build tools and selected inputs worked in that environment. |
| Packaged source suite | 29 tests passed locally and in Docker. | Configuration, guards and reviewed failure paths passed at that recorded source. |
| Later malformed-catalogue correction | 30 tests passed locally and in Docker; its regression failed before the fix. | Null, array, text, numeric and boolean hardware entries receive the intended refusal. |
| Practice image build and embedded-file readback | Passed. | The image contained its intended files and a native-parser-valid answer. |
| Build with private-style inputs | Passed with invented settings and unusable synthetic credentials. | The build path worked without publishing real private inputs. |
| Vendor filesystem metadata | All 25,210 other records preserved. | The startup script was the sole intentional changed record. |
| Six guarded virtual boot cases | Passed, with zero target-disk writes. | The cases below checked the image's stop/refusal behaviour. |
| Physical installation and first-start networking | Not performed in that packaged qualification; a later physical result is recorded below. | Check your own machine at installation. |
| Physical write by the reusable USB helper | Not performed for this package. | A fresh write needs its own complete readback receipt. An earlier target-specific helper completed a separate write/readback. |

The detailed [validation summary](validation.json) binds the earlier qualification
to its exact source and image hashes. [The source manifest](source-manifest.json)
records a later source snapshot. They are historical records, not manifests to
silently regenerate after a documentation edit or proof that every later checkout
was boot-tested. Current PR build/boot results appear in
[GitHub Actions](https://github.com/theaussiepom/homelab/actions/workflows/ci.yml).

## Later physical installation: 25 October 2026

The maintainer installed the custom ISO on the intended pair of new SSDs.
Authenticated host checks found the new two-drive ZFS mirror `ONLINE` with no
reported data errors, the original disk present outside that mirror, both named
network interfaces up, the configured VLAN addresses and the management route.
The web interface and SSH access worked after the host's SSH fingerprint was
compared with its local console.

The real installation required the selected Thunderbolt adapter's authorisation
fix. Network access also required correcting the physical switch port and the
management VLAN on a connecting uplink. These observations explain the
walkthrough's cable/VLAN checks; the ISO does not configure switches or routers.

The [physical bootstrap record](../../bootstrap/verification.md#physical-host-bootstrap-passed-after-a-correction-on-25-october-2026)
continues from that installed host to one guest and a real GitHub check. The
operator subsequently reported returning to the original Ubuntu system.

This records first-start installation/access, not every future physical reboot,
every file on the original disk or household application acceptance. It does
not replace the earlier image-specific receipts or qualify someone else's build.
Private hardware identities, network settings, credentials and raw evidence
remain outside this public summary.

The subsequent PR review corrected uppercase machine-UUID handling and added
revocation of a newly granted adapter authorisation after failed MAC validation.
**45 source tests passed** after those regressions first failed. These later
failure-path changes were not exercised on the physical host, and do not update
an already installed helper or an existing USB. A new image still needs its own
build, qualification and write/readback results.

## What did the six boot cases do?

| Case | Expected and observed result |
| --- | --- |
| Matching invented computer | CHECK ONLY succeeds and stops. |
| Wrong machine | Refuses the machine UUID. |
| Missing disk | Refuses the incomplete layout. |
| Duplicate disk identity | Refuses the ambiguous layout. |
| Cancelled installation confirmation | Refuses to launch installation. |
| Real-image build path on the wrong virtual computer | Refuses the machine UUID. |

Five cases use the practice image; the sixth uses the invented-input build path.
All six accepted receipts identify their rebuilt images. They stop before a
native installation and cannot prove that a mirror, physical port or switch
works after installing your host.

## 1. Check a new image you build

Return to the [ISO walkthrough](../README.md) and run its practice tests, then
`make build`, `make test-profile` and `make qualify` for your own settings.

**Expected result:** `make qualify` creates
`evidence/media-acceptance.json` for the current exact image hashes. A build receipt
alone records construction; it does not replace the later acceptance record.

After USB writing, wait for `usb_ready: true`, `readback_verified: true` and
`ejected: true` in that operation's receipt.

## 2. Check the actual installation

At your chosen installation window, use the
[attended installation steps](../README.md#6-boot-and-install--at-your-chosen-maintenance-window),
then [host access and checks](../../host-access.md).

**Expected result:** the intended host, healthy new mirror, preserved original
disk identity, correct port/address setup and working verified SSH access.
Those observations belong to your installation, not to the earlier virtual tests.

## When a check fails

Keep the failed files and console output. Use the
[ISO troubleshooting table](../README.md#when-something-goes-wrong).
Do not count an incomplete/queued case as a pass, delete failure receipts, or
credit earlier images' results to a revised image.

During qualification, an initial build changed root ownership metadata and a
test missed the serial-console menu entry. Both failures were preserved.
Ownership/mode/time handling and paced menu selection were corrected, and the
affected images/cases were checked again.

## Technical detail and limits

The earlier packaged review covered optimised-Python trust checks, stale metadata
and ordinary guard failures. Its historical test counts included an older compiler
that has since been removed, together with its tests. Current source coverage is
measured by the framework's report-only coverage command; these historical boot
results do not qualify later source changes. The observer remains unchanged.

The generated network file intentionally uses Proxmox's conventional `0644`
mode and contains no credentials. See the [technical reference](../docs/technical-reference.md)
for its CodeQL explanation. No blanket suppression was added. The metadata
receipt also binds the verified SquashFS hash required by media acceptance.

Real-password interactive entry, other build hosts, physical installation,
cabling/switching, first-start hook execution and guest/application rollout were
not established by these packaged tests. The original completed USB was not
changed. Builds used invented inputs, and raw logs/images stayed outside Git.

Follow [the next guest guide](../../bootstrap/README.md) only after your host's
installation checks pass.
