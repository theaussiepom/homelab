# Verification status

Reverified on **25 October 2026**, using Docker Desktop on an Apple Silicon Mac. These are bounded preparation results, not acceptance of a physical Proxmox deployment.

| Check | Result |
| --- | --- |
| Documented Docker tool-image builds | Passed. |
| Vendor ISO/helper/runtime verification and derived-input preparation | Passed using the existing public download cache, with its signed chain and digests rechecked. The full network download was not repeated. |
| Source checks locally and in the documented Docker builder | **29 tests passed**, with matching source digests. |
| Practice ISO build, native answer parser and embedded-file readback | Passed. |
| Private-input build path | Passed using invented hardware/site settings and unusable synthetic credentials. No real private inputs were copied. |
| Vendor filesystem metadata | All **25210 other records preserved**; the startup script is the sole intentional changed record. |
| Matching virtual hardware | CHECK ONLY passed and stopped, with zero target-disk writes. |
| Wrong machine, missing disk and duplicate disk identities | Refused for the expected reasons, with zero target-disk writes. |
| Cancelled installation confirmation | Refused, with zero target-disk writes. |
| Exact private-input image on the wrong virtual machine | Refused the machine UUID, with zero target-disk writes. |
| Physical installation / first-start networking | **Not performed.** Still requires the actual target and its installation window. |
| Reusable USB helper physical write | **Not performed for this package.** Selection and receipt behavior have source tests. The earlier target-specific writer completed its own full physical write/readback. |

The six new accepted boot receipts bind the rebuilt images' exact hashes. The guard now holds on ordinary runtime failures, and retained legacy compiler helpers have bounded review fixes. The observer remains unchanged. Seven new regression tests cover optimised-Python trust checks, stale metadata, guard failures, unsupported legacy mirror compilation, captured signature bytes, output creation and single-render manifest consistency. All 29 source tests passed locally and in Docker. Earlier image results were not credited to the revised images.

During the original packaging qualification, two local failures were retained and corrected: the first ordinary-user build changed root ownership metadata, and one test missed the serial-console menu entry. Root ownership/mode/time are now explicit, menu selection waits for the complete menu and paces keys, and the affected images/case were checked again. Failed/incomplete cases are not counted as passes. Raw logs and generated test images remain outside Git.

The generated network interfaces file intentionally retains mode `0644`, following Proxmox's network writer convention for this payload without credentials. Its CodeQL report is documented in the [technical reference](../docs/technical-reference.md); no blanket suppression was added. The metadata preservation receipt now includes the verified SquashFS hash, which media acceptance requires to match the current build.

The interactive password prompt was not exercised with a real credential during packaging. Linux and other build hosts were not separately qualified. Successful full native installation, physical cabling/switching, first-start hook execution, network/SSH access and guest/application rollout are separate outcomes.

The original completed USB was not changed. All new image builds used synthetic or invented integration inputs. These verification runs performed no physical installation or live service operation; repository publication is separate from deployment.

- [Machine-readable validation summary](validation.json)
- [Source file checksums](source-manifest.json)

A build receipt records the build phase; the separate acceptance record records later test completion. For a new local build, `make qualify` produces `evidence/media-acceptance.json` for that build's exact image hashes.
