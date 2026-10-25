# Bootstrap verification

`bootstrap test` checks the current source snapshot inside an isolated Docker
container: the small site example, guest selection, saved-plan safety,
workstation GitHub token handling, local workspace locking, one-way state
handover and backups, provider-schema mock plans, plus real Ansible synthetic
runner registration/process/redaction/failure cases and native-playbook syntax.
It also checks scripted Proxmox token capture/partial-failure preservation,
exact non-propagating resource grants, and the automatic narrow host API rule:
existing-rule preservation, duplicate avoidance and refusal without replay.
Cached-template tests cover the private read-only Docker input, exact hash and
size, automatic pinned SSH transfer, no overwrite and preserved partial files.

`bootstrap test-backend` runs real OpenTofu clients with networking disabled.
It creates only disposable `terraform_data` fixtures. It separately checks the
workstation lock around Docker invocations and OpenTofu's native state lock on
a Linux filesystem. The exact state passes through the same handover helper
used by the real runner; the receiving workspace preserves lineage/serial and
produces a fresh no-change plan; and the operator copy is frozen while an
independently readable private backup remains available.
No database, Proxmox provider, NAS mount or real GitHub registration is involved.

The first local-state fixture exposed that native state locking was insufficient
between separate Docker Desktop bind-mounted containers. Its failed evidence
is retained under `.work/bootstrap-local-state-e957y8k6`. The corrected caller
holds a workstation lock for the whole Docker operation. This is why bypassing
the launcher or introducing another active workstation is not supported.

Tools remain pinned to OpenTofu 1.13.1, bpg/proxmox 0.117.0 and hash-locked Python
requirements. The runner archive is pinned to official version 2.338.1.
Synthetic runner checks do not prove real runner registration. Docker package
installation is not a byte-identical image rebuild guarantee.

Successful runs save evidence under `.work/`; source rehearsal results include
exact source hashes. Earlier PostgreSQL fixture receipts remain historical
evidence for the old design and do not qualify the current local-state route.

## Earlier staged native rehearsal: passed on 25 October 2026

The isolated NAS-hosted Proxmox rehearsal verified actual guest creation and
boot through a saved OpenTofu plan, pinned SSH access, Ansible setup and transfer
of the exact state. The deployment guest then produced a fresh no-change plan,
registered one private GitHub runner and started its service.

One manually dispatched GitHub job ran successfully on that same runner. Its
actual provider result reported no changes for the selected guest. The state
checksum, lineage and serial emitted by the job matched the handover receipt.
The workstation, staged copy and separate private Mac backup stayed unchanged.
This is the technical proof of the first-guest handover to GitHub.

The rehearsal exposed missing Debian prerequisites (`python3-packaging` and
`sudo`), a temporary-directory permission issue and BOM-prefixed GitHub runner
metadata. The fixes passed affected Docker checks, including normal and
BOM-prefixed registration fixtures. A narrowly approved API-only host firewall
allowance resolved the guest-to-host connection block; direct TLS verification
and the subsequent authenticated provider checks passed.

This was a staged rehearsal with incremental corrections. The separate fresh
qualification below subsequently tested the final source. Production
installation, physical restart and application rollout remain unverified. The
independent NAS state-backup destination also remains unverified; the Mac
snapshot is not that backup. The rehearsal firewall allowance persists until
separately removed.

## Fresh-machine qualification: passed on 25 October 2026

The unchanged executable source completed the selected route on a separate,
freshly installed, disposable NAS-hosted Proxmox 9.2 machine:

1. The workstation built the pinned AMD64 Docker tools image and prepared the
   private bundle. The source manifest and runtime image matched the qualified
   inputs.
2. The script uploaded the checksum-pinned cached Debian template and created
   one separated six-hour API token with the reviewed resource grants.
3. A reviewed saved OpenTofu plan created one protected, unprivileged deployment
   container and its guest firewall configuration. A fresh provider plan then
   reported no changes.
4. The script added the exact guest-to-host TCP 8006 allowance while preserving
   existing host rules and options. Ansible verified the trusted CA and HTTPS
   access before transferring state and registering the runner.
5. The exact state was backed up locally and handed to the new deployment
   guest. The workstation copy was frozen against further plans/applies.
6. One manually dispatched private GitHub job ran successfully on the uniquely
   labelled new runner. Its real provider verification reported no changes for
   the new guest. The emitted state checksum, lineage and serial matched the
   workstation backup, handover and runner receipts.

No executable source changes or manual Proxmox configuration repairs were made
between script stages. The retained earlier lab, runner and locked restore
point were preserved. Initial local prerequisites required correction: the
operator image tag was absent and the workstation's ARP cache had no entry.
The normal preparation built the image, and one bounded network-identity check
preceded the first baseline connection. Those earlier failed checks remain
failed in their original receipts.

### Limits of this result

- The lab used a vendor-based installer fixture. It does not qualify the custom
  two-SSD ISO on physical hardware, the household services or production cutover.
- The installer's completion screen was not captured. Subsequent authenticated
  identity, running-system, storage and provider checks established the usable
  installed lab baseline; they do not rewrite that missing witness.
- The virtual console stayed blank and the kernel reported a virtual graphics
  driver failure. The operator explicitly accepted first-contact SSH trust for
  this isolated test. This does not relax the normal console-fingerprint
  verification instructions or establish production host trust.
- The API token was time limited, and the guest used DHCP without commissioning
  a reservation. Choose durable credential and address policies before ongoing CD.
- The verified backup was a private local state/configuration snapshot. An
  independent NAS/offsite backup and ongoing backup scheduling were not tested.
- A host automatic package-update warning remained uninvestigated; no parent
  repository or display-driver maintenance was performed.
- The helper's broader `native_verified` flag remains false. Actual
  `provider_noop` results and the state-matched real GitHub job establish this
  one-guest bootstrap result, not full-estate native qualification.

Private receipts retain the exact source, workflow, commit, runner and job-log
bindings. Credentials, state, plans and raw private receipts remain outside Git.
Preserve earlier failed attempts rather than treating the final success as
proof that those attempts succeeded.

## Publication review follow-up

The subsequent public review identified failure-path and credential-boundary
corrections: timed-out applies now receive a bounded graceful interruption;
runner handover rejects account passwords and requires the scoped API token;
and the unused Proxmox API template-download variant was removed. The selected
cached-template SSH path remains the supported MVP. Regression results for
these corrections are recorded separately from the earlier real-host rehearsal;
that rehearsal was not repeated or relabelled as a test of the later source.

The regressions first failed against the previous source. After the fixes,
**67 unit tests passed** in the network-disabled Docker executor, together with
real OpenTofu 1.13.1 validation and mocked provider plans for the root and guest
module, Ansible syntax checks and the synthetic runner scenarios. Both source
and fixture changes were included in that check. All 134 Python functions have
docstrings; adding those docstrings left the executable AST unchanged.

The follow-up also refuses equivalent firewall rules owned by a different
comment and verifies the created rule's owner on readback. Docker preparation
has explicit build/run timeouts and reports that a timed-out CLI does not prove
container completion. The ownership and timeout regressions failed before
those fixes and passed in the final offline check. No live firewall was changed.
