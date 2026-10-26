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
qualification below subsequently tested that source. This staged rehearsal did
not establish physical installation, physical restart or application rollout.
The later physical bootstrap is recorded separately below. That stage did not verify the
independent NAS state-backup destination; the Mac snapshot was not that backup.
The later physical NAS result is recorded below. The operator retains the
rehearsal firewall allowance while the runner is approved for ongoing CD and
keeps its address reserved. If ongoing-CD approval is revoked, the operator
removes the exact TCP 8006 allowance even if the runner is retained.
When retiring that runner, the operator removes the
exact allowance before releasing or reassigning its address; removal remains a
separately approved live change. See the [firewall operating reference](OPERATIONS.md#the-host-firewall-allowance).

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

## Physical host bootstrap: passed after a correction on 25 October 2026

After the custom ISO's physical installation, the host's identity, healthy ZFS
mirror, separate original disk and management access were checked. The bootstrap
then created the deployment guest and handed over to a real private GitHub job.

This run exposed an important difference from the lab: the guest used a tagged
management VLAN. The first apply was refused with `403` because the token had
permission for the bridge but not its exact VLAN. Readback found no guest or
guest disk from that failed attempt; the logs and original hold were preserved.

The correction passes the selected VLAN to credential setup, adds only its exact
non-propagating bridge/VLAN grant and checks the effective permission. Its new
regressions failed against the old implementation. **70 unit tests then passed**
in the network-disabled Docker executor.

One explicitly approved corrected attempt created the protected deployment LXC.
A fresh provider plan reported no changes. The normal runner step configured
the host API allowance, installed the runner and transferred the state.
One manually dispatched job then ran on the uniquely selected physical-host
runner. Its no-change result and state checksum, lineage and serial matched
the handover and the private workstation backup. The workstation copy stayed
frozen after handover.

### What this establishes, and what remains

- The installed physical host can run the first guest and its GitHub deployment
  runner. The lab result and this corrected physical result are separate records;
  the latter is not a clean, unchanged first-attempt run.
- The guest used a selected static address and an explicitly approved revocable
  token without automatic expiry. Its token was subsequently saved and synced
  in the operator's password manager.
- The initial state/configuration backup was an explicitly approved private Mac
  snapshot. At the end of that run, ongoing NAS state backup remained outstanding.
  The later 26 October physical configuration below closed that gap; the initial
  Mac snapshot itself was not NAS proof.
- These results do not qualify PegaProx, household applications, new guest
  permissions or repeated physical restart behaviour.

The maintainer retains the private host readback, source/test bindings, failed
attempt, corrected-attempt approval, backup/handover receipts and GitHub job
metadata/logs. Real credentials, addresses, keys, plans and state remain outside
this public record.

## Existing lab bootstrap configuration: passed on 26 October 2026

The supported `configure` step was exercised on the retained lab deployment
guest after its GitHub handover. The Proxmox host mounted the selected NAS NFS
export and shared only the dedicated private backup directory into the guest.
Readback confirmed the intended mount, mapped numeric owner, owner-only mode
and restored deletion protection.

The completed configuration checked NAS write/sync/readback as the deployment
account, saved active-state recovery copies, prepared the application SSH key
and verified the declared next guest's API access. A repeat with the same
settings returned `configured` with `changed: false`; Ansible made no changes
and OpenTofu proposed none. The existing guest, runner registration, token and
state were retained. The final continuation required no guest restart.

This was not a clean first-attempt result. Earlier NFS, directory-permission,
protected-mount and mount-identity failures were inspected and corrected under
separate approvals; their failed receipts and logs remain preserved privately.
**94 bootstrap unit tests passed** for the corrected source.

This establishes the existing-bootstrap configuration path in that lab. It
does not apply the update to the physical host, qualify its network/NAS path,
back up application data or prove application startup. Those remain separate
steps before household migration. The subsequent physical-host result below
records what was actually completed after this lab result.

## Physical NAS and database foundation: passed on 26 October 2026

The existing physical deployment guest subsequently passed the supported
NAS/application-access configuration. The host mounted the selected NFS export
and shared only the dedicated backup directory into the unprivileged runner.
Mount identity, mapped ownership, private modes, protection and deployment-account
write/sync/readback were checked. The active OpenTofu states and failed-operation
receipts were copied to that NAS destination and their contents were read back.
This establishes the physical NAS mount and immediate state/receipt copy
readback. This run did not audit NAS-side access controls, encryption at rest
or protection against later modification. It does not establish application-data
backup or a restore of those state copies.

Merge-triggered host CD then configured the isolated backend bridge and the three
declared database guest grants. The host job's subsequent runs reported no bridge
creation, no new grants and no token-lifetime or guest-lifecycle changes. Earlier
API-field failures remain preserved as failures; the accepted correction was
separately approved and verified.

All three empty database guests were created through OpenTofu CD. Their original
identity phase stopped on Proxmox's Debian/systemd nesting warning. The maintainer
explicitly approved the feature/address correction, one graceful restart per
retained guest, original SSH fingerprint verification and one CD continuation.
The disks and guests were preserved. Failed state, plans, inputs and logs were
archived locally and verified on NAS before continuing.

The corrected CD runs installed PostgreSQL 16.10, MariaDB 12.3.3 and InfluxDB 2.7.12
with CLI 2.7.5. Actual LXC checks passed for the pinned native packages, active and
enabled systemd services, backend listeners and local SQL/readiness probes. Only
default databases were present; InfluxDB setup remained uninitialised. A normal
follow-up merge returned only the shared read-only `verify` result for all three,
without applying changes, installing software or restarting services.

The private installation run is 40328910928; the follow-up verification run
is 40330643215. They used public application source
`f313136dbceeec6268d6f66d2ebb0a4d6bf4c1e3`. Exact private receipts bind the source,
plans, workflow commits, host/guest identities and runtime readback. Credentials,
site addresses, raw state and the underlying private receipts remain outside Git.

These are results after approved corrections. A fresh uninterrupted database
Deploy from the corrected baseline and a host reboot after database installation
have not been retested. Household restores, database users/grants, real consumers,
later application guests and live-data protection remain separate migration work.
