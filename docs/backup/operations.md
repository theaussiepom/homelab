# Verify and operate backups

[Backup setup](README.md) → [Configure and deploy](configure.md) → **Verify and operate**

Finish this procedure before relying on unattended backups. A successful deployment, a successful upload, a PBS verification task and a working application restore establish different things. Keep a dated result for each, with the source revision, snapshot identities and public key fingerprints; never include secrets.

## Observe the first backup

1. Let the installed schedule reach its first authorized window. Confirm the controller is available and the intended complete group participates. Do not bypass a failed-operation hold or invoke an old worker by hand.
2. Check the producer's completion record and the actual PBS task/snapshots. The expected members, namespaces, capture times and data manifest must agree. A successful snapshot from only one member does not complete a coordinated group.
3. Check that any paused applications resumed and real service checks pass. Database exports and file captures must be associated with the intended recovery generation.
4. Confirm that every required encrypted snapshot contains its recovery-wrapped client key and that the configured public-key identity is the intended one. The producer downloads `rsa-encrypted.key` using the client key to verify the signed snapshot manifest, checks its RSA-4096 envelope size, and records the envelope digest and selected recovery public-key fingerprint. This proves the envelope was read back; only the independent private-key recovery test below proves it can recover the client key.
5. Record actual runtime and datastore/staging growth. Adjust declared bounds or timing through reviewed configuration if measured usage requires it; do not disable checks to accommodate unexplained growth.

No backup completion record can establish that a stopped scheduler will run tomorrow. [Missing-backup monitoring](#notifications-and-missing-backups) is a separate requirement.

### Find the schedule and completion records

Use the existing CD account on the deployment controller, with read access to its protected state. Substitute your `backup.job.name` for `example-recovery` below. These commands inspect the timer; they do not start a backup:

```bash
export XDG_RUNTIME_DIR="/run/user/$(id -u)"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"
systemctl --user show homelab-backup-example-recovery.timer \
  --property=ActiveState --property=NextElapseUSecRealtime
systemctl --user show homelab-backup-example-recovery.service \
  --property=Result --property=ExecMainStatus
```

Expect an active timer with a next scheduled time. After a run, the service must report `Result=success` and `ExecMainStatus=0`; before its first run these values are not backup evidence. Inspect the corresponding generation below as well.

| Location | What to verify |
| --- | --- |
| Controller `<state_root>/backup-controller/schedules/homelab-backup-<job-name>.json` | Account-owned private group membership and schedule match the reviewed configuration. This is not a credential file. |
| CD account home, `.config/systemd/user/homelab-backup-<job-name>.service` and `.timer` | The one user-scope alarm matches the selected source and schedule. Use the existing CD account and its persistent user manager; do not enable a root/system-scope namesake. |
| Controller `<state_root>/backup-controller/framework/<source-hash>/proxmox/` | Complete account-owned public source is verified before use and preserved independently of a runner checkout. It is not root-immutable. |
| Controller `<state_root>/backup-controller/installations/<job-name>/<identity>/complete.json` | Successful early schedule installation, binding expected coverage and the selected source. Failed or interrupted installation remains held for explicit recovery. |
| Each guest `<state_root>/<vmid>/ordinary-complete.json` and its immutable `pbs-agent` phase payload | Genuine guest readiness: the worker configuration and exact private inputs were installed and checked by that completed deployment. Nightly capture compares every member with the current schedule. |
| Historical `<state_root>/backup-activation/<job-name>/<identity>/` | Retained old group-activation evidence. Success is not new readiness; failure or interruption remains a refusal. Do not edit or remove it. |
| Controller `<state_root>/backup-groups/<generation>/started.json` | The attempted group and ordinary deployment receipt digests. The generation is a 32-character hexadecimal identifier. For a group spanning state roots, use the lexicographically first configured state root. |
| Same directory, `complete.json` and `recovery-set.json` | Successful whole-group completion and the exact destinations/snapshots for restoration. `restore_verified: false` is intentional until a separate restore drill. |
| Same directory, `failed.json` | The run failed; retain it and any holds. A successful member is not whole-group success. |
| Each guest `<staging-volume-path>/.homelab-backup/<generation>/complete.json` | `status: uploaded`, matching generation, `archive_readback_verified: true`, the recovery public fingerprint and envelope digest. |
| Same guest directory, `manifest.json` | Digests and sizes for the complete uploaded recovery payload. This is private operational metadata. |

Choose the generation belonging to the observed run; do not select a directory merely because it has the newest modification time. From the controller, use the following read-only check after replacing both synthetic values. It prints only the group identifier and snapshot coordinates needed for the restore procedure:

```bash
PBS_STATE_ROOT=/var/lib/example-deployment-state
PBS_GENERATION=0123456789abcdef0123456789abcdef
python3 - "$PBS_STATE_ROOT" "$PBS_GENERATION" <<'PYCODE'
import hashlib, json, pathlib, re, sys
assert re.fullmatch('[0-9a-f]{32}', sys.argv[2])
operation = pathlib.Path(sys.argv[1]) / 'backup-groups' / sys.argv[2]
assert not (operation / 'failed.json').exists(), 'This group failed'
complete = json.loads((operation / 'complete.json').read_text())
raw = (operation / 'recovery-set.json').read_bytes()
group = json.loads(raw)
assert complete['status'] == 'passed'
assert complete['generation'] == group['generation'] == sys.argv[2]
assert complete['recovery_set_sha256'] == hashlib.sha256(raw).hexdigest()
assert group['members'], 'No completed group members'
print('Completed generation:', group['generation'])
for member, row in sorted(group['members'].items()):
    print(member, row['server'], row['port'], row['datastore'], row['namespace'], row['snapshot'])
PYCODE
```

Preserve the verified `recovery-set.json` in the protected rehearsal record. During restoration, compare the downloaded `group.json` byte-for-byte with it and compare the downloaded `data-manifest.json` digest with that member's `data_manifest_sha256` in the group. This binds the restored artifacts to the observed group rather than trusting an arbitrary timestamp.

In PBS, select **Datastore → your datastore → Content**, select each recorded namespace and expand its `host/<backup-id>` group. Its exact UTC snapshot must exist. In the corresponding task history, confirm the backup task finished successfully. Later server verification has a separate task/result; it does not decrypt the data or test application behavior.

### Verify the client access boundary

On the trusted PBS console, obtain the client's non-secret `auth_id` and namespace from its deployed coverage or protected ownership record. Run these read-only commands as the PBS administrator, replacing the synthetic token identity and namespace with the real values:

```bash
PBS_CLIENT_ID='hl-0123456789abcdef0123456789abcdef@pbs!backup'
PBS_CLIENT_PATH='/datastore/recovery/guests/guest-610'
proxmox-backup-manager user permissions "$PBS_CLIENT_ID" --path "$PBS_CLIENT_PATH"
proxmox-backup-manager user permissions "$PBS_CLIENT_ID" --path /
proxmox-backup-manager user permissions "$PBS_CLIENT_ID" --path /datastore/recovery
```

The namespace must have the intended `DatastoreBackup` role's effective backup permissions. Root and datastore-parent paths must have no effective privileges. Repeat the path check for a different existing client namespace: it must have no privileges there either. Inspect both user and token grants in **Configuration → Access Control → Permissions**, including inherited permissions. Do not test pruning or administrative writes to prove their denial. [PBS user/token permission checks](https://pbs.proxmox.com/docs/proxmox-backup-manager/man1.html) and [role meanings](https://pbs.proxmox.com/docs/user-management.html#access-control) are authoritative for the installed release.

The successful encrypted upload and own-namespace readback then demonstrate that the issued secret actually authenticates with that scope. A permissions listing alone does not validate the saved token value. If the effective scope is broader, stop activation and correct the reviewed configuration/ownership; do not declare the boundary proven from role labels alone.

## Prove recovery

Use a fresh isolated restore destination, not a production guest's data directory. Follow [recovery-key rehearsal](recovery-key.md#rehearse-recovery) with a private key exported from an independent store. Make the original guest/client key unavailable to the recovery process so the test really exercises the recovery route.

Verify representative configuration and durable files against expected hashes/metadata. For databases, restore the native export into a compatible isolated database instance and test the expected objects and data. For app state tied to a database, test the matching generation together. Do not connect restored automation/device services to production integrations as an accidental part of the test.

Record what worked, what was deliberately isolated, and what remains untested. PBS server verification checks stored backup integrity; it cannot replace a client-side decryption test or prove application consistency. A recovery private key also cannot authenticate to PBS, so verify the independent access procedure.

## Configure server maintenance

After the first datastore exists, configure its maintenance in PBS under the chosen site's server-management ownership. Use the PBS UI below for the initial operator-owned setup; if the deployment repository already manages these jobs declaratively, update that source instead of creating a second writer. Do not assume the guest backup schedule creates these jobs.

| Job | Setup and verification |
| --- | --- |
| Verification | In PBS, select the datastore and its verification-job page. Add a schedule covering new snapshots and periodic re-verification. Run the first task and confirm its final result. |
| Retention/pruning | Add a prune job for the intended datastore/namespace and choose the keep policy. Review the prune preview against real snapshots before enabling deletion. |
| Garbage collection | Configure the datastore's GC schedule and observe its result and remaining free space. Pruning alone does not immediately reclaim all unreferenced data. |

Choose times that fit measured backup/verification runtime and storage load. Retention must meet your recovery objectives and available capacity; there is no universal safe count. Preserve required known-good snapshots before destructive retention changes. See [PBS maintenance behavior](https://pbs.proxmox.com/docs/maintenance.html) for scheduling, verification and garbage-collection grace periods.

These tasks do not make the server maintenance-free. Assign responsibility for OS updates, hardware/storage health, capacity review and periodic recovery drills.

## Notifications and missing backups

1. In PBS **Configuration → Notifications**, configure a destination you will actually receive, such as an SMTP relay, and the matcher rules that route relevant failures to it.
2. Send its supported test notification and confirm receipt outside PBS. Entering an email address during installation alone does not prove delivery.
3. Monitor producer failures as well as PBS tasks. A client that cannot reach PBS, or a stopped controller, may create no failed PBS task to notify about.
4. Add an external freshness check for the expected last successful recovery generation per group/member. Set the threshold from schedule, jitter, maximum normal duration and your tolerance for missed backups. Test the alert using an isolated fixture or monitoring test—not by silently interrupting production backups.
5. Alert on datastore/staging capacity and credential expiry. Document who responds and where the recovery instructions are stored.

The notification destination should remain usable if the services being protected fail. [PBS notification setup](https://pbs.proxmox.com/docs/notifications.html) explains targets and matchers; your monitoring implementation owns the absence/freshness alarm.

## Full-guest protection

When your recovery policy requires full PVE guest images, establish the native PVE-to-PBS tier separately:

1. Create a separate PBS user/token and namespace for the PVE writer, scoped to its backup destination. Do not reuse the CD administrator token or a guest's token.
2. In your deployment repository's PVE storage/job configuration, select the actual PBS server, fingerprint, datastore and namespace, the PVE writer token, a stable storage encryption key and the verified recovery public key.
3. Configure a native backup job for the intended VMIDs and included managed volumes. Preserve the guest/volume selection from source; bind/device-mounted paths are not automatically covered by managed-volume flags.
4. Deploy through the owner of those PVE resources. For installations where those resources are operator-owned, the native PVE **Datacenter → Storage** PBS entry and **Datacenter → Backup** job perform the corresponding setup. Do not edit CD-owned resources in the UI.
5. Verify an encrypted full-guest backup and restore it into an isolated target. Confirm the included volumes and recover its key independently before relying on this tier.

Use the [native PVE backup documentation](https://pve.proxmox.com/pve-docs/chapter-vzdump.html) for its supported storage and job options. PVE storage encryption keys have a different ownership boundary from per-guest client keys: do not repeatedly select automatic key generation during storage updates. This tier may include client-key files inside the image, so it also needs encryption and independent recovery custody.

## Ready for unattended operation

Complete this checklist with actual observations:

- [ ] PBS and its backup mount survive a planned normal restart with the expected identity and capacity.
- [ ] Direct management/recovery access works independently of the protected DNS, proxy and SSO services.
- [ ] The management token is limited to the [protected setup/enrollment steps](access.md#what-goes-where); guest tokens cannot access other guests or administer/prune PBS.
- [ ] Recovery PEM copies and their passphrase are available outside the protected estate, and an exported copy has been tested.
- [ ] All intended guests/apps/volumes are covered; exclusions are explicit and database exports are coherent.
- [ ] The first complete backup succeeded, with the expected encryption and recoverable key copy.
- [ ] Isolated file/database recovery succeeded using independently held recovery material.
- [ ] A later CD preserved keys, identities and history, and the following scheduled backup succeeded.
- [ ] Server verification, retention preview and GC were checked and their schedules established.
- [ ] Failure notifications and missing-backup alerts were received and their response owner is known.
- [ ] Capacity, update and recovery-drill responsibilities are assigned.
- [ ] Full-guest backup/restore was tested if required by the recovery policy.
- [ ] An independent data replica was tested if recovery must survive loss of the PBS storage/site.

If a required box is unchecked, identify that limit explicitly. Do not describe the installation as recoverable merely because CD or a PBS task is green.

## Later changes and failures

### Rehearse an amended guide from a clean setup

When a setup instruction fails, stop at that step and correct the guide before continuing the rehearsal. Record the cause, the corrected instruction and its expected result. Choose a clean rehearsal at the boundary changed by that instruction.

For a **server or storage installation change**, repeat the affected installation sequence on an authorised isolated disposable server/storage setup. A later client-enrollment rehearsal against an existing server does not prove a fresh server installation.

For a **client-enrollment change**, explicitly inventoried and independently verified PBS/datastore, controller/toolchain, repository, recovery-key/custody and management-credential prerequisites may remain in place. Record their identities, readiness evidence and the fact that they are retained prerequisites. A second PBS server, controller or repository is not required solely to rehearse this client lifecycle. Preserve existing application data and ordinary deployment receipts; a clean backup enrollment does not require recreating the application.

Start that client lifecycle without silently adopting prior enrollment, activation or failed-operation state. Use new enrollment objects or reset only explicitly inventoried disposable test objects with authority. Prove first CD, a backup, repeated CD preserving the same identities and keys, a subsequent backup, then independent isolated file and database restores where applicable. Restore into the reviewed isolated destination, never over production application data. The retained foundation must be distinguished from installation steps actually replayed.

Keep a manifest of exactly which test objects were created: server or datastore, namespaces, API users/tokens, client keys, test guests and test snapshots. Reset only those disposable objects after preserving the rehearsal results. Never use a blanket cleanup against a production datastore, revoke an existing deployment token, delete recovery keys, or remove failed-operation records merely to obtain a clean run. If an object proposed for reset is shared or its ownership is uncertain, leave it intact and use a fresh isolated test object instead.

The successful rehearsal must not rely on undocumented or unverified credentials, accounts, configuration files or manual fixes left behind by the failed pass. Explicitly verified retained prerequisites are different from such leftovers. Retain the corrected guide and its tests; resetting the test environment does not mean reverting those corrections.

Maintain guest coverage and schedules through reviewed site configuration. Keep the existing client keys and stable namespace/backup IDs. Removing a guest from a CD run is not retirement of its backups. Loss of a token secret, a foreign owner or a failed-operation record needs its specific recovery procedure, not generic cleanup.

If a backup fails, establish the failed phase and whether capture, pause, upload or resume already occurred. Preserve the record and restore service continuity through the authorized operation. Retry only after the cause and the supported retry boundary are understood. Consult [backup failure semantics](../reference/backup.md#coordinated-execution-and-failure-behavior) and [framework troubleshooting](../operations/troubleshooting.md).

For server or storage loss, recover the existing datastore and access configuration before resuming writers. Private keys recover encryption, not missing data; offsite replication is what covers loss of all local backup media.
