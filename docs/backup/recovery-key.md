# Prepare and protect a PBS recovery key

[Backup setup](README.md) · [Backup configuration](../reference/backup.md) · [Deployment preparation](../guides/prepare-deployment.md)

Use this guide to create a Proxmox Backup Server (PBS) recovery key pair once, keep independent private copies and verify that those copies can be opened. You can finish this preparation on the PBS VM before deploying any backup clients. Normal continuous deployment (CD) does not need the recovery private key or access to the password manager holding it.

## Contents

- [Understand the three credentials](#understand-the-three-credentials)
- [Prepare the generation environment](#prepare-the-generation-environment)
- [Generate the pair once](#generate-the-pair-once)
- [Store independent recovery copies](#store-independent-recovery-copies)
- [Verify an exported copy](#verify-an-exported-copy)
- [Hand the public key to deployment](#hand-the-public-key-to-deployment)
- [Rehearse recovery](#rehearse-recovery)
- [Later deployments and key replacement](#later-deployments-and-key-replacement)
- [Troubleshoot without replacing keys](#troubleshoot-without-replacing-keys)
- [Compatibility and recorded evidence](#compatibility-and-recorded-evidence)

## Understand the three credentials

| Material | What it does | Who needs it |
| --- | --- | --- |
| Client encryption key | Encrypts one client's backup contents | The client when backing up or restoring |
| Recovery public key | Encrypts a recovery copy of the client key, stored alongside the backup | Clients configured to produce recoverable backups |
| Recovery private key and its passphrase | Unlock that stored copy if the original client key is lost | An operator performing recovery |
| PBS API token | Authenticates to PBS and authorizes access to specified backups | The client or recovery operator, according to its permissions |

The recovery public/private pair is one credential, distinct from the client encryption key and API token. It does not replace either. The recovery private key cannot log in to PBS; a working API token cannot decrypt encrypted backup contents by itself. See [PBS authentication and permissions](https://pbs.proxmox.com/docs/user-management.html#api-tokens).

For a backup configured with a recovery public key, PBS's native client writes the encrypted client-key copy as `rsa-encrypted.key`. Recovery uses the matching private key to recover the client key, then uses that client key to decrypt data. The private key itself is never embedded in the backup. See the [upstream recovery-key procedure](https://pbs.proxmox.com/docs/backup-client.html#using-a-master-key-to-store-and-recover-encryption-keys).

## Prepare the generation environment

This is a **first-installation preparation procedure**. It creates private files but does not create a datastore, run a backup, change a guest or start CD. Obtain authority to create and store this installation's recovery pair first.

Use an interactive Bash shell on the PBS VM or another trusted Linux machine with a compatible `proxmox-backup-client`, OpenSSL and GNU coreutils installed. The commands below follow the PBS 4.2 client interface; confirm the installed command help before proceeding. The working directory must be on a private filesystem outside any Git checkout, CI workspace, shared folder or automatic artifact collection. Do not run the session with shell tracing or a recorder that captures secrets.

Have ready:

- A strong, unique recovery passphrase that can be entered interactively and retrieved independently during a disaster.
- A password manager or other protected store that can preserve the complete encrypted PEM file, plus an independent offline copy destination.
- An installation label and a place to record public fingerprints, storage locations, required access and verification dates. Keep actual private values in their protected store, not in repository documentation.

These **read-only prerequisite commands** may run from any directory:

```bash
proxmox-backup-client version
proxmox-backup-client help key create-master-key
openssl version
```

Confirm that the native `key create-master-key` command is available. If the installed release differs, review its [client command reference](https://pbs.proxmox.com/docs/proxmox-backup-client/man1.html) before using the procedure. Do not install unreviewed packages as an incidental step on a managed machine.

## Generate the pair once

The following **operator commands** require the prepared interactive Bash shell. They create a new private working directory and leave it available for verified export. Run each command only after the preceding command succeeds; stop on any error.

<!-- example: pbs-recovery-key-generation -->
```bash
umask 077
PBS_KEY_WORK=$(mktemp -d /var/tmp/pbs-recovery-key.XXXXXXXX)
cd -- "$PBS_KEY_WORK"
proxmox-backup-client key create-master-key
chmod 600 master-private.pem
chmod 644 master-public.pem
stat -c '%a %n' master-private.pem master-public.pem
```

Enter and confirm the passphrase at the native prompt. Never supply it in command arguments, source files or chat. The expected files are `master-private.pem`, protected by that passphrase, and `master-public.pem`. The expected modes are `600` for the private file and `644` for the public file; their containing directory remains private. The upstream tool creates an RSA-4096 pair.

The generation command must not be rerun in this directory: it can replace the named output files. If interrupted, preserve the directory and inspect whether either file exists before deciding how to proceed. Do not label a second pair as the original.

Verify that the private file opens and corresponds to the public file. These **local verification commands** run in the same directory and prompt for the passphrase:

<!-- example: pbs-recovery-key-pair-check -->
```bash
openssl pkey -in master-private.pem -check -noout
openssl pkey -in master-private.pem -pubout -out derived-public.pem
cmp -- master-public.pem derived-public.pem
openssl pkey -pubin -in master-public.pem -outform DER -out public-key.der
sha256sum public-key.der
```

The private-key check must succeed. `cmp` must exit zero with no difference. Record the SHA-256 of the DER public key as the recovery-pair identifier. It is public metadata, not the key or passphrase. The intermediate files contain only public material; do not use commands that print the private key.

## Store independent recovery copies

Keep the encrypted `master-private.pem` and its passphrase recoverable without the services being backed up. Recommended custody is:

1. **Convenient copy:** an encrypted password-manager item, for example a Bitwarden item with the PEM attached, the passphrase and the recovery-pair identifier. If attachments are unavailable, use another protected file store that preserves the exact file; do not assume a subscription feature exists.
2. **Independent offline copy:** the same encrypted PEM on a securely stored USB drive. Keep its passphrase separately accessible, such as a sealed record in a different secure location.
3. **Offsite copy:** another protected copy outside the location containing the servers and first offline copy, if recovery must survive loss of that location.

A self-hosted password manager on the protected estate must not be the only copy of either the PEM or its passphrase. Otherwise restoring the password manager may require the key trapped inside it. No vault API or unlock is required for normal backups or CD.

Store the public PEM alongside each private copy. Record the installation label, public-key fingerprint, creation date, file names, passphrase location, PBS access procedure and the date of the latest successful test. Retain an independently accessible copy of these instructions. Do not record secret values in an ordinary checklist.

An offline USB file copy is different from importing a key into a hardware security token. This guide does not qualify YubiKey recovery: PBS's standard import command reads a private PEM file, while a hardware-held private key may be non-exportable. A token-specific procedure needs its own compatibility checks and recovery test.

## Verify an exported copy

Download or copy the material back from each intended recovery store into a **new private directory**, rather than testing only the originals left on the PBS VM. Use the same protected Bash session:

```bash
PBS_KEY_CHECK=$(mktemp -d /var/tmp/pbs-recovery-check.XXXXXXXX)
chmod 700 "$PBS_KEY_CHECK"
```

Using the store's supported export or download method, place the recovered files in that directory as `master-private.pem` and `master-public.pem`. Paths and credentials for the store belong in the operator's private procedure; none are assumed by this guide. Then run:

```bash
cd -- "$PBS_KEY_CHECK"
chmod 600 master-private.pem
openssl pkey -in master-private.pem -check -noout
openssl pkey -in master-private.pem -pubout -out derived-public.pem
cmp -- master-public.pem derived-public.pem
openssl pkey -pubin -in master-public.pem -outform DER -out public-key.der
sha256sum public-key.der
```

The passphrase retrieved from the recovery instructions must open the file. The public-key digest must match the identifier recorded during generation. This proves that this exported copy contains the matching usable private key. It does not yet prove that a backup contains a wrapped client key or that an application can be restored.

Once all required copies pass, export the public PEM for deployment preparation and remove only the temporary private-key files created for generation/export checks, after confirming their exact paths. Do not use wildcard or recursive cleanup. Normal file deletion does not guarantee erasure of filesystem snapshots, SSD remnants or previous backups; use an appropriately protected generation environment from the beginning. Keep the independent recovery copies and verification record.

## Hand the public key to deployment

The setup boundary ends with a verified public PEM, independent private copies and a verification record. The public key may be kept in the deployment repository; changes to it still require review because it controls recovery of future backups. Do not put the recovery private key or passphrase in Git, ordinary GitHub Actions secrets, guest packets or PBS datastore configuration.

Supply the public PEM using the [recovery public-key binding](../reference/backup.md#backup-recovery-public-key). CD installs it on enrolled clients and passes it explicitly to the native backup command. Each client keeps its own encryption key; CD creates it once and preserves it on later deployments. The global private key is never a client input. Confirm the emitted backup contains the expected wrapped client key during the [first recovery test](operations.md#prove-recovery).

The initial PBS management credential is a separate installation prerequisite. Supplying it enables authorized server configuration; it does not supply recovery-key custody. Follow the deployment repository's protected Environment policy rather than placing an administrator credential on every guest.

## Rehearse recovery

This is a separate, authorized **isolated restore test**, after a backup producer has been configured to use the public key. It must not write into a running application's files or replace a live client key. Obtain the following first:

- The exact repository, namespace and snapshot selected for the test.
- A scoped PBS recovery credential and verified server identity, usable without relying on the failed guest, home SSO or proxy.
- A fresh private output directory on a compatible recovery machine.
- The private PEM retrieved from an independent store and its independently retrieved passphrase.
- The chosen backup's expected non-secret file digests or application-level acceptance criteria.

Use a new isolated **Linux recovery VM**, with no production disks, shared mounts, device integrations or application network access. Permit only the reviewed PBS recovery connection. Run the following restore commands as root inside that VM: both PXAR and tar restore numeric owners and protected metadata. The VM filesystem must support the owners, modes, ACLs and extended attributes present in the backup. An unprivileged container or a filesystem that discards those attributes is not a substitute for this test.

Install a compatible PBS 4.2 client, OpenSSL, Python 3.12 or later, GNU tar, GNU coreutils, and the `acl` and `attr` utilities. Use an interactive Bash terminal without shell tracing or session recording. Confirm there is no default client key at `/root/.config/proxmox-backup/encryption-key.json`; do not copy the original guest or controller key into this VM. Clear inherited encryption-password and PBS password-provider variables before starting, using the commands below. These are the [documented client inputs](https://pbs.proxmox.com/docs/backup-client.html#environment-variables), not the key files themselves. The [native recovery procedure](https://pbs.proxmox.com/docs/backup-client.html#using-a-master-key-to-store-and-recover-encryption-keys) underlies these HomeLab-specific steps.

### Retrieve and decrypt the client key

The values below are **synthetic substitutions**, not a reachable repository. Replace them with the repository, namespace, certificate fingerprint and exact snapshot shown in your successful backup record. The snapshot timestamp is UTC. Do not put the token secret in a command argument.

```bash
umask 077
unset PBS_ENCRYPTION_PASSWORD PBS_ENCRYPTION_PASSWORD_FD PBS_ENCRYPTION_PASSWORD_FILE PBS_ENCRYPTION_PASSWORD_CMD
unset PBS_PASSWORD PBS_PASSWORD_FD PBS_PASSWORD_FILE PBS_PASSWORD_CMD
PBS_RESTORE_WORK=$(mktemp -d /var/tmp/pbs-isolated-restore.XXXXXXXX)
export PBS_REPOSITORY='recovery-reader@pbs!restore@192.0.2.50:8007:recovery'
export PBS_FINGERPRINT='ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab:ab'
PBS_RESTORE_NS='guests/guest-610'
PBS_RESTORE_SNAPSHOT='host/guest-610/2026-01-01T02:00:00Z'
read -r -s -p 'PBS recovery token secret: ' PBS_PASSWORD
printf '\n'
export PBS_PASSWORD
proxmox-backup-client restore "$PBS_RESTORE_SNAPSHOT" rsa-encrypted.key \
  "$PBS_RESTORE_WORK/rsa-encrypted.key" --ns "$PBS_RESTORE_NS"
test "$(stat -c %s "$PBS_RESTORE_WORK/rsa-encrypted.key")" -eq 512
```

Stop on any failed command. A 512-byte envelope is expected for the selected RSA-4096 recovery key, but its size alone does not prove recoverability or authenticate the snapshot. Export your independently stored `master-private.pem` and `master-public.pem` into this fresh directory, then verify the actual file that the import will consume:

```bash
chmod 600 "$PBS_RESTORE_WORK/master-private.pem"
openssl pkey -in "$PBS_RESTORE_WORK/master-private.pem" -check -noout
openssl pkey -in "$PBS_RESTORE_WORK/master-private.pem" -pubout \
  -out "$PBS_RESTORE_WORK/derived-public.pem"
cmp -- "$PBS_RESTORE_WORK/master-public.pem" "$PBS_RESTORE_WORK/derived-public.pem"
openssl pkey -pubin -in "$PBS_RESTORE_WORK/derived-public.pem" -outform DER \
  -out "$PBS_RESTORE_WORK/public-key.der"
sha256sum "$PBS_RESTORE_WORK/public-key.der"
```

The printed SHA-256 must match the independently recorded recovery fingerprint and the producer's `recovery_public_fingerprint`. A successful `cmp` alone only compares the two exported files. After that independent comparison succeeds, recover the client key and archive:

```bash
test ! -e "$PBS_RESTORE_WORK/recovered-client-key.json"
proxmox-backup-client key import-with-master-key \
  "$PBS_RESTORE_WORK/recovered-client-key.json" \
  --master-keyfile "$PBS_RESTORE_WORK/master-private.pem" \
  --encrypted-keyfile "$PBS_RESTORE_WORK/rsa-encrypted.key"
chmod 600 "$PBS_RESTORE_WORK/recovered-client-key.json"
proxmox-backup-client restore "$PBS_RESTORE_SNAPSHOT" recovery.pxar \
  "$PBS_RESTORE_WORK/recovery" --ns "$PBS_RESTORE_NS" \
  --keyfile "$PBS_RESTORE_WORK/recovered-client-key.json"
unset PBS_PASSWORD
```

Enter the recovery private-key passphrase and the new recovered-client-key passphrase at the native prompts. Do not use `--ignore-missing-signature` or disable TLS checks to make recovery pass. The restore must exit successfully using this explicitly recovered key. Keep the private PEM and recovered client key inside the protected recovery directory until the rehearsal is complete.

### Inspect the HomeLab recovery generation

The extracted `recovery` directory contains:

| Artifact | Meaning |
| --- | --- |
| `configuration-and-state.tar` | Selected configuration and application state, with source-relative paths and captured filesystem metadata |
| `inventory.json` | Guest identity, path classifications, database relationships and the selected job; treat this as private operational metadata |
| `data-manifest.json` | SHA-256 and size for each captured file before group metadata was added |
| `group.json` | The matching coordinated member set, snapshot locations and member manifest digests |
| `<app-id>/cluster.sql` | Native PostgreSQL or MariaDB export when that producer is selected |
| `<app-id>/native/` | Native InfluxDB export when that producer is selected |

Check the listed captured files without printing their contents:

```bash
python3 - "$PBS_RESTORE_WORK/recovery" <<'PYCODE'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1]).resolve()
manifest = json.loads((root / 'data-manifest.json').read_text())
assert manifest, 'The recovery manifest is empty'
for name, expected in manifest.items():
    relative = pathlib.PurePosixPath(name)
    assert not relative.is_absolute() and '..' not in relative.parts
    path = root.joinpath(*relative.parts)
    assert path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root)
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            digest.update(block)
    assert path.stat().st_size == expected['bytes'] and digest.hexdigest() == expected['sha256']
print('Verified captured files:', len(manifest))
PYCODE
tar --list --file "$PBS_RESTORE_WORK/recovery/configuration-and-state.tar" \
  > "$PBS_RESTORE_WORK/tar-members.txt"
```

Compare the private member list and inventory with the required configuration and exclusions. Check `group.json` against the independently retained successful group record; for a database-dependent app, recover the referenced database snapshot from that same group. The manifest checks captured bytes, not database usability or application behavior.

### Restore files and metadata

Remain in the isolated recovery VM as root. Create a new empty extraction directory; never use `/` as the extraction target. These GNU tar commands preserve the captured numeric ownership, permissions, ACLs, extended attributes and SELinux labels:

```bash
PBS_RESTORE_FILES="$PBS_RESTORE_WORK/files"
test ! -e "$PBS_RESTORE_FILES"
mkdir -m 700 -- "$PBS_RESTORE_FILES"
tar --extract --file "$PBS_RESTORE_WORK/recovery/configuration-and-state.tar" \
  --directory "$PBS_RESTORE_FILES" --numeric-owner --same-owner \
  --same-permissions --acls --xattrs --xattrs-include='*' --selinux
tar --compare --file "$PBS_RESTORE_WORK/recovery/configuration-and-state.tar" \
  --directory "$PBS_RESTORE_FILES" --numeric-owner --acls --xattrs --selinux
```

Both commands must finish with exit status zero. The compare checks the archive against the extracted files; it does not prove the source application was captured consistently. Some filesystem security attributes need matching kernel/filesystem support. Treat a preservation warning or failed comparison as a failed test; do not suppress it or omit metadata options to make the test pass.

Before the backup rehearsal, choose representative files and retain their expected hashes, numeric owners, modes, ACLs and relevant extended attributes in its private acceptance record. Include any attributes the application relies on. In the isolated restore, inspect those same relative paths beneath `$PBS_RESTORE_FILES` with `sha256sum`, `stat -c '%u:%g %a %s'`, `getfacl --numeric` and `getfattr -d -m-`. Replace each path with a reviewed file from the private tar listing; do not publish file contents, ACL identities or attribute values. Compare these results with the recorded expectations. For a disposable synthetic rehearsal, create known files with distinct owners/modes and a known ACL/xattr before backup so omissions cannot pass unnoticed.

### Restore database exports

Restore each selected database export into a fresh compatible instance **inside the isolated recovery environment**. Read the package versions in `inventory.json`, install compatible extensions/plugins, and use the following native procedure for the artifact. Never submit `cluster.sql` to production as a test.

| Export | Restore procedure and checks |
| --- | --- |
| PostgreSQL `<app-id>/cluster.sql` | Follow [restoring `pg_dumpall`](https://www.postgresql.org/docs/current/app-pg-dumpall.html). Initialize the isolated cluster with a different bootstrap superuser name that is absent from the source dump; this avoids the documented duplicate-bootstrap-role error. Use `psql -X --set=ON_ERROR_STOP=on` as that superuser against the isolated cluster, with the dump as input. Required tablespace directories and extensions must already exist in that isolated instance. Check databases, roles, grants, representative row counts and application queries. |
| MariaDB `<app-id>/cluster.sql` | Follow [loading a `mariadb-dump` export](https://mariadb.com/docs/server/clients-and-utilities/backup-restore-and-import-clients/mariadb-dump) using the compatible `mariadb` client and isolated server's local administrative socket. The export includes system accounts, routines, events and triggers; keep the event scheduler off during the drill. Check schemas, grants, those objects and representative rows before any isolated application connection. |
| InfluxDB `<app-id>/native/` | Follow [full native restore](https://docs.influxdata.com/influxdb/v2/admin/backup-restore/restore/) for the recorded server/CLI versions. Full restore replaces the isolated instance's metadata and tokens. Backups from versions with token hashing require the original operator token through the supported restore option; preserve it in independent protected recovery custody. Check organizations, buckets, permissions and representative time-range queries. |

Record the exact isolated target, versions, commands, successful exit status and application-level assertions in the private rehearsal record. Database tooling and credentials vary by selected version, so these native procedures own those options. A file digest match alone is not database recovery acceptance. For an app related to a database, restore its matching generation from `group.json` and exercise it with production integrations disabled.

The test succeeds only when the original client key was unavailable to the recovery process, the independent private copy recovers the wrapped key, and the restored data passes its stated checks. Missing or wrong recovery material must fail. A database export additionally needs a compatible isolated database restore; file checks alone do not prove a usable service. Record the snapshot identity, recovery-pair identifier, tool versions and actual results without secrets. See [evidence levels](../concepts/evidence.md) and [service verification](../operations/verify-and-maintain.md#service-verification).

## Later deployments and key replacement

Keep the same recovery public key during ordinary CD. Adding clients does not require regenerating the recovery pair or unlocking its private copy. Backup clients continue to use their own encryption keys; the shared recovery pair provides an additional recovery route.

Changing the public key affects backups made afterwards; it does not update existing wrapped keys. Retain each old private key and passphrase for as long as any required backup depends on it. Loss or compromise needs an explicit rotation/recovery plan. Never regenerate a missing key under the old identity or delete older copies merely because deployment succeeded. See [backup retirement and preservation](../reference/backup.md#later-deployments-and-retirement).

If both the live estate and all backup media are lost, possession of the recovery key cannot recreate the data. Independent key custody and independent backup replication solve different problems.

## Troubleshoot without replacing keys

| Observation | Meaning and next step |
| --- | --- |
| Generation says `unable to create master key - no tty` | Use an interactive terminal. Do not turn the process into a CI job or place the passphrase in arguments. |
| One output file exists after an interrupted generation | Preserve it and inspect the pair. Do not rerun in the same directory or assume the private copy was exported. |
| OpenSSL cannot open the exported PEM | Check that the intended complete file and passphrase were retrieved. Preserve the originals; do not generate a replacement. |
| Derived public key or fingerprint differs | This is the wrong pair or a damaged copy. Stop and locate the copy matching the recorded identifier. |
| The snapshot has no `rsa-encrypted.key` | It may not have been backed up with a recovery public key. Preserve the original client key and inspect the producer's configuration; adding a public key later does not repair old snapshots. |
| Key recovery succeeds but PBS access is denied | Authentication/ACLs are separate from decryption. Use the authorized recovery-access procedure; do not broaden guest permissions as a workaround. |
| Archive readback succeeds but an application fails to restore | Investigate the application's capture format, version and dependencies. Do not report service recovery from archive success alone. |

## Compatibility and recorded evidence

Use the PBS 4.2 native command interfaces shown in the [client manual](https://pbs.proxmox.com/docs/proxmox-backup-client/man1.html), and select compatible framework/library revisions as described in [deployment preparation](../guides/prepare-deployment.md#select-compatible-source). Record the actual tool versions used. Package installation or a successful compiler run does not prove the private recovery copies work.

Keep the generation date, public fingerprint, exported-copy checks and isolated restore result in the deployment owner's protected records. Do not record the passphrase or decrypted client key in the report. See [the completion checklist](operations.md#ready-for-unattended-operation) before relying on unattended backups.

[Backup setup](README.md) · [Backup reference](../reference/backup.md) · [Documentation standard](../contributing/documentation-standard.md)
