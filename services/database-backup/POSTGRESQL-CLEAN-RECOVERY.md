# PostgreSQL native clean backup and recovery addendum

Status: completed on 8 October 2026. Both native backup jobs passed; fresh NAS
restoration and independent R2 retrieval/SQL checks passed. See [ACCEPTANCE.md](POSTGRESQL-CLEAN-ACCEPTANCE.md)
and the named receipts for the exact archive and runtime evidence. The helper
variants have 46 passing local tests, with 12 deployment and 14 clean-restore
tests. This is not a production recovery or application-start claim.

Path placeholders such as `${PRIVATE_INPUT_DIR}` refer to operator-supplied private
locations. Resolve them from the reviewed deployment inputs; they are not defaults.

## Persistent configuration

The canonical `db_backup` service retains these PostgreSQL clean-backup options:

```text
DB07_EXTRA_BACKUP_OPTS=--clean --if-exists
DB08_EXTRA_BACKUP_OPTS=--clean --if-exists
```

Use Compose project `database`, project directory
`${DATABASE_STACK_DIR}`, the canonical file
`${DATABASE_STACK_DIR}/compose.yaml`, and protected
interpolation file `${PRIVATE_INPUT_DIR}/database.env`.
The service's private env file is
`${PRIVATE_INPUT_DIR}/database.db_backup.env`.
Do not add historical image/extension override files to these current inputs.

Only the selected backup service is recreated for backup configuration changes.
Its image remains pinned to
`sha256:d1002822e1742779f3e4e0410b2bc260af6dbcb9b8bc4d8272590d3c136eb490`.
The replacement container's reviewed full ID must be supplied explicitly to
capture, input preparation, and execution. Image, service name, and source
container pins remain enforced. Deployment acceptance must prove that the other
34 production containers and the preserved configuration are unchanged.

## Capture and restore contract

Job 07 remains the native PostgreSQL NAS job; job 08 remains its native cloud
counterpart. Their schedules, destinations, credentials, compression, and native
retention policy are retained. The new dump options encode DROP/recreate commands
in the backup; they do not execute those commands against the source database.

Apply these clean dumps only to the disposable isolated restore target. Preserve
the original dump bytes. Do not strip SQL, rewrite ownership/grants, or apply an
unrecorded grant supplement. The target uses the installed matching PostgreSQL
image, fresh SSD scratch, no published ports, no external network, and no
application consumers. It retains the source bootstrap identity `postgres` at
OID 10 and imports through a unique validation superuser/database.

The fixture-verified import exception contract is exactly one PostgreSQL SQLSTATE
`2BP01` for the protected bootstrap `DROP ROLE postgres`, followed by exactly one
`42710` for `CREATE ROLE postgres` already existing. The parser must match the
reviewed exact diagnostic text and order; every other ERROR/FATAL/PANIC or client
failure fails the restore. Normal NOTICE/INFO output is retained privately.
Post-import validation uses `ON_ERROR_STOP=1`. The PostgreSQL 16.15 client and
pinned PostgreSQL 16 server reproduced this sequence in the isolated fixture.
The protected DROP location is `checkSharedDependencies, pg_shdepend.c`; the
duplicate CREATE location is `CreateRole, user.c`. Source-line numbers may vary,
but the diagnostic message, SQLSTATE, function and count must match.

## Required acceptance evidence

- Native job success must correlate the exact new archive name and byte size
  with dump/checksum markers and one zero routine exit. Independently verify
  MD5, SHA256, compression integrity, stable file identity, and dispatch-time
  freshness. Cloud retrieval integrity is recorded separately.
- Hash-pin the read-only source metadata snapshot for `authentik`, `postgres`,
  `template1`, and `zabbix`. Compare normalized ACLs, ownership, encoding,
  collation, connection properties, tablespace, comments, and settings before
  and after target restart. Explicit `homelab_backup` CONNECT on `postgres`
  must survive, as must its native backup capabilities.
- Test correct and wrong credentials for all five required combinations:
  `homelab_backup` on all three application/default databases, `zabbix` on
  `zabbix`, and `authentik` on `authentik`. Source probes are read-only; target
  authentication and structural checks must pass before and after restart.
- Execution acceptance independently requires both metadata comparison flags,
  the exact source metadata SHA256, target cleanup, and an unchanged production
  container baseline. Failed scratch is retained for diagnosis.

## Private paths and evidence

The historical 8 October evidence is retained under
`${RECOVERY_EVIDENCE_DIR}`, including
`source-metadata-before.json`, `postgresql-nas-checkpoint/receipt.json` and
`postgresql-inputs/receipt.json`. It records that deployment, not the current
container identity.

For current recovery, read `deployment_metadata.postgresql_backup_recovery` in
`${RECOVERY_MANIFEST}`. Resolve
the canonical backup Compose using its protected env inputs. This mapping names
the captured canonical Compose source and protected `DB07_PASS`/`DB08_PASS` keys;
it contains no password value. Host, port and username come from `DB07_HOST`,
`DB07_PORT` and `DB07_USER`. Require the DB08 identity to agree before use.

The recovery maintenance database is `postgres`. This is distinct from scheduled
`DB07_NAME=ALL` and `DB08_NAME=ALL`, which must stay unchanged. If a reviewed
restore helper needs the old credential JSON shape, reconstruct a unique
mode-0600 temporary file inside private recovery scratch from the canonical
resolved identity, with fields `host`, `port`, `username`, `password` and
`database` (the last fixed to `postgres`). Keep the identity on the host, never
print or put credentials on a command line, and do not reuse a stale credential
file as the authoritative source. Validate the helper's contract and pins before
running it; this documentation update does not launch a restore.

Preparation writes the five credentials only to
`postgresql-inputs/postgresql-auth-complete.private.json`; logs and receipts remain
private and never print secrets. `execute-postgresql-restore.py` requires the
reviewed full backup ID and SHA256 of `restore-sql-clean.py`.

The shared restore lock remains
`${RESTORE_LOCK}`. Target scratch is
under `${RESTORE_SCRATCH}`; previous receipts and source archives
are retained, subject to the already configured native retention policy.

These helpers perform no production database writes or database storage moves.
Live applications can continue their normal writes. Source ACL/property equality
and container preservation are separate checks; they do not claim a frozen
cross-database snapshot or successful application startup.
