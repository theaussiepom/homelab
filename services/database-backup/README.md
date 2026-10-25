# Database backups on BenBeast

[Back to the main README](../../README.md)

This folder contains the existing BenBeast database-backup extension and its
recovery notes. It helps capture databases to the NAS and an existing private
S3-compatible destination. **S3-compatible** means an object store accessed using
the S3 API; this deployment's offsite destination is Cloudflare R2.

This is a **site-specific operating guide**, not a fresh-install recipe. It is
separate from the [Proxmox installer and first guest](../../proxmox/README.md).
The bootstrap does not require a database.

## What is covered?

| Data | NAS schedule | Offsite schedule | Retention |
| --- | --- | --- | --- |
| Bitwarden MariaDB database | Hourly | Hourly, five minutes later | NAS 7 days; offsite 3 days |
| Home Assistant MariaDB database | Every 6 hours | Daily | 7 days |
| Full InfluxDB, all buckets | Every 6 hours | Daily, at 00:45 Brisbane time | 3 days |
| PostgreSQL databases, roles and permissions | Every 6 hours | Daily | 7 days |
| MariaDB system/accounts and configuration recovery bundle | Daily | Daily | 7 days |

Schedules use the recorded **Australia/Brisbane** scheduler timezone. Redis is
not covered. See [exact job numbers, cron expressions and cleanup behaviour](OPERATIONS.md#coverage-and-retention)
before changing any schedule or assuming an old archive will be retained.

## What you need before using these tools

- Access to the existing Linux Docker host and its reviewed `db_backup` service.
- The private canonical Compose files, environment files and recovery manifest.
- Existing NAS/offsite access and enough space for capture and isolated restore.
- The engine-specific restore procedure and the selected archive's exact identity.

These are private deployment inputs; this public folder cannot recreate them:

| Private input | Meaning |
| --- | --- |
| `DATABASE_STACK_DIR` | Folder containing the canonical `compose.yaml`. |
| `PRIVATE_INPUT_DIR` | Protected environment files used by Compose and the backup service. |
| `BACKUP_SOURCE_DIR` | Maintained source folder for the derived backup image. |
| `RECOVERY_MANIFEST` | Exact list of configuration files included in recovery bundles. |
| `RECOVERY_EVIDENCE_DIR` | Private deployment, capture and restore receipts. |

Do not invent missing values, reuse old override files or paste resolved settings
into public logs. Recovery bundles contain credentials; treat them like passwords.

## 1. Check the existing deployment

On the **Docker host**, inspect the named backup container without recreating it:

```sh
docker ps --filter name=database-db_backup-1 --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'
```

**Expected result:** the intended backup container appears running. This alone
does not prove a backup succeeded. Compare its deployment with the current private
canonical inputs and inspect the private scheduler/job receipts.

Use [the operating reference](OPERATIONS.md#deployment-inputs) for exact mappings,
permissions and the reviewed service-only update process. Stop if the deployed
identity differs; do not run a historical recreation command to make it match.

## 2. Check a completed backup

Use the normal scheduler's result for the selected job. Check its completion time,
successful status, archive and checksum. An archive's mere presence is insufficient.

The [retrieval helper](verify-s3-download.py) can independently download a
selected completed offsite archive and verify its integrity. It runs **inside
the existing backup container**, reads offsite storage and saves protected NAS
copies. It neither starts backups nor writes to offsite storage.

See [retrieval instructions](OPERATIONS.md#retrieval-and-restore-evidence) for
`--scope`, `--not-before` and paths. Supply the start time of the backup you are
checking. The cutoff is a lower bound, not an exact-run selector: compare the
retrieved archive identity with that run's receipt, especially if a newer backup
has since completed.

**Expected result:** a receipt identifying the exact independently retrieved
bytes and successful checks. This still does not prove restoration.

## 3. Prove restoration on an isolated target

For PostgreSQL, follow the [current clean-recovery procedure](POSTGRESQL-CLEAN-RECOVERY.md)
and compare with its [dated acceptance record](POSTGRESQL-CLEAN-ACCEPTANCE.md).

A **clean** dump contains statements that drop and recreate destination objects.
Restore only to a deliberately selected, isolated recovery target. Do not reuse
production database mounts, networks or published ports for a practice restore.

**Expected result:** the intended engine restores the selected unchanged archive,
with the required roles, permissions, settings and credential checks passing
before and after restart. Each engine needs its own checks; a checksum is not
a substitute for a restore.

## When something goes wrong

| What you see | What to do |
| --- | --- |
| A dump fails its privilege/coverage check | Keep the failure and inspect the exact permission or unsupported object. Do not skip data to produce a passing archive. |
| A checksum, download or decompression check fails | Preserve the bytes/receipt; do not restore or silently replace them. |
| Restore runs out of scratch space | Stop at the space guard; do not borrow a production database volume. |
| Restore reports an unexpected SQL error | Stop and use the engine's restore contract. Never edit dump bytes just to get a pass. |
| Service update fails | Inspect the exact runtime and retained deployment receipt before a separately reviewed recovery action. Do not replay an old rollback model. |

## What has actually been verified?

The [operating reference](OPERATIONS.md) preserves the **7 October 2026**
records. The newer [8 October PostgreSQL acceptance](POSTGRESQL-CLEAN-ACCEPTANCE.md)
records native clean dumps, an isolated NAS restore with database permissions
and five credential checks preserved across restart, and independent R2 retrieval.

The independently retrieved R2 archive was integrity/permission-SQL checked,
not separately restored. Earlier InfluxDB and MariaDB results have their own
dated limits; they do not establish current coverage for every database.
These are historical receipts, not a fresh health check of today's services.

For exact retention, sensitive-role permissions, scheduler behaviour and update
ordering, continue to the [operating reference](OPERATIONS.md).
