# Database backup operating reference

[Start with the reader guide](README.md). This reference preserves the detailed
7–8 October 2026 deployment and recovery records. They describe those dated
checks, not a fresh inspection of the current host.

## Update 8 October 2026: PostgreSQL native clean recovery verified

Jobs 07 (NAS) and 08 (R2) now use `--clean --if-exists`. The formerly missing default-database CONNECT grant is preserved natively. Fresh NAS restoration matched all four database ACLs/properties and five credential checks before and after restart; independent R2 retrieval passed integrity and grant-SQL checks. Only the backup container was recreated; the other 34 containers remained unchanged.

Use [the current recovery procedure](POSTGRESQL-CLEAN-RECOVERY.md) and [acceptance record](POSTGRESQL-CLEAN-ACCEPTANCE.md). The older results below describe their original archives and are retained as history. Private current receipts are under `${RECOVERY_EVIDENCE_DIR}`; deployment rollback snapshots are in its `deployment` directory. Existing configuration recovery jobs will collect these updated source notes on their normal schedule.

# BenBeast database backup extension

This extends `database-db_backup-1` only. Production database images and storage are unchanged. The initial extension was deployed at 2026-10-07 08:55 UTC. The r2 image is `sha256:d1002822e1742779f3e4e0410b2bc260af6dbcb9b8bc4d8272590d3c136eb490`; deployment acceptance is recorded in `r2/deployment-verified.json`. The raw apply check rejected a reordered mount array; independent comparison confirmed identical mounts and all other runtime settings. The other 34 production containers remained unchanged. Backup capture, destination retrieval and isolated restoration are separate acceptance checks.

## Deployment inputs

The maintained deployment uses Compose project `database`, project directory
`${DATABASE_STACK_DIR}`, and the single canonical file
`${DATABASE_STACK_DIR}/compose.yaml`. Compose interpolation
uses `${PRIVATE_INPUT_DIR}/database.env`; the backup service's
protected env file is `${PRIVATE_INPUT_DIR}/database.db_backup.env`.
The resolved service preserves the ten job definitions, retention, destinations,
logging and pinned image. The maintained image build source is
`${BACKUP_SOURCE_DIR}`.

Recovery bundles include the canonical Compose and private inputs. Their manifest
is `${RECOVERY_MANIFEST}`.
The four retired duplicate input labels have been consolidated into the remaining
21 mappings; their original files and historical deployment receipts are retained.
Do not recreate the service from an old extension/image override or replay an old
rollback argument list. Those describe historical deployments.

## Coverage and retention

| Job | Contents | Destination | Cron expression | Retention |
| --- | --- | --- | --- | --- |
| 01 | MariaDB `bitwarden_vault` | NAS | `0 * * * *` | 7 days |
| 02 | Same | Existing private S3 destination | `5 * * * *` | 3 days |
| 03 | MariaDB `homeassistant` | NAS | `10 0,6,12,18 * * *` | 7 days |
| 04 | Same | S3 | `20 0 * * *` | 7 days |
| 05 | Full InfluxDB backup, all buckets | NAS | `30 0,6,12,18 * * *` | 3 days |
| 06 | Same | S3 | `45 0 * * *` | 3 days |
| 07 | PostgreSQL cluster, roles, password hashes, grants and databases | NAS `/backup/postgresql` | `15 2,8,14,20 * * *` | 7 days |
| 08 | Same | S3, relative prefix `${DB08_S3_PATH}` | `15 3 * * *` | 7 days |
| 09 | MariaDB `mysql`, `phpmyadmin`, portable users/grants and recovery configuration bundle | NAS | `40 2 * * *` | 7 days |
| 10 | Same | S3, relative prefix `${DB10_S3_PATH}` | `40 3 * * *` | 7 days |

These expressions run in the observed scheduler timezone, Australia/Brisbane (AEST, UTC+10). On 7 October, the scheduler process inherited `TZ=Australia/Brisbane` and runtime dates/archive filenames matched AEST, although the base image also retained `TIMEZONE=Etc/GMT`. The extension did not change either setting. Recheck the effective scheduler environment after future base-image changes.

Jobs 01–04 retain their original settings. Jobs 05–06 changed only their selected Influx database/bucket name to `ALL`. Older archives remain subject to their existing retention. Redis has no backup job in this extension.

The `/backup` directory is the existing NAS Docker volume with subpath `homelab-data/backups/databases`. Recovery bundles are retained in `/backup/database-recovery/configs`; job 10 also uploads its bundle and SHA-256 sidecar alongside native dumps. Native S3 cleanup covers all flat objects in the job 10 prefix after seven days. After a failure, subsequent cleanup is skipped; an earlier successful split component may already have performed its retention cleanup. These copies share the existing NAS/S3 access and encryption policies; this extension did not add a new encryption key system.

## Credentials and controls

The protected extension directory, PostgreSQL role credential, resolved models, rollback snapshots, and logs must remain private. Directories use mode 0700 and sensitive files mode 0600. Do not print resolved Compose, environment values, dumps, archive contents, bucket names or endpoints into routine logs or commit them to Git. Literal dollar signs are escaped only when serializing the private Compose overlay.

`homelab_backup` is a dedicated PostgreSQL login with `pg_read_all_data`, `BYPASSRLS`, explicit `SELECT` on `pg_authid`, and database connection grants. It is not a superuser and cannot create databases, roles, or replication connections. Its access to all data and password hashes still makes its credentials highly sensitive. Application accounts were not changed.

The pinned derived backup image adds PostgreSQL 16 clients without upgrading existing packages. Both scheduler PATH and sudo's fixed PATH select the PostgreSQL 16 tools. The guarded `pg_dumpall` validates privileges and checks every connectable database before each dump. Large objects, subscriptions, user mappings, or foreign tables cause a failure pending privilege/coverage review; none existed at preparation. A guard failure prevents the dump, destination move, and retention cleanup. The preflight and dump use separate sessions, so concurrent object creation is not synchronized.

Recovery bundles contain portable MariaDB users/grants, active database configuration, private Compose/environment inputs, the PostgreSQL backup credential, build sources, and a checksum manifest. Protect them as credentials. The manifest records preparation-time image identities; review current deployed images before restoration.

The candidate's `patch-native-hooks.py` checks the exact pinned framework source hash before fixing native status propagation. Backup, destination transfer, checksum-upload, and named post-script failures set the scheduler's aggregate failure status. Post-script settings are bare executable paths with `POST_SCRIPT_X_VERIFY=false`; the wrappers run the recovery bundle after the last successful split component. This patch is included in the r2 image. The earlier 08:55 image receipt describes r1; r2 has its own preparation and deployment verification records.

## Recreate only the backup service

Use a reviewed change with a fresh full runtime/source baseline. Safely pause the
native scheduler, drain active backup/retention/hook processes, then stop and
recreate only `db_backup` from the canonical inputs above. Preserve its exact
image, environment, job schedules, destinations and remaining mounts. In
particular, single-file bind mounts must be verified in the replacement container;
changing their host paths or files is not proof of the running container's view.

Validate the complete resolved model and running configuration, all 21 exact
recovery mappings, the current canonical source views, and preservation of the
other containers/networks/storage before resuming all ten schedules. Verify the
actual scheduler process after resumption. Do not start a manual cloud job for
acceptance. A subsequent normally scheduled recovery bundle provides evidence
that the new source set was archived; retain originals until that is verified.

If a guard or publication step fails, preserve its evidence and inspect the exact
state. Do not automatically replay, retry, or apply the historical rollback model.

## Retrieval and restore evidence

`verify-s3-download.py` is a later-run operator helper, not a scheduled job. Run it inside the existing backup container after the selected jobs succeed, with `--not-before` set to the start of that backup run. The default `--scope both` retrieves jobs 08 and 10; `postgresql` and `recovery` select either alone. `--scope influxdb` retrieves job 06 only, requires its configured name to be `ALL`, and accepts only a new `influx2_all_*.tar.zst` archive. It reads private S3 configuration from the container, downloads the selected archives and checksum sidecars, and retains protected verified copies beneath `/backup/database-recovery/s3-verification`. It prints a sanitized receipt and never extracts SQL or configuration contents. Its independent SHA-256 hashes identify the retrieved bytes; native checksum validation uses the actual configured sidecar algorithm. Influx selection, checksum and compression verification do not independently verify bucket contents or restoration; the receipt explicitly separates those claims.

After the reviewed helper is placed alongside this README in the host build-source directory, its existing read-only source mount exposes it inside the container; no image rebuild or service recreation is needed to run it:

```text
python3 /recovery-source/backup/image-build-source/verify-s3-download.py --not-before 2026-10-07T09:20:00Z
```

Use the receipt's protected PostgreSQL path as the isolated restore input. `/backup/...` maps to `/mnt/nas/docker/homelab-data/backups/databases/...` on BenBeast. The helper neither triggers backups nor writes to S3. Downloaded verification copies are retained for the operator; they have no automatic cleanup policy.

Archive presence, upload success, remote metadata, checksum validation, and decompression checks do not prove restoration. Acceptance requires strict isolated restores with the intended production engine versions, preserved roles/grants/configuration, appropriate application authentication checks, and independent NAS/S3 evidence. Use a unique scratch administrator for portable MariaDB accounts. For PostgreSQL, initialize with the original `postgres` bootstrap identity (OID 10), then add a separate validation administrator. For the current clean dumps, the runner requires exactly one `2BP01` diagnostic for the protected `DROP ROLE postgres`, followed by exactly one `42710` duplicate `CREATE ROLE postgres`, in that order. Every other error fails restoration. See the [current clean-restore contract](POSTGRESQL-CLEAN-RECOVERY.md#capture-and-restore-contract). Preserve the dump bytes unchanged. Raw `mysql` tables are a version-specific fallback. InfluxDB needs full metadata/all-bucket restoration; bucket-only archives do not prove full recovery. No production database mount, network, or published port should be reused by a restore test.

## Verified results and remaining boundary (7 October 2026)

- Local storage inspection found 850.816406 GiB unallocated in the existing VG. No filesystem was created and no production data was moved. SSD health showed no critical warning or media errors at the check.
- PostgreSQL NAS and S3 backup jobs passed. The independently retrieved S3 archive passed native checksum, compression and TLS checks, then restored with PostgreSQL 16.10. Authentik had 165 tables and Zabbix 203; index checks and recorded backup/Zabbix credential probes passed before and after isolated restart. The scratch container and data were removed.
- Native PostgreSQL no-clean dumps omit explicit ACL metadata for the default `postgres` database. The source's explicit backup-role CONNECT grant was absent after restore, while effective CONNECT and all recorded backup capabilities passed. No supplement was silently applied. Application authentication was excluded from that historical acceptance; detailed authentication observations remain in protected receipts. No application service was started against scratch.
- Full InfluxDB NAS capture and isolated InfluxDB 2.7.12 restoration passed for all four buckets. Selected history timestamps, retention/metadata and the backup token passed checks across restart. Scratch was removed and production identity/start time stayed unchanged. Full S3 job 06 passed and an independent download of its 2,302,124,551-byte archive passed native MD5, compression and HTTPS certificate checks. The SHA-256 receipt identifies these bytes. This newer S3 snapshot was not separately restored; the successful full restore used the earlier NAS archive.
- MariaDB recovery jobs remain blocked until an administrator grants SHOW VIEW on mysql.* to backup@%. Do not omit the mysql.user view, edit privilege tables or reset credentials to bypass the failure. The corrected r2 job 09 returned exit 1 for MariaDB error 1142 (SHOW VIEW denied on mysql.user), withheld the failed system archive and skipped its recovery hook. No complete portable MariaDB/configuration recovery claim is made until NAS/S3 jobs and the isolated restore pass.

The active temporary backup staging location is `/tmp/backups` in the container's writable layer on the host root filesystem, not the NAS. The existing scheduler serializes backup jobs; the full Influx test stayed within the reviewed scratch capacity, but future growth still requires capacity review. The independent restore runner stops at its free-space guard. This work did not relocate staging.

MariaDB metadata was inspected read-only: application tables are InnoDB, mysql includes Aria/CSV tables and one view, and the server has built-in routines. Native dump settings include routines, events and single-transaction mode; source event scheduling was off. A metadata inventory and command flags are not proof of successful recovery, especially for nontransactional system tables.

The former coordination hold was released at 09:30 UTC on 7 October. It no longer blocks this authorized backup verification. Preserve historical receipts rather than overwriting failed attempts. Sanitized acceptance evidence lives in the originating task under `work/database-backup-readiness-20261007`; protected runtime receipts and logs remain in the extension and restore directories on BenBeast.

A final configuration-source check found historical recorder rehearsal dumps nested under the legacy MariaDB config directory. The task-created manifest now selects that directory's only configuration file, `my.cnf`, preserving its archive path; the active canonical `my.cnf` remains a separate source. Historical dumps were not moved or deleted. All 16 manifest sources (27 files) passed readability/size checks afterward. Add any future configuration files deliberately to this manifest. The manifest was rewritten in place while idle, preserving its bind-mounted inode; `config-scope-correction.json` records before/after hashes and the original bytes remain preserved.

Final runtime inspection at 10:42 UTC confirmed 35 production containers running, the other 34 unchanged from the backup-revision baseline, no isolated restore containers, preserved MariaDB emergency archives, and approximately 32.6 GiB root free space. No database migration or production database restart was performed in this backup extension.
