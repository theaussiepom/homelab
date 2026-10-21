# PostgreSQL backup permissions — completed 8 October 2026

The missing default-database grant is now preserved natively in new backups.
No compensating SQL was applied to the source or restored databases.

## Deployed change

Both existing PostgreSQL jobs now use `--clean --if-exists`: job 07 to NAS and
job 08 to the existing R2 destination. Only the backup container was recreated,
at 13:23 AEST. Its image, all other environment values, mounts, networks,
schedules, retention and three Compose inputs were preserved. All ten native
jobs remain configured; the scheduler is running.

## Verified results

| Check | Result | Evidence |
| --- | --- | --- |
| Native clean fixture | PostgreSQL 16.15 preserved bootstrap OID 10, grants, a PUBLIC revoke, comments and settings across restart | `clean-fixture-result-r2.json` |
| NAS backup | 13:24:13 AEST archive, 396,671,996 bytes; native job success, MD5, SHA256 and compression verified | `postgresql-nas-checkpoint.json` |
| Full NAS restore | 165 Authentik tables, 203 Zabbix tables, no invalid/unready indexes | `postgresql-full-restore-receipt.json` |
| Database permissions/settings | Exact normalized comparison across authentik, postgres, template1 and zabbix before and after restart; explicit backup CONNECT on postgres restored | Same receipt |
| Authentication | All five account/database combinations accepted correct passwords and rejected wrong passwords before and after restart | Same receipt |
| R2 backup | 13:25:25 AEST archive; native job completed successfully; independent 396,689,991-byte retrieval passed checksum, compression and TLS verification | `postgresql-cloud-verification.json` |
| R2 permission SQL | Retrieved archive contains the native default-database recreation and explicit postgres CONNECT grant | `postgresql-cloud-clean-markers.json` |
| Source preservation | Source database metadata remained identical across backup and restore | `source-metadata-before.json`, `source-metadata-after.json` |
| Runtime preservation | Only backup container recreated; other 34 unchanged; all 35 unchanged during isolated restore; no restore containers remain | `deployment.json`, `postgresql-full-restore-execution.json`, `final-runtime-verification.json` |

The clean restore accepts only the fixture-proven, ordered pair of protected
bootstrap DROP (`2BP01`) and duplicate CREATE (`42710`) diagnostics. Every other
error fails validation. Dump bytes were not edited, and successful scratch data
was removed.

## Recovery implications and limits

Use the procedure in [RECOVERY.md](POSTGRESQL-CLEAN-RECOVERY.md). Clean dumps contain destination
DROP/recreate statements and belong on a deliberate recovery target. Older
archives retain their previous format. The isolated restore used the named NAS
archive; the independently retrieved R2 archive was integrity-checked and its
permission SQL checked, but was not separately restored. No applications were
started against scratch and no exact live-data or cross-database snapshot equality
is claimed.

Production databases were neither restarted nor moved. The SSD database migration
remains a separate next step. The first synthetic fixture attempt failed on a
local logging option before database startup; its evidence remains retained, and
the corrected fixture passed without changing production.
