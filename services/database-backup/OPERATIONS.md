# Database backup helper contracts

[Reader guide](README.md) · [PostgreSQL clean restore](POSTGRESQL-CLEAN-RECOVERY.md)

## Inputs and ownership

The operator supplies the authoritative Compose configuration, protected environment files, recovery manifest, exact source-container identity, image pin and selected archive. Schedules, retention, database names, account capabilities, destinations and timezone are chosen by the deployment owner. Public source does not record a verified live deployment or the current configuration of any installation.

Private directories use mode 0700 and sensitive files 0600. Recovery bundles can contain database accounts, configuration and private keys; protect them as credentials. Do not print resolved Compose, environment values, dumps or bucket identifiers to routine logs. Literal dollar signs are escaped only while serializing the private Compose overlay.

## Capture and hooks

The pinned image build verifies its upstream hook source before patching status propagation. Failures during database capture, transfer to the destination, checksum upload or the post-backup hook contribute to the final status. Guarded PostgreSQL capture checks its required privileges and supported objects before dumping. Preflight and dumping run in separate sessions, so they do not prevent concurrent changes to the source.

The patched post-script dispatcher requires an executable hook and propagates its failure. An executable-bit check is not a runtime signature or content check. Before applying a service update, verify selected hook bytes, owners, modes and read-only mounts against the reviewed private model. Keep exact existing job configuration; do not infer it from the slot numbers used by helper compatibility contracts.

## Service updates

Use the normal reviewed deployment path. Pause new work from the selected backup scheduler and wait for its active jobs to finish before replacing only that managed service. Preserve image, mounts, job definitions, credentials, destinations and retention unless a reviewed change explicitly selects them. Verify the single-file mounts inside the replacement container and compare unrelated runtime identities before resuming schedules. A failed or uncertain update retains its evidence; commands recorded from earlier operations do not authorize a retry or rollback.

## Retrieval

`verify-s3-download.py` runs in the selected backup container. It reads existing protected S3 configuration, retrieves archives and sidecars to protected local storage, verifies checksum/compression integrity and emits a receipt containing only the defined result fields. It neither dispatches backups nor writes to the remote destination.

Its defined scope selectors retain compatibility with numbered backup slots: `postgresql`, `recovery`, `both`, and `influxdb`. Inspect the helper's selected slot/name contract against the private deployment before use. `--not-before` requires a UTC timestamp, but is a lower bound, not an exact-run selector. Compare the returned archive identity with the intended completed job, particularly when newer archives can exist. Verification copies have no automatic cleanup policy.

## Restore acceptance

Use the unchanged archive with the matching database engine in a new, isolated scratch environment. Verify schema/data, owners/grants, database properties and whether correct application credentials succeed and wrong credentials fail before and after restart. Full InfluxDB recovery requires metadata and all selected buckets; a bucket-only archive is not a full recovery. MariaDB portable accounts and version-specific system tables need their own documented contract. PostgreSQL clean imports permit only the two specific errors described in the linked reference. Capture, upload, retrieval, integrity and restore results are distinct evidence and must be reported separately.
