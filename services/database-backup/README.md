# Database backup and recovery helpers

[Back to the main README](../../README.md)

This component contains reusable backup-image hooks, guarded database capture,
protected configuration bundles, retrieval verification and isolated restore
helpers. It does not select a site's databases, schedules, storage destinations,
credentials or deployed container. Those are explicit private inputs.

The [operating contract](OPERATIONS.md) describes the helper boundaries. The
[PostgreSQL clean-restore contract](POSTGRESQL-CLEAN-RECOVERY.md) explains the
strict import exception handling. Source and synthetic tests establish code
behavior; they are not evidence of a current backup, working schedule or restore.

Before using an operator helper, review its input schema and bind the exact
container, image, archive and protected paths. Keep resolved configuration,
credentials, archive contents and operation receipts private. A retrieved archive
and matching checksum prove byte integrity; isolated engine and authentication
checks are required to establish recoverability.

No helper here is an automatic production recovery engine. Never reuse a
production data mount, network or published port as restore scratch, and never
edit dump bytes or omit failed database objects to claim a successful restore.
