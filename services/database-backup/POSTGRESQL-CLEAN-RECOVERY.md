# PostgreSQL clean backup and isolated recovery

The capture helper supports native `--clean --if-exists` dumps. These options encode DROP/recreate statements in the archive; they do not execute them on the source. The deployment owner selects the exact backup service, image, database/account configuration, schedules, protected paths and archive. This document makes no claim about a deployed site or a completed recovery.

## Capture and restore contract

Preserve dump bytes unchanged. Record and check the reviewed full source-container ID, image and service identity at each preparation and execution stage. Restore only into a new isolated scratch environment using the matching database engine, with no production mounts, external network, published ports or application consumers.

The strict parser permits exactly one SQLSTATE `2BP01` diagnostic for the protected bootstrap `DROP ROLE postgres`, followed by exactly one `42710` diagnostic for the already-existing `CREATE ROLE postgres`. It validates exact message, function, order and counts; it rejects every other ERROR, FATAL or PANIC message and every client failure. Source line numbers may differ. The retained bootstrap identity is `postgres` at OID 10, and validation uses a separate unique administrator. Post-import checks use `ON_ERROR_STOP=1`.

## Required evidence

- Match success reported by the database tool to the exact archive identity, byte size, completed dump/checksum markers and successful command exit.
- Independently verify stable file identity, freshness, checksum and compression. Remote retrieval establishes its own byte identity; it is not a restore.
- Record and verify the identity of a read-only source metadata snapshot, then compare the selected databases' ACLs, ownership, encoding/collation, connection properties, comments and settings before and after isolated restart.
- Verify the required accounts' correct and wrong credentials without resetting accounts or silently supplementing grants.
- Preserve failures and scratch evidence. Any separately authorized cleanup must stay within that isolated target; the production container and data identities must remain unchanged.

Private deployment inputs may reconstruct an existing helper's protected credential JSON only in a mode 0700 private scratch directory, with the credential file itself mode 0600. Values and source metadata remain outside public source and logs. A manifest or test result alone does not establish source freshness, application authentication or current recoverability.
