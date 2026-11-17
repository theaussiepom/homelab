# Deployment resilience tests

`test_deployment_resilience.py` starts independent Python processes against disposable private directories. Only input selection and transport to guests use test doubles; the deployment state machine, locks, file writes and process signals are real. Checkpoints coordinate processes without timing-based sleeps.

The cases cover SIGTERM/SIGKILL after infrastructure or application work, competing deployments, simultaneous first input publication, interrupted input publication, and receipt write/flush/fsync/rename failures. An interruption retains its hold and evidence and rejects another attempt. After a successful rename followed by failed directory fsync, the receipt may contain the complete new value; the hold must still survive.

`test_private_files.py` rejects hard-linked outputs before either append or truncation. The Linux cases in `test_monitoring_database.py` use actual user extended attributes (xattrs), file permissions and ownership during host-based authentication (HBA) file replacement and failure recovery. These execute in the existing pinned Debian 13 application test image in CI; they skip on macOS. All tests use synthetic state and credentials and contact no guest or database.

Run the application suite with the hash-locked test environment:

```sh
python3 tools/measure_coverage.py --suite applications --output /tmp/application-coverage
```

The existing `applications` CI job runs that suite in the pinned test container with a read-only source mount and disposable Linux `/tmp` filesystem.

`test_component_recovery.py`, `test_component_current.py` and
`test_component_restore.py` exercise genuine sealed inputs, immutable receipts,
backend generations, exact holds and local managed-file restoration. Native
Proxmox/Ansible transport is replaced with fakes. They cover failed forward
work, uncertain writers, interrupted publication, rollback checkpoints,
reconciliation, future deployment admission and preservation of failure history.
`test_backup_readiness.py` verifies backup admission after rollback and explicit
reconciliation without replacing backup keys. These are source and local
transaction checks, not a live rollback or database-restore exercise. See
[CD recovery](../../../docs/operations/cd-recovery.md) for the supported boundary.

The separate CloudBeaver Community/OIDC fixture retains failed queries and
private server logs before removing its owned containers. Its public failure
summary includes only closed exception names and frames, plus a bounded PID
count and configured PID limit from that same owned Community container.
Unavailable or timed-out process statistics remain unknown; they cannot change
the original query failure or prevent cleanup. These observations help
distinguish resource limits from application errors without exporting server
messages, sessions or query results. They do not establish a cause by themselves.
