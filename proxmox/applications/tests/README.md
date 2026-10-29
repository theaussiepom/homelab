# Deployment resilience tests

`test_deployment_resilience.py` starts independent Python processes against
disposable private directories. Only input selection and native guest transports
are fixtures; the deployment state machine, locks, file writes and process signals
are real. Checkpoints coordinate processes without timing-based sleeps.

The cases cover SIGTERM/SIGKILL after infrastructure or application work, competing
deployments, simultaneous first input publication, interrupted input publication,
and receipt write/flush/fsync/rename failures. An interruption retains its hold and
evidence and refuses replay. After a successful rename followed by failed directory
fsync, the receipt may contain the complete new value; the hold must still survive.

`test_private_files.py` rejects hard-linked outputs before either append or
truncation. The Linux cases in `test_monitoring_database.py` use actual user xattrs,
mode and ownership during HBA replacement and failure recovery. These execute in
the existing pinned Debian 13 application test image in CI; they skip on macOS.
All tests use synthetic state and credentials and contact no guest or database.

Run the application suite with the hash-locked test environment:

```sh
python3 tools/measure_coverage.py --suite applications --output /tmp/application-coverage
```

The existing `applications` CI job runs that suite in the pinned test container
with a read-only source mount and disposable Linux `/tmp` filesystem.
