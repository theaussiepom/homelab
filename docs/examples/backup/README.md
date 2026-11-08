# Complete backup configuration example

[Backup guide](../../backup/README.md) · [Configuration reference](../../reference/backup.md)

This complete **offline synthetic example** uses the `homelab-components-v1` schema. It combines one DNS guest, its PBS client profile, an unprotected staging volume, a declared PBS endpoint, an Environment-secret reference and a public recovery-key fixture. It contains no real credentials. The image digest, addresses, trust fingerprint and controller paths are deliberately nonfunctional: do not deploy or pull this example.

## Files and compatibility

- [stack.json](stack.json) defines the reusable guest, application and backup profiles.
- [images.json](images.json) is the synthetic image catalogue.
- [site.yaml](site.yaml) binds those profiles to one enrolled guest and a backup job.
- [Public key fixture](assets/master-public.pem.fixture) is a valid synthetic RSA-4096 public key. Its private key is not supplied; generate your own recovery pair for a real installation.

Framework, library, site and catalogue all come from the **same reviewed checkout**. No external library branch is selected. Use that checkout's hash-locked tooling; mixing these files with an older published framework is not a supported example. Record `git rev-parse HEAD` with your results. The package version in this offline fixture is a declaration, not evidence that a particular operating system or package repository can install it.

## Compile and inspect

Start at the framework repository root. Use Python 3.12 or later and create a disposable virtual environment using the hash-locked installation commands in [your first configuration](../../guides/first-configuration.md). Keep that environment activated for the commands below; do not use an unrelated system interpreter. These commands run locally, do not read the referenced secrets and do not contact PBS. They write one packet in a fresh private temporary directory.

<!-- example: backup-complete-compile -->
```bash
FRAMEWORK=$(pwd -P)
PBS_EXAMPLE="$FRAMEWORK/docs/examples/backup"
PBS_EXAMPLE_WORK=$(mktemp -d)
python3 "$FRAMEWORK/blueprints/compile.py" \
  --stack "$PBS_EXAMPLE" --site "$PBS_EXAMPLE/site.yaml" \
  --guest resolver --output "$PBS_EXAMPLE_WORK/resolver.json"
python3 - "$PBS_EXAMPLE_WORK/resolver.json" <<'PYCODE'
import json, sys
packet = json.load(open(sys.argv[1]))
cfg = json.loads(packet['files']['site.json'])
backup = cfg['app']['backup']
assert cfg['guest']['volumes']['backup-stage']['backup'] is False
assert backup['job']['destination']['datastore'] == 'recovery'
assert backup['job']['destination']['backup_id'] == 'guest-610'
assert 'pbs-agent' in cfg['deployment']['phases']
print('Enrolled: resolver; datastore: recovery; staging: excluded; PBS agent: selected')
PYCODE
```

The final line must match the printed text above. The packet contains public source and references, not token or encryption-key values. Compilation is not a datastore check, credential creation, package-installation test or backup.

## Try a meaningful change

Copy this directory to a new disposable location before editing it. Remove the guest's `backup` marker and remove the operational `job`, `management` and `recovery_public_key` objects, leaving root `backup: {}`. Compile again: the guest must receive no PBS phase. Root settings alone do not enroll it. Removing a guest marker while leaving its job-client entry must instead fail with `component.backup-client-coverage`.

These edits teach source selection only. Removing protection from a real installation needs the [retirement procedure](../../reference/backup.md#later-deployments-and-retirement); this exercise grants no permission to delete credentials or backups.

Continue with [real input preparation](../../backup/configure.md). Replace synthetic allocations, use compatible published source selections, verify storage and trust, and create the operator recovery pair before a real deployment.
