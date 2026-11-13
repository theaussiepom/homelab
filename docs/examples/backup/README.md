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
print('Enrolled: resolver; datastore: recovery; staging: excluded; Backup step: selected')
PYCODE
```

The final line must match the printed text above. The packet contains public source and references, not token or encryption-key values. Compilation is not a datastore check, credential creation, package-installation test or backup.

## Try a meaningful change

From the framework repository root, run the following commands to make a disposable copy. They remove the guest's `backup` marker and replace shared operational settings with `backup: {}` in that copy only. Compilation and inspection both use the changed copy; the original example stays enrolled.

<!-- example: backup-unenrolment-compile -->
```bash
FRAMEWORK=$(pwd -P)
PBS_CHANGE_WORK=$(mktemp -d "${TMPDIR:-/tmp}/homelab-backup-example.XXXXXXXX")
PBS_CHANGE_WORK=$(cd "$PBS_CHANGE_WORK" && pwd -P)
cp -R "$FRAMEWORK/docs/examples/backup" "$PBS_CHANGE_WORK/example"
PBS_CHANGED_EXAMPLE="$PBS_CHANGE_WORK/example"
python3 - "$PBS_CHANGED_EXAMPLE/site.yaml" <<'PY_CHANGE'
from pathlib import Path
import sys, yaml
path = Path(sys.argv[1])
site = yaml.safe_load(path.read_text())
del site['guests']['resolver']['backup']
site['backup'] = {}
path.write_text(yaml.safe_dump(site, sort_keys=False))
PY_CHANGE
python3 "$FRAMEWORK/blueprints/compile.py" \
  --stack "$PBS_CHANGED_EXAMPLE" --site "$PBS_CHANGED_EXAMPLE/site.yaml" \
  --guest resolver --output "$PBS_CHANGE_WORK/resolver.json"
python3 - "$PBS_CHANGE_WORK/resolver.json" <<'PY_CHANGE_CHECK'
import json, sys
packet = json.load(open(sys.argv[1]))
cfg = json.loads(packet['files']['site.json'])
assert 'backup' not in cfg['app']
assert 'pbs-agent' not in cfg['deployment']['phases']
print('Unenrolled: resolver; Backup step: absent')
PY_CHANGE_CHECK
```

The last line must match the printed text above. Root settings alone do not enroll guests. Keeping a job with no enrolled guests is refused. Defaults never enroll an omitted guest. Existing configurations with a legacy client map must keep it exclusive of defaults and nonempty guest bindings.

These edits teach source selection only. Removing protection from a real installation needs the [retirement procedure](../../reference/backup.md#later-deployments-and-retirement); this exercise grants no permission to delete credentials or backups.

Continue with [real input preparation](../../backup/configure.md). Replace synthetic allocations, use compatible published source selections, verify storage and trust, and create the operator recovery pair before a real deployment.

## Size clients independently

[client-limits.yaml](client-limits.yaml) is a second complete site using this directory's same library, catalogue and public-key fixture. It adds `replica` and a second DNS app. `backup.defaults` supplies `management` and `backup-stage` to both guests. `resolver.backup.limits` has a 64 MiB/20,000-entry override; `replica` inherits 32 MiB/10,000 entries from the root. Both inherit the 300-second timeout, use one schedule and group, and have distinct guest identities. The numbers teach resolution; they are not real sizing recommendations.

From the repository root with the prepared Python environment, compile both guests into a new private output directory:

<!-- example: backup-client-limits-compile -->
```bash
FRAMEWORK=$(pwd -P)
PBS_LIMITS_WORK=$(mktemp -d)
PBS_LIMITS_WORK=$(cd "$PBS_LIMITS_WORK" && pwd -P)
python3 "$FRAMEWORK/blueprints/compile.py" \
  --stack "$FRAMEWORK/docs/examples/backup" \
  --site "$FRAMEWORK/docs/examples/backup/client-limits.yaml" \
  --guest resolver --output "$PBS_LIMITS_WORK/resolver.json"
python3 "$FRAMEWORK/blueprints/compile.py" \
  --stack "$FRAMEWORK/docs/examples/backup" \
  --site "$FRAMEWORK/docs/examples/backup/client-limits.yaml" \
  --guest replica --output "$PBS_LIMITS_WORK/replica.json"
python3 - "$PBS_LIMITS_WORK/resolver.json" "$PBS_LIMITS_WORK/replica.json" <<'PY_LIMITS'
import json, sys
jobs = [json.loads(json.load(open(path))['files']['site.json'])['app']['backup']['job']
        for path in sys.argv[1:]]
assert jobs[0]['limits'] == {'max_bytes': 67108864, 'max_files': 20000, 'timeout_seconds': 300}
assert jobs[1]['limits'] == {'max_bytes': 33554432, 'max_files': 10000, 'timeout_seconds': 300}
assert jobs[0]['group']['name'] == jobs[1]['group']['name'] == 'example-recovery'
print('resolver: overridden; replica: inherited; one group and timeout')
PY_LIMITS
```

The last line must match the printed text above. To test refusal, edit a disposable copy: adding `timeout_seconds` under a guest's `backup.limits` fails with `component.fields`. Setting `guests.resolver.backup.limits.max_bytes` to `268435457` exceeds one quarter of its 1 GiB staging volume and fails with `component.backup-staging-volume`. Exactly `268435456` is accepted. A changed effective limit in a real installation needs an enabled deployment and [its own successful Backup step](../../backup/configure.md#size-each-client-and-review-later-changes); compilation performs neither.
