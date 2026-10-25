# homelab migration tooling — draft

Reusable OpenTofu/Ansible structure, strict catalog validation, local rehearsal and private deployment examples. This starter release has working local validation/rendering/synthetic execution and provider-schema-valid infrastructure drafts. **The full-site PVE execution adapter remains held.** Full-site provisioning and restore are not ready; the separate one-guest bootstrap and its current verification limits are described below.

The public implementation and private site use the same `bin/homelab` commands. A synthetic apply changes only a local JSON model; it never contacts Proxmox, a Pi, a database or a radio. Native OpenTofu tests use only its built-in local `terraform_data` fixture.

## Start with Proxmox

Read the [combined Proxmox guide](proxmox/README.md) for the complete sequence: build the installation USB, install Proxmox, then run the small bootstrap that creates a deployment guest and hands over to private GitHub CD (continuous deployment).

That guide links to the detailed instructions for each step. The one-guest bootstrap has passed a fresh isolated Proxmox-to-GitHub test; physical installation and later guest/application rollout remain separate work. The bootstrap requires no database.

## Run the complete local example

Use Python3.12+ and a new checkout/work directory. The dependency lock is hashed; no sudo/system installation is required.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock.txt
python -m pytest -q tests --basetemp .work/pytest
python bin/homelab validate --catalog examples/site/catalog/site.json
python bin/homelab render --catalog examples/site/catalog/site.json --out .work/rendered
python bin/homelab plan --catalog examples/site/catalog/site.json --workspace .work/example --target synthetic
python bin/homelab approve --catalog examples/site/catalog/site.json --workspace .work/example --target synthetic
python bin/homelab apply --catalog examples/site/catalog/site.json --workspace .work/example --target synthetic
python bin/homelab verify --catalog examples/site/catalog/site.json --workspace .work/example --target synthetic
python bin/homelab plan --catalog examples/site/catalog/site.json --workspace .work/example --target synthetic
```

Expected:15 PVE guest records plus3 Pi records in the local synthetic model; verification passes and the final plan reports zero changes. Approval is a local synthetic HMAC exercise, with no production authority. Select a new render destination each time; rendering preserves earlier directories/edits. Synthetic addresses are in198.18.0.0/15 and hostnames underexample.invalid.

```bash
python tools/bootstrap-tools.py --directory .work/tools
python tools/native_tofu_fixture.py --tofu .work/tools/tofu --work .work/native-encryption
```

This downloads the pinned binary with checksum verification and runs an encrypted local state/plan roundtrip, wrong/missing-key refusal and plaintext-marker checks. It does not test R2 or PVE. Archive signature verification is a separate release-trust step.

Read [private site setup](docs/configure-private-site.md), [shared command contract](docs/execution.md), [installer/recovery](docs/installer-and-recovery.md), [ownership/lifecycle](docs/ownership-and-lifecycle.md), and [rehearsal](docs/rehearsal.md). Public CI calls these same commands on hosted runners. Site catalog, keys, fabrics, private state/plans and operational reports stay in the private deployment site.
