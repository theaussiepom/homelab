# Try the homelab example on your computer

[Back to the main README](../../README.md)

This example lets you practise the broader homelab commands with invented data.
It creates a **local model**: a JSON file describing pretend guests and Raspberry
Pis. It does not connect to Proxmox, your NAS, databases or household devices.

For a real first deployment container, use the separate
[Proxmox bootstrap guide](../../proxmox/bootstrap/README.md).

## What you need

- A [copy of this repository](../../README.md#1-get-a-copy-on-your-computer).
- Python **3.12 or newer**, with virtual-environment support.
- Internet access for the initial Python dependency installation.

Run all commands below from the **repository root**, the folder containing the
main README. The sample addresses and image checksums are invented and must not
be reused as real deployment settings.

## 1. Prepare the local tools

A virtual environment keeps the example's Python packages separate from your
computer's other software:

```sh
python3 --version
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock.txt
```

**Expected result:** Python reports version 3.12 or newer, and package
installation finishes successfully. If your Linux distribution says virtual
environments are unavailable, install its Python venv package first.

## 2. Check the example and generate drafts

```sh
python bin/homelab validate --catalog examples/site/catalog/site.json
python bin/homelab render --catalog examples/site/catalog/site.json --out .work/example-render
```

**Expected result:** validation succeeds and a new `.work/example-render`
directory contains OpenTofu drafts and an Ansible inventory. These are files
only; rendering does not create real infrastructure. Choose a new output name
if a previous render already exists.

## 3. Plan and apply to the pretend site

Use a new workspace for this first run:

```sh
python bin/homelab plan --catalog examples/site/catalog/site.json --workspace .work/example --target synthetic
python bin/homelab approve --catalog examples/site/catalog/site.json --workspace .work/example --target synthetic
python bin/homelab apply --catalog examples/site/catalog/site.json --workspace .work/example --target synthetic
python bin/homelab verify --catalog examples/site/catalog/site.json --workspace .work/example --target synthetic
python bin/homelab plan --catalog examples/site/catalog/site.json --workspace .work/example --target synthetic
```

**Expected result:** the local model contains 15 Proxmox guest records and
3 Pi records, verification succeeds, and the final plan has zero changes.
The `approve` command exercises a local test approval; it grants no permission
to touch a real system.

## When something goes wrong

| What you see | What to do |
| --- | --- |
| Unsupported Python version | Select Python 3.12 or newer before creating the virtual environment. |
| Dependency hash failure | Stop and inspect the lock/download failure. Do not remove the hash checks. |
| Output directory already exists | Keep it and choose a new render destination. |
| Saved plan or approval is refused | Read the reason and inspect that workspace. Do not edit its saved state to make it pass. |
| Real Proxmox execution is refused | The broader framework's real-target adapter is held. This example is synthetic; use the separate one-container bootstrap for that supported route. |

## What has actually been verified?

Public CI runs the same synthetic CLI commands, source tests, local OpenTofu
fixtures and Ansible syntax checks without production access. Passing this
example proves the local workflow, not a real guest or application deployment.

For maintainers, run `python -m pytest -q tests` from the activated environment.
See [contributing safely](../../docs/contributing-safely.md) for the complete
repository requirements.

## Next steps

The [private-site reference](../../docs/configure-private-site.md) describes the
broader design's inputs and holds. Keep actual settings in a private repository
and consume reviewed public implementation pins; do not copy its execution logic.
Files ending in `.yml.example` are inactive templates, not enabled deployment jobs.

The independently supported initial guest path is
[installation USB → bootstrap → GitHub](../../proxmox/README.md).
