# CLI reference

Run commands from the selected framework checkout with its locked Python dependencies. Paths below are arguments, not shell templates embedded in source.

## Compile: blueprints/compile.py

| Argument | Required/default | Effect |
| --- | --- | --- |
| --stack PATH | Required | Library root containing stack.json |
| --site FILE | Exactly one of site/site-root | Exact JSON/YAML file |
| --site-root DIR | Exactly one of site/site-root | Discover sole site.yaml/site.yml/site.json |
| --disabled JSON | Default [] | Unique authored guest IDs excluded from execution |
| --check | Optional flag | Compile all packets offline and print fixed success message, no packet output |
| --guest ID | Required without check | Select authored packet |
| --output FILE | Required without check | Writes a new JSON packet with mode 0600. The output file must not already exist, and its parent directory must exist. |
| --admit | Optional flag | Additional source suitability checks; selected output must be enabled |

Compilation does not read credentials or contact targets. With admission enabled, it rejects known synthetic addresses, domains, SSH keys and image selections. Deployment checks the actual paths, permissions and ownership later. Keep runtime packets private.

The Python APIs are `compile.resolve_plan(stack_root, site_source, disabled=None, admit=False)`, `compile.lower_plan(plan)` and `compile.compile_site(...)`. A resolved plan seals a snapshot of its source, resolved values and selected pins. Changing that snapshot causes packet generation to fail.

## Generate: blueprints/workflows.py

This command requires `--stack PATH` and `--site FILE`. It also accepts `--disabled JSON` (default []) and `--check`. With `--check`, it compares existing files with the expected generated files and fails if they differ. Otherwise, it synchronizes three library workflows and selected composite actions from the current framework recipe. It generates files without executing a workflow. Supply the input filename explicitly; this command has no site-root option.

## Consumer wrapper: blueprints/private_workflows.py

This command requires `--stack PATH` and `--site PATH`, and optionally accepts `--check`. It generates the consumer workflow, or checks that the existing workflow matches, using the selected published library and framework workflow references and the site configuration. Checks preserve the existing CI and security policy fields. The wrapper uses the existing parser and deployment engine.

The generated Deploy has one early **Backup** job when operational backup or the supported local `.github/workflows/pbs-firewall.yml` is selected. There is no final group activation job. Operationally enrolled guests depend on early setup and finish their own Backup step; nightly readiness comes from their genuine completion receipts and sealed worker inputs.

The optional PBS workflow retains its pure PR validation and fixed named `PBS_FIREWALL_SSH_KEY` contract. Generation combines its pure check and selected native policy steps into the early Backup job, retaining its protected `homelab-bootstrap` Environment, 15-minute bound and target-selection condition. An absent real binding skips host contact while still permitting schedule maintenance. Source checkouts and dependency installation are supplied by the shared immutable job setup; any framework checkout quoted in the local workflow must select the same framework revision. PBS commands must use the selected job tools, not absolute shared-environment executables. Step identifiers are scoped to keep their output references distinct. Unsupported contexts, source drift, permissive failure flags and unsafe present files are refused.

Only the existing named PBS host key reaches its native policy step. The PBS API token reaches early schedule setup and each enrolled guest Backup step; it is never placed in a guest payload. The early combined job uses the existing PBS protected environment, while a public schedule without local PBS policy uses `backup`. The site owner supplies the existing named secret bindings in those protected environments. The outer Deploy retains its one shared queue. Setup does not install PBS, start a backup or change application/database capture ordering.

## Coverage: tools/measure_coverage.py

| Argument | Meaning |
| --- | --- |
| --output PATH | Required nonexistent output directory; its parent must exist |
| --all | Complete Python inventory including bootstrap/installer/network/source tooling |
| --suite NAME | Repeatable unique suite selection: framework, blueprints, applications, bootstrap, installer, network-recovery, source-tooling, stack, site |
| --stack PATH | Optional consuming library tests |
| --site PATH | Optional consuming site tests |
| --fail-under NUMBER | Required coverage checks use --fail-under 100. Omitting the option is only for exploratory measurement. |

See the [verified commands and prerequisites](../contributing/testing.md). Reports may be private; do not upload them.

## Protected execution interfaces

`blueprints/credentials.py --packet FILE` loads and checks the selected provider and SSH credentials. `proxmox/applications/deploy.py --packet FILE --phase ID` executes the selected phase subject to deployment checks. These internal workflow commands have real effects. They are not supported commands for local authoring, recovery, retries or clearing HOLDs. They require the selected workflow provenance, a protected environment, verified controller ownership and trust, the expected backend, and the exact inputs and phase. Follow [Deployment](../operations/deployment.md); do not pass a tutorial packet to them.

[Reference index](README.md)
