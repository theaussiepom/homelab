# CLI reference

Run commands from the selected framework checkout with its locked Python
dependencies. Paths below are arguments, not shell templates embedded in source.

## Compile: blueprints/compile.py

| Argument | Required/default | Effect |
| --- | --- | --- |
| --stack PATH | Required | Library root containing stack.json |
| --site FILE | Exactly one of site/site-root | Exact JSON/YAML file |
| --site-root DIR | Exactly one of site/site-root | Discover sole site.yaml/site.yml/site.json |
| --disabled JSON | Default [] | Unique authored guest IDs excluded from execution |
| --check | Optional flag | Compile all packets offline and print fixed success message, no packet output |
| --guest ID | Required without check | Select authored packet |
| --output FILE | Required without check | New create-only mode0600 JSON packet, parent must exist |
| --admit | Optional flag | Additional source suitability checks; selected output must be enabled |

Compilation does not access credentials/targets. It rejects known synthetic
address/domain/SSH/image bindings when admission is requested. Native paths,
permissions and ownership remain later gates. Runtime packets are private.

Python APIs: `compile.resolve_plan(stack_root, site_source, disabled=None,
admit=False)`, `compile.lower_plan(plan)`, `compile.compile_site(...)`.
A resolved plan seals its source/resolved/pin snapshot; post-resolution mutation
refuses lowering.

## Generate: blueprints/workflows.py

Required `--stack PATH`, `--site FILE`; optional `--disabled JSON` ([])
and `--check`. Check compares generated files and refuses mismatch.
Without check, it synchronizes three library workflows and selected composite
actions from the current framework recipe. It does not execute a workflow.
Input filename is explicit; this command has no site-root option.

## Consumer wrapper: blueprints/private_workflows.py

Required `--stack PATH`, `--site PATH`; optional `--check`.
It generates/checks the thin consumer workflow from the selected published
library/framework workflow references and real site model. Existing CI/security
policy fields remain guarded. It is not a second parser or deployment engine.

## Coverage: tools/measure_coverage.py

| Argument | Meaning |
| --- | --- |
| --output PATH | Required nonexistent output directory; its parent must exist |
| --all | Complete Python inventory including bootstrap/installer/network/source tooling |
| --suite NAME | Repeatable unique suite selection: framework, blueprints, applications, bootstrap, installer, network-recovery, source-tooling, stack, site |
| --stack PATH | Optional consuming library tests |
| --site PATH | Optional consuming site tests |
| --fail-under NUMBER | Required gate convention100; omission permits exploratory measurement only |

See the [verified commands and prerequisites](../contributing/testing.md).
Reports may be private; do not upload them.

## Protected execution interfaces

`blueprints/credentials.py --packet FILE` binds the selected provider/SSH
credential boundary. `proxmox/applications/deploy.py --packet FILE --phase ID`
executes the current guarded phase.
These are internal workflow interfaces with real effects, not local authoring,
recovery, retry or HOLD-clearing commands. Their complete prerequisites include
the selected workflow provenance, protected environment, controller ownership,
trust, backend and exact input/phase selection. Use
[Deployment](../operations/deployment.md); do not try a tutorial packet against them.

[Reference index](README.md)
