# Working agreement

- Maintain the reusable component contracts, validation, compilation and deployment capabilities as a public API.
- Keep site allocations, credentials, local policy and private repository details out of code and reusable definitions.
- Reuse existing components. Add a component only when an existing contract cannot express the requirement.
- New components need a schema that rejects unknown fields, useful diagnostics, explicit references, compiler integration and documentation. Avoid objects that accept arbitrary configuration.
- Test component behavior directly with successful and extensive failure cases. App and guest units mock component contracts. Compiler integration exercises real components; deployment end-to-end tests verify actual services.
- Preserve data, stable identities, credential ownership, locks and holds.
- OpenTofu owns infrastructure/state; Ansible owns configuration/services. Maintain through protected CD.
- Retire superseded code, duplicate tests and stale documentation after proving replacements. Keep required regressions and historical evidence.
- Preserve coverage, security, signing and review gates. Report source, integration, deployment and service verification separately.
- Read docs/README.md for the canonical guides and reference. Keep public contracts, documentation, complete examples and tests in sync.
- Follow the [documentation standard](docs/contributing/documentation-standard.md) and [reusable templates](docs/templates/configuration-reference.md) for public contract and documentation changes. Keep canonical records for each field path and variant, complete examples and test-local mappings between source, documentation and evidence in sync. Configuration and validators remain authoritative; mappings store pointers. State the limits for first installation and later deployments. Report source checks, hosted CI enforcement and verification on the target separately.

- Host firewall CD lives under `proxmox/bootstrap/host_firewall*.py` and `proxmox/bootstrap/host-firewall/`. Keep its two imported state resources separate from guest/bootstrap state. Normal source describes the desired policy; imports and recovery for a particular environment are separate operator work. Do not introduce migration flags or competing host-rule writers.

- Keep the complete [backup setup and recovery guide](docs/backup/README.md) aligned with implementation. Correct the guide before taking an alternative setup step; prove first installation, repeated CD and an isolated restore using independently stored recovery material. Reset only explicitly inventoried disposable rehearsal objects.

- Follow the [PBS backup contract](docs/reference/backup.md). Reuse the existing path and protected-record components, support only the declared native export commands, and require explicit permission to pause services. Test invalid component inputs, coordinated failures and complete packet generation separately. Preserve failed operations and backup history. Passing source tests or reading an archive back does not prove that a service can be restored.
