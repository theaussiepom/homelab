# Working agreement

- Own reusable component contracts, validation, compilation and deployment
  capabilities. Treat them as a public API.
- Keep site allocations, credentials, local policy and private repository
  details out of code and reusable definitions.
- Reuse existing components. Add a component only when an existing contract
  cannot express the requirement.
- New components need a closed schema, useful diagnostics, explicit references,
  compiler integration and documentation. Avoid generic configuration bags.
- Test component behavior directly with successful and extensive failure cases.
  App and guest units mock component contracts. Compiler integration exercises
  real components; deployment end-to-end tests verify actual services.
- Preserve data, stable identities, credential ownership, locks and holds.
- OpenTofu owns infrastructure/state; Ansible owns configuration/services.
  Maintain through protected CD.
- Retire superseded code, duplicate tests and stale documentation after proving
  replacements. Keep required regressions and historical evidence.
- Preserve coverage, security, signing and review gates. Report source,
  integration, deployment and service verification separately.
- Read docs/README.md for the canonical guides and reference. Keep public
  contracts, documentation, complete examples and tests in sync.
- Follow the [documentation standard](docs/contributing/documentation.md) and
  [reusable templates](docs/templates/configuration-reference.md) when adding
  or changing documentation; validate concrete examples at the
  owning contract and state first-installation/later-deployment limits.

- Host firewall CD lives under `proxmox/bootstrap/host_firewall*.py` and
  `proxmox/bootstrap/host-firewall/`. Keep its two imported state resources
  separate from guest/bootstrap state. Normal source describes desired policy;
  environmental imports/recovery are separate operator work. Do not introduce
  migration flags or competing host-rule writers.
