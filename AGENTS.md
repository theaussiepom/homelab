# Working agreement

- Own reusable schemas, blueprints, compilation and deployment capabilities.
  Treat these contracts as a public API and preserve compatibility.
- Keep site values, secrets, topology and private repository references out.
- Follow the existing architecture. Add capabilities here rather than expecting
  consumers to duplicate deployment code.
- Consumers deploy through CD: OpenTofu manages infrastructure and state;
  Ansible manages guest configuration and applications.
- Preserve data, identities and state. Keep existing validation, coverage,
  security and review gates intact.
- Distinguish source tests from integration, deployment and service verification.
