# Working agreement

- Own reusable schemas, blueprints, compilation and OpenTofu/Ansible
  capabilities. Treat these contracts as a public API.
- Keep site allocations and policy out of reusable definitions and code:
  IPs, subnets, VLAN IDs, bridge names, VMIDs, MACs, hostnames, domains,
  storage endpoints, credential references and access allowlists.
- Accept concrete site settings through validated inputs. Do not infer them,
  supply local fallback values or encode one site's topology as a requirement.
- Keep public examples and fixtures explicitly synthetic and separate from
  reusable definitions. Protocol constants and public vendor endpoints are
  permitted; actual site identities and private repository references are not.
- Follow the existing architecture. Implement reusable capabilities here;
  do not require consumers to duplicate compilation or deployment engines.
- Manage desired state through protected CD: OpenTofu owns infrastructure
  and state; Ansible owns guest configuration and services.
- Do not add migration or cutover executors, one-off site repair scripts,
  or site-specific operating histories and deployment receipts.
- Preserve data, identities, genuine state, locks, holds and failure evidence.
  Removing obsolete source does not authorize changing runtime custody.
- Keep dependency, version and hash selections in their declared authoritative
  manifests or workflow references. Preserve declared image policies.
- Maintain automated ownership and public-boundary checks. Test reusable
  contracts with distinct synthetic site settings.
- Preserve validation, coverage, security and review gates. Distinguish source
  checks from integration, deployment and service acceptance.
