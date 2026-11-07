# Contexts

A context selects a Proxmox LXC provider and the trust, credentials and paths its controller needs. Declare it at `contexts.<id>` in your site; it cannot be a separate typed source file. The table paths below are relative to that value. Use only the listed fields, supply every required value and do not substitute null or an empty map for a required object. See [shared types](supporting-types.md#scalar-and-path-types) for scalar rules and [secret sources](identity-and-secrets.md#secret-sources) for credential references.

| Field | Type / requirement | Constraint or default |
| --- | --- | --- |
| <a id="context-backend"></a>`backend` | Required string | Exactly `proxmox-lxc` |
| <a id="context-node"></a>`node` | Required text | Nonempty, at most 4096 characters |
| <a id="context-api-endpoint"></a>`api_endpoint` | Required endpoint reference | Must select an external endpoint; resolved API HTTPS port 8006 |
| <a id="context-trust"></a>`trust ` | Required object | Exactly the two trust fields below |
| <a id="context-trust-ca-file"></a>`trust.ca_file ` | Required canonical absolute path | Selects the provider CA trust file; no default, and compilation does not read its contents |
| <a id="context-trust-known-hosts"></a>`trust.known_hosts ` | Required canonical absolute path | Selects the SSH known-host file; trust is checked during execution |
| <a id="context-credentials"></a>`credentials ` | Required object | Exactly the two source IDs below |
| <a id="context-credentials-api-token"></a>`credentials.api_token ` | Required ID | Declared protected API token source; not inline token bytes |
| <a id="context-credentials-ssh-private-key"></a>`credentials.ssh_private_key ` | Required ID | Declared protected SSH key source; actual key validation is later |
| <a id="context-paths"></a>`paths` | Required object | Exactly `state_root`, `backup_directory`, `backup_mount`, `backup_source` |
| <a id="context-paths-state-root"></a>`paths.state_root` | Required absolute path | Directory in which the controller manages ordinary state and operation records |
| <a id="context-paths-backup-directory"></a>`paths.backup_directory` | Required absolute path | Existing backup location |
| <a id="context-paths-backup-mount"></a>`paths.backup_mount` | Required absolute path | Existing mount boundary |
| <a id="context-paths-backup-source"></a>`paths.backup_source` | Required text | Nonempty source identity, at most 4096 characters |
| <a id="context-protected-guests"></a>`protected_guests` | Required integer list | Unique positive VMIDs reserved from use by selected guests |
| <a id="context-ssh-public-keys"></a>`ssh_public_keys` | Required string list | Unique nonempty strings; deployment admission also requires actual Ed25519 public keys |
| <a id="context-dns-servers"></a>`dns_servers` | Required nonempty endpoint-reference list | Resolved DNS TCP/UDP port 53 with IPv4 addresses |
| <a id="context-capabilities"></a>`capabilities ` | Optional named map, {} | Named serial capabilities, exact fields below |
| <a id="context-capability-type"></a>`capabilities.<id>.type ` | Required `serial-device` | No discovery or alternate capability discriminator |
| <a id="context-capability-ssh-private-key"></a>`capabilities.<id>.ssh_private_key ` | Required source ID | Protected key used by the selected capability |
| <a id="context-capability-known-hosts"></a>`capabilities.<id>.known_hosts ` | Required absolute path | Selects the SSH trust file used for this capability |
| <a id="context-timezone"></a>`timezone` | Optional string | Default `Etc/UTC`; 1–128 characters, slash-separated `[A-Za-z0-9_+-]+` parts |

[Path constraints](supporting-types.md#scalar-and-path-types) apply to every absolute path. Compilation checks the references without reading trust files or keys, or mounting the backup. Deployment later checks the actual protected inputs and state.

A [guest can override its DNS servers, SSH public keys and timezone](guests.md#guest-dns-servers), but those overrides do not change its provider ownership. Continuing a retained installation requires the previous API endpoint, node, VMID and hostname. Pointing an existing ID at another context does not import or replace it. Runtime checks continue to enforce protected IDs, permanent locks and HOLDs.

## First installation

A context supplies the provider, trust and controller inputs for a [guest](guests.md); it does not install anything independently. Follow [deployment preparation](../guides/prepare-deployment.md) to check actual paths, permissions, host and network capacity, template availability and admission requirements. The synthetic values below cannot establish those prerequisites.

## Later deployments

A context change can affect every guest that uses it. [Ownership checks](lifecycle.md#later-deployments-and-ownership-checks) preserve provider, node and state identities. Changing a context key or credential-source reference does not import an installation or rotate its protected credentials. Trust and path updates must pass runtime checks; successful configuration checks do not prove that the controller can reach the target.

## Worked context

This minimal context follows the tutorial's `contexts.lab` shape. Its endpoint and secret-source IDs are declared in that same site. The paths are public synthetic examples: source checks validate their spelling without opening them.

<!-- example: context-minimal -->
```yaml
backend: proxmox-lxc
node: example-node
api_endpoint: {external: api}
trust: {ca_file: /example/ca.pem, known_hosts: /example/known_hosts}
credentials: {api_token: token, ssh_private_key: ssh}
paths:
  state_root: /example/state
  backup_directory: /example/backup/data
  backup_mount: /example/backup
  backup_source: example:/backup
protected_guests: [9900]
ssh_public_keys: []
dns_servers: [{external: dns}]
```

To support a serial device, the context can declare this capability and a site [device](supporting-types.md#devices) can reference `host_serial`. The capability selects the credentials and trust file used to access the device; it does not discover devices.

<!-- example: context-capability -->
```yaml
capabilities:
  host_serial:
    type: serial-device
    ssh_private_key: ssh
    known_hosts: /example/host-known_hosts
```

**Invalid variation:** remove `trust.known_hosts` to see validation reject a missing required field. An empty SSH key list is allowed in offline examples but rejected by deployment admission. Ordinary updates also reject a different provider endpoint or node for an existing HomeLab-managed guest. Trust-file changes must pass actual trust checks; renaming the context does not bypass ownership checks.

The [`context` validator](../../blueprints/component_types.py) checks field shapes, and [`context_values`](../../blueprints/component_plan.py) checks API, DNS and credential references. [Reference example tests](../../blueprints/test_component_reference_examples.py) validate the context and capability and reject the missing trust field. They run configuration checks only.

[Reference index](README.md) · [Networks](networks.md) · [Lifecycle](lifecycle.md)
