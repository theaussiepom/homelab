# Contexts

A context binds one declared Proxmox LXC authority and controller prerequisites.
It is a site `contexts.<id>` value, not a source leaf. The table paths below are
relative to that value. Objects are closed, required fields have no defaults,
and null/empty mappings do not substitute for required objects. Scalar rules
come from [shared types](supporting-types.md#scalar-and-path-types); source
references come from [secret sources](identity-and-secrets.md#secret-sources).

| Field | Type / requirement | Constraint or default |
| --- | --- | --- |
| <a id="context-backend"></a>`backend` | Required string | Exactly `proxmox-lxc` |
| <a id="context-node"></a>`node` | Required text | Nonempty, at most 4096 characters |
| <a id="context-api-endpoint"></a>`api_endpoint` | Required endpoint reference | Must select an external endpoint; resolved API HTTPS port 8006 |
| <a id="context-trust"></a>`trust ` | Required object | Exactly the two trust fields below |
| <a id="context-trust-ca-file"></a>`trust.ca_file ` | Required canonical absolute path | Provider CA trust input; no default or content read during compilation |
| <a id="context-trust-known-hosts"></a>`trust.known_hosts ` | Required canonical absolute path | SSH known-host input; actual trust checked at execution |
| <a id="context-credentials"></a>`credentials ` | Required object | Exactly the two source IDs below |
| <a id="context-credentials-api-token"></a>`credentials.api_token ` | Required ID | Declared protected API token source; not inline token bytes |
| <a id="context-credentials-ssh-private-key"></a>`credentials.ssh_private_key ` | Required ID | Declared protected SSH key source; actual key validation is later |
| <a id="context-paths"></a>`paths` | Required object | Exactly `state_root`, `backup_directory`, `backup_mount`, `backup_source` |
| <a id="context-paths-state-root"></a>`paths.state_root` | Required absolute path | Controller-owned ordinary state/operation namespace |
| <a id="context-paths-backup-directory"></a>`paths.backup_directory` | Required absolute path | Existing backup location |
| <a id="context-paths-backup-mount"></a>`paths.backup_mount` | Required absolute path | Existing mount boundary |
| <a id="context-paths-backup-source"></a>`paths.backup_source` | Required text | Nonempty source identity, at most 4096 characters |
| <a id="context-protected-guests"></a>`protected_guests` | Required integer list | Unique positive VMIDs; no selected guest may use one |
| <a id="context-ssh-public-keys"></a>`ssh_public_keys` | Required string list | Unique nonempty strings; deployment admission additionally requires genuine Ed25519 public keys |
| <a id="context-dns-servers"></a>`dns_servers` | Required nonempty endpoint-reference list | Resolved DNS TCP/UDP port 53 with IPv4 addresses |
| <a id="context-capabilities"></a>`capabilities ` | Optional named map, {} | Named serial capabilities, exact fields below |
| <a id="context-capability-type"></a>`capabilities.<id>.type ` | Required `serial-device` | No discovery or alternate capability discriminator |
| <a id="context-capability-ssh-private-key"></a>`capabilities.<id>.ssh_private_key ` | Required source ID | Protected key used by the selected capability |
| <a id="context-capability-known-hosts"></a>`capabilities.<id>.known_hosts ` | Required absolute path | Capability's SSH trust boundary |
| <a id="context-timezone"></a>`timezone` | Optional string | Default `Etc/UTC`; 1–128 characters, slash-separated `[A-Za-z0-9_+-]+` parts |

[Path constraints](supporting-types.md#scalar-and-path-types) apply to every
absolute path. Compilation checks references, never reads trust/key contents or
mounts the backup. Execution later validates real protected inputs and state.

A [guest can override its DNS/key/timezone selection](guests.md#guest-dns-servers). It cannot change the
context's provider ownership implicitly. Retained continuation binds the prior
API endpoint, node, VMID and hostname. Pointing an existing ID at another context
is not an import or replacement operation. Protected IDs and permanent locks/
HOLDs remain runtime safeguards.

## First installation

A context has no independent guest installation action. It supplies provider,
trust and controller prerequisites to a [guest](guests.md). Qualify actual paths,
permissions, host/template/network capacity and source admission through
[deployment preparation](../guides/prepare-deployment.md). Synthetic context
values below deliberately cannot establish those prerequisites.

## Later deployments

Context changes can affect every consuming guest. Provider/node/state identities
remain bound by [ownership continuity](lifecycle.md#later-deployments-and-ownership-checks).
Changing a context key or private-source reference cannot import an installation
or rotate its sealed material. Trust/path updates require their actual runtime
checks; source acceptance does not prove controller access or target reachability.

## Worked context

This minimal context follows the tutorial's `contexts.lab` shape. Its endpoint and
secret-source IDs are declared in that same site. The paths are public synthetic
examples: source checks validate their spelling without opening them.

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

A serial-equipped context can additionally declare this capability, then a site
[device](supporting-types.md#devices) can reference `host_serial`. This is an
explicit credential/trust boundary, not device discovery.

<!-- example: context-capability -->
```yaml
capabilities:
  host_serial:
    type: serial-device
    ssh_private_key: ssh
    known_hosts: /example/host-known_hosts
```

**Invalid variation:** removing `trust.known_hosts` fails the closed required
shape. An empty SSH key list is allowed for offline examples but refuses real
deployment admission. Changing provider endpoint/node on an owned guest refuses
normal continuity; changing trust files requires real trust validation, not a
new context name to bypass the old owner.

The owning [`context` validator](../../blueprints/component_types.py) checks
shape; [`context_values`](../../blueprints/component_plan.py) resolves API/DNS
and credential relationships. [Reference examples](../../blueprints/test_component_reference_examples.py)
exercise the context/capability and missing-trust refusal at source boundaries.

[Reference index](README.md) · [Networks](networks.md) · [Lifecycle](lifecycle.md)
