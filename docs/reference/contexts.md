# Contexts

A context binds one declared Proxmox LXC authority and controller prerequisites.
It is a site `contexts.<id>` value, not a source leaf.

| Field | Type / requirement | Constraint or default |
| --- | --- | --- |
| backend | Required string | Exactly `proxmox-lxc` |
| node | Required text | Nonempty, at most 4096 characters |
| api_endpoint | Required endpoint reference | Must select an external endpoint; resolved API HTTPS port 8006 |
| trust | Required object | Exactly `ca_file` and `known_hosts`, canonical absolute paths |
| credentials | Required object | Exactly `api_token` and `ssh_private_key`, secret-source IDs |
| paths | Required object | Exactly `state_root`, `backup_directory`, `backup_mount`, `backup_source` |
| paths.state_root | Required absolute path | Controller-owned ordinary state/operation namespace |
| paths.backup_directory | Required absolute path | Existing backup location |
| paths.backup_mount | Required absolute path | Existing mount boundary |
| paths.backup_source | Required text | Nonempty source identity, at most 4096 characters |
| protected_guests | Required integer list | Unique positive VMIDs; no selected guest may use one |
| ssh_public_keys | Required string list | Unique nonempty strings; deployment admission additionally requires genuine Ed25519 public keys |
| dns_servers | Required nonempty endpoint-reference list | Resolved DNS TCP/UDP port 53 with IPv4 addresses |
| capabilities | Optional named map, {} | Each capability is `{type: serial-device, ssh_private_key: source_id, known_hosts: absolute_path}` |
| timezone | Optional string | Default `Etc/UTC`; 1–128 characters, slash-separated `[A-Za-z0-9_+-]+` parts |

[Path constraints](supporting-types.md#scalar-and-path-types) apply to every
absolute path. Compilation checks references, never reads trust/key contents or
mounts the backup. Execution later validates real protected inputs and state.

A guest can override its DNS/key/timezone selection. It cannot change the
context's provider ownership implicitly. Retained continuation binds the prior
API endpoint, node, VMID and hostname. Pointing an existing ID at another context
is not an import or replacement operation. Protected IDs and permanent locks/
HOLDs remain runtime safeguards.

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

[Reference index](README.md) · [Networks](networks.md) · [Lifecycle](lifecycle.md)
