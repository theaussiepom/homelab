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

[Reference index](README.md) · [Networks](networks.md) · [Lifecycle](lifecycle.md)
