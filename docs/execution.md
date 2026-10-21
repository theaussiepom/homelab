# Shared execution interface

All commands are implemented by `src/homelab` and exposed through `python bin/homelab`. Private workflows and operator commands select the same reviewed release. No deployment logic lives solely in GitHub YAML.

| Command | Current behavior | Evidence limit |
|---|---|---|
| `validate --catalog FILE` | Strict schema, duplicate keys/IDs/MAC/IP/volumes/routes, policy and unresolved-field count | Design validity; no live state observed |
| `render --catalog FILE --out NEW_DIRECTORY` | Four OpenTofu root drafts, module tree, variable projection and Ansible inventory | Files only; production rendering refused inside public implementation tree |
| `plan --catalog FILE --workspace DIRECTORY --target synthetic` | Preview local guest/Pi records against local model under a lock | No PVE/SSH/database/device access |
| `approve ... --target synthetic` | Short-lived HMAC fixture approval bound to catalog/plan | Local test key, never production authority |
| `apply ... --target synthetic` | Validate saved plan/approval/base state, update local model and preserve local checkpoints | No real target; local history is not immutable/distributed |
| `verify ... --target synthetic` | Compare local model to selected desired records | No native application acceptance |
| `plan/apply/verify --target pve` | Refuse with required production-adapter gates | Not implemented/qualified by this draft |
| `guard-plan --input FILE --change-class routine` | Inspect supported actual OpenTofu plan-JSON fields; reject replacements/nested protected edits/unknown values | Bounded field policy, not operation approval or complete initial/foundation policy |
| `disk-check --expected FILE --input FILE` | Require one exact by-id/serial/size match and known writable state | Identity match never authorizes erase |
| `recovery-check --input MANIFEST --workspace CAPTURE_DIRECTORY` | Require nonempty exact-size SHA256-matching local capture files, safe paths/no symlinks | No native consistency, independent destination or restore proof |
| `installer-answer --catalog SYNTHETIC --root-password-hash-file PRIVATE_FILE --out NEW_FILE` | Generate a synthetic answer TOML from required fields | No production media/boot/native parser qualification |

Routine guard currently admits only explicitly bounded guest CPU core/dedicated-memory and description/tag updates, with disk/network/privilege/lifecycle identities protected. Any initial plan containing computed unknowns holds until a field-specific actual-provider policy is qualified. Removing a resource or changing its root ownership is not a routine disable operation. Persistent holds and original generations are preserved.

The synthetic filesystem lock is a local algorithm/concurrency exercise. Production uses the separately qualified project-wide execution lock plus native per-state locking. Likewise the synthetic HMAC key stored in the private work directory is not a production approver identity. Saved state/history/plan files and caches are excluded by `.gitignore`; that exclusion provides neither permissions nor backup.
