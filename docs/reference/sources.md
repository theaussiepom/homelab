# Source documents

Use source files to organise complete declarations without adding an overlay language. Paths are relative to the owning library or site's root directory.

## Syntax and kinds

```yaml
connections:
  frontend_database:
    source: connections/frontend-database.yaml
exposures:
  frontend:
    source: exposures/frontend.yaml
```

The referenced file contains the complete connection declaration:

```yaml
schema: homelab-components-v1
kind: connection
consumer:
  app: frontend
  connection: database
target:
  app: database
  endpoint: service_endpoint
source_interface: database_interface
```

This example still requires compatible profile roles and policy in the surrounding configuration. Moving the declaration to a file does not make its references optional.

| Owning map | Required leaf kind |
| --- | --- |
| Site `guests`, `apps`, `connections`, `exposures` | `guest`, `app`, `connection`, `exposure` respectively |
| Library `guest_templates`, `app_profiles` | `guest-template`, `app-profile` |
| Library `software`, `runtime_profiles`, `health_profiles` | `software`, `runtime-profile`, `health-profile` |
| Library `authentication_profiles`, `monitoring_profiles`, `bundles` | `authentication-profile`, `monitoring-profile`, `bundle` |
| Library `backup_profiles` | [`backup-profile`](backup.md#backup-profiles) |
| Any policies submap | `network-policy`, `transport-policy`, `tls-policy`, `middlewares-policy`, `authentication-policy` |

Every typed source file requires `schema: homelab-components-v1` and the matching `kind`. The reader removes those two header fields, then passes the complete body to the same validator used for inline values. Inline values do not include these headers. The parent map key remains the declaration's stable identity.

## Constraints

- A source reference contains exactly one `source` field: a nonempty canonical relative path of at most 4096 characters. Absolute paths, `.`, `..`, repeated path separators and symlink components are rejected. The path must point to a regular file.
- Supported extensions are `.json`, `.yaml`, `.yml`. Exactly one same-stem sibling may exist; an explicitly named missing file has no fallback.
- The reader opens the root and each directory using directory descriptors and NOFOLLOW, preventing traversal through symlinks. It records each file snapshot in the source SHA256 pins and rejects a later read if the bytes have changed under the same authority.
- A leaf cannot recursively include another source, append siblings, merge defaults, rename its parent key or supply an arbitrary parser/plugin.
- Other site maps remain inline. Raw [assets/evidence](supporting-types.md) use their separate exact-byte/hash forms.

## YAML and JSON values

Each source is limited to 8 MiB, a nesting depth of 64 and 100,000 values. The reader rejects duplicate object keys, custom tags, anchors, aliases, YAML merge keys, non-string keys and nonfinite numbers. It preserves JSON-compatible scalar types: only lowercase `true/false/null` and JSON-style numbers receive those types. An empty YAML value is null; `on`, `yes` and values resembling dates remain strings. Quote text that looks like a Boolean, number or null. Literal blocks remain literal text.

## First installation and later deployments

A typed source file is a way to organise a declaration; it does not create a resource or run an installation step. Execution and lifecycle follow the rules for the declared [guest](guests.md), [app](apps.md), [connection](connections.md) or [exposure](exposures.md). Moving a declaration into a file does not permit adoption, data moves or retries.

<a id="update-and-validation"></a>
## Source identity and validation

Moving an unchanged complete declaration into a typed file preserves the resulting plan, deployment packets and workflow graph. The source pins change because the compiler reads different files and bytes. Editing the file triggers the same validation as editing an inline declaration; required fields, access checks, ownership and readiness rules still apply. Compiler tests compare inline and separate-file JSON/YAML output. They also check wrong kinds and schemas, incomplete bodies, unknown fields, path escapes, symlinks, ambiguous sibling files, duplicate fields and files that change between reads.

## Worked extraction without an overlay

Move the tutorial's entire `apps.recursive_a` value into `apps/recursive.yaml` and replace its site entry with `{source: apps/recursive.yaml}`. This complete leaf is validated as an app after its two headers are removed:

<!-- example: source-app -->
```yaml
schema: homelab-components-v1
kind: app
profile: recursive
guest: resolver
lifecycle: fresh
interfaces:
  private_interface:
    scope: app-network
    network: default
  local_interface:
    scope: guest-loopback
```

The inline and separate-file forms produce identical app values, runtime packets and dependency graphs. Only the source filenames and hashes differ. To add an app `display_name`, put it inside the typed file rather than beside `source` in the parent. **Invalid variation:** `{source: apps/recursive.yaml, display_name: Another label}` is rejected because a reference cannot contain overrides. The app file also rejects `kind: guest`. These checks use the actual reader and its filesystem restrictions, including during offline compilation.

[Reference index](README.md) · [References guide](../guides/references-and-reuse.md)
