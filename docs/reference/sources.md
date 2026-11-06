# Source documents

Use source files to organise complete declarations without adding an overlay
language. Paths are relative to the owning library or site's root directory.

## Syntax and kinds

```yaml
connections:
  frontend_database: {source: connections/frontend-database.yaml}
exposures:
  frontend: {source: exposures/frontend.yaml}
```

A referenced connection has the complete existing connection body:

```yaml
schema: homelab-components-v1
kind: connection
consumer: {app: frontend, connection: database}
target: {app: database, endpoint: service}
source_interface: database
```

This is a fragment requiring compatible profile roles and policy; extraction
does not make those references optional.

| Owning map | Required leaf kind |
| --- | --- |
| Site `guests`, `apps`, `connections`, `exposures` | `guest`, `app`, `connection`, `exposure` respectively |
| Library `guest_templates`, `app_profiles` | `guest-template`, `app-profile` |
| Library `software`, `runtime_profiles`, `health_profiles` | `software`, `runtime-profile`, `health-profile` |
| Library `authentication_profiles`, `monitoring_profiles`, `bundles` | `authentication-profile`, `monitoring-profile`, `bundle` |
| Any policies submap | `network-policy`, `transport-policy`, `tls-policy`, `middlewares-policy`, `authentication-policy` |

Every leaf requires `schema: homelab-components-v1` and its matching `kind`.
The reader removes only these two header fields, then the existing owning
validator checks the complete body. Inline values have no leaf headers.
The map key in the parent remains the stable identity.

## Constraints

- A source reference contains exactly one `source` field, a nonempty canonical
  relative path up to 4096 characters. Absolute paths, `.`, `..`, repeated path
  separators and symlink components refuse. Files must be regular.
- Supported extensions are `.json`, `.yaml`, `.yml`. Exactly one same-stem
  sibling may exist; an explicitly named missing file has no fallback.
- The root and each directory are anchored using directory descriptors and
  NOFOLLOW. Every consumed snapshot joins the source SHA256 pins. A second read
  of changed bytes under the same authority refuses.
- A leaf cannot recursively include another source, append siblings, merge
  defaults, rename its parent key or supply an arbitrary parser/plugin.
- Other site maps remain inline. Raw [assets/evidence](supporting-types.md)
  use their separate exact-byte/hash forms.

## YAML and JSON values

Each source is at most 8 MiB, depth 64 and 100,000 values. Duplicate object keys,
custom tags, anchors, aliases, YAML merge keys, non-string keys and nonfinite
numbers refuse. JSON-compatible scalars are preserved: only lowercase
`true/false/null` and JSON-style numbers resolve specially. An empty YAML value
is null; `on`, `yes` and date-looking values remain strings. Quote text which
looks like a boolean, number or null. Literal blocks remain literal text.

## First installation and later deployments

A typed source file is organization of a declaration, not a resource or an
installation action. The consuming [guest](guests.md), [app](apps.md),
[connection](connections.md) or [exposure](exposures.md) owns execution and
lifecycle. Extracting a file cannot create adoption, data-move or retry authority.

<a id="update-and-validation"></a>
## Source identity and validation

Moving an unchanged complete entry into a leaf preserves the effective plan,
packets and workflow graph. Source pins change because different bytes were
consumed. Editing a leaf is a source change and is revalidated through the same
binder; it cannot bypass required fields, access checks, ownership or readiness.
The real compiler tests compare inline/leaf JSON/YAML output and exercise wrong
kind/schema, partial/unknown bodies, path escapes, symlinks, ambiguous siblings,
duplicate fields and leaf drift.

## Worked extraction without an overlay

Move the tutorial's entire `apps.recursive_a` value into `apps/recursive.yaml`
and replace its site entry with `{source: apps/recursive.yaml}`. This complete
leaf is validated as an app after its two headers are removed:

<!-- example: source-app -->
```yaml
schema: homelab-components-v1
kind: app
profile: recursive
guest: resolver
lifecycle: fresh
interfaces:
  private: {scope: app-network, network: default}
  local: {scope: guest-loopback}
```

The original inline and extracted forms have identical resolved apps, runtime
packets and dependency graph. The consumed source filenames/hashes differ.
Combine extraction with an explicit app `display_name` inside that leaf, not
beside `source` in the parent. **Invalid variation:**
`{source: apps/recursive.yaml, display_name: Another label}` refuses; a reference
is not an override. A `kind: guest` header in this same app leaf also refuses.
These checks use the real confined reader, including for source-only compilation.

[Reference index](README.md) · [References guide](../guides/references-and-reuse.md)
