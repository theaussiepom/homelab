# Library

A library is a versioned set of reusable definitions. Its root is `stack.json`;
individual definitions may be JSON/YAML typed files. `images.json` is read when
image selections require it.

| Property | Type / required / default | Definition |
| --- | --- | --- |
| <a id="library-schema"></a>`schema` | Required string | `homelab-components-v1` |
| <a id="library-kind"></a>`kind` | Required string | `library` |
| <a id="library-guest-templates"></a>`guest_templates` | Required named map | Complete default resources/startup/security and optional selections |
| <a id="library-app-profiles"></a>`app_profiles` | Required named map | Adapter capability contracts |
| <a id="library-software"></a>`software` | Optional named map, {} | Packages, image roles and repositories |
| <a id="library-runtime-profiles"></a>`runtime_profiles` | Optional named map, {} | Limits/security and native memory reservations |
| <a id="library-health-profiles"></a>`health_profiles` | Optional named map, {} | Adapter readiness checks |
| <a id="library-authentication-profiles"></a>`authentication_profiles` | Optional named map, {} | `{type, required}`; type is `cloudbeaver-oidc`, `node-red-retained-oidc` or `zabbix-saml`; required is Boolean |
| <a id="library-monitoring-profiles"></a>`monitoring_profiles` | Optional named map, {} | `{type: zabbix-agent, profiles: [...]}` |
| <a id="library-assets"></a>`assets` | Optional named map, {} | Hash-pinned raw UTF-8 files |
| <a id="library-policies"></a>`policies` | Optional closed map | `network/transport/tls/middlewares/authentication`, each a named map |
| <a id="library-bundles"></a>`bundles` | Optional named map, {} | Loaded/pinned reserved definitions; the current compiler does not expand bundle placement or provide a bundle authoring contract |

All maps use the [identifier and size rules](site.md#properties).
Definitions can use [complete typed sources](sources.md).
Do not use reserved bundles to recreate the retired fixed guest catalogue.

## Guest template

Required `resources`, `startup` and `security` are complete
[guest default objects](guests.md). Optional `software` and `runtime` are unique
ID lists, default []. Optional `monitoring` is `{profile: monitoring_profile_id}`.
A template has no VMID, network allocation or private path authority.

## App profile

Required `adapter`, `display_name`, `interfaces`.
Optional maps default {}: `listeners`, `endpoints`, `storage`, `connections`,
`health`, `properties`, `devices`, `secrets`.
Optional unique ID lists `software/runtime` default [].
Optional `authentication` is an authentication-profile ID.
Optional `monitoring` is `{profile: monitoring_profile_id}`.

The adapter is one of the [18 registered adapters](support.md).
Display name is nonempty text up to 4096 characters.
Every nested profile field is described in [Supporting types](supporting-types.md);
properties are the adapter's [closed property object](app-properties.md).
Profiles can provide partial property defaults; the effective merged app
properties must be complete.

## First installation

A library is a source selection, not an installed service. Selecting a profile
chooses its required roles and adapter capability; the consumer must supply
valid instances and the selected profile's actual prepared inputs. Use the
[support matrix](support.md) and [deployment preparation](../guides/prepare-deployment.md)
to determine whether a fresh path exists.

<a id="ownership-and-updates"></a>
## Later deployments and effective defaults

The library owns software/image versions, required roles, renderer service roles
and defaults. The site owns instance bindings and allocations.
Template resources/startup/security receive explicit guest field overrides.
Profile properties receive explicit app field overrides. Lists of selected
software/runtime are concatenated and conflicts refuse; there is no recursive
merge language.

Changing a default can affect every consuming instance. Compare effective
outputs, budgets and native plans, and document changed support requirements.
A profile name change does not itself move retained data or transfer ownership.

## Worked reusable definition

The library root is still fixed `stack.json`; the following is a complete YAML
**guest-template leaf**, referenced by
`guest_templates.base: {source: templates/base.yaml}` in that JSON manifest.
It contains defaults, not a concrete VMID, host address or credential.

<!-- example: template-minimal -->
```yaml
schema: homelab-components-v1
kind: guest-template
resources: {cpu_cores: 1, memory_mib: 512, root_gib: 8, os_reserve_mib: 128}
startup: {started: true, start_on_boot: true, boot_order: 30}
security: {unprivileged: true, protection: true, nesting: true, keyctl: false}
```

Combine this with the tutorial's complete `recursive` app profile, its software,
image/runtime/health declarations and the worked [guest](guests.md#worked-guest-and-inherited-defaults).
A site may override only `memory_mib` while inheriting the other template fields.
**Invalid variation:** omit `security.protection`, or set it false. The template
must be complete and protected. Do not put an `identity` field here; VMID and
hostname belong to the guest instance.

See the [complete tutorial library](../examples/first-configuration/stack.json)
for a minimal useful library that compiles and lowers without an external
catalogue. Extracting its template into this leaf preserves effective packets;
changing a default can affect all instances that inherit it.

[Reference index](README.md) · [Supporting types](supporting-types.md)
