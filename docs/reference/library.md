# Library

A library is a versioned set of reusable definitions. Its root is `stack.json`; individual definitions may be JSON/YAML typed files. `images.json` is read when image selections require it.

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
| <a id="library-backup-profiles"></a>`backup_profiles` | Optional named map, {} | [PBS client software and configuration to protect](backup.md#backup-profiles) |
| <a id="library-monitoring-profiles"></a>`monitoring_profiles` | Optional named map, {} | `{type: zabbix-agent, profiles: [...]}` |
| <a id="library-assets"></a>`assets` | Optional named map, {} | Hash-pinned raw UTF-8 files |
| <a id="library-policies"></a>`policies` | Optional closed map | `network/transport/tls/middlewares/authentication`, each a named map |
| <a id="library-bundles"></a>`bundles` | Optional named map, {} | Loaded/pinned reserved definitions; the current compiler does not expand bundle placement or provide a bundle authoring contract |

All maps use the [identifier and size rules](site.md#properties). Definitions can use [complete typed sources](sources.md). Do not use reserved bundles to recreate the retired fixed guest catalogue.

## Guest template

A guest template requires complete [guest default objects](guests.md) for `resources`, `startup` and `security`. The optional `software` and `runtime` lists contain unique IDs and default to []. Optional `monitoring` has the form `{profile: monitoring_profile_id}`. A template does not assign a VMID, allocate a network address or take ownership of private paths.

## App profile

An app profile requires `adapter`, `display_name` and `interfaces`. The optional maps `listeners`, `endpoints`, `storage`, `connections`, `health`, `properties`, `devices` and `secrets` each default to {}. The optional `software/runtime` lists contain unique IDs and default to []. Optional `authentication` selects an authentication-profile ID, and optional `monitoring` has the form `{profile: monitoring_profile_id}`.

Select one of the [18 registered adapters](support.md). The display name must be nonempty text of at most 4096 characters. [Supporting types](supporting-types.md) describes every nested profile field, and [Application properties](app-properties.md) lists the properties each adapter accepts. Profiles may provide partial property defaults, but the result after merging app overrides must be complete.

An app profile may also declare the [backup coverage object](backup.md#application-recovery-declarations). It classifies every storage role as included or excluded and can list native configuration paths. These declarations reuse guest storage bindings rather than repeating their allocations. Every app profile selected on an explicitly [enrolled guest](backup.md#backup-guest) must supply this coverage, with the required root backup selection. Root presence alone neither enrolls nor protects a guest.

## First installation

Selecting a library provides definitions for your configuration; it does not install a service. A profile determines the required roles and supported adapter behavior. Your site must supply valid instances and the prepared inputs that profile needs. Use the [support matrix](support.md) and [deployment preparation](../guides/prepare-deployment.md) to determine whether first installation is supported.

<a id="ownership-and-updates"></a>
## Later deployments and effective defaults

The library selects software and image versions, required roles, the service roles used by renderers and default values. Your site supplies instance bindings and allocations. Explicit guest fields override the corresponding template resources, startup and security fields. Explicit app properties override the corresponding profile properties. Software and runtime lists are concatenated, and conflicting selections are rejected. Objects are not merged recursively.

Changing a default can affect every consuming instance. Compare effective outputs, budgets and native plans, and document changed support requirements. A profile name change does not itself move retained data or transfer ownership.

## Worked reusable definition

The library root is still fixed `stack.json`; the following is a complete YAML **guest-template leaf**, referenced by `guest_templates.base: {source: templates/base.yaml}` in that JSON manifest. It contains defaults, not a concrete VMID, host address or credential.

<!-- example: template-minimal -->
```yaml
schema: homelab-components-v1
kind: guest-template
resources: {cpu_cores: 1, memory_mib: 512, root_gib: 8, os_reserve_mib: 128}
startup: {started: true, start_on_boot: true, boot_order: 30}
security: {unprivileged: true, protection: true, nesting: true, keyctl: false}
```

Combine this with the tutorial's complete `recursive` app profile, its software, image/runtime/health declarations and the worked [guest](guests.md#worked-guest-and-inherited-defaults). A site may override only `memory_mib` while inheriting the other template fields. **Invalid variation:** omit `security.protection`, or set it false. The template must be complete and protected. Do not put an `identity` field here; VMID and hostname belong to the guest instance.

See the [complete tutorial library](../examples/first-configuration/stack.json) for a small working library that compiles into deployment packets without an external catalogue. Moving its template into this source file preserves the generated deployment inputs. Changing a default, however, can affect every instance that inherits it.

[Reference index](README.md) · [Supporting types](supporting-types.md)
