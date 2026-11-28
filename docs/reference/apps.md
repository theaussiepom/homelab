# App instances

An app is one `apps.<id>` value in a [site](site.md). It chooses a library profile, places that instance on one guest and binds the profile's named roles. An inline value and a complete `kind: app` [typed source](sources.md) have the same meaning. A profile's available roles and defaults belong to its selected library; this page defines the framework's instance grammar.

## Instance fields

Use only the fields listed below. IDs and scalar values follow the [shared rules](supporting-types.md#scalar-and-path-types). Required values have no default. Optional maps and lists use the stated defaults; null does not mean an empty collection or an instruction to inherit a value.

| Path under `apps.<id>` | Presence / type | Meaning and resolution |
| --- | --- | --- |
| <a id="app-profile"></a>`profile` | Required ID | Existing library [app profile](library.md#app-profile) |
| <a id="app-guest"></a>`guest` | Required ID | Existing [site guest](guests.md); names and paths must not conflict, and capacity must suffice |
| <a id="app-lifecycle"></a>`lifecycle` | Required `fresh` or `retained` | [Creation/continuation policy](lifecycle.md), constrained by adapter support |
| <a id="app-interfaces"></a>`interfaces` | Required named map | Assign values to profile roles; supply every required role using one of the [accepted forms](#interface-roles) |
| <a id="app-display-name"></a>`display_name` | Optional nonempty text ≤4096, no NUL | Omission uses profile display name; cosmetic |
| <a id="app-identity"></a>`identity` | Optional for fresh; retained has required members | [Persistent runtime identity](#runtime-identity) |
| <a id="app-storage"></a>`storage` | Optional named map, omitted `{}` | Profile role to [storage binding](storage.md#app-storage-bindings) |
| <a id="app-properties"></a>`properties` | Optional object, omitted `{}` | Apply profile defaults, then explicit app keys; use only the [adapter's accepted fields](app-properties.md) |
| <a id="app-software"></a>`software` | Optional unique ID list, omitted `[]` | Appends to profile software; conflicting selections are rejected |
| <a id="app-runtime"></a>`runtime` | Optional unique ID list, omitted `[]` | Appends to profile runtime; all resulting requirements must still be met |
| <a id="app-runtime-dns"></a>`runtime_dns` | Optional `context` or `host` | Overrides the profile mode; otherwise defaults to its mode, then `context`. Selects [container DNS](contexts.md#application-runtime-dns); null/empty/unknown values are rejected. |
| <a id="app-authentication"></a>`authentication` | Optional ID | Named [authentication policy](policies.md#authentication-policies); may be required by profile |
| <a id="app-forward-auth"></a>`forward_auth` | Optional object | Declare one native Authentik proxy provider and access binding for this app's canonical HTTPS exposure. [Forward authentication](#authentik-forward-authentication) |
| `retained_oidc_registration` | Optional object | Give Identity ownership of a confidential client with completed, reviewed callback additions. [Existing OIDC client](#existing-oidc-client) |
| <a id="app-retained-proxy-registrations"></a>`retained_proxy_registrations` | Optional object | Adopt existing Authentik single-host registrations for independently routed hosts. [Existing registrations](#existing-proxy-registrations) |
| <a id="app-devices"></a>`devices` | Optional named map, omitted `{}` | Profile role to [site device](supporting-types.md#devices) ID; one physical owner |
| <a id="app-origin"></a>`origin` | Optional closed reference | `{exposure: id, domain?: id}` selects an owned [HTTP exposure origin](exposures.md#public-origin) |
| <a id="app-secrets"></a>`secrets` | Optional named map, omitted `{}` | Maps a declared private role to a [secret-source ID](identity-and-secrets.md#secret-sources); adapter requirements for files still apply |
| <a id="app-resources"></a>`resources` | Optional closed object | Exactly `containers`, a nonempty service-role allocation map; [allocation rules](#allocations) |

## Authentik forward authentication

Identity reconciles a single-application proxy provider for the HTTPS host in the app's canonical exposure. The existing embedded outpost must belong to the Authentik installation selected by the route's forward authentication middleware. The worker and server must use the same pinned image from 2026.8.6 or later.

| Field under `forward_auth` | Required value |
| --- | --- |
| `middleware` | ID of the route's forward-auth middleware |
| `slug` | Unique app slug of up to 63 lowercase letters, digits and single hyphens |
| `provider_name` | Unique Authentik provider name |
| `admission_group` | Name of one existing group allowed into the application |
| `outpost` | `embedded` |
| `authorization_flow` | Slug of the existing provider authorization flow |
| `invalidation_flow` | Slug of the existing provider invalidation flow |
| `retained_application` | Optional on a retained app. Supply its existing Authentik `name`, `policy_engine_mode` (`any` or `all`) and `launch_url` (empty or the canonical HTTPS origin followed by `/`). |

The required fields are nonempty strings of at most 150 characters. By default the worker can create an application and provider and add the verified provider to the outpost. With `retained_application`, the existing application, provider, single group binding and embedded outpost assignment must already exist. The first import verifies the declared portal settings and access policy. A repeat checks the file hash, provider settings, admission binding and outpost membership. This declaration references the group's existing members. Removing the declaration leaves the registered objects in Authentik.

The CloudBeaver forward-auth profile requires a separate `secrets.recovery_password` reference. On a retained installation that previously used the dedicated OAuth gateway, supply the recovery password already installed for the same recovery administrator. Protected deployment compares the selected credential with the previous successful configuration before removing the gateway. An ordinary repeat verifies the dedicated secret against its existing material proof.

## Existing proxy registrations

Use `retained_proxy_registrations` for an app with multiple registered hostnames, an external backend or a gateway that already authenticates requests. The app keeps its own lifecycle selection. Select the Authentik app by its `identity` app ID. Supply `outpost: embedded` and the existing `authorization_flow` and `invalidation_flow` slugs. Under `registrations`, key each record by its unique existing Authentik application slug.

Each record requires `origin`, `provider_name`, `admission_group`, `name`, `policy_engine_mode` and `launch_path`. The origin references a named HTTPS exposure, optionally selecting one of its domain aliases, or a named site domain. Use the exact provider, group and portal display names. The policy mode is `any` or `all`. An empty launch path preserves an empty portal URL. A path such as `/admin` preserves a portal link on that registration's own origin.

Specify the existing group with `admission_group`. If the application has zero bindings and admits signed-in users, explicitly set `admission_group: null`. The worker checks that the binding count is zero before every application. A missing field is an error.

For an existing custom scope, define a named entry under the collection’s optional `additional_scope_mappings`. Supply the native mapping’s `name`, `scope_name` and lowercase 64-character `expression_sha256`. A registration selects that entry with `additional_scope_mapping`. Identity references the existing mapping by name and checks its scope and fingerprint each time. The mapping expression stays in Authentik.

On first use the Identity worker requires the matching existing portal, proxy provider, declared bindings, scope mappings and embedded outpost membership. Later deployments verify the native receipt and settings. The declaration manages identity objects only. DNS records, ingress routes and the guest's own authentication remain the responsibility of their existing declarations. Verify the actual browser return separately.

## Existing OIDC client

To retire a retained proxy, keep its declaration and add `retire` to the registration. Supply `application_id` (the existing application UUID) and `provider_id` (its positive integer provider ID). A scheduled file import leaves the objects alone. Protected Identity deployment checks the slug, hostname, application and provider identities, grant, flows, mappings and exclusive embedded outpost assignment. It applies the two native `absent` entries in a serializable transaction and verifies that both objects are gone. The transaction refuses unexpected dependent objects or links. The associated application grants, provider mapping links, outpost assignment and provider access tokens are removed. Groups, reusable mappings and the outpost keep their identities.

On a repeat deployment, the same declaration verifies absence and refuses a newly introduced registration that conflicts with the retired identity. A fresh installation can record absence when the referenced shared dependencies exist. Removing a declaration alone does not retire an existing registration. Restoring a prior registration after deletion requires recovery of its native identity.

An app can take over an existing confidential Authentik client whose callback list is already under the Identity app’s `callbacks.evidence` control. Declare `retained_oidc_registration` on the app that owns the registration. Its `identity` selects the Authentik app. `provider_id` selects exactly one reviewed callback record by its positive native integer ID. Supply the existing `provider_name`, application `slug`, `application_name`, `admission_group` and `policy_engine_mode` (`any` or `all`). This form accepts an empty `launch_url`. The registration requires one enabled group grant at order zero.

To remove a historical alias from this client, set `retire_callbacks` to a nonempty list of exact strict URLs from its reviewed `existing_redirects`. At least one original callback must remain. Identity accepts the complete previous or final guarded state, removes only the selected callbacks and verifies the client, secret, grants, signing settings and complete remaining ordered callback list. Unrecognized callbacks or changed policy stop deployment.


At compilation the selected callback record moves to the blueprint. Unrelated records stay with the callback reconciler. The worker requires the completed callback list and matching reviewed client, provider, application and policy fingerprints before applying the native YAML. It checks the same state and the existing client secret after import. The secret stays in Authentik. The existing installation and its reviewed evidence are prerequisites for this form.

## Interface roles

Each `apps.<id>.interfaces.<role>` uses exactly one of the forms below. The selected profile must declare the role and accept the chosen scope.

| Branch | Full nested fields | Effective value and restriction |
| --- | --- | --- |
| Guest interface | Required `.interface` identifier only | This guest's NIC; resolves its IPv4 address; manual NICs cannot supply an address |
| Guest loopback | Required `.scope: guest-loopback` only | `127.0.0.1`; does not reach a different guest |
| App network | Required `.scope: app-network` and `.network` identifier | Selects a network role owned by the adapter; does not create a host address |

Each branch requires exactly the fields listed; there are no defaults, and missing required fields, null values and unknown keys are rejected. An app interface assigns an existing address or network to a profile role. It does not allocate another NIC. See the [NIC address record](networks.md#field-guest-nic-address) for physical addresses and the [profile listener/endpoint contract](supporting-types.md#profile-interface-listener-and-endpoint-types) for sockets. A [connection](connections.md) must use a physical source or a supported same-guest loopback source. These bindings do not grant network access or make execution wait for another app.

## Instance, interface role and exported endpoint

In `apps.home.profile: homeassistant`, `home` names one site instance. The selected library's `homeassistant` profile supplies its supported software, roles, listeners and endpoints. A second instance can select the same profile, subject to placement and identity constraints; the instance name is not a software selector.

Suppose `apps.home.guest` is `automation` and `apps.home.interfaces.web_interface` is `{interface: primary}`. `primary` names a NIC in `guests.automation.interfaces`. The app's `web_interface` role receives that NIC's resolved IPv4 address; it does not allocate a NIC or imply isolation. The purpose and kind are explicit in each name:

- `interfaces.web_interface` declares a role that the site must bind.
- `listeners.web_listener` declares the actual socket, such as host TCP port 8123.
- `endpoints.web_endpoint` exports a named connection: `listener: web_listener`, `protocol: http`, `via: web_interface`.

For that profile, `{app: home, endpoint: web_endpoint}` resolves HTTP, port 8123 and the address supplied through the `web_interface` role. The site writes neither the port nor a copied backend address in its [exposure](exposures.md). `exposures.home_web.target` selects that exported connection; `ingress` separately selects the frontend HTTPS connection. A guest address change follows these references. The library owns which endpoints exist; do not assume that an arbitrary profile exports `web_endpoint` or rename endpoint keys without migrating their consumers.

A wildcard host listener still accepts other guest addresses unless access policy prevents it. App role binding and route selection do not alter listener isolation, authorize traffic or create a readiness dependency. See [connections](connections.md), [network policy](policies.md) and the selected profile's actual listener contract.

## Runtime identity

The paths below are `apps.<id>.identity.<field>`. Generated identities for a fresh app establish new ownership; they cannot rename or adopt an existing service. Retained configuration must supply the required stable names and genuine runtime evidence that HomeLab already manages the app.

| Field | Accepted type / fresh default | Retained/adapter requirement |
| --- | --- | --- |
| <a id="app-identity-phase"></a>`phase` | ID; defaults to app key | Required and unique within the guest; reserved execution stage names are forbidden |
| <a id="app-identity-runtime-id"></a>`runtime_id` | ID; defaults to app key | Required |
| <a id="app-identity-project"></a>`project` | Guest compose-project ID; generated selection when missing | Required for container adapters; an explicit reference must select an existing project |
| <a id="app-identity-services"></a>`services` | Adapter service-role → runtime-name map | For retained apps, supply exactly the adapter's complete set of roles |
| <a id="app-identity-networks"></a>`networks` | Adapter network-role → runtime-name map | For retained apps, supply exactly the adapter's complete set of roles |
| <a id="app-identity-runtime-directory"></a>`runtime_directory` | Absolute path under `/opt/homelab-app/runtime` | Required when the adapter manages runtime files |
| <a id="app-identity-custody-directory"></a>`custody_directory` | Adapter-specific absolute path | Only for CloudBeaver/Explorer directories containing managed private files; forbidden for other adapters |

For a fresh app, the generated project name is `homelab-<guest-key>-<app-key>` and the service name is `<app-key>_<service-role>`. Runtime service names must match `[a-z0-9][a-z0-9_-]{0,127}` and be unique within the project. Paths for runtime and private files must not overlap or expose another app's entire private directory. The complete [relationship composition](../examples/relationships/README.md) shows explicit identities for its selected apps.

## Allocations

`apps.<id>.resources.containers.<service-role>` contains one or more of:

| Field | Accepted domain | Resolution |
| --- | --- | --- |
| <a id="app-allocation-memory-mib"></a>`memory_mib` | Integer 1–2147483647 MiB | Override selected runtime role allocation, subject to minimums/budget |
| <a id="app-allocation-pids-limit"></a>`pids_limit` | Integer 1–2147483647 | Override selected role's process limit |
| <a id="app-allocation-cpu-limit"></a>`cpu_limit` | Number greater than 0 and at most 256 | Override selected role's CPU limit |

An allocation must contain at least one field, name a known service role and use numbers rather than Booleans. Runtime security requirements and profile minimums still apply. The guest must have enough capacity for the selected allocations and its effective OS reserve.

## First installation

Select a supported [adapter creation path](support.md), choose unused names and paths, and prepare the inputs required by the profile. A binding that is optional in the input format can still be required when the compiler connects the declarations or when the adapter runs. Check the [private role contract](identity-and-secrets.md#secret-sources) and compile the complete configuration into a packet. Selecting an image alone does not commission a service.

## Later deployments

Keep the same supported `fresh` configuration for ordinary updates. Deployment checks use genuine receipts to preserve app placement, service and project identities, storage, private files and credentials. Editing configuration does not automatically move or rename an app, transfer accounts, remove private roles or rotate credentials. See [lifecycle](lifecycle.md#change-effects) and any tighter limits in the selected profile. Configuration and software changes can restart services; source checks do not prove that an update will be uninterrupted. Verify the [actual service result](../operations/verify-and-maintain.md).

## Worked app and combination

This is the complete value of `apps.recursive_a` in the [offline tutorial](../examples/first-configuration/site.yaml). It compiles with that tutorial's `recursive` profile and `resolver` guest; it is not a standalone site or deployment-ready configuration.

<!-- example: app-minimal -->
```yaml
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

For a practical override, add the following fields to this app. The `unbound` role comes from its selected runtime; 256 MiB remains within the tutorial guest's budget. The display label is independent of its persistent identity.

<!-- example: app-overrides -->
```yaml
display_name: Example recursive resolver
resources:
  containers:
    unbound:
      memory_mib: 256
      cpu_limit: 1
      pids_limit: 128
```

**Invalid variation:** change `interfaces.local_interface` to `{scope: app-network, network: default}`. Although that is a valid scope for some profiles, this profile accepts only guest loopback for the role, so reference resolution rejects it. Keep `lifecycle: fresh` for later ordinary deployments; do not toggle it after installation. See [First installation and later deployments](lifecycle.md).

## Verification and navigation

[`app` and `role`](../../blueprints/component_types.py) validate the input structure. [`app_values`](../../blueprints/component_plan.py) checks the selected profile, placement, identity and role bindings. The [maintained example tests](../../blueprints/test_component_reference_examples.py) compile the complete example and reject a role scope that its profile does not allow. They do not verify ownership on a target or test the running application.

[Reference index](README.md) · [Adapter properties](app-properties.md) · [Relationship guide](../guides/references-and-reuse.md)
