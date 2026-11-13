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
| <a id="app-authentication"></a>`authentication` | Optional ID | Named [authentication policy](policies.md#authentication-policies); may be required by profile |
| <a id="app-devices"></a>`devices` | Optional named map, omitted `{}` | Profile role to [site device](supporting-types.md#devices) ID; one physical owner |
| <a id="app-origin"></a>`origin` | Optional closed reference | `{exposure: id, domain?: id}` selects an owned [HTTP exposure origin](exposures.md#public-origin) |
| <a id="app-secrets"></a>`secrets` | Optional named map, omitted `{}` | Maps a declared private role to a [secret-source ID](identity-and-secrets.md#secret-sources); adapter requirements for files still apply |
| <a id="app-resources"></a>`resources` | Optional closed object | Exactly `containers`, a nonempty service-role allocation map; [allocation rules](#allocations) |

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
