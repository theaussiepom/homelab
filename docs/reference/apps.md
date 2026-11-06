# App instances

An app is one `apps.<id>` value in a [site](site.md). It chooses a library
profile, places that instance on one guest and binds the profile's named roles.
An inline value and a complete `kind: app` [typed source](sources.md) have the
same meaning. A profile's available roles and defaults belong to its selected
library; this page defines the framework's instance grammar.

## Instance fields

Objects are closed; IDs and scalar values follow the [shared rules](supporting-types.md#scalar-and-path-types).
Required values have no default. Optional maps/lists use the defaults below;
null is not an empty map/list or an inheritance request.

| Path under `apps.<id>` | Presence / type | Meaning and resolution |
| --- | --- | --- |
| <a id="app-profile"></a>`profile` | Required ID | Existing library [app profile](library.md#app-profile) |
| <a id="app-guest"></a>`guest` | Required ID | Existing [site guest](guests.md); placement must fit namespaces and capacity |
| <a id="app-lifecycle"></a>`lifecycle` | Required `fresh` or `retained` | [Creation/continuation policy](lifecycle.md), constrained by adapter support |
| <a id="app-interfaces"></a>`interfaces` | Required named map | Bind profile roles; required roles must be present; [exact branches](#interface-roles) |
| <a id="app-display-name"></a>`display_name` | Optional nonempty text ≤4096, no NUL | Omission uses profile display name; cosmetic |
| <a id="app-identity"></a>`identity` | Optional for fresh; retained has required members | [Persistent runtime identity](#runtime-identity) |
| <a id="app-storage"></a>`storage` | Optional named map, omitted `{}` | Profile role to [storage binding](storage.md#app-storage-bindings) |
| <a id="app-properties"></a>`properties` | Optional object, omitted `{}` | Profile direct defaults then explicit app keys; [adapter-specific closed shape](app-properties.md) |
| <a id="app-software"></a>`software` | Optional unique ID list, omitted `[]` | Appends to profile software; conflicting selections refuse |
| <a id="app-runtime"></a>`runtime` | Optional unique ID list, omitted `[]` | Appends to profile runtime; effective requirements still apply |
| <a id="app-authentication"></a>`authentication` | Optional ID | Named [authentication policy](policies.md#authentication-policies); may be required by profile |
| <a id="app-devices"></a>`devices` | Optional named map, omitted `{}` | Profile role to [site device](supporting-types.md#devices) ID; one physical owner |
| <a id="app-origin"></a>`origin` | Optional closed reference | `{exposure: id, domain?: id}` selects an owned [HTTP exposure origin](exposures.md#public-origin) |
| <a id="app-secrets"></a>`secrets` | Optional named map, omitted `{}` | Declared private role to [secret-source ID](identity-and-secrets.md#secret-sources); adapter file floors still apply |
| <a id="app-resources"></a>`resources` | Optional closed object | Exactly `containers`, a nonempty service-role allocation map; [allocation rules](#allocations) |

## Interface roles

Each `apps.<id>.interfaces.<role>` is exactly one closed branch. The selected
profile must declare the role and accept the chosen scope.

| Branch | Full nested fields | Effective value and restriction |
| --- | --- | --- |
| Guest interface | Required `.interface` identifier only | This guest's NIC; resolves its IPv4 address; manual NICs cannot supply an address |
| Guest loopback | Required `.scope: guest-loopback` only | `127.0.0.1`; does not reach a different guest |
| App network | Required `.scope: app-network` and `.network` identifier | Adapter-owned network role; no invented host address |

There are no branch defaults; missing/null/unknown keys refuse. An app interface
is a role binding, not another NIC allocation. Link physical values to the
[NIC address record](networks.md#field-guest-nic-address); link actual sockets
to the [profile listener/endpoint contract](supporting-types.md#profile-interface-listener-and-endpoint-types).
A [connection](connections.md) source must be physical or use its supported
same-guest loopback case. None of these bindings adds a permission or wait.

## Runtime identity

Paths below are `apps.<id>.identity.<field>`. Generated fresh identities establish
new ownership; they cannot rename or adopt an existing service. Retained source
must supply its required stable names and genuine runtime proof.

| Field | Accepted type / fresh default | Retained/adapter requirement |
| --- | --- | --- |
| <a id="app-identity-phase"></a>`phase` | ID; defaults to app key | Required; unique within guest, excludes reserved execution stages |
| <a id="app-identity-runtime-id"></a>`runtime_id` | ID; defaults to app key | Required |
| <a id="app-identity-project"></a>`project` | Guest compose-project ID; generated selection when missing | Required for container adapters; explicit references must exist |
| <a id="app-identity-services"></a>`services` | Adapter service-role → runtime-name map | Exact complete adapter role set for retained |
| <a id="app-identity-networks"></a>`networks` | Adapter network-role → runtime-name map | Exact complete adapter role set for retained |
| <a id="app-identity-runtime-directory"></a>`runtime_directory` | Absolute path under `/opt/homelab-app/runtime` | Required where the adapter owns runtime leaves |
| <a id="app-identity-custody-directory"></a>`custody_directory` | Adapter-specific absolute path | CloudBeaver/Explorer owned custody roots only; forbidden for other adapters |

Fresh generated project name is `homelab-<guest-key>-<app-key>` and service name
is `<app-key>_<service-role>`. Service execution names match
`[a-z0-9][a-z0-9_-]{0,127}` and are unique inside the project. Runtime/custody
leaves cannot collide or expose an entire peer-private directory. The complete
[relationship composition](../examples/relationships/README.md) illustrates
explicit identities for its selected apps.

## Allocations

`apps.<id>.resources.containers.<service-role>` contains one or more of:

| Field | Accepted domain | Resolution |
| --- | --- | --- |
| <a id="app-allocation-memory-mib"></a>`memory_mib` | Integer 1–2147483647 MiB | Override selected runtime role allocation, subject to minimums/budget |
| <a id="app-allocation-pids-limit"></a>`pids_limit` | Integer 1–2147483647 | Override selected role's process limit |
| <a id="app-allocation-cpu-limit"></a>`cpu_limit` | Number greater than 0 and at most 256 | Override selected role's CPU limit |

An empty allocation, unknown service role or Boolean numeric value refuses.
These are instance allocations, not an escape from runtime security or profile
minimums. Guest capacity and effective OS reserve must still cover the selection.

## First installation

Select a supported [adapter creation path](support.md), free owned namespaces
and the profile's actual prepared inputs. A structurally optional binding can
be required by resolution or a later adapter guard; the
[private role contract](identity-and-secrets.md#secret-sources) and full lowering
must be checked. An image selection alone does not commission a service.

## Later deployments

Keep the same supported `fresh` source for ordinary owned updates. Placement,
service/project identity, storage and private-material continuity remain bound
to genuine receipts. No automatic move, rename, account transfer, private-role
removal or credential rotation follows from source changes. See
[lifecycle](lifecycle.md#change-effects) and the selected profile's tighter limits.
App configuration/software changes can restart services; source checks do not
qualify uninterrupted operation. Verify the [actual service result](../operations/verify-and-maintain.md).

## Worked app and combination

This is the complete value of `apps.recursive_a` in the
[offline tutorial](../examples/first-configuration/site.yaml). It compiles with
that tutorial's `recursive` profile and `resolver` guest; it is not a standalone
site or deployment-ready configuration.

<!-- example: app-minimal -->
```yaml
profile: recursive
guest: resolver
lifecycle: fresh
interfaces:
  private: {scope: app-network, network: default}
  local: {scope: guest-loopback}
```

For a practical override, add the following fields to this app. The `unbound`
role comes from its selected runtime; 256 MiB remains within the tutorial guest's
budget. The display label is independent of its persistent identity.

<!-- example: app-overrides -->
```yaml
display_name: Example recursive resolver
resources:
  containers:
    unbound: {memory_mib: 256, cpu_limit: 1, pids_limit: 128}
```

**Invalid variation:** change `interfaces.local` to `{scope: app-network,
network: default}`. This is a valid scope generally, but this profile accepts
only guest loopback for that role, so real resolution refuses it.
Keep `lifecycle: fresh` for later ordinary deployments of this owned app; do not
toggle it after installation. See [First installation and later deployments](lifecycle.md).

## Verification and navigation

[`app` and `role`](../../blueprints/component_types.py) validate structure;
[`app_values`](../../blueprints/component_plan.py) resolves profile/placement/
identity and selected role constraints. The [maintained examples](../../blueprints/test_component_reference_examples.py)
resolve/lower the complete example and refuse the wrong profile scope. Native
ownership and application acceptance remain separate evidence.

[Reference index](README.md) · [Adapter properties](app-properties.md) ·
[Relationship guide](../guides/references-and-reuse.md)
