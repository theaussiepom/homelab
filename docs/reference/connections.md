# Connections

A connection binds one profile-declared consumer role to a socket.
Site `connections.<id>` is inline or a complete `kind: connection` source.

| Field | Type / required / default | Rules |
| --- | --- | --- |
| <a id="connection-consumer"></a>`consumer` | Required object | Exactly `{app: app_id, connection: role_id}`; role declared once by that profile |
| <a id="connection-target"></a>`target` | Required endpoint reference | App endpoint or external endpoint |
| <a id="connection-source-interface"></a>`source_interface` | Required app role ID | Physical role; supported same-guest loopback is allowed |
| <a id="connection-transport"></a>`transport` | Optional policy ID | Existing transport policy; no implicit selection from endpoint metadata |
| <a id="connection-account"></a>`account` | Optional account ID | Owned managed account, mutually exclusive with credential |
| <a id="connection-credential"></a>`credential` | Optional object | Exactly `{principal: nonempty_text, secret: source_id}`; file/environment only |
| <a id="connection-readiness"></a>`readiness` | Optional enum | `configure` or `start`, explicitly allowed by profile role |
| <a id="connection-hostname"></a>`hostname` | Optional typed reference | `{domain: id}`, `{alias: id}`, or `{exposure: id, domain?: id}` |

No optional field has a default relationship effect.
The target protocol must match the declared role: DNS accepts TCP/UDP;
PostgreSQL/MariaDB/MQTT require TCP; HTTP/InfluxDB require HTTP; HTTPS requires
HTTPS. Managed producer adapters must match that type.
Internal dashboard endpoints cannot be connection targets.
A loopback target must belong to the same guest and use a loopback source.

Credentials target unmanaged endpoints, or the supported managed MQTT case.
An account's owner and target must exactly match the consumer and connection.
Hostname references reuse declared names; an exposure hostname must belong to
the same target. Required profile connection roles cannot be omitted.

Readiness creates app edges and, when crossing guests, guest edges.
Self-dependency, cycles, unknown targets and disabled required dependencies
refuse. Without readiness the connection is value-only; it does not start peers.
Required cross-guest communication must match explicit source and destination
guest rules. Nothing here generates an access grant.

Profile metadata can permit omission while an adapter's final health contract
still requires a role. Current CloudBeaver and Music Assistant packets need a
`public` HTTPS connection (IPv4 ingress port 443) and owned HTTPS origin for their
public-route health checks. Music Assistant also binds that check to its physical
web source. Resolve **and lower** the complete profile composition; a structurally
optional declaration does not prove that omitting it yields an executable packet.

## Nested references and conditional fields

The table paths above are relative to `connections.<id>`. Nested objects are
closed and have no implicit defaults:

| Full nested path | Required condition / accepted shape | Reference/effect |
| --- | --- | --- |
| `connections.<id>.consumer.app` | Required identifier | Existing consumer app |
| `connections.<id>.consumer.connection` | Required identifier | Declared connection role of that app's selected profile |
| `connections.<id>.target.external` | External target branch; required identifier | Selects site external endpoint; forbids app/endpoint keys |
| `connections.<id>.target.app` and `.endpoint` | App target branch; both required identifiers | Selects the declared endpoint of the producer app; forbids external |
| `connections.<id>.credential.principal` | Existing-credential branch; required nonempty text | Existing account identity; not an account-creation request |
| `connections.<id>.credential.secret` | Existing-credential branch; required source ID | File/environment source; forbidden beside `account` |
| `connections.<id>.hostname.domain` | Domain branch; required identifier only | Reuses a declared site domain |
| `connections.<id>.hostname.alias` | Alias branch; required identifier only | Reuses Docker-local host alias metadata |
| `connections.<id>.hostname.exposure` | Exposure branch; required identifier | Selects the target's exposure; optional `domain` selects one declared main/alias domain |

Endpoint references reuse declared socket values. A hostname reference selects
a name for that socket; it does not change address allocation or publish DNS.
See [network values](networks.md#external-endpoints) and
[exposure ownership](exposures.md#public-origin). The
[complete relationship composition](../examples/relationships/README.md) shows
these bindings with every required surrounding declaration.

## Accounts

Site `accounts.<id>` requires all of:

| Field | Type and constraint |
| --- | --- |
| <a id="account-adapter"></a>`adapter` | `postgresql-admin`, `mariadb-admin`, `mqtt-client` |
| <a id="account-owner"></a>`owner` | Consumer app ID |
| <a id="account-target"></a>`target` | Managed producer app endpoint, TCP and matching adapter |
| <a id="account-principal"></a>`principal` | Identifier; PostgreSQL also excludes all/public/none and pg_ prefix |
| <a id="account-credential"></a>`credential` | Generated secret-source ID; credential_id cannot be reused |
| <a id="account-access"></a>`access` | `server-administration` for DB, `read-write-all` for MQTT |
| <a id="account-lifecycle"></a>`lifecycle` | Exactly `create-once` |

Every account must be used. Duplicate canonical producer/principal pairs and
credential aliases refuse. Existing credentials are read/verified by their owner;
source changes do not rotate them. Account deletion, privilege expansion and
transfer are not inferred from a new connection.

## First installation

A connection is a relationship, not an independently installed service. Its
consumer/producer profiles must support the chosen installation path and their
real inputs. An account declaration follows its exact create-once owner; it is
not a generic credential bootstrap for an arbitrary endpoint. Source checks
validate metadata and leave actual material and service checks to
[deployment preparation](../guides/prepare-deployment.md).

<a id="update-and-checks"></a>
## Later deployments

The real binders check type/scope/account/transport/hostname/readiness;
source extraction leaves those checks intact. Changing a target can change
reachability and app configuration, so review policies, credentials and native
service effect. The compiler provides no interruption-free or account-migration
guarantee.

## Worked connection and account combination

This complete connection value binds an Explorer's broker role to a managed
MQTT endpoint. It requires compatible `browser`/`broker` app profiles and physical
role bindings, a `broker` domain, and the `client` account below. It is a worked
relationship, not a complete site or a credential value.

The complete tested [broker/browser/ingress composition](../examples/relationships/README.md)
contains every prerequisite in its [site.yaml](../examples/relationships/site.yaml)
and adjacent library/image indexes. In that source, `connections.broker`,
`accounts.client` and `secret_sources.browser_password` have the exact values
shown below; `apps.browser` and `apps.broker` bind their profile roles.

<!-- example: connection-managed -->
```yaml
consumer: {app: browser, connection: broker}
target: {app: broker, endpoint: backend}
source_interface: broker
hostname: {domain: broker}
account: client
```

Declare the account as `accounts.client` and its generated source as
`secret_sources.browser_password`. The producer/principal/credential owner is
create-once; the connection does not supply a password inline.

<!-- example: account-managed -->
```yaml
adapter: mqtt-client
owner: browser
target: {app: broker, endpoint: backend}
principal: browser
credential: browser_password
access: read-write-all
lifecycle: create-once
```

<!-- example: account-source -->
```yaml
type: generated
credential_id: example-browser-password
```

**Invalid variation:** also add `credential: {principal: browser, secret: probe}`
to the connection. It cannot select both an account and an existing credential.
Changing `source_interface` to an undeclared role likewise refuses.
An optional connection without `readiness` adds no execution wait; add readiness
only if that exact profile role permits it. Changing the target does not transfer
an existing account's ownership or authorise rotating its material.

The [connection binder](../../blueprints/component_connections.py) and
[account binder](../../blueprints/component_accounts.py) own these relationships.
[Reference examples](../../blueprints/test_component_reference_examples.py)
compare complete-source excerpts and exercise intended source refusals. They
establish no account creation or live broker authentication.

[Reference index](README.md) · [Policies](policies.md) · [Sources](sources.md)
