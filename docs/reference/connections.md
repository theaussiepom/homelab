# Connections

A connection tells an app where to reach the socket required by one of its profile roles. Declare it inline at `connections.<id>` in your site or in a complete `kind: connection` source file.

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

Omitting an optional field does not add a relationship. The target protocol must match the declared role: DNS accepts TCP/UDP; PostgreSQL/MariaDB/MQTT require TCP; HTTP/InfluxDB require HTTP; HTTPS requires HTTPS. A HomeLab-managed producer must use the matching adapter. Internal dashboard endpoints cannot be connection targets. A loopback target must belong to the same guest as the consumer and use a loopback source.

Use `credential` for an unmanaged endpoint or the supported managed MQTT case. When using an account, its owner must match the consumer and its target must match the connection target. Hostname references reuse declared names, and an exposure hostname must belong to the same target. Supply every connection role required by the profile.

Readiness makes execution wait for another app and, when the apps are on different guests, for that guest. Checks reject self-dependencies, cycles, unknown targets and disabled required dependencies. Without readiness, a connection only supplies values; it does not start another app. Communication between guests must match explicit rules on both the source and destination guest. A connection does not grant network access.

A profile can mark a role optional even though the adapter needs it for its generated health checks. CloudBeaver and Music Assistant currently require a `public` HTTPS connection to IPv4 ingress port 443 and an HTTPS origin they own. Music Assistant also uses its physical web interface as the source for that check. Resolve **and lower** the complete configuration: check all references and generate the deployment packet. Checking the input shape alone cannot establish that an optional role may be omitted.

## Nested references and conditional fields

The table paths above are relative to `connections.<id>`. Nested objects accept only the listed fields and have no implicit defaults:

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

Endpoint references reuse declared socket values. A hostname reference selects a name for that socket; it does not change address allocation or publish DNS. See [network values](networks.md#external-endpoints) and [exposure ownership](exposures.md#public-origin). The [complete relationship composition](../examples/relationships/README.md) shows these bindings with every required surrounding declaration.

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

Every account must be used by a connection. Checks reject duplicate canonical producer/principal pairs and credential aliases. The account owner reads and verifies existing credentials; changing configuration does not rotate them. A new connection does not request account deletion, additional privileges or an ownership transfer.

## First installation

A connection is not installed separately. Both the consumer and producer profiles must support the chosen installation path and have their required inputs prepared. An account declaration follows its specific create-once procedure; it cannot bootstrap credentials for an arbitrary endpoint. Configuration checks validate the references and metadata. Follow [deployment preparation](../guides/prepare-deployment.md) to check actual credentials, files and services.

<a id="update-and-checks"></a>
## Later deployments

The compiler checks connection types, scopes, accounts, transport, hostnames and readiness, whether declarations are inline or in separate source files. Changing a target can affect reachability and app configuration. Review the relevant policies, credentials and effects on the running service. The compiler does not guarantee uninterrupted changes or account migration.

## Worked connection and account combination

This complete connection value binds an Explorer's broker role to a managed MQTT endpoint. It requires compatible `browser`/`broker` app profiles and physical role bindings, a `broker` domain, and the `client` account below. It is a worked relationship, not a complete site or a credential value.

The complete tested [broker/browser/ingress composition](../examples/relationships/README.md) contains every prerequisite in its [site.yaml](../examples/relationships/site.yaml) and adjacent library/image indexes. In that source, `connections.broker`, `accounts.client` and `secret_sources.browser_password` have the exact values shown below; `apps.browser` and `apps.broker` bind their profile roles.

<!-- example: connection-managed -->
```yaml
consumer:
  app: browser
  connection: broker
target:
  app: broker
  endpoint: backend_endpoint
source_interface: broker_interface
hostname:
  domain: broker
account: client
```

Declare the account as `accounts.client` and its generated source as `secret_sources.browser_password`. HomeLab creates the account and credential once, preserving the selected producer and principal. The connection does not contain a password.

<!-- example: account-managed -->
```yaml
adapter: mqtt-client
owner: browser
target:
  app: broker
  endpoint: backend_endpoint
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

**Invalid variation:** also add `credential: {principal: browser, secret: probe}` to the connection. Validation rejects a connection that selects both an account and an existing credential. It also rejects an undeclared `source_interface` role. An optional connection without `readiness` does not make execution wait; add readiness only if that profile role permits it. Changing the target does not transfer an existing account or authorise credential rotation.

The [connection binder](../../blueprints/component_connections.py) and [account binder](../../blueprints/component_accounts.py) check these relationships. [Reference example tests](../../blueprints/test_component_reference_examples.py) compare the excerpts with complete source files and check that invalid declarations fail as intended. They do not create accounts or test authentication against a running broker.

[Reference index](README.md) · [Policies](policies.md) · [Sources](sources.md)
