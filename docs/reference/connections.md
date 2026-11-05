# Connections

A connection binds one profile-declared consumer role to a socket.
Site `connections.<id>` is inline or a complete `kind: connection` source.

| Field | Type / required / default | Rules |
| --- | --- | --- |
| consumer | Required object | Exactly `{app: app_id, connection: role_id}`; role declared once by that profile |
| target | Required endpoint reference | App endpoint or external endpoint |
| source_interface | Required app role ID | Physical role; supported same-guest loopback is allowed |
| transport | Optional policy ID | Existing transport policy; no implicit selection from endpoint metadata |
| account | Optional account ID | Owned managed account, mutually exclusive with credential |
| credential | Optional object | Exactly `{principal: nonempty_text, secret: source_id}`; file/environment only |
| readiness | Optional enum | `configure` or `start`, explicitly allowed by profile role |
| hostname | Optional typed reference | `{domain: id}`, `{alias: id}`, or `{exposure: id, domain?: id}` |

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

## Accounts

Site `accounts.<id>` requires all of:

| Field | Type and constraint |
| --- | --- |
| adapter | `postgresql-admin`, `mariadb-admin`, `mqtt-client` |
| owner | Consumer app ID |
| target | Managed producer app endpoint, TCP and matching adapter |
| principal | Identifier; PostgreSQL also excludes all/public/none and pg_ prefix |
| credential | Generated secret-source ID; credential_id cannot be reused |
| access | `server-administration` for DB, `read-write-all` for MQTT |
| lifecycle | Exactly `create-once` |

Every account must be used. Duplicate canonical producer/principal pairs and
credential aliases refuse. Existing credentials are read/verified by their owner;
source changes do not rotate them. Account deletion, privilege expansion and
transfer are not inferred from a new connection.

## Update and checks

The real binders check type/scope/account/transport/hostname/readiness;
source extraction leaves those checks intact. Changing a target can change
reachability and app configuration, so review policies, credentials and native
service effect. The compiler provides no interruption-free or account-migration
guarantee.

[Reference index](README.md) · [Policies](policies.md) · [Sources](sources.md)
