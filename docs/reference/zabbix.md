# Root Zabbix monitoring

Root `zabbix` is an explicit monitoring feature, separate from app value links.

| Source | Meaning |
| --- | --- |
| Property absent | No root monitoring expansion |
| zabbix: null (or empty YAML value) | Exactly one selected Zabbix app must exist; select it |
| zabbix: {server: app_id} | Select that existing Zabbix app |
| false, true, empty object, extra keys | Refused |

The site still declares the Zabbix app, guest, database/metrics connections,
software and exposure. Root presence does not invent a guest allocation.
Every selected guest's combined monitoring profiles must include linux.

## Derived behavior

The compiler selects active Agent2 settings and stable node-VMID host/PSK
identities. Profiles choose Linux, Docker, PostgreSQL, MySQL or InfluxDB support.
Docker monitoring grants the local agent access to the guest's Docker group/API;
no central Docker socket is published.

This root feature explicitly adds narrow monitoring traffic: active TCP10051
between monitored guests/server, frontend TCP8080 from selected ingress, and
selected PostgreSQL/InfluxDB storage flows. Ordinary connections and value
references do not otherwise add grants. Database statistics accounts and
monitoring credentials have their own create-once ownership.

The monitoring server cannot be disabled while other guests remain enabled.
An all-disabled inventory can compile for inspection. Server-owned inventory,
template/PSK/SAML/database readiness remains separate from native service acceptance.

See [authentication policies](policies.md#authentication-policies) and
[app properties](app-properties.md#authentik-and-zabbix).
No fresh commissioning, automatic restore or TLS identity guarantee should be
inferred merely from root presence. The selected library's profile and existing
protected inputs/native prerequisites determine the supported path.

## Credentials, login and preservation

Controller monitoring credentials are create-once private owner-bound records.
Do not print, regenerate or replace a commissioned PSK/password to repair a
failed run. Template/inventory updates preserve host identities, secret macros
and history; they do not use destructive deleteMissing imports.

Selected SAML default login changes the entry screen, not password/API
authentication or user roles. The vendor local recovery form remains at
`/index.php?form=default`. Keep a working local administrator and verify the
real SSO session separately. The public IdP certificate is not a private key.

The monitoring-owned PostgreSQL storage path requires its existing native TLS
precheck and exact HBA contract. It does not create/replace production database
certificates. An encrypted connection alone is not a newly qualified certificate
identity policy. InfluxDB organization/bucket discovery needs its own scoped
credential and is not inferred from the metrics connection.

[Reference index](README.md) · [Deployment](../operations/deployment.md)
