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

Current ordinary app preparation requires this root-owned monitoring capability:
its generated database credential and exact monitoring files. A Zabbix app
outside the root feature may pass structural/source binding with a selected
`database_password`, but that combination is not supported by the ordinary
preparation caller. Do not treat source acceptance as a standalone server
installation recipe or pass an arbitrary scalar password to bypass that owner.

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

## Worked selection and profile

This is a **site-root fragment**, not an installation recipe:

<!-- example: zabbix-selection -->
```yaml
zabbix: {server: monitoring}
```

It selects an already declared Zabbix app named `monitoring`. A reusable
`monitoring_profiles.linux_host` value can be:

<!-- example: zabbix-profile -->
```yaml
type: zabbix-agent
profiles: [linux]
```

A template or guest can then select `monitoring: {profile: linux_host}`.
Add `docker` to the same profile only for a guest whose selected workload needs
that integration and whose runtime prerequisites are supported. Root monitoring
still requires the declared server's database, software and connections.
**Invalid variation:** `zabbix: false` refuses; omission is the disabled form.
`profiles: [docker]` validates as a profile type but does not satisfy the root
feature's required Linux profile for every selected guest.
A later run updates the owned monitoring configuration without replacing host
identities or regenerating existing credentials.

[Reference index](README.md) · [Deployment](../operations/deployment.md)
