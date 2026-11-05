# Identity, accounts and secrets

Public source contains references and public metadata, never credential values.
Compilation does not open configured secret paths or contact an identity provider.

## Secret sources

Each site `secret_sources.<id>` is exactly one form:

| type | Fields | Constraint |
| --- | --- | --- |
| file | path | Canonical absolute path; runtime selected private reader requires owned regular mode-0600 nonempty file, ≤1 MiB |
| environment | name, optional workflow_secret | Each `[A-Z][A-Z0-9_]{0,127}`; workflow_secret defaults to name |
| generated | credential_id | `[a-z][a-z0-9-]{2,62}`; create-once account source, not app secret bytes |

The `type` field is required in every form. File/generated forms cannot include
workflow_secret. An app's `secrets` maps declared profile roles to file/environment
sources. Generated sources belong to the separate [account](connections.md#accounts)
owner. Scalar inputs are nonempty ≤65536 UTF-8 bytes with no CR/LF/NUL and remain
unchanged. File-only compound roles still require their exact parser.

For a complete generated-account use, the
[relationship example](../examples/relationships/README.md) connects
`apps.browser` to `apps.broker` using `accounts.client` and
`secret_sources.browser_password` in its authored site. Existing-credential and
OIDC values below illustrate their own source/provider validator boundary;
they do not, by themselves, supply all prerequisites for an app installation.

| Adapter | Finite private roles |
| --- | --- |
| authentik | secret_key, postgresql_password, smtp_password |
| traefik | cloudflare_dns_token, proxmox_token |
| zabbix | database_password is accepted structurally outside root; ordinary preparation requires root-owned monitoring instead, with no selected role |
| node_red | api_token |
| bitwarden | runtime_environment |
| pegaprox | database_key |
| winet | options |
| mqtt | probe |
| cloudbeaver | client_secret, selected through OIDC policy |
| mqtt_explorer | broker_password, selected through existing connection credential |

Profile declarations contain `{required: Boolean}` per allowed role.
Cloud/Explorer derive roles from authentication/connection contracts rather than
ordinary profile secret declarations. Required/conditional adapter checks still
apply: for example MQTT probe, WiNet options, Pega key and Bitwarden environment
are files. Context API/SSH credentials use their own protected workflow boundary.

## Identity providers

Site `identity_providers.<id>` supports three closed forms.

### OIDC

Required: `type: oidc`, `origin`, `issuer_path`, `endpoints`,
`signing_algorithms`.
Origin is `{domain: id}` or `{exposure: id, domain?: id}`, resolved to HTTPS.
`endpoints` requires exactly `authorization`, `token`, `userinfo`, `jwks`,
each a relative path beginning with one slash. `issuer_path` uses the same rule.
Paths cannot contain whitespace/control, ?, #, backslash, percent or dot
traversal. Algorithms are a nonempty unique subset of
RS256/384/512, PS256/384/512, ES256/384/512, EdDSA.
No symmetric client-secret signing or inferred discovery URL is accepted.

### Existing Node-RED OIDC strategy

Required: `type: retained-node-red-oidc`, `origin`, `provider_slug`.
Origin uses the same typed form, with standard HTTPS port.
Slug matches `[a-z0-9][a-z0-9-]{0,62}`.
This names an ongoing existing strategy/material contract, not a one-time
migration admission. Selecting it does not provision an IdP application.

### SAML

Required: `type: saml`, `signing_certificate`.
Certificate is one valid public PEM certificate, ≤65536 UTF-8 bytes, no private
key. It binds Zabbix's existing identity provider. The policy selects local or
SAML default login; it does not create users/roles or weaken assertion checks.

## Protected material continuity

Ordinary app payloads seal private roles. Later source runs may add selected
roles but cannot remove a sealed role or change its credential material.
Source-ID rename does not waive role continuity. Compound WiNet/MQTT/provider
inputs compare credential identity/material through existing parsers, allowing
unrelated public metadata to evolve. Bitwarden's opaque environment and immutable
keys keep their exact-byte contract.

Comparison happens when the selected app's material is available, before that
app's payload publication, credential writers, STARTED and service executor.
Infrastructure/preparation may already have completed. There is no implicit
rotation, reset or authored override. Generated accounts have separate stable
producer/principal/create-once ownership.

## Worked sources and OIDC combination

These are complete source values placed under separate named `secret_sources`
keys. They describe where selected material comes from, never its contents.

<!-- example: secret-file -->
```yaml
type: file
path: /example/private/application.env
```

<!-- example: secret-environment -->
```yaml
type: environment
name: EXAMPLE_API_TOKEN
workflow_secret: EXAMPLE_WORKFLOW_TOKEN
```

A file-only role cannot use the environment form. **Invalid variation:** add
`workflow_secret` to the file source; that key is accepted only for environment
sources. The source reader does not test runtime mode/owner/contents.

This complete OIDC provider value requires `domains.login` in the same site.
A matching app policy still needs its own client ID/secret source and owned
origin; this object does not provision an IdP application.

<!-- example: identity-oidc -->
```yaml
type: oidc
origin: {domain: login}
issuer_path: /application/o/example/
endpoints:
  authorization: /application/o/authorize/
  token: /application/o/token/
  userinfo: /application/o/userinfo/
  jwks: /application/o/example/jwks/
signing_algorithms: [RS256]
```

**Invalid variation:** replace RS256 with HS256, or add a query to `issuer_path`.
Both refuse. Later deployment may change supported public provider metadata, but
source-ID renaming cannot remove or replace a sealed private role's material.

[Reference index](README.md) · [Lifecycle](lifecycle.md) · [Policies](policies.md)
