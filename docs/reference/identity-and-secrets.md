# Identity, accounts and secrets

Public configuration contains references and public metadata, never credential values. Compilation does not open configured secret files or contact an identity provider (IdP).

## Secret sources

Each site `secret_sources.<id>` is exactly one form:

| type | Fields | Constraint |
| --- | --- | --- |
| file | path | Canonical absolute path. The runtime private-file reader requires a nonempty regular file owned by the expected Unix user, with mode 0600 and size at most 1 MiB. |
| environment | name, optional workflow_secret | Each `[A-Z][A-Z0-9_]{0,127}`; workflow_secret defaults to name |
| generated | credential_id | `[a-z][a-z0-9-]{2,62}`; identifies a credential created once by an account, not inline app secret bytes |

Every form requires `type`. File and generated sources cannot include workflow_secret. An app's `secrets` map connects declared profile roles to file or environment sources. Generated sources belong to the separate [account](connections.md#accounts) that creates and manages the credential. Scalar inputs must be nonempty, at most 65536 UTF-8 bytes and contain no CR/LF/NUL; they are passed through unchanged. Roles requiring a structured file still use their specific parser.

The complete [relationship example](../examples/relationships/README.md) shows a generated account: it connects `apps.browser` to `apps.broker` through `accounts.client` and `secret_sources.browser_password`. The existing-credential and OpenID Connect (OIDC) examples below demonstrate their respective validators. They do not supply every prerequisite needed to install an app.

| Adapter | Finite private roles |
| --- | --- |
| authentik | secret_key, postgresql_password, smtp_password |
| traefik | cloudflare_dns_token, proxmox_token |
| zabbix | database_password passes structural validation without root monitoring, but ordinary preparation requires root monitoring to manage the credential instead, with no selected role |
| node_red | api_token |
| bitwarden | runtime_environment |
| pegaprox | database_key |
| winet | options |
| mqtt | probe |
| cloudbeaver | client_secret, selected through OIDC policy |
| mqtt_explorer | broker_password, selected through existing connection credential |

A profile declares `{required: Boolean}` for each allowed role. CloudBeaver and MQTT Explorer obtain their roles from authentication and connection declarations instead of ordinary profile secret declarations. Adapter requirements still apply even when a profile marks a role optional: MQTT probe, WiNet options, Pega key and Bitwarden environment, for example, must be files. The protected workflow handles context API and SSH credentials separately.

## Identity providers

Each `identity_providers.<id>` value supports one of the following three forms. Use only the fields listed for that form.

### OIDC

OIDC requires `type: oidc`, `origin`, `issuer_path`, `endpoints` and `signing_algorithms`. Set `origin` to `{domain: id}` or `{exposure: id, domain?: id}`; the compiler derives an HTTPS URL. The `endpoints` object requires exactly `authorization`, `token`, `userinfo` and `jwks`. Each endpoint and `issuer_path` must be a relative path beginning with one slash. Paths cannot contain whitespace, control characters, ?, #, backslash, percent or dot traversal. Supply a nonempty, unique selection of RS256/384/512, PS256/384/512, ES256/384/512 or EdDSA. Symmetric client-secret signing is unsupported, and no discovery URL is inferred.

### Existing Node-RED OIDC strategy

This form requires `type: retained-node-red-oidc`, `origin` and `provider_slug`. The origin uses the same reference forms as OIDC and requires the standard HTTPS port. The slug must match `[a-z0-9][a-z0-9-]{0,62}`. This declaration continues using an existing strategy and its credentials. It is not a one-time migration exception and does not provision an IdP application.

### SAML

A Security Assertion Markup Language (SAML) provider requires `type: saml` and `signing_certificate`. Supply one valid public PEM certificate of at most 65536 UTF-8 bytes, with no private key. It connects Zabbix to its existing identity provider. The policy selects local or SAML as the default login method; it does not create users or roles, or weaken assertion checks.

## Protected material continuity

An ordinary app payload is a record of the app's deployment inputs. It seals the app's private roles so later runs can compare them. Later deployments may add selected roles, but cannot remove a sealed role or change its credentials. Renaming the source ID does not bypass those checks. For structured WiNet, MQTT and provider inputs, the existing parsers compare credential identities and values while allowing unrelated public metadata to change. Bitwarden's opaque environment file and immutable keys must remain byte-for-byte identical.

Once the selected app's private inputs are available, HomeLab compares them before publishing its payload, writing credentials, marking STARTED or running its service executor. Infrastructure and preparation may already have completed. Configuration does not provide an implicit rotation, reset or override. Generated accounts separately preserve their producer, principal and create-once ownership.

## Worked sources and OIDC combination

Place these complete values under separate named `secret_sources` keys. They describe where to obtain the selected credentials or files without including their contents.

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

A file-only role cannot use the environment form. **Invalid variation:** add `workflow_secret` to the file source. That key is accepted only for environment sources. The source reader does not inspect the actual file's permissions, Unix owner or contents.

This complete OIDC provider value requires `domains.login` in the same site. A matching app policy still needs its own client ID/secret source and owned origin; this object does not provision an IdP application.

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

**Invalid variation:** replace RS256 with HS256, or add a query to `issuer_path`. Validation rejects both changes. Later deployments may change supported public provider metadata, but renaming a source ID cannot remove or replace a sealed private role's credentials.

[Reference index](README.md) · [Lifecycle](lifecycle.md) · [Policies](policies.md)
