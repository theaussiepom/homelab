# Native PegaProx OIDC

This `homelab-components-v1` authentication policy configures an existing PegaProx installation through its server-settings API. Select it at `apps.<id>.authentication`; declare it at `policies.authentication.<id>`. The compiler resolves references without opening credentials or contacting the identity provider. The adapter applies the resolved settings after the selected service starts.

[Policy reference](policies.md#authentication-policies) · [Providers and secrets](identity-and-secrets.md) · [Application bindings](apps.md)

## Syntax and properties

This complete policy value needs the referenced OIDC provider, secret sources and an HTTPS app origin in its containing site:

```yaml
type: pegaprox-oidc
provider: management_identity
client_id: management-ui
client_secret: management_client_secret
management_token: management_api_token
display_name: Sign in with Identity
user_claim: preferred_username
enabled: true
allow_private_ip: true
group_mappings:
- group_id: Management administrators
  role: admin
```

Every field below is required; omission, null and unknown keys are rejected. There is no inheritance or arbitrary settings passthrough. See the library's [complete edge/manager example](https://github.com/theaussiepom/homelab-stack/blob/main/examples/catalogue/edge-management.yaml) for the containing composition; that moving example must be used with the framework revision selected by its library.

| Field | Type, domain and effect |
| --- | --- |
| <a id="type"></a>`type` | Literal `pegaprox-oidc`; only the `pegaprox` adapter accepts it. |
| <a id="provider"></a>`provider` | Existing OIDC provider ID. Its HTTPS issuer and four endpoints become the expected discovery metadata. Discovery must return the same issuer/endpoints and advertise the declared asymmetric algorithms. |
| <a id="client-id"></a>`client_id` | Nonempty string, at most 256 characters, no surrounding whitespace or control characters. Selects the existing confidential OIDC client. |
| <a id="client-secret"></a>`client_secret` | Existing file or environment secret-source ID. The deployment receives the actual scalar separately from public compilation. It must differ from `management_token`. |
| <a id="management-token"></a>`management_token` | Separate file or environment secret-source ID holding a PegaProx `pgx_` API token with `admin.settings`. It is used only for the container's loopback API. Provision the token before selecting this policy. |
| <a id="display-name"></a>`display_name` | Nonempty string, at most 256 characters, no surrounding whitespace or control characters. Sets the native sign-in button text. |
| <a id="user-claim"></a>`user_claim` | `preferred_username`, `email` or `upn`. Selects the username claim from the verified identity response. A matching existing local/LDAP username is not adopted. |
| <a id="enabled"></a>`enabled` | Boolean. `false` disables the OIDC button while retaining managed settings and protected input ownership; discovery need not be reachable when disabling. |
| <a id="allow-private-ip"></a>`allow_private_ip` | Boolean selecting PegaProx's explicit private-address IdP allowance. It does not disable TLS certificate or hostname verification. |
| <a id="group-mappings"></a>`group_mappings` | List of 1–32 closed objects with exactly `group_id` and `role`. Declaration order is preserved. |
| <a id="group-id"></a>`group_mappings[].group_id` | Nonempty string of at most 256 characters, no surrounding whitespace/control characters, unique ignoring case. Match the identity provider's signed group claim. |
| <a id="role"></a>`group_mappings[].role` | `admin`, `user` or `viewer`. The fallback role is always `viewer`; new OIDC users may be created by PegaProx. Restrict application admission at the IdP separately. |

Both private scalars must be nonempty UTF-8, at most 64 KiB, with no surrounding whitespace or control characters; the masked value `********` is not a client secret. Runtime validation also rejects using the same value for both credentials. The database key remains opaque bytes under its existing parity guard.

### Optional Authentik registration

`registration` makes the Authentik guest the owner of the confidential client, application and group admission binding. Omit it to keep an externally managed registration. The provider origin must reference the exposure of the selected Authentik app. Select matching server and worker images tagged 2026.8.6 or newer for this integration. Configure the client's secret source in both protected environments. Only PegaProx receives the separate management token.

| Field in `registration` | Meaning |
| --- | --- |
| `slug` | Stable application identifier matching the provider's per-application issuer path. |
| `provider_name` | Display name of the OAuth2 provider keyed by the existing client ID. |
| `admission_group` | Group allowed into the application. Existing members are preserved. A new group starts empty. |
| `signing_key` | Name of an existing Authentik certificate and key pair. |
| `authentication_flow`, `authorization_flow`, `invalidation_flow` | Slugs of existing Authentik flows used by the provider. |

The following value belongs under the native client's authentication policy. The application display name and strict callback come from the app. Each selected registration has a separate scalar secret input, up to eight per Identity app in the reusable workflow.

```yaml
registration:
  slug: management-ui
  provider_name: Management console
  admission_group: Console users
  signing_key: authentik Self-signed Certificate
  authentication_flow: default-authentication-flow
  authorization_flow: default-provider-authorization-implicit-consent
  invalidation_flow: default-provider-invalidation-flow
```

CI generates native YAML with a secret-file reference. The worker reads the mounted file, applies the blueprint through its native task and checks the SHA-512 hash and registration state. On first adoption the existing client, application, access binding, scopes, key, flows and credential must match the declaration. For an upgraded provider whose stored callback omits the URI type, the worker also checks that Authentik resolves it to the single declared strict authorization callback. An unexpected binding refuses the import. Reapplying a matching registration preserves the native identifiers. A failed or timed-out worker causes the Identity phase to fail. Removing its declaration leaves existing Authentik objects in the database. Select the canonical exposure's deferred OIDC check to verify the client after the guest jobs finish. [Routed checks](routed-checks.md)

## Resolution and deployment

The callback is always the app's HTTPS origin plus `/oidc/callback`. The native provider is `generic`, scopes are `openid profile email`, additional audiences are empty, and TLS/JWT skip switches are always false. Legacy built-in group mappings are cleared in favour of the declared list. Local login remains available. The native sign-in button starts the flow. The optional registration controls the Authentik application.

An optional HTTPS connection can supply an explicit hostname-to-endpoint alias through the existing connection component. Network policy and routing must permit that connection. A hostname reference alone creates neither a firewall allowance nor a deployment dependency.

The adapter materializes `pegaprox-oidc.json` as root-owned mode 0600 in the app's reserved runtime directory. It includes the two credentials and is not mounted into the service. The installed helper sends it on stdin to a fixed client inside the selected Compose service. Credentials never enter command arguments or public output. The settings helper uses the loopback API on `http://127.0.0.1:5000`. Selecting the deferred OIDC check sends discovery to the final web job. Other declarations retain the existing verified HTTPS preflight. Responses are bounded to 1 MiB and individual requests to 20 seconds.

Only differing declared OIDC settings are posted. PegaProx masks the client secret on reads, so the adapter reserves a separate root-owned `pegaprox-oidc-applied.json` success record containing a configuration fingerprint and selected service identity. It writes this atomically only after API readback and the public initialized/login state agree. A failed request leaves the prior record intact. Repeating the same successfully applied input does not rewrite the secret. The record is not copied from the controller or overwritten during runtime-file installation.

This record cannot detect an out-of-band replacement of a nonempty masked secret. Keep CD as the settings owner. Preserve malformed, foreign or pending records for investigation rather than deleting them to force a retry. Ordinary deployment also preserves sealed private-role material: it does not rotate either credential or remove its continuity evidence.

## First selection and later changes

Use an initialized, already managed installation, its original database key and a distinct local recovery administrator. Configure the confidential IdP client, strict callback, asymmetric signing key, group claim and admission binding first. Register a PegaProx management token with a role limited to `admin.settings`; the OIDC client secret is not that token. Preserve independently recoverable configuration and key material before a software change.

Qualify and deploy the selected image before first enabling this policy. When moving from an older image, complete an image-only deployment first and verify its ordinary success, then enable OIDC in a second deployment. The previous accepted image must already support the required token checks: the generic CD rollback restores managed files/services but does not undo settings stored through this API in the application database. A failed settings change needs explicit settings readback and, if necessary, a reviewed corrective deployment.

Qualify the selected image against native token verification. The initial integration uses PegaProx 1.5.0, whose token validation rejects invalid signatures/claims rather than the older permissive failure path. PegaProx 1.5.0 still has a TLS token-response fallback when signing keys cannot be obtained; setting the skip switches to false does not remove that upstream fallback. The adapter does not make an older image safe merely by setting skip switches to false. See the upstream [OIDC implementation](https://github.com/PegaProx/project-pegaprox/blob/v1.5.0/pegaprox/utils/oidc.py) and [upgrade guidance](https://docs.pegaprox.com/getting-started/upgrade-1.5/).

Changing public policy values updates only the named OIDC settings. Removing the policy is not a supported credential-retirement operation; use `enabled: false` for a reviewed disable. Deployment failures keep the normal CD hold/evidence. Existing data, account passwords and cluster credentials remain outside this reconciler.

## Verification and diagnostics

`component.authentication` rejects unsupported types, claims, groups, secrets or unsafe values. For example, `user_claim: sub` is invalid for this adapter; select one of its three documented username claims. Unknown fields such as `skip_ssl_verify` are rejected rather than forwarded.

Compiler tests cover accepted policies, references, strict refusal and private input selection. Runtime tests cover repeat application, public-setting drift, failed writes/readback, private-file custody and preservation of unrelated settings. These checks do not prove a user's browser login. After protected CD, verify the native button, Authentik authentication/MFA, intended role, excluded-user rejection and local recovery login in the target environment.
