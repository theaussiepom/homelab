# Existing Authentik callbacks

Routing declarations use [exposures](reference/exposures.md) and typed [forward-auth middleware](reference/policies.md#middlewares), rather than arbitrary route or Traefik settings. The middleware endpoint binds the existing outpost. The selected adapter still controls how those routes are generated.

Authentik's separate callback additions use [callbacks.evidence](reference/app-properties.md#authentik-and-zabbix), whose [records](reference/supporting-types.md#evidence-and-assets) accept only the defined fields for existing provider, application and policy metadata, exact redirects and the fixed /oauth2/callback additions. Execution still checks the existing metadata. These additions do not provision new identity-provider (IdP) accounts, applications, providers or outposts.

Keep the existing ownership of route hosts, backends and middleware. Verify real browser login and callback behavior separately from source checks and synthetic routing tests. The source does not accept arbitrary overrides for callbacks, priorities or TLS.

[Documentation index](README.md)
