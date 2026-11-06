# Existing Authentik callbacks

Current authored routing uses [exposures](reference/exposures.md) and typed
[forward-auth middleware](reference/policies.md#middlewares), not raw route or
Traefik configuration bags. The middleware endpoint binds the existing outpost.
Selected routing remains owned by the fixed adapter.

Authentik's separate callback additions use
[callbacks.evidence](reference/app-properties.md#authentik-and-zabbix), whose
[closed records](reference/supporting-types.md#evidence-and-assets) bind existing
provider/application/policy metadata, exact redirects and the fixed
/oauth2/callback additions. Existing metadata guards still apply at execution.
It does not provision new IdP accounts/applications/providers/outposts.

Preserve normal route host/backend/middleware ownership and verify real browser
login/callback behavior separately from source and synthetic routing fixtures.
Opaque callback/priority/TLS overrides are not accepted source properties.

[Documentation index](README.md)
