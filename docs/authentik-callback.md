# Existing Authentik forward-auth callbacks

A normal route can opt into the fixed callback needed by an existing Authentik
single-application provider. It must apply the same declared file middleware:

```json
{
  "host": "app.example.invalid",
  "target": {"endpoint": "example.app.ui"},
  "middlewares": ["security-headers", "authentik"],
  "authentik_forward_auth": "authentik"
}
```

The named middleware must define `forwardAuth.address` as a private HTTP(S)
origin followed by exactly `/outpost.goauthentik.io/auth/traefik`. The callback
backend is derived from that same origin; it is not a separate route URL input.
Custom forward-auth TLS overrides require separate review and are refused here.

The normal application's Host rule, priority 10, backend and middleware order
stay intact. The generated file-provider callback uses the same hosts/aliases
AND fixed ``PathPrefix(`/outpost.goauthentik.io/`)``, priority 15, `websecure` and
`letsencrypt`. It bypasses only the selected forward-auth middleware and keeps
the route's direct headers, IP allowlist, rate-limit and compression policies.
Additional auth, chains and opaque callback middleware are refused.

Managed application routes keep their ordinary discovery Notes and backend
ownership. The compiler derives their file-provider callback descriptions in
`routing.authentik_callbacks`; stack/profile inputs cannot supply that map.
External routes use the same typed intent and derive their callbacks directly.
Normal route hosts remain globally unique. Generated callback-name collisions,
raw rules, custom paths/priorities, unknown providers and unsafe origins fail
validation. Ordinary routes without this opt-in keep their previous output.

This renders routing for existing providers/outposts. It creates no Authentik
account, application, provider or outpost. Native callback/login acceptance is
separate from source and synthetic tests.

See the [official Authentik Traefik template](https://docs.goauthentik.io/add-secure-apps/providers/proxy/server_traefik/).
