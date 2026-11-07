# Exposures

An exposure declares a DNS record or an HTTPS frontend route. Declare it inline at `exposures.<id>` in your site or in a complete `kind: exposure` [source file](sources.md). Its `type` selects the DNS or HTTP fields shown below; other fields are rejected. Required fields have no defaults. Omitted optional lists are empty, but null is not equivalent to omission. The table paths are relative to the exposure.

| Field | DNS exposure | HTTP exposure |
| --- | --- | --- |
| <a id="exposure-type"></a>`type` | Required `dns` | Required `http` |
| <a id="exposure-endpoint"></a>`endpoint` | Required app/external socket reference | Required HTTP/HTTPS app/external or authenticated internal dashboard endpoint |
| <a id="exposure-domain"></a>`domain` | Required site domain ID | Required site domain ID |
| <a id="exposure-aliases"></a>`aliases` | Optional unique domain-ID list, [] | Same |
| <a id="exposure-resolver"></a>`resolver` | Required Pi-hole app ID | Optional Pi-hole app ID; omission does not publish managed DNS |
| <a id="exposure-ingress"></a>`ingress` | Not accepted | Required Traefik app HTTPS endpoint |
| <a id="exposure-tls"></a>`tls` | Not accepted | Required TLS policy ID |
| <a id="exposure-middlewares"></a>`middlewares` | Not accepted | Optional ordered unique middleware-ID list, [] |
| <a id="exposure-transport"></a>`transport` | Not accepted | Optional backend transport-policy ID, only for HTTPS backend |

Every selected domain must exist. Main/alias domain IDs and their case-folded hostnames are globally unique among exposures. A DNS target needs an address and cannot be an internal service. Managed Pi-hole records require IPv4. HTTP app backends cannot use loopback. The selected ingress must be Traefik; dashboard exposure must use the same Traefik instance with dashboard enabled and a forward-auth middleware. TLS policies currently use the implemented ACME resolver contract; Traefik requires resolver `letsencrypt`.

## Public origin

An app uses `origin: {exposure: id, domain?: id}` to select the public HTTPS origin of one of its own HTTP exposures. The optional domain chooses the main domain or an alias. The generated URL includes the ingress port when it is nonstandard. The app cannot use an unrelated route's origin; authentication checks require an origin belonging to that app.

## Worked exposure

The complete [relationship example](../examples/relationships/README.md) supplies `apps.browser`, `apps.ingress`, `domains.browser` and `policies.tls.public`. Its [site.yaml](../examples/relationships/site.yaml) uses this exact exposure body plus the explicitly declared middleware combination explained below.

<!-- example: exposure-http -->
```yaml
schema: homelab-components-v1
kind: exposure
type: http
endpoint: {app: browser, endpoint: web}
domain: browser
ingress: {app: ingress, endpoint: https}
tls: public
```

This complete source file requires the `browser` web and `ingress` HTTPS endpoints, `domains.browser` and TLS policy `public: {type: acme, resolver: letsencrypt}`. It does not add readiness dependencies or general firewall rules. To use named `default-headers` and `ip-allow-list` middleware, declare both policies and add `middlewares: [headers, office_only]`. The main and alias hostnames belong to this exposure, allowing its app to select the corresponding origin.

**Invalid variation:** repeat `browser` in `aliases`, or select a missing TLS policy. The exposure binder rejects both; declaring a domain alone does not create a valid public route.

## First installation

The compiler turns an exposure into inputs for the selected DNS or ingress app. Pi-hole or Traefik, and the backend, must each meet their own installation, trust and authentication requirements. An HTTP exposure does not create a managed DNS record if you omit `resolver`. Compiling a route does not test DNS, ACME, TLS or authentication. Follow [preparation](../guides/prepare-deployment.md) and [service verification](../operations/verify-and-maintain.md#service-verification).

<a id="updates-and-dns-retirement"></a>
## Later deployments and DNS retirement

Changing hostnames changes the managed routes or records and may affect public origins, callbacks and authentication. To remove an old managed Pi-hole record, HomeLab reads the previous selection from the genuine prior ordinary receipt and sealed app payload. It removes a name only when the new configuration omits it and its current value exactly matches the previously managed value. A conflict or ambiguity stops the operation. Unrelated aliases and their order are preserved. Repeating the same source uses the same immutable DNS input; a later source generation updates the recorded previous selection. There is no user-written retired-host list or general DNS pruning operation.

Unselected Compose services or private data are not deleted by removing an exposure. Validate the source, review the affected app changes and verify DNS, TLS, backend health and login separately after authorised CD.

The [exposure binder](../../blueprints/component_exposures.py) checks name, ingress, transport and origin relationships. [Reference example tests](../../blueprints/test_component_reference_examples.py) check the exact route fragment within the complete configuration and reject the intended alias and TLS errors. They do not contact a public endpoint.

[Reference index](README.md) · [Policies](policies.md)
