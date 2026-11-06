# Exposures

An exposure names a DNS record or an HTTPS frontend route.
Site `exposures.<id>` is inline or a complete `kind: exposure` [source](sources.md).
The `type` discriminator selects a closed DNS or HTTP branch. Required fields
have no defaults; omitted optional lists are empty, while null does not stand
for an omitted value. The following field paths are relative to the exposure.

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

Every selected domain must exist. Main/alias domain IDs and their case-folded
hostnames are globally unique among exposures. A DNS target needs an address and
cannot be an internal service. Managed Pi-hole records require IPv4.
HTTP app backends cannot use loopback. The selected ingress must be Traefik;
dashboard exposure must use the same Traefik instance with dashboard enabled
and a forward-auth middleware. TLS policies currently use the implemented ACME
resolver contract; Traefik requires resolver `letsencrypt`.

## Public origin

App `origin: {exposure: id, domain?: id}` selects a public HTTPS origin from
one of its own HTTP exposures. Optional domain selects its main/alias ID.
The derived URL includes a nonstandard ingress port. It does not copy an
unrelated route's origin. Authentication binders require this owned origin.

## Worked exposure

The complete [relationship example](../examples/relationships/README.md) supplies
`apps.browser`, `apps.ingress`, `domains.browser` and `policies.tls.public`.
Its [site.yaml](../examples/relationships/site.yaml) uses this exact exposure
body plus the explicitly declared middleware combination explained below.

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

This complete leaf requires the `browser` web and `ingress` HTTPS endpoints,
`domains.browser` and TLS policy `public: {type: acme, resolver: letsencrypt}`.
It creates no readiness or general firewall rule. Combine it with named
`default-headers` and `ip-allow-list` middleware values by adding
`middlewares: [headers, office_only]` after declaring both policies. Main/alias
hosts belong to this one exposure, so an app may select its origin.
**Invalid variation:** repeat `browser` in `aliases`, or select a missing TLS
policy. Both refuse in the real exposure binder; a domain alone does not make
a valid public route.

## First installation

An exposure emits desired publication inputs for its selected DNS/ingress owner.
The actual Pi-hole/Traefik and backend must have their own supported installation,
trust and authentication prerequisites. An HTTP exposure does not itself create
a managed DNS record when `resolver` is omitted. A compiled route is not evidence
that DNS, ACME, TLS or authentication works; follow
[preparation](../guides/prepare-deployment.md) and [service verification](../operations/verify-and-maintain.md#service-verification).

<a id="updates-and-dns-retirement"></a>
## Later deployments and DNS retirement

Changing hosts changes the owned route/record selection and may change public
origins, callbacks and authentication requirements. Managed Pi-hole DNS
retirement derives the previous selection from genuine prior ordinary receipt
and sealed app payload. It removes only an omitted previously owned name with
the exact previous native value. A conflicting/ambiguous value refuses; unrelated
aliases/order remain. Same-source repeats reuse immutable DNS input, while later
source generations advance the previous selection. No authored retired-host
list or generic DNS prune exists.

Unselected Compose services or private data are not deleted by removing an
exposure. Validate the source, review the affected app changes and verify DNS,
TLS, backend health and login separately after authorised CD.

The [exposure binder](../../blueprints/component_exposures.py) owns name, ingress,
transport and origin relationships. [Reference examples](../../blueprints/test_component_reference_examples.py)
exercise the exact route fragment within the complete composition and intended
alias/TLS refusals; no public endpoint is contacted.

[Reference index](README.md) · [Policies](policies.md)
