# Exposures

An exposure names a DNS record or an HTTPS frontend route.
Site `exposures.<id>` is inline or a complete `kind: exposure` source.

| Field | DNS exposure | HTTP exposure |
| --- | --- | --- |
| type | Required `dns` | Required `http` |
| endpoint | Required app/external socket reference | Required HTTP/HTTPS app/external or authenticated internal dashboard endpoint |
| domain | Required site domain ID | Required site domain ID |
| aliases | Optional unique domain-ID list, [] | Same |
| resolver | Required Pi-hole app ID | Optional Pi-hole app ID; omission does not publish managed DNS |
| ingress | Not accepted | Required Traefik app HTTPS endpoint |
| tls | Not accepted | Required TLS policy ID |
| middlewares | Not accepted | Optional ordered unique middleware-ID list, [] |
| transport | Not accepted | Optional backend transport-policy ID, only for HTTPS backend |

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

## Example fragment

```yaml
schema: homelab-components-v1
kind: exposure
type: http
endpoint: {app: browser, endpoint: web}
domain: browser
ingress: {app: ingress, endpoint: https}
tls: public
middlewares: [headers, office_only]
```

This complete leaf requires declared app endpoints, domain and policies in its
own site/library. It creates no readiness or general firewall rule.

## Updates and DNS retirement

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

[Reference index](README.md) · [Policies](policies.md)
