# Check configured web routes during deployment

Select `guests.<id>.route_checks` to verify every guest-backed HTTP exposure owned by that guest, including aliases. The compiler derives DNS, ingress and managed identity-provider prerequisites from those declarations. Inline selection adds explicit guest deployment waits; deferred selection adds those waits only to the separate check job. An ordinary exposure or connection reference alone does not. External-service exposures remain outside this feature.

The checks query the exposure's configured Pi-hole resolver for the exact ingress address, then use the hostname for TLS certificate verification, SNI and HTTP Host. They bind the declared source address. They use neither a resolver override nor insecure TLS, browser cookies or application credentials. A page check requires an expected response marker; an authentication check requires a redirect to the configured provider origin. A successful redirect does not prove user sign-in or authorization.

## Guest selection

Paths in this table are relative to `guests.<id>.route_checks`. The object is optional and closed. Omission leaves the guest's existing local checks and deployment dependencies unchanged. Null is refused. Selecting it requires at least one guest-backed HTTP exposure, a managed resolver on every selected route, and existing network and middleware permission for the chosen source.

| Field | Type and default | Effect |
| --- | --- | --- |
| `mode` | Required `inline` or `deferred` | Inline runs on the guest before its final ordinary phase completes. Deferred selects the owner for one final Check web endpoints job. |
| `source` | Required closed object | Selects one explicit check source; no automatic fallback or policy grant. |
| `source.interface` | Required guest interface ID for inline mode | Uses that interface's resolved IPv4 address for HTTPS. DNS uses the guest's existing connected/default route source. Deferred mode refuses this field. |
| `source.address_group` | Required address-group ID for deferred mode | Must resolve to exactly one IPv4 `/32` on the deployment controller. Used for both HTTPS and DNS. Inline mode refuses this field. |
| `name` | Required nonempty workflow label for deferred mode | Endpoint-group report label in the final check job; expressions/control characters are refused. Inline mode refuses this field. |

An inline guest job waits for its existing app prerequisites plus the selected DNS, ingress and managed provider guests. Self-edges are removed; cycles refuse. A deferred guest retains only its existing declared app and preparation prerequisites. One final Check web endpoints job waits until all enabled guest jobs have finished, then checks each eligible owner independently. That owner's required DNS, ingress and managed-provider jobs must also have succeeded. No guest waits for the final check job. Deferral is explicit; the compiler never moves checks into another app's job or silently drops a dependency.

To let guests deploy independently of DNS and ingress startup, select deferral on each routed guest and supply independently usable startup resolvers through the ordinary [guest DNS setting](guests.md), with the exact TCP/UDP DNS grants on the selected interfaces. Remove a declared readiness edge only after checking that setup and local health do not actually contact that producer. Database and broker connections that setup uses still need their explicit readiness. Deferred FQDN checks continue querying the exposure's configured Pi-hole resolver, regardless of the operating-system startup resolvers. This feature does not change resolver configuration or firewall policy itself.

## HTTP exposure expectation

Paths below are relative to `exposures.<id>.check`. This closed object is optional on HTTP exposures and refused on DNS exposures. It requires a target guest that selected route checks. A selected forward-auth route can omit it only when its single managed provider has one unambiguous published HTTP exposure; then the expected provider redirect is derived. Other selected routes require an explicit expectation.

| Field | Type and default | Effect |
| --- | --- | --- |
| `type` | Required `page` or `auth-redirect` | Selects the response contract. |
| `path` | Optional absolute path, `/` | At most 1,024 characters; no query, fragment, escapes, control characters, dot segments or scheme-relative path. |
| `contains` | Required nonempty text for page mode | At most 256 characters without control characters; requires HTTP 200 and this text within the inspected response prefix, case-insensitively. Refused for auth-redirect. |
| `provider` | Required for auth-redirect, optional for page | Existing [origin reference](identity-and-secrets.md#identity-providers): `{exposure: id, domain?: id}` or `{domain: id}`. A managed exposure supplies its actual guest prerequisite. A domain-only external origin adds no guest job. A page can declare its provider dependency while checking its local sign-in page. |

All hostnames and aliases of the selected route are checked. Redirects may remain within that route's declared origins, or terminate at the declared provider for auth-redirect mode. A foreign origin, downgrade to HTTP, credentials in a URL, loop, missing marker, unexpected status, wrong DNS answer or invalid TLS certificate fails. There are at most eight redirect hops. Inline checks retain one shared 600-second retry budget per guest. In the final deferred job, each endpoint gets 600 seconds from its worker start, with eight shared probe workers and at most 256 selected endpoints across the composition. The generated job budget is ten minutes plus ten minutes per batch of eight endpoints, at most 330 minutes.

Each response is inspected through a prefix of at most one MiB. The reader requests at most one additional sentinel byte to distinguish a complete body from a truncated prefix, then closes the connection. A larger response can pass a page check only when HTTP 200 and the actual required marker are present within that prefix. A marker absent from the prefix, including one located only beyond the budget, fails as `marker_missing`; the total response size is not measured. UTF-8 decoding retains replacement of malformed bytes while withholding an incomplete character cut by the inspection boundary. The separate one-MiB limit on command JSON inputs is unchanged. These limits apply to first and later deployments alike.

Authentication redirect checks request `text/html`, matching a browser login entry rather than negotiating a JSON API response. Page checks continue to request `text/html,application/json`. An HTTP 401 response does not satisfy an authentication redirect check; it must redirect to the declared provider. The request profile adds no cookies or application credentials and does not change the allowed origins.

## First installation and later deployments

For a native PegaProx client, select `oidc: true` on the canonical exposure's page check. The guest must select deferred checks and the issuer must reference a managed HTTPS exposure. The compiler derives the public client ID, callback, issuer, endpoints and allowed signing algorithms from the app's authentication binding. Disabling the client omits the sign-in probe. On first installation and subsequent deployments, the guest saves and reads back its local settings even if the issuer is offline.

A retained Node-RED editor can select the same deferred check on its canonical page exposure. Select the standard OIDC provider with the editor's native endpoint paths. The check requests `/auth/strategy` and verifies the redirect includes the canonical `/auth/strategy/callback/`, including its trailing slash. The editor guest keeps its existing deployment dependencies. [Node-RED provider](identity-and-secrets.md#existing-node-red-oidc-strategy)

The existing final job reports the page and native sign-in separately. The sign-in probe verifies the issuer's discovery document through its declared DNS and ingress, then requests the app's login route. It checks the authorization endpoint and exactly one matching client ID and callback in the redirect. No browser session, password, MFA or token exchange is involved.

Use the [complete synthetic configuration](../examples/route-checks/README.md) to inspect the accepted source and packet. Both installation and later deployments use the same declaration. The selected source must already permit the DNS/HTTPS paths and middleware source; compilation refuses absent guest grants and does not widen access. Controller egress, physical routing, DNS service readiness, public certificates and actual responses still require target evidence.

Inline checks execute through the existing admitted Ansible transport after local phases, before the ordinary success is recorded. Their failure preserves the ordinary hold and evidence. Local app, socket, integration, monitoring and backup checks remain. Only CloudBeaver's former direct HTTPS redirect check and Music Assistant's former direct HTTPS `/info` check are superseded when those apps have configured routed verification.

When the retry budget expires, the existing private `checks.log` retains one JSON diagnostic for the failing endpoint: its zero-based selection index, exposure ID, attempt count, last failed stage and fixed cause code, with an HTTP status when available. Stages distinguish DNS, connection, TLS, HTTP, redirect and response expectations. Exception messages, URLs, headers and response bodies are excluded. Earlier attempts do not produce diagnostic output. Invalid input or an unexpected internal failure retains the generic failure message. These diagnostics identify the last observed failure; a connection timeout alone does not identify a firewall rule or dropping hop.

The final deferred job uses an explicitly selected common controller Environment and requests no GitHub application, PBS, provider-token or SSH-key values. It uses the already protected controller input publication. For every owner it calls the same ordinary runtime admission: exact current run/source/static input binding, genuine ordinary success, unchanged backend and existing custody locks. The database-network lock remains shared and each guest's workflow/deployment locks remain exclusive. A failed unrelated guest does not prevent other eligible owners from being admitted.

The job runs under the protected-main predicate with `always()` and `!cancelled()`. Every selected endpoint and alias gets a passed, failed or blocked result. Failed/skipped/missing required jobs and refused runtime admission produce blocked results; any failed or blocked endpoint fails the final job. Probe failures do not cancel other eligible probes. Reports contain configured guest/exposure/hostname identities and fixed cause/status fields, without response bodies, headers, cookies, secret values or exception messages.

Deferred checks write separate `http-checks-<run>-<attempt>` evidence. They do not modify backend state or canonical receipts. Failed or repeated check evidence is preserved; no automatic replay or cleanup is introduced. Guest-owned backup enrollment and ordinary success remain independent of the final web result. A successful workflow requires both the guest jobs and final checks; a local ordinary receipt alone is not web acceptance. Login and application/device functions still need separate acceptance.

[Guest reference](guests.md) · [Exposures](exposures.md) · [Deployment](../operations/deployment.md)
