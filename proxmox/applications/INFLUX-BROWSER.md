# Influx browser route preparation

The existing ingress can serve Influx through its watched file provider while
retaining Influx's own login. The optional typed `foundation.browser_route`
renderer and the separate `homelab-ingress-browser-update-v1` maintenance packet
produce the same namespaced HTTP objects. Existing commissioned inputs remain
unchanged; adding a route is a separate operation through `foundation_maintenance.py`.

The route uses the existing `websecure` entry point and `letsencrypt` resolver.
It has a direct socket-peer source allowlist, Authentik forward authentication,
and the scoped security-header policy including the UI's existing unsafe-eval
allowance. The same-host `/outpost.goauthentik.io/` callback goes to Authentik
without recursively applying forward authentication. Native Basic/Token
authorization and Influx session cookies continue to reach Influx. There is no
native OAuth conversion or additional Traefik plugin. The old Cloudflare
normalization plugin is not an IP allowlist; replacing it with a direct-peer
allowlist is an explicit access-policy decision.

`ingress_browser.validate()` accepts a closed settings object. The synthetic
test fixture is an example; deployment values belong in private source. It
requires a single literal hostname, credential-free private HTTP origins on
8086 and 9000, a distinct HTTPS identity issuer, the admitted proxy and frontend
addresses, explicit private source CIDRs and the header domain. Aliases and
arbitrary dynamic middleware definitions are excluded. Existing objects are
preserved. Reserved-name collisions, a router claiming the browser hostname,
or a nonliteral existing HTTP rule hold the update for review.

## Admission and execution

A route packet binds the immutable helper revision, original plan/completion,
current post-network state, unchanged Compose/static/image, exact shared-file
before/after hashes and two separately admitted evidence files. Both evidence
files must be private owned regular files beneath the selected guest's state.

* Network evidence is the existing `homelab-database-network-overlay-v1`
  completion, with the same guest and current state hash. The CD caller must
  run the existing exact network-overlay verification before invoking this
  maintenance path. A packet is not a manual-NIC prerequisite waiver.
* Policy evidence uses `homelab-influx-browser-policy-evidence-v1`, the same
  VMID and `route_sha256` (SHA256 of sorted, two-space-indented JSON plus a final
  newline). It requires true `provider_host_confirmed`,
  `outpost_membership_confirmed`, `access_policy_confirmed`,
  `issuer_alignment_confirmed`, and `direct_peer_allowlist_approved` fields.
  Its `cors_allow_origin` must match the selected route exactly, and
  `cors_wildcard_approved` must be true for `*` and false for the same HTTPS
  browser origin. A new route must select one of those two explicit CORS values.
  Produce this only after the restored configuration and the access decision
  are actually reviewed; retained snapshots alone do not establish them.

Controller locks, standard holds, immutable original installation bindings and
NAS custody surround the update. The original shared file reaches NAS and is
read back before any guest configuration write. The guest also retains its
original. The helper writes the existing bind-mounted inode, preserving its
UID, GID, mode and extended attributes. It never replaces the mount, modifies
static configuration, pulls an image, or restarts the container. It checks the
admitted client address and Influx health/setup first, then verifies the
browser hostname's TLS certificate against the selected frontend and observes
an anonymous SSO redirect. Container identity/start time must stay unchanged.

A failed attempt keeps its original and holds. Changing the source revision
does not grant another attempt. A later successful CD invocation must keep the
completed claim's exact revision selected: the checked-out HEAD must match it.
It verifies the same overlay and installed helper bytes without rewriting them.
A newer helper revision does not inherit verification authority. The original
installation renderer must not be replayed after maintenance; normal CD must
select the maintained state and its exact verification path.

## Accepted network baseline prerequisite

This route helper does not plan or apply a network. An ingress that already
has an accepted ACME firewall overlay cannot use the generic planner's original
guest baseline: that would refuse the existing DNS rules or propose removing
them. Before admitting its additive database NIC, the network source needs a
reviewed composition path shared by planning, saved-plan admission and later
overlay verification. It must:

1. Preserve the original installer, inputs, tfvars and installation receipts.
2. Bind the accepted ACME claim/completion, saved DNS plan, current state and
   matching NAS custody, deriving only its exact accepted DNS-rule append.
3. Compute the network candidate from that derived baseline, check the saved
   plan against it and retain the same baseline binding in apply/verify custody.
4. Reject missing/failed receipts, state drift, extra rule changes and altered
   guest identity before planning or applying. Keep provider lifecycle effects
   a separate explicit decision.
5. Retire old image/resolver/original-install verification paths from the
   selected network-overlay CD branch so they cannot reintroduce old state.

Until that composition path and its regression tests are qualified, the private
selector remains prepared/null and admits no native network or route phase.
Do not substitute current TCP silence or whole-ingress inactivity for route
absence. A future consumer admission needs a fresh scoped mounted-file and
discovery-rule inventory plus current connection evidence; the ingress remains
running for its other applications.

## Evidence limits

Unit tests cover closed policies, collision guards, actual file ownership and
inode preservation, unchanged static/Compose/container identity, custody,
failure holds and replay refusal. The pinned Traefik fixture proves watched-file
reload, source allow/deny with spoofed forwarded headers, SSO denial/callback,
native authorization/cookies and an unrelated route in an isolated namespace.
Its loopback origins and self-signed fixture TLS do not prove production SSO,
certificate issuance, network/firewall enforcement or browser login. Native
acceptance still needs the actual allowed/denied-source and SSO tests, native
Influx login, and a minimal authenticated query after separate admission.
