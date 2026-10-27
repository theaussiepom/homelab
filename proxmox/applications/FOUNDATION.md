# HTTPS, sign-in and database administration

[Back to the application guide](README.md)

This stage adds three small guests after DNS and PostgreSQL are working:
**Traefik** provides HTTPS, **Authentik** provides sign-in, and **pgAdmin** gives
you a web interface for PostgreSQL. You review the private deployment settings
and merge them; GitHub then creates and configures the selected guests.

You do not need to create empty containers in Proxmox or paste settings into
individual Docker containers. The same OpenTofu and Ansible installer handles
each guest. Existing databases are restored separately; this stage does not
restore or replace PostgreSQL.

```mermaid
flowchart LR
  B[Bootstrap: declared guest access] --> D[DNS]
  D --> T[Traefik]
  D --> P[PostgreSQL]
  T --> A[Authentik]
  P --> A
  A --> G[pgAdmin]
  T --> G
```

## What you prepare

Keep site settings in your **private deployment repository**:

- One `foundation/site.json`, copied from the public
  [site example](examples/foundation.site.example.json): your addresses, guest
  IDs, DNS names, NAS path, public SSH key and selected capture hashes.
- One `foundation/source.json` with the exact reviewed public implementation
  commit. Keep already commissioned DNS/database source locks unchanged.
- A coherent copy of Authentik's media/templates/certificates and its selected
  Redis state, plus a separate restore of its PostgreSQL database. Retain the
  original Authentik secret key; changing it can make restored credentials unusable.
- A consistent pgAdmin profile backup. Use SQLite's online backup facility;
  copying a live database and its journal separately is not a consistent backup.
- A private GitHub Environment with the existing Authentik key/database password,
  pgAdmin OAuth client secret and a Cloudflare DNS token restricted to the
  intended zone. Any required SMTP password is another Secret.
- NAS recovery copies and a reviewed, unused guest identity for each new guest.

Keep the same application versions for this migration. Upgrading them is a
separate change. If pgAdmin's saved profile is present, its pinned image can
start without inventing another local administrator password.

## One place to enter your settings

The public `homelab` repository contains the profile structure, resource and image
pins, validation, firewall/route generation, and deployment/DNS helpers. Your
private repository contains the actual site settings and the Actions graph.
Passwords stay in GitHub Secrets; do not put them in the site file.

Enter each address once. For example, changing the proxy's frontend address
updates its listener, firewall destinations, HTTPS checks and selected DNS
answers together. Changing a guest ID updates its bootstrap grant, rollout
policy and discovery identity. IDs are stable inventory labels; they do not
select a VLAN or control startup order.

To preview the generated files without contacting Proxmox, run this using your
checked-out public implementation (Python 3 only):

```sh
python3 public-source/proxmox/applications/site_config.py \
  --config foundation/site.json --output /tmp/my-foundation-preview
```

Use a new output directory each time. Read `bootstrap.json`, the guest
`site.json`/`stack.json` pairs and `dns-settings.json` before merging. They are
generated inputs, so edit the original site file rather than these previews.
The renderer rejects missing fields, duplicate identities, overlapping networks
and addresses outside their declared subnet. It does not verify live availability.

The selected profiles use unprivileged Debian LXCs with Docker Compose for the
three applications. Existing state/input files are never rewritten by this
preview, and no guest is created until the reviewed CD workflow runs.

## How addresses become HTTPS routes

The selected **NX211 Proxmox provider** reads Traefik labels from guests' Proxmox
Notes. Private profiles declare only a route name, hostname and explicit backend
HTTP address. The installer turns those into Notes during guest creation.

For example, an identity guest might declare:

```json
"discovery_routes": [
  {"name": "identity", "host": "sso.example.net", "url": "http://10.77.30.20:9000"}
]
```

The backend must be a private IPv4 address on that guest. This avoids guessing
which of a guest's network interfaces should serve the application. The provider
is pinned to `v0.7.0`; the installer emits `key: value` Notes because that
version's parser can misread an equals-form URL containing a colon.
The catalog ZIP is also pinned by its SHA256 archive hash, independently
matched to tested commit `e35cce5af139328b8e424836a0b32638ed777016`. Traefik refuses
to start if the archive changes or the required plugin cannot load.

Shared HTTPS settings live in freshly generated Traefik configuration. No Docker
socket or old collection of routing files is copied across. Authentik and
pgAdmin use their own sign-in; they do not receive a second forward-auth layer.

The ingress `foundation` settings must also list the recursive DNS servers its
firewall allows, including port 53, for example
`"acme_dns_resolvers": ["198.18.40.2:53", "198.18.100.4:53"]`.
For certificate creation and renewal, Traefik checks the challenge TXT record at
every listed resolver. It avoids direct queries to external authoritative DNS
servers, which the restricted guest firewall blocks. These resolvers must be
able to retrieve public TXT records; ordinary certificate and Proxmox TLS
verification remain enabled. See the [Traefik DNS propagation settings](https://doc.traefik.io/traefik/v3.7/reference/install-configuration/tls/certificate-resolvers/acme/).

The provider has its own read-only Proxmox token. Bootstrap CD creates it for
only the declared node/guest scopes, verifies TLS using the host CA, saves the
credential privately on the runner and NAS, and admits only the proxy's address
to the host API. Review that new access in
[service discovery access](../bootstrap/SERVICE-DISCOVERY.md) before deployment.

## Replies use the frontend network

Traefik has management, private backend and client-facing interfaces. HTTPS
replies from its frontend address must return through that network's gateway;
otherwise a reply to a management client can bypass the router that handled the
request. Enter the frontend gateway in the single site file as well.

Ansible installs a small routing service inside the ingress guest, before Docker
starts. It manages only table/rule10040 for the frontend's own source address.
The management default route and direct backend routes stay in place. Unexpected
existing policy is refused, and verification reads the policy back without
changing it. Other guests do not receive this service.

The isolated routing fixture checks verified HTTPS from a management client and
a guest with both management and backend interfaces through a stateful router.
It also checks repeat runs, fresh kernel-state setup and preservation of foreign
policy. This is source confidence; the real UDM/PVE path and physical reboot are
still checked during the selected native deployment.

## Where passwords go

The optional `foundation` stack settings contain **file paths**, not passwords.
CD takes values from GitHub Secrets and writes private runner inputs. Ansible
installs read-only files owned by the application user inside the new guest.
Authentik reads `file://` references; pgAdmin reads its generated `config_local.py`;
Traefik receives a private provider configuration and DNS-token file.

Compose files and Proxmox Notes contain no secret values. Keep logs, state,
captures and generated runtime files private too. GitHub masks known Secrets,
but that does not make arbitrary diagnostic output safe to publish.

## What happens on merge

The public foundation adapter plans once, checks that the plan creates only the
selected new guest and its two firewall resources, and deploys **that same saved
plan**. The reviewed merge authorizes this narrow creation policy. Updates,
imports, replacements and adoption of an existing guest are refused.

A completed repeat verifies the existing guest and unchanged inputs; it does
not reinstall, restore or restart the application. A failed or interrupted
rollout keeps its receipts and hold. A later job cannot silently retry it.

The new foundation and bootstrap jobs share one immutable foundation source lock.
Do not change the source pin or saved input files of already commissioned
DNS/database guests just to deploy these services.

The selected internal DNS records should point to the proxy before application
checks run. Router/firewall/WAN forwarding and browser sign-in are separate
acceptance checks; a passing synthetic test does not establish those live paths.

## What has been tested

Source tests cover configuration, private-file permissions, route generation,
plan admission and stopped/failed rollouts. A real pinned Traefik/provider Docker
fixture discovers synthetic LXC Notes over HTTPS, rejects an unrelated CA and
routes to explicit backend addresses. It does not create a real Proxmox guest or
prove a household login.

A native deployment still has to prove creation, nested Docker startup, real
certificate issuance, database connectivity and the new URLs. Complete those
checks on the selected host before describing the migration as successful.
