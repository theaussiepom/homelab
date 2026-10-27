# Prepare internal administration routes

This is an **offline preparation tool**, not an installer or maintenance action.
It adds one or two explicit HTTPS backends to a copy of the existing Traefik
file-provider document. Hosts and appliances do not need invented guest labels.

Use the normal foundation PR, reviewed merge and automatic GitHub CD process
when a later maintenance action has been prepared and approved. This proposal
is deliberately rejected by the existing maintenance packet parser. It makes no
SSH, API, DNS or firewall calls, and does not change commissioned source pins.

## Inputs and preview

Keep real addresses, names, allowed client networks and trust material private.
The following example uses invented values:

```json
{
  "schema": "homelab-ingress-admin-routes-v1",
  "client_networks": ["10.15.0.0/24"],
  "routes": [{
    "name": "pve",
    "host": "proxmox.example.invalid",
    "url": "https://10.25.0.10:8006",
    "server_name": "pve.example.invalid",
    "root_cas": ["/etc/ssl/certs/homelab-pve.pem"]
  }]
}
```

`server_name` must match the backend certificate, independently of the browser
hostname. `root_cas` names public CA files already mounted in the container;
an empty list selects the normal system trust store. The tool does not read or
mount these files, and cannot establish that they exist or are suitable.
Never use a private key as a trust input or bypass certificate verification.

Obtain the **shared dynamic document only**, through the normal authorized read
path. Do not export static provider configuration, which can contain tokens.
Run locally against that saved JSON document:

```sh
python3 proxmox/applications/ingress_admin.py \
  --shared current-shared.json --settings admin-settings.json \
  --output admin-proposal.json
```

The new output contains the proposed document, before/after SHA-256 and
`deployable: false`. It never overwrites its inputs or an existing output.
Output permissions are owner-only. Static/provider documents are refused.
Existing TLS settings, middlewares and routes are preserved. Names or Host
rules that collide in this document stop preparation. Separately inspect
discovery-provider Host rules and aliases: the offline document cannot see them.
Do not feed the whole proposal wrapper to Traefik; `shared` is the document being
reviewed, and the after hash uses two-space JSON indentation plus a final newline.

## Access and authentication

Use an explicit administration client range. The generated IP allowlist uses
the directly connected peer address, with no forwarded-header IP strategy.
This assumes clients connect directly to Traefik. If a gateway proxies or NATs
requests, establish the real source boundary first; never allow a shared proxy
address merely to make a failing test pass. Internal DNS alone is not an access
control. Review IPv4/IPv6, WAN forwarding and any other listeners before admission.

The routes preserve the Host header and native application authentication/MFA.
They add no Authentik forward-auth gate or security-header policy that could
break the administrative frontend. Existing HTTP-to-HTTPS entrypoint redirects,
certificate resolver/store, discovery provider and other applications stay as-is.

## Backend and console expectations

Proxmox's [pveproxy documentation](https://github.com/proxmox/pve-docs/blob/master/pveproxy.adoc)
specifies HTTPS port 8006. It may serve a custom certificate or fall back to its
cluster-issued certificate. Check the certificate actually served and use its
matching SAN and trusted CA. A discovery API connection using an IP does not
prove the web frontend's requested SNI name or certificate chain.

Synology's [Login Portal documentation](https://kb.synology.com/en-br/DSM/help/DSM/AdminCenter/system_login_portal_dsm?version=7)
allows custom DSM HTTP/HTTPS ports. Read the actual secure listener; do not
assume 5001 or send an HTTPS backend to an old HTTP port. Test redirects without
following them first, including whether DSM emits a backend port or another
hostname. A redirect requiring a DSM setting change is a separate decision.

[Traefik supports WebSocket upgrades automatically](https://doc.traefik.io/traefik/master/expose/overview/#exposing-websocket-services).
No forced Connection/Upgrade/Origin override is needed. Its
[ServersTransport](https://doc.traefik.io/traefik/v3.7/reference/routing-configuration/http/load-balancing/serverstransport/)
selects SNI and trusted roots while keeping verification enabled. The fixture
tests backend trust rejection, Host/path preservation, redirects, a real
WebSocket 101 and a frame, and denial of spoofed forwarded client addresses.
It does not test real Proxmox noVNC, an authenticated shell, DSM sessions or MFA.
Proxmox's [node-console API source](https://github.com/proxmox/pve-manager/blob/master/PVE/API2/Nodes.pm)
defines `vncwebsocket` with a valid console ticket and `Sys.Console` permission.
Browser-console acceptance therefore needs native authentication and a real
console test; discovery-token success is insufficient. No direct VNC port range
or SPICE exposure is proposed by this HTTPS routing preparation.

## Entry criteria for an executable maintenance packet

1. Confirm names and admin client CIDRs. Inventory every selected DNS view and
   ensure the names reach the existing internal frontend, without public exposure.
2. Read the current shared document, static/Compose hashes and installed
   completion/state bindings through the normal path. Inspect discovery collisions.
3. Verify HTTPS from the Traefik guest to each exact backend, including SNI,
   SAN/expiry/chain and redirects. Any additional CA mount needs its own reviewed
   private trust binding; the offline renderer does not install trust.
4. Read the source route and effective guest/host/appliance firewalls. Existing
   discovery access may already cover Proxmox. Propose only any missing exact
   source /32, destination /32 and TCP destination port; no VLAN-wide grants.
5. Extend the existing foundation maintenance action, preserving original
   installation inputs and pins. Bind exact current/desired hashes and use its
   backup, identity, lock, one-use claim, hold and receipt conventions. Qualify
   file-provider reload behavior for the existing bind mount before promising a
   restart-free action. This PR contains no target writer or automatic replay.
6. Review the complete action and obtain scoped native approval. After deployment,
   verify allowed and denied clients, trusted frontend TLS, native login/MFA,
   redirects, Proxmox console and DSM UI, plus existing Authentik/pgAdmin routes.

Keep direct management access for recovery. A healthy proxy route is additional
convenience, not a prerequisite for repairing the proxy or its hosting node.
