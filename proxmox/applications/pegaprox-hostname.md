# PegaProx hostname route

The initial PegaProx installation publishes direct HTTPS on port 5000. This
addition supplies a permanent explicit hostname route through Traefik's existing
watched shared file. It preserves native local login and defers Authentik.
No discovery grant for the application or new NIC is needed. The only backend
flow is the existing management-side proxy address to the exact application
address on TCP 5000.

`pegaprox_browser.py` adds reserved router/service/transport objects, preserving
the existing Influx objects and rejecting collisions. The transport supplies the
exact hostname as SNI and trusts the selected public certificate inline. That
avoids a certificate mount or Traefik restart. Hostname and trust verification
remain enabled. An explicit finite client allowlist uses the actual socket peer;
no forwarded-header/IP-strategy trust or Authentik middleware is introduced.
The client restriction needs its exact separate admission before activation.
Guest firewall testing remains separately deferred.

The selected certificate must contain the browser DNS name and backend IP SANs.
Normal clean installation now generates SANs before first start, using optional
`app.pegaprox.tls_hostname` (defaulting to the guest hostname), the guest IP and
loopback. Existing state prevents regeneration. This installer is never used
to adjust an already commissioned guest.

The current guest's certificate correction is a separately reviewed SSH
maintenance action: retain the existing key and original public certificate,
install the exact prepared public candidate, and restart only the selected
PegaProx container once if its certificate changes. That temporary adjustment
has no CD controller, workflow or recovery variant in this source.

## Installation and admission

The permanent route uses the existing `foundation_maintenance.py` entry point
and `ingress_browser_maintenance.run(..., profile='pegaprox')`. It keeps the
original source/input/trust checks, global CD queue, guest lock, hold protocol,
NAS state backups, mirrored claims and original watched-file custody. The
Ansible entry is `component-pegaprox-hostname.yml`; it installs only the route
helpers. No new ongoing native check job or schedule is introduced.

Before activation, bind the exact resulting canonical ingress state and network
acceptance after the separately approved access plan. A historical state hash
cannot stand in for that result. Bind a policy receipt to the exact route,
retained native login, explicitly approved direct-peer client list and the agreed
Authentik/guest-firewall deferrals.
Backend readiness verifies the certificate/SNI from the exact management-side
source before any route write. Frontend readiness verifies normal HTTPS and denial of the controller, which is
not an admitted browser client. It does not add a probe exception. A selected
client must separately verify the actual page and native login.

The component reuses the established inode-preserving watched-file writer.
It protects static configuration, Compose, image, all four NICs and the accepted
network startup gate; Traefik identity/start time must remain unchanged.
Partial claims preserve originals and holds and cannot automatically replay.
Retire consumed installer selectors after acceptance. The historical Influx
whole-file verifier must be retired with its receipt preserved before adding
an overlay; its old digest must not be loosened or rewritten.

## Validation

Unit tests cover closed peers, SNI/source binding, policy admission, custody,
collisions, Influx preservation and failure holds. The clean-install Ansible
fixture checks actual generated SANs and refusal to regenerate existing state.
The pinned PegaProx/Traefik fixture uses an internal Docker network and no host
ports. It proves inline trust, rejects wrong SNI and a wrong trust anchor, and
checks initialized native authentication through the proxy, plus rejection of an
unadmitted peer even when it forges forwarded/Cloudflare client-IP headers.

Primary references: [Traefik ServersTransport](https://doc.traefik.io/traefik/reference/routing-configuration/http/load-balancing/serverstransport/),
[typed RootCAs](https://github.com/traefik/traefik/blob/v3.6/pkg/config/dynamic/http_config.go),
[FileOrContent](https://github.com/traefik/traefik/blob/v3.6/pkg/types/file_or_content.go).
