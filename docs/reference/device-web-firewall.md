# Protect one device web listener through CD

Use `homelab-device-web-firewall-v1` for a Linux device that already has a
separate IPv4 web address. This host configuration adds one listener boundary
through the [Ansible playbook](../../proxmox/bootstrap/ansible/device-web-firewall.yml).
It does not create a guest or join the application declaration language. The
consumer owns the actual identity, protected SSH input and deployment selection.

## Complete input and field records

The [maintained synthetic example](../../proxmox/bootstrap/device-web-firewall.example.yaml)
is a complete input to the shared bounded authored loader:

```yaml
schema: homelab-device-web-firewall-v1
target:
  address: 198.18.25.4
  hostname: radio
  user: operator
web:
  interface: eth0.40
  mac: '02:00:00:00:40:04'
  address: 198.18.40.4
  proxy: 198.18.40.33
  port: 8080
```

Every field is required, with no default or inheritance. Unknown fields,
omission, null and empty values are refused. The three addresses must differ;
they are literal identities, with no DNS lookup or implicit allocation.

| Field | Type, meaning and refusal |
| --- | --- |
| <a id="schema"></a>`schema` | String, exactly `homelab-device-web-firewall-v1`. Other versions are unsupported. |
| <a id="target-address"></a>`target.address` | Canonical unicast IPv4 management address. Hostnames, prefixes, loopback, unspecified, link-local, multicast and reserved addresses are refused. |
| <a id="target-hostname"></a>`target.hostname` | Observed short hostname, 1–63 ASCII letters/digits/hyphens, beginning and ending with a letter/digit. It binds the sole inventory alias and actual host. |
| <a id="target-user"></a>`target.user` | Existing SSH account: 1–32 lowercase ASCII letters/digits/underscore/hyphen, beginning with a letter or underscore. The playbook requires that account's existing privilege escalation to root; it creates no account, key or sudo permission. |
| <a id="web-interface"></a>`web.interface` | Existing Linux interface, 1–15 ASCII letters/digits/underscore/dot/hyphen, beginning with a letter; `lo` is refused. It must have the selected MAC and web address and must not be a bridge/bond slave. VLAN interfaces can share their parent's MAC. |
| <a id="web-mac"></a>`web.mac` | Canonical lowercase six-octet unicast MAC, excluding all-zero. It identifies the selected existing interface; no MAC is assigned. |
| <a id="web-address"></a>`web.address` | Canonical unicast IPv4 listener address under the same address rules. It must occur exactly once on the selected interface; management must be assigned to another interface. |
| <a id="web-proxy"></a>`web.proxy` | Sole remote caller's canonical unicast IPv4 address, under the same address rules. Groups, prefixes and extra callers are unsupported. |
| <a id="web-port"></a>`web.port` | Integer TCP destination port, 1–65535. Booleans, strings and additional ports are refused. |

## Result and scope

The renderer creates only `inet homelab_device_web`. Its INPUT chain accepts
the exact proxy, destination and TCP port on the selected interface; accepts
guest-local traffic to that same listener through loopback; then drops every
other IPv4 request to that destination and port, including requests arriving
through another interface. All other traffic passes this chain. Other policy
owners can still deny an allowed request.

The boundary does not filter another address, port, IPv6 listener, OUTPUT or
FORWARD. Bind the application itself to the selected IPv4 address. This is not
a whole-device default-deny policy. Existing DNS, device APIs, discovery,
network configuration and data remain under their existing owners.

The own-table replacement is one atomic nftables batch, without a global flush
or includes. `/etc/homelab-device-web/web.nft` is root-owned mode 0600. The
dedicated root-owned mode 0644 `homelab-device-web-firewall.service` applies it
at boot after any selected stock nftables service and before Docker. It has no
stop action; stopping it leaves enforcement in place. CD does not enable,
replace or stop the global nftables service or restart an application.

## Prepare and validate

From the framework checkout, using its locked source environment:

```sh
python3 proxmox/bootstrap/device_web_firewall.py --config proxmox/bootstrap/device-web-firewall.example.yaml --check
python3 proxmox/bootstrap/device_web_firewall.py --config proxmox/bootstrap/device-web-firewall.example.yaml --emit
```

These commands validate source only. For example, changing `web.proxy` to
`198.18.40.0/24` refuses with the sanitized device-web-firewall diagnostic;
select one explicit caller instead. The accepted source and rendered output
are authoritative; the test mapping stores only field and evidence pointers.

The target must already have Linux, systemd, nftables, iproute2, Python and its
assigned management/web interfaces. Prepare console/management recovery and
independently trusted SSH access first. The sole `device_web` inventory host
must match the configured hostname, management address and account. The
existing account must support the selected root privilege escalation.
The effective SSH plugin host and user must match that same selection, with
port 22. Matching aliases are supported; a conflicting alias or inherited
different port refuses before target contact.

Use the same explicit key custody and strict SSH options as the
[PBS host configuration](pbs-firewall.md#validate-and-deploy). Its private key
remains outside Git. The shared precontact validator reads only its metadata
and the pinned public host file. The same literal key/trust-path and protected
ancestor-directory requirements apply to device CD. Disable Ansible SSH TTY
allocation with
`ANSIBLE_SSH_USETTY=False`; the actual plugin setting is checked before contact.
Local admission is delegated with privilege escalation disabled. Set
`device_web_firewall_config` to the absolute, reviewed authored input when
calling the playbook through protected CD.

## Installation, updates and verification

First installation requires the dedicated files, loaded unit and table to be
absent. Existing unrelated tables are supported and remain outside this
capability. Foreign paths, links, writable files, unit overrides or an existing
unowned table refuse before mutation. CD syntax-checks the nft batch before
installing it, starts only its dedicated unit, then reads the real files,
loaded unit and complete owned table back for exact comparison.
Metadata observation disables checksum and MIME probes; file ownership, mode,
link count and the 16 KiB size limit are checked before reading file content.

Later CD requires the exact generated configuration, unchanged network/account
identity and matching active/enabled unit and kernel table. A pending systemd
daemon reload refuses admission even when the unit file on disk matches;
the loaded service configuration may still differ. CD does not silently
reload that uncertain state. Only the proxy
allowance can change in an ordinary update. Unchanged input does not reload
the unit. A changed listener identity requires a separately reviewed handover.
A failed or uncertain application retains its CD evidence; there is no
automatic rollback, retry, takeover or policy-removal branch.

The [contract tests](../../proxmox/bootstrap/tests/test_device_web_firewall.py)
cover closed inputs, exact scope, ownership refusals, updates, shared transport
admission and playbook wiring. They do not establish native installation,
future boot or client acceptance. After CD, verify the actual proxy HTTP/TLS
path, a prohibited real peer and other-interface denial, continuing local
health and unchanged device/API behaviour. Keep listener activation separate
until protection is applied and verified.

[Reference index](README.md) · [Separate web and device paths](../guides/separate-web-and-device-networks.md)
