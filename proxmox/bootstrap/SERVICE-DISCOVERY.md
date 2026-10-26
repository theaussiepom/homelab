# Let Traefik read the selected guests

Traefik can discover application routes from their Proxmox Notes. It needs its
own read-only API token. It must never receive the administrator credential used
by bootstrap CD or the application deployment token.

This is an optional addition to the existing
[host prerequisite workflow](README.md#9-let-github-maintain-the-host-prerequisites).
Review it with the application profiles before merging. The merge lets bootstrap
CD create the token and one host firewall allowance; no workstation command or
root SSH key is needed on the runner.

Add `service_discovery` to the private host settings. These are example addresses
and guest IDs; replace them together with the rest of the host configuration:

```json
"service_discovery": {
  "vmid": 212,
  "address": "10.77.25.33",
  "guests": [202, 211, 212]
}
```

`vmid` selects the Traefik guest. `address` is its fixed management address.
`guests` is the complete list of guests whose routes it may read, including
Traefik itself. Every ID must already appear in `applications`. The selected host
endpoint must use a literal private IPv4 address on HTTPS port 8006, with its
existing pinned CA. The optional object accepts no extra fields or custom
privileges.

For the example, bootstrap creates:

| Item | Result |
| --- | --- |
| API token | `root@pam!homelab-traefik-212`, privilege separation enabled, no expiry |
| Custom role | `HomelabTraefikRead212`, containing only `Sys.Audit` and `VM.Audit` |
| Grants | That role on the exact node and `/vms/202`, `/vms/211`, `/vms/212`; propagation disabled |
| Host firewall | One incoming TCP 8006 allowance from `10.77.25.33/32` to the selected host address `/32` |

The role permits reading metadata and Notes at those paths. It cannot create,
configure, start, stop or delete guests. It receives no storage, guest-agent,
console or secret-management permission. Other host firewall rules and options
are preserved. This does not add a UDM rule or change guest networking.

The token is returned once by Proxmox. Before granting it access, the workflow
saves it under the existing bootstrap state directory:

```text
/var/lib/homelab-bootstrap/service-discovery/token.json
```

The same private file is saved in the admitted NAS backup directory as
`service-discovery/token.json`. Both files have mode 0600 inside mode 0700 folders.
The `token` field is the complete API credential. Application CD may read that
file privately to install the provider configuration; it must never print the
file, place it in Proxmox Notes, or upload it as an Actions artifact. The private
folder also retains the once-returned response for recovery from a partial
operation. Keep the NAS copy protected like your other credentials.

**Expected result:** `service_discovery.status: ready`. This means the API
credential, exact privileges, stored firewall rule and private backup passed
readback. Application CD still needs to prove that the running Traefik guest can
connect and discover its routes. It should use explicit backend `server.url`
labels so a multi-interface guest uses the intended application network.

A repeat verifies the saved credential and makes no further changes. The
workflow refuses to adopt an existing token, rotate a token, expand its guest
list, rewrite changed privileges, or move an existing firewall rule. A partial
failure leaves the normal bootstrap hold and maintenance marker. Preserve the
private receipts and review the actual outcome before authorising a correction;
do not delete files or repeatedly rerun the workflow.

Omit `service_discovery` when this provider is not part of your deployment. The
original host prerequisite workflow keeps its existing behaviour.
