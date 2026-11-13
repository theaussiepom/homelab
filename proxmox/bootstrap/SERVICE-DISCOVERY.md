# Let Traefik read the selected guests

Traefik can discover application routes from their Proxmox Notes. It needs its own read-only API token. It must never receive the administrator credential used by bootstrap CD or the application deployment token.

This is an optional addition to the existing [host prerequisite workflow](README.md#9-let-github-maintain-the-host-prerequisites). Review it with the application profiles before merging. The merge lets bootstrap CD create the token and one host firewall allowance; no workstation command or root SSH key is needed on the runner.

Add `service_discovery` to the private host settings. The following uses synthetic addresses from the RFC2544 benchmarking range and lab guest IDs; replace them together with the rest of the host configuration:

```json
"service_discovery": {
  "vmid": 12012,
  "address": "198.19.125.43",
  "guests": [12002, 12011, 12012]
}
```

`vmid` selects the Traefik guest. `address` is its fixed management address. `guests` is the complete list of guests whose routes it may read, including Traefik itself. Every ID must already appear in `applications`. The selected host endpoint must use a literal private IPv4 address on HTTPS port 8006, with its existing pinned CA. The optional object accepts no extra fields or custom privileges.

For the example, bootstrap creates:

| Item | Result |
| --- | --- |
| API token | `root@pam!homelab-traefik-12012`, privilege separation enabled, no expiry |
| Custom role | `HomelabTraefikRead12012`, containing only `Sys.Audit` and `VM.Audit` |
| Grants | That role on the exact node and `/vms/12002`, `/vms/12011`, `/vms/12012`; propagation disabled |
| Host firewall | One incoming TCP 8006 allowance from `198.19.125.43/32` to the selected host address `/32` |

The role permits reading metadata and Notes at those paths. It cannot create, configure, start, stop or delete guests. It receives no storage, guest-agent, console or secret-management permission. Other host firewall rules and options are preserved. This does not add a UDM rule or change guest networking.

The token is returned once by Proxmox. Before granting it access, the workflow saves it under the existing bootstrap state directory:

```text
/var/lib/homelab-bootstrap/service-discovery/token.json
```

The same private file is saved in the NAS backup directory that passed admission checks as `service-discovery/token.json`. Both files have mode 0600 inside mode 0700 folders. The `token` field is the complete API credential. Application CD may read that file privately to install the provider configuration; it must never print the file, place it in Proxmox Notes, or upload it as an Actions artifact. The private folder also retains the once-returned response for recovery from a partial operation. Keep the NAS copy protected like your other credentials.

**Expected result:** `service_discovery.status: ready`. This means the API credential, exact privileges, stored firewall rule and private backup passed readback. Application CD still needs to prove that the running Traefik guest can connect and discover its routes. It should use explicit backend `server.url` labels so a multi-interface guest uses the intended application network.

A repeat verifies the saved credential and makes no further changes. The workflow refuses to adopt an existing token, rotate a token, silently expand its guest list, rewrite changed privileges, or move an existing firewall rule. A partial failure leaves the normal bootstrap hold and maintenance marker. Preserve the private receipts and review the actual outcome before authorising a correction; do not delete files or repeatedly rerun the workflow.

## Add another application later

Keep the existing token. Append the new guest to `applications` and to the end of `service_discovery.guests`, then include an explicit extension in the same reviewed host-settings change:

```json
"service_discovery_extension": {
  "owner_sha256": "<SHA256 of the current non-secret discovery owner>",
  "guests": [12015]
}
```

Use `provider_access.owner_sha256()` on the current owner content to calculate this hash. Initially, that content is `service-discovery/owner.json`; after an extension it is the `owner` in the last `scope-extensions/NNNN.json` receipt. This hash describes the existing node, address, token identity, role and full guest list. It contains no credential.

On the runner, run this from the private repository checkout containing `public-source/`. It prints only the non-secret owner hash:

```sh
python3 - <<'PY'
import json
import sys
from pathlib import Path

sys.path.insert(0, 'public-source/proxmox/bootstrap')
from provider_access import owner_sha256

base = Path('/var/lib/homelab-bootstrap/service-discovery')
receipts = sorted((base / 'scope-extensions').glob('*.json'))
owner = (json.loads(receipts[-1].read_text())['owner'] if receipts
         else json.loads((base / 'owner.json').read_text()))
print(owner_sha256(owner))
PY
```

Do not hash the stored file with `sha256sum`: its whitespace differs from the canonical JSON content checked by bootstrap. Before changing access, normal bootstrap checks still validate the complete receipt chain and its NAS copies.

Review and approve the exact added guest access before merging. Bootstrap adds only the declared read grants, without propagation. It verifies the retained credential, role and all previous grants first. A changed address, removed or reordered old guest, extra privilege or missing NAS copy stops the operation.

The original owner and token files remain unchanged. Each successful extension adds one numbered receipt in `service-discovery/scope-extensions/` on the runner and NAS. Later runs use that complete chain to check the effective scope and make no further changes. A partial extension stays under the normal bootstrap hold; it cannot be adopted or automatically retried. After success the optional extension request may be removed, retaining the full desired guest list.

Omit `service_discovery` when this provider is not part of your deployment. The original host prerequisite workflow keeps its existing behaviour.

## Extend only an already owned scope

When the complete historical host plan is not being changed, the same protected bootstrap workflow can invoke `bootstrap_cd.py --owned-discovery-extension --config <private-json> --ca <pinned-ca>`. Ordinary application CD does not receive the bootstrap credential. This mode accepts exactly these fields:

```json
{
  "schema": "homelab-owned-discovery-extension-v1",
  "endpoint": "https://198.19.125.11:8006/",
  "node": "fixture-node",
  "backup_source": "198.19.120.2:/backups/fixture",
  "application_vmids": [12002, 12011, 12012, 12015],
  "service_discovery": {
    "vmid": 12012,
    "address": "198.19.125.43",
    "guests": [12002, 12011, 12012, 12015]
  },
  "service_discovery_extension": {
    "owner_sha256": "<canonical current owner SHA256>",
    "guests": [12015]
  },
  "added_guests": [
    {"node": "fixture-node", "vmid": 12015, "hostname": "fixture-mqtt", "type": "lxc"}
  ]
}
```

These values are synthetic; the owner hash must come from the actual current ownership records. `added_guests` binds every appended ID, in order, to its exact node, guest type and hostname on Proxmox. CD reads only those added guest configurations before its saved plan and again before granting access. CD rejects the change if an identity is missing or different.

The mode requires matching `owner.json`, `token.json` and `READY.json` in both `service-discovery` directories, the expected mounted NAS, and no bootstrap hold or maintenance marker. The mirrored `scope-extensions` chain is required only when previous extensions exist; it is absent for the first extension. The mode can add only the declared discovery access rules without propagation, plus matching receipts on the runner and NAS. It cannot mint credentials or change bridges, application grants, monitoring or firewall rules. Plans and results remain in the existing protected evidence directories. The single matching API allowance may appear after other input rules only when each preceding rule names one literal IPv4 source or CIDR that excludes the discovery guest. CD rejects unknown, inverted, compound or overlapping sources. It never moves or edits those rules. Preflight refusals create no hold. Failures after plan and hold creation retain that hold and do not retry; an unchanged successful repeat verifies the exact completed extension without another grant or receipt.
