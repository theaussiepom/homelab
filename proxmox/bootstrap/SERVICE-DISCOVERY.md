# Let Traefik read all guests

Traefik discovers application routes from Proxmox Notes using its own read-only API token. Bootstrap owns that token and its permissions. Ordinary application jobs never receive the bootstrap administrator credential.

Add the optional `service_discovery` object to the reviewed [host prerequisite configuration](README.md#9-let-github-maintain-the-host-prerequisites). These addresses and IDs are synthetic:

```json
"service_discovery": {
  "vmid": 12012,
  "address": "198.19.125.43",
  "scope": "all-guests"
}
```

| Field | Presence and accepted value | Effect |
| --- | --- | --- |
| `vmid` | Required integer selecting a declared application guest | Owns the stable `homelab-traefik-<vmid>` token and `HomelabTraefikRead<vmid>` role. No default. |
| `address` | Required individual private IPv4 address, distinct from the host API address | Selects the source `/32` of the existing TCP 8006 host allowance. No default. |
| `scope` | Required string `all-guests` | Reads metadata for current and future guests through an inherited `/vms` grant. No guest inventory or owner digest belongs in source. |

The object rejects unknown fields, nulls and empty values. The host endpoint must be credential-free HTTPS on port 8006 using its existing pinned CA and literal private IPv4 address. Omit the object when this provider is not selected.

Bootstrap produces exactly this discovery policy:

| Item | Result |
| --- | --- |
| Token | `root@pam!homelab-traefik-12012`, privilege separation enabled, no expiry |
| Role | `HomelabTraefikRead12012`, only `Sys.Audit` and `VM.Audit` |
| Guest grant | `/vms`, propagation enabled |
| Node grant | `/nodes/<selected-node>`, propagation disabled |
| Host firewall | One incoming TCP 8006 allowance from the selected guest `/32` to the selected host `/32` |

These privileges allow metadata and Notes reads. They grant no guest creation, configuration, power, console, guest-agent or credential-management operations. No root ACL is added. Existing firewall options and unrelated ACLs stay intact. An unchanged repeat verifies the policy and makes no permission changes.

Visibility does not publish a route. The pinned [provider v0.7.0](https://github.com/NX211/traefik-proxmox-provider/tree/v0.7.0#required-labels) ignores guests without `traefik.enable=true` in their Notes. HomeLab emits that label only for declared routes. Explicit backend `server.url` labels select the intended interface. Adding a guest needs no discovery permission extension or privileged application job.

## Retain the credential and history

Proxmox returns a new token secret once. Before granting access, bootstrap saves it as `service-discovery/token.json` under the admitted bootstrap state root and independently mounted NAS backup. The mode is 0600 inside 0700 directories. The `token` field holds the complete credential. Never print it, place it in Notes or upload it as an Actions artifact.

The original `owner.json`, `token.json`, `READY.json` and once-returned mint response remain private. New installations use owner schema `homelab-service-discovery-v2`; token and READY records keep their original v1 schemas. A successful credential/permission readback is bootstrap readiness, not proof that running Traefik can reach or route an application.

Existing finite-scope installations retain their original owner and every numbered `scope-extensions/NNNN.json` receipt unchanged. The reader validates the full contiguous mirrored historical chain. The reviewed conversion writes one new mirrored `read-scope.json`, schema `homelab-service-discovery-read-scope-v1`, containing the canonical hash of the genuine final historical owner and its unchanged identity, node, endpoint and address with `scope: all-guests`. This records verified read capability; it is not an application deployment or success receipt. Source no longer pins that hash.

Missing, mismatched, partial or symlinked custody is refused. Bootstrap does not rotate credentials, invent previous ownership, change role privileges, move an allowance or rewrite unrelated ACLs. A failure after the saved plan and hold leaves the hold for review, with no automatic retry.

## Reconcile only an already owned discovery identity

Use the existing protected bootstrap workflow with `bootstrap_cd.py --owned-discovery --config <private-json> --ca <pinned-ca>` when the complete host plan is not changing. The closed input is:

```json
{
  "schema": "homelab-owned-discovery-v1",
  "endpoint": "https://198.19.125.11:8006/",
  "node": "fixture-node",
  "backup_source": "198.19.120.2:/backups/fixture",
  "service_discovery": {
    "vmid": 12012,
    "address": "198.19.125.43",
    "scope": "all-guests"
  }
}
```

`schema` is required and exact. `endpoint`, `node` and `backup_source` bind the retained API origin, node and actual mounted NAS source; none has a default. The mode has no application inventory, added-guest list or permission-extension packet. It cannot mint or adopt an unowned identity, modify application grants, networking, monitoring or firewall rules.

The native scope must match either the genuine last historical owner exactly or the desired two-grant policy exactly. From the historical policy, bootstrap adds `/vms` with propagation, removes only the superseded per-guest grants of that same token and role, verifies the unchanged role, token metadata and firewall, then saves the read-scope record. If an explicitly authorised manual conversion already produced the exact policy, it verifies the same endstate and saves custody with zero API writes. Partial and foreign scope changes are refused.

The effective-permissions API may enumerate inherited `/vms/<id>` paths beyond the two explicit ACLs. Each must contain only `Sys.Audit` and `VM.Audit`, with inheritance enabled. Unexpected paths, privileges or propagation flags fail verification. Ordinary ingress CD uses only GET requests to verify this capability and list guests, without a frozen VMID list.

The mode requires no bootstrap hold or maintenance marker, matching private local/NAS custody, the admitted NAS mount, and the unchanged API allowance. Preceding firewall rules must have literal nonoverlapping IPv4 sources; unknown, compound, inverted or overlapping sources are refused. Plans, results and failures use the existing protected evidence directories. A completed repeat verifies without creating another receipt.

## Source evidence and limits

The maintained `test_provider_access.py`, `test_owned_discovery_scope.py`, `test_application_scope.py` and application discovery tests cover fresh issuance, exact conversion, already-converted adoption, six retained extensions, unchanged repeats, future guest admission, malformed custody, permission drift and held failures using synthetic APIs and directories. These checks do not execute a production conversion or prove service routing. Target permission readback, source integration, protected bootstrap execution and running application acceptance remain separate evidence.
