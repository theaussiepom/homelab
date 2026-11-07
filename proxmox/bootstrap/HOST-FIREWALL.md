# Host firewall policy through CD

This separate bootstrap capability maintains a Proxmox node's complete ordered list of rules allowing incoming TCP traffic and the cluster-wide firewall options. Application guest firewall rules, host firewall options, deployment guest 900 and application-token permissions remain under their existing owners. The privileged bootstrap token is supplied through the protected `homelab-bootstrap` environment; it is never placed in the configuration source or runtime tfvars.

First installation requires an explicitly reviewed transfer of management for the existing configuration. The existing node rules and cluster options must be imported into a new, dedicated OpenTofu state. Later deployments use that same state and the declared desired policy. There is no import, recovery, adoption or temporary-test mode in the CD caller.

## Author the desired policy

Use `bootstrap/firewall.yaml` in the private deployment repository. The complete [public synthetic example](host-firewall.example.yaml) is accepted by the source validator and renders the two provider resources. It is a configuration example, not authorization to apply documentation addresses to a real host.

```yaml
schema: homelab-host-firewall-v1
endpoint: https://pve.example.invalid:8006/
node: pve
host_address: 198.18.25.10
allowances:
  - source: 198.18.25.11/32
    port: 8006
    comment: Existing deployment API
  - source: 192.0.2.0/24
    port: 22
    comment: Approved management SSH
cluster:
  enabled: true
  ebtables: true
  input_policy: DROP
  output_policy: ACCEPT
  forward_policy: ACCEPT
  log_ratelimit:
    enabled: true
    rate: 1/second
    burst: 5
```

| Field | Type and requirement | Meaning and constraints |
| --- | --- | --- |
| schema | Required string | Exactly `homelab-host-firewall-v1` |
| endpoint | Required string | Pinned HTTPS API URL with explicit port 8006; no userinfo, query, fragment, whitespace or non-root path |
| node | Required string | Existing node name: 1–63 ASCII letters/digits/hyphens, first character a letter or digit |
| host_address | Required string | Usable individual canonical IPv4 address; no prefix, loopback, link-local, multicast, reserved or unspecified address |
| allowances | Required ordered list | 1–32 distinct records; the entire desired node rule list, including every allowance that must remain |
| allowances[].source | Required string | Canonical IPv4 CIDR with a nonzero prefix; no host bits, loopback, link-local, multicast, reserved or unspecified network |
| allowances[].port | Required integer | TCP destination port 1–65535; booleans and strings are refused |
| allowances[].comment | Required string | Unique printable ASCII purpose, 1–200 characters, no surrounding whitespace or control characters |
| cluster.enabled | Required boolean | Desired global enforcement. `false` is an ordinary later configuration change; destroying/removing the resource is not a disable operation |
| cluster.ebtables | Required boolean | Explicit desired bridge filtering option |
| cluster.input_policy / output_policy | Required strings | `ACCEPT`, `DROP` or `REJECT` |
| cluster.forward_policy | Required string | `ACCEPT` or `DROP` |
| cluster.log_ratelimit.enabled | Required boolean | Explicit logging-rate switch |
| cluster.log_ratelimit.rate | Required string | Positive integer of at most 9 digits followed by `/second`, `/minute`, `/hour` or `/day` |
| cluster.log_ratelimit.burst | Required integer | 1–2147483647; boolean values refused |

Every field must be supplied; the source has no defaults. The validator rejects unknown or missing keys, null values, duplicate source/port pairs and duplicate comments. The existing [bounded authored reader](../../docs/reference/sources.md) rejects aliases, tags, merge keys, duplicate mappings and competing `.yaml`/`.yml`/`.json` siblings. This document does not support component source references or includes.

The controller converts each allowance to an enabled `in ACCEPT tcp`, destination `host_address/32`, and its declared source/port/comment. Interface, macro, log, source port and security group are empty. The controller does not infer an allowance for API port 8006, SSH, guests or management access. A source record using `port: true` or `source: 0.0.0.0/0` is invalid. A valid request to change the node/endpoint/host address is also refused in a workspace already managed by this capability: it selects a different target.

The node resource owns the whole ordered list. Omitting a previously declared allowance requests its removal. Changing source/port/comment is an ordinary reviewed desired-state change, not a migration. Preserve all existing management access in the private source before enabling enforcement.

## Cluster defaults are effective behavior

Pinned bpg 0.117.0 writes all supported cluster options when it updates the resource, so `enabled: true` alone is insufficient. Explicitly declare the intended ebtables, policies and logging values. The normal guard distinguishes omitted native defaults from explicit values: omitted ebtables means the documented PVE default `true`; explicit `false` remains false. Provider null fields and an absent log block normalize to the documented PVE defaults: `enabled=false`, `ebtables=true`, `input_policy=DROP`, `output_policy=ACCEPT`, `forward_policy=ACCEPT` and logging enabled at one event per second with burst 5. Persisting those formerly implicit values changes stored representation while preserving effective behavior. An explicitly false value changing to true is a real policy change and must be reviewed as such.

The controller rejects unknown fields in platform options and unsupported rule shapes; it does not silently remove them. This capability supports only rules that accept incoming TCP traffic. It does not configure node options, default host trust, IPv6 host allowances, arbitrary actions or guest rules. A broader existing node policy needs a separately reviewed contract.

## Validate and run

From a checked-out framework revision containing this capability, validate the private YAML with its hash-locked Python dependencies installed:

```sh
python3 proxmox/bootstrap/host_firewall.py --check --config /path/to/private/bootstrap/firewall.yaml
```

That command reads authored source only. It does not read the token, state or CA, and does not contact the API. The inactive [private workflow template](templates/private-host-firewall.yml.example) shows source validation before the protected target job. Its two zero commit IDs are explicit template placeholders: replace both with one reviewed immutable published framework commit. The existing runner labels and environment must match your protected deployment setup. Do not introduce a second nested concurrency group.

The normal controller job uses the tool versions already pinned on the controller:

```sh
/opt/homelab-tools/bin/python3 framework-source/proxmox/bootstrap/host_firewall.py \
  --config bootstrap/firewall.yaml \
  --work /var/lib/homelab-bootstrap/host-firewall
```

OpenTofu 1.13.1 must already be installed at `/usr/local/bin/tofu`; bpg/proxmox is locked at 0.117.0. The existing CA is `/usr/local/share/ca-certificates/homelab-pve.crt`. Docker is used by source tests, not by this controller deployment. Only the bootstrap token is forwarded to the provider under its normal environment name. Debug logs, caller `TF_VAR_*`, proxy, user provider-config and unrelated secret environment variables are not inherited.

The dedicated private workspace must already contain `terraform.tfstate` and `policy.auto.tfvars.json` (`{"policy": <the validated projection>}`), mode 0600 inside an owned mode 0700 directory. Existing state must contain exactly the two selected managed resources with the expected node and no guest selector. The saved normal configuration binds endpoint, node and host address across updates. The caller never creates a fresh empty state or imports an existing object.

Before refreshing state, the controller checks that the API rules and effective options match the imported state. It rejects changes made outside this workflow. The saved plan must declare exactly `proxmox_virtual_environment_firewall_rules.host` and `proxmox_virtual_environment_cluster_firewall.cluster`, with update/no-op actions and planned final values exactly matching the source. The controller rejects creation, deletion, replacement, import, unrelated changes and missing declarations. Both HCL resources prevent destruction; cluster options depend on completion of the host-rule resource.

The caller records the exact identities of the private state, source, HCL and saved plan together, then rechecks them and the API snapshot and digests before applying that saved plan. Afterward it verifies the API and state, then runs a fresh provider plan to confirm that no changes remain. Bootstrap maintenance markers and OpenTofu state locks prevent cooperating operations from running at the same time. They cannot prevent every external manual change or guarantee that future operations will succeed.

## Initial environmental ownership

This is a separately approved operator step outside normal source/CD. The provider refuses creating node rules when native rules already exist. Its normal import selector is `node/<node>`; cluster options use the passthrough import ID `cluster-firewall`. Import reads API state and writes the new dedicated local state; it does not apply policy or enable enforcement. No existing guest/bootstrap state is merged, replaced or manually edited.

Before importing, verify the exact target, current rules and options, absence of an existing backend, file ownership and permissions, pinned tool versions, state path, prevention of concurrent operations, and preservation of evidence. After imports, review a normal refreshed saved plan and distinguish effective changes from persistence of defaults. This guide does not authorize an import.

After the ownership handoff, later changes to host rules must use this desired policy. Earlier host API, monitoring and host-device allowance helpers describe first-installation paths; do not use them as competing writers for a host policy already managed through this state. Existing application CD does not call those first-installation writers.

## Failure and evidence

Private attempts remain under `host-firewall/operations/`. A failure retains the existing bootstrap `BOOTSTRAP-CD-HOLD.json` and `CONFIGURING` claim plus private logs/state/plan evidence. The result records API verification separately from successful release of the markers. If marker release fails, the controller attempts to retain the blocking HOLD for this same operation, creating it only if absent. It never replaces another operation's marker. Do not rerun, clear markers, restore state or invoke an older host writer automatically. Investigate uncertainty about the actual environment separately. A timeout is not evidence that no remote change occurred.

A passing result confirms that the API configuration and state match the declared policy and that a fresh provider plan proposes no changes. It explicitly reports `kernel_verified: false`. Kernel enforcement, management reachability and intentional household communications require separate target verification. No temporary enable/disable watchdog or recovery behavior is part of this capability.
