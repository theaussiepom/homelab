# Host firewall policy through CD

This separate bootstrap capability maintains a Proxmox node's complete ordered list of rules allowing incoming TCP traffic and the cluster-wide firewall options. A standalone node can also declare its automatic management trust. Application guest firewall rules, host firewall options, deployment guest 900 and application-token permissions remain under their existing owners. The privileged bootstrap token is supplied through the protected `homelab-bootstrap` environment and stays outside configuration source and runtime tfvars.

First installation requires an explicitly reviewed transfer of management for the existing configuration. The existing node rules and cluster options must be imported into a new, dedicated OpenTofu state. Later deployments use that same state and the declared desired policy. There is no import, recovery, adoption or temporary-test mode in the CD caller.

## Author the desired policy

Use `bootstrap/firewall.yaml` in the private deployment repository. The [complete synthetic example](host-firewall.example.yaml) exercises the standalone host policy and the three resources it selects.

```yaml
schema: homelab-host-firewall-v1
endpoint: https://pve.example.invalid:8006/
node: pve
host_address: 198.18.25.10
local_network: host-only
allowances:
  - source: 198.18.25.11/32
    port: 8006
    comment: Existing deployment API
  - source: 192.0.2.0/24
    port: 22
    comment: Approved management SSH
  - source: 198.18.40.33/32
    destination: 198.18.40.10
    port: 8006
    comment: Application ingress to host UI
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
| [local_network](#local_network) | Optional string | `host-only` selects an explicit `host_address/32` cluster alias on a standalone node. Omit the field to continue using the existing two-resource contract |
| allowances | Required ordered list | 1–32 distinct records; the entire desired node rule list, including every allowance that must remain |
| allowances[].source | Required string | Canonical IPv4 CIDR with a nonzero prefix; no host bits, loopback, link-local, multicast, reserved or unspecified network |
| allowances[].destination | Optional string | One usable canonical IPv4 address on this same node, with the same address restrictions as `host_address`; no CIDR prefix. When omitted, both the controller and provider configuration use `host_address`. Null and empty values are refused |
| allowances[].port | Required integer | TCP destination port 1–65535; booleans and strings are refused |
| allowances[].comment | Required string | Unique printable ASCII purpose, 1–200 characters, no surrounding whitespace or control characters |
| cluster.enabled | Required boolean | Desired global enforcement. `false` is an ordinary later configuration change; destroying/removing the resource is not a disable operation |
| cluster.ebtables | Required boolean | Explicit desired bridge filtering option |
| cluster.input_policy / output_policy | Required strings | `ACCEPT`, `DROP` or `REJECT` |
| cluster.forward_policy | Required string | `ACCEPT` or `DROP` |
| cluster.log_ratelimit.enabled | Required boolean | Explicit logging-rate switch |
| cluster.log_ratelimit.rate | Required string | Positive integer of at most 9 digits followed by `/second`, `/minute`, `/hour` or `/day` |
| cluster.log_ratelimit.burst | Required integer | 1–2147483647; boolean values refused |

The validator rejects unknown or missing required keys, null values, duplicate source/effective-destination/port tuples and duplicate comments. Explicitly supplying `host_address` as a destination cannot bypass duplicate detection for an allowance that omits it. The existing [bounded authored reader](../../docs/reference/sources.md) rejects YAML aliases, tags, merge keys, duplicate mappings and competing `.yaml`/`.yml`/`.json` siblings.

The controller converts each allowance to an enabled `in ACCEPT tcp` with destination `destination/32` or the default `host_address/32` and its declared source, port and comment. Interface, macro, log, source port and security group are empty. Declare all required API and SSH access explicitly. A source record using `port: true`, `source: 0.0.0.0/0` or `destination: 198.18.40.0/24` is invalid. The dedicated workspace binds the node, endpoint and host address across runs. Verify each allowance destination and its service listener before deployment.

The node resource owns the whole ordered list. Omitting a previously declared allowance requests its removal. Changing source/destination/port/comment is an ordinary reviewed desired-state change. Policies that omit `destination` retain their existing behavior. Preserve all existing management access in the private source before enabling enforcement.

## Cluster defaults are effective behavior

Pinned bpg 0.117.0 writes all supported cluster options when it updates the resource, so `enabled: true` alone is insufficient. Explicitly declare the intended ebtables, policies and logging values. The normal guard distinguishes omitted native defaults from explicit values: omitted ebtables means the documented PVE default `true`; explicit `false` remains false. Provider null fields and an absent log block normalize to the documented PVE defaults: `enabled=false`, `ebtables=true`, `input_policy=DROP`, `output_policy=ACCEPT`, `forward_policy=ACCEPT` and logging enabled at one event per second with burst 5. Persisting those formerly implicit values changes stored representation while preserving effective behavior. An explicitly false value changing to true is a real policy change and must be reviewed as such.

The controller rejects unknown fields in platform options and unsupported rule shapes. This capability accepts explicitly declared incoming IPv4 TCP allowances and cluster options. A broader existing node policy needs a separately reviewed contract.

### `local_network`

With `host-only`, the protected deployment installs the cluster alias `local_network` with its CIDR derived from `host_address`. In the classic Proxmox firewall this replaces the automatically detected management subnet with the host's own IPv4 address. Check the active firewall backend, exact approved sources and an independent recovery path before applying. Validate both access from those sources and denial from an unrelated client on the management subnet after applying. Inspect the effective kernel management sets for both address families.

The controller requires the cluster status to report the intended standalone host and refuses a configured `management` IP set or `cluster_network` alias. A pre-existing unmanaged `local_network` alias is a collision. The saved plan can create the one cluster alias after the declared node rules and cluster options complete. Later runs require API and state agreement on that alias and a no-op plan for it. An enrolled workspace refuses removal of the declaration.

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

The dedicated private workspace must already contain `terraform.tfstate` and `policy.auto.tfvars.json` (`{"policy": <the validated projection>}`), mode 0600 inside an owned mode 0700 directory. Existing state must contain exactly the two imported resources, with the alias added once `host-only` takes ownership. The saved configuration binds the endpoint, node and host address across updates. The caller requires already owned state.

Before refreshing state, the controller checks that the API rules and effective options match the imported state. The saved plan requires `proxmox_virtual_environment_firewall_rules.host` and `proxmox_virtual_environment_cluster_firewall.cluster` with update or no-op actions and planned values exactly matching the source. The `host-only` policy also requires `proxmox_virtual_environment_firewall_alias.local_network` and checks its identity, scope and values during creation and on repeat. All managed resources prevent destruction. Cluster options depend on completion of the host-rule resource.

The caller records the exact identities of the private state, source, HCL and saved plan together, then rechecks them and the API snapshot and digests before applying that saved plan. Afterward it verifies the API and state, then runs a fresh provider plan to confirm that no changes remain. Bootstrap maintenance markers and OpenTofu state locks prevent cooperating operations from running at the same time. They cannot prevent every external manual change or guarantee that future operations will succeed.

## Initial environmental ownership

This is a separately approved operator step outside normal source/CD. The provider refuses creating node rules when native rules already exist. Its normal import selector is `node/<node>`; cluster options use the passthrough import ID `cluster-firewall`. Import reads API state and writes the new dedicated local state; it does not apply policy or enable enforcement. No existing guest/bootstrap state is merged, replaced or manually edited.

Before importing, verify the exact target, current rules and options, absence of an existing backend, file ownership and permissions, pinned tool versions, state path, prevention of concurrent operations, and preservation of evidence. After imports, review a normal refreshed saved plan and distinguish effective changes from persistence of defaults. This guide does not authorize an import.

After the ownership handoff, later changes to host rules must use this desired policy. Earlier host API, monitoring and host-device allowance helpers describe first-installation paths; do not use them as competing writers for a host policy already managed through this state. Existing application CD does not call those first-installation writers.

## Failure and evidence

Private attempts remain under `host-firewall/operations/`. A failure retains the existing bootstrap `BOOTSTRAP-CD-HOLD.json` and `CONFIGURING` claim plus private logs/state/plan evidence. The result records API verification separately from successful release of the markers. If marker release fails, the controller attempts to retain the blocking HOLD for this same operation, creating it only if absent. It never replaces another operation's marker. Do not rerun, clear markers, restore state or invoke an older host writer automatically. Investigate uncertainty about the actual environment separately. A timeout is not evidence that no remote change occurred.

A passing result confirms that the API configuration and state match the declared policy and that a fresh provider plan proposes no changes. It explicitly reports `kernel_verified: false`. Kernel enforcement, management reachability and intentional household communications require separate target verification. No temporary enable/disable watchdog or recovery behavior is part of this capability.
