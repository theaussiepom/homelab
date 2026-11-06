# Host firewall policy through CD

This separate bootstrap capability maintains a Proxmox node's complete ordered
TCP ingress allowances and the cluster-wide firewall options. Application guest
firewall rules, host firewall options, deployment guest 900 and application-token
permissions remain under their existing owners. The privileged bootstrap token
is supplied through the protected `homelab-bootstrap` environment; it is never
placed in the authored file or runtime tfvars.

First installation means an explicitly reviewed environmental ownership handoff:
existing node rules and cluster options must be imported into a new dedicated
OpenTofu state. Later deployments use that same state and ordinary desired source.
There is no import, recovery, adoption or temporary-test mode in the CD caller.

## Author the desired policy

Use `bootstrap/firewall.yaml` in the private deployment repository. The complete
[public synthetic example](host-firewall.example.yaml) is accepted by the source
validator and renders the two provider resources. It is a configuration example,
not authorization to apply documentation addresses to a real host.

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
| allowances | Required ordered list |1–32 distinct records; the entire desired node rule list, including every allowance that must remain |
| allowances[].source | Required string | Canonical IPv4 CIDR with a nonzero prefix; no host bits, loopback, link-local, multicast, reserved or unspecified network |
| allowances[].port | Required integer | TCP destination port 1–65535; booleans and strings are refused |
| allowances[].comment | Required string | Unique printable ASCII purpose,1–200 characters, no surrounding whitespace or control characters |
| cluster.enabled | Required boolean | Desired global enforcement. `false` is an ordinary later configuration change; destroying/removing the resource is not a disable operation |
| cluster.ebtables | Required boolean | Explicit desired bridge filtering option |
| cluster.input_policy / output_policy | Required strings | `ACCEPT`, `DROP` or `REJECT` |
| cluster.forward_policy | Required string | `ACCEPT` or `DROP` |
| cluster.log_ratelimit.enabled | Required boolean | Explicit logging-rate switch |
| cluster.log_ratelimit.rate | Required string | Positive integer of at most9 digits followed by `/second`, `/minute`, `/hour` or `/day` |
| cluster.log_ratelimit.burst | Required integer |1–2147483647; boolean values refused |

All fields are explicit; there are no authored defaults. Unknown/missing keys,
null values and duplicate source/port pairs or comments refuse. The existing
[bounded authored reader](../../docs/reference/sources.md) rejects aliases, tags,
merge keys, duplicate mappings and competing `.yaml`/`.yml`/`.json` siblings.
This document does not support component source references or includes.

Each allowance lowers to enabled `in ACCEPT tcp`, destination
`host_address/32`, and its declared source/port/comment. Interface, macro, log,
source port and security group are empty. No API8006, SSH, guest or management
allowance is inferred. A source record using `port: true` or `source: 0.0.0.0/0`
is invalid. A valid request to change the node/endpoint/host address is also
refused against an already owned workspace: it selects a different target.

The node resource owns the whole ordered list. Omitting a previously declared
allowance requests its removal. Changing source/port/comment is an ordinary
reviewed desired-state change, not a migration. Preserve all existing management
access in the private source before enabling enforcement.

## Cluster defaults are effective behavior

Pinned bpg 0.117.0 writes all supported cluster options when it updates the
resource, so `enabled: true` alone is insufficient. Explicitly declare the intended
ebtables, policies and logging values. The normal guard distinguishes omitted
native defaults from explicit values: omitted ebtables means the documented PVE
default `true`; explicit `false` remains false. Provider null fields and an absent
log block normalize to the documented PVE defaults: `enabled=false`, `ebtables=true`,
`input_policy=DROP`, `output_policy=ACCEPT`, `forward_policy=ACCEPT` and logging
enabled at one event per second with burst 5.
Persisting those formerly implicit values changes stored representation while
preserving effective behavior. An explicitly false value changing to true is a
real policy change and must be reviewed as such.

Unknown native option fields or rule shapes refuse; they are not silently removed.
The current capability represents TCP ingress accepts only. It does not configure
node options, default host trust, IPv6 host allowances, arbitrary actions or guest
rules. A broader existing node policy needs a separately reviewed contract.

## Validate and run

From a checked-out framework revision containing this capability, validate the
private YAML with its hash-locked Python dependencies installed:

```sh
python3 proxmox/bootstrap/host_firewall.py --check --config /path/to/private/bootstrap/firewall.yaml
```

That command reads authored source only. It does not read the token, state or CA,
and does not contact the API. The inactive
[private workflow template](templates/private-host-firewall.yml.example) shows
source validation before the protected target job. Its two zero commit IDs are
explicit template placeholders: replace both with one reviewed immutable published
framework commit. The existing runner labels and environment must match your
protected deployment setup. Do not introduce a second nested concurrency group.

The normal controller job uses its existing pinned native runtime:

```sh
/opt/homelab-tools/bin/python3 framework-source/proxmox/bootstrap/host_firewall.py \
  --config bootstrap/firewall.yaml \
  --work /var/lib/homelab-bootstrap/host-firewall
```

OpenTofu 1.13.1 must already be installed at `/usr/local/bin/tofu`; bpg/proxmox is
locked at 0.117.0. The existing CA is
`/usr/local/share/ca-certificates/homelab-pve.crt`. Docker is used by source tests,
not by this controller deployment. Only the bootstrap token is forwarded to the
provider under its normal environment name. Debug logs, caller `TF_VAR_*`, proxy,
user provider-config and unrelated secret environment variables are not inherited.

The dedicated private workspace must already contain `terraform.tfstate` and
`policy.auto.tfvars.json` (`{"policy": <the validated projection>}`), mode 0600
inside an owned mode 0700 directory. Existing state must contain exactly the two
selected managed resources with the expected node and no guest selector. The
saved normal configuration binds endpoint, node and host address across updates.
The caller never creates a fresh empty state or imports an existing object.

Before refresh, native API rules/effective options must equal that imported state.
Outside changes refuse. The saved plan must declare exactly
`proxmox_virtual_environment_firewall_rules.host` and
`proxmox_virtual_environment_cluster_firewall.cluster`, with update/no-op actions
and after-values exactly equal to source. Create, delete, replace, import,
unrelated drift and missing declarations refuse. Both HCL resources prevent
destruction; cluster options depend on completion of the host-rule resource.

The caller binds private state, source, HCL and saved plan, then rechecks them and
the API snapshot/digests before saved apply. It verifies API/state and a fresh
provider no-op afterward. Bootstrap maintenance markers and OpenTofu state locking
serialize cooperative work. They do not protect against every external manual
writer or prove future continuity.

## Initial environmental ownership

This is a separately approved operator step outside normal source/CD. The provider
refuses creating node rules when native rules already exist. Its normal import
selector is `node/<node>`; cluster options use the passthrough import ID
`cluster-firewall`. Import reads API state and writes the new dedicated local
state; it does not apply policy or enable enforcement. No existing guest/bootstrap
state is merged, replaced or manually edited.

Before any import, qualify the exact target, current rules/options, backend
absence, owner/modes, tool pins, state path, serialization and evidence preservation.
After imports, review a normal refreshed saved plan and distinguish effective
changes from persistence of defaults. This guide supplies no execution grant.

After the ownership handoff, subsequent host-row changes must use this desired
policy. Earlier host API, monitoring and host-device allowance helpers describe
first-installation paths; do not use them as competing writers for an owned host
policy. Existing application CD does not call those first-installation writers.

## Failure and evidence

Private attempts remain under `host-firewall/operations/`. A failure retains the
existing bootstrap `BOOTSTRAP-CD-HOLD.json` and `CONFIGURING` claim plus private
logs/state/plan evidence. API verification is recorded separately from completed
marker release. Any release-stage failure attempts to keep the same owned blocking
HOLD with create-only semantics; a foreign marker is never replaced. Do not rerun, clear markers, restore state or invoke an
older host writer automatically. Resolve environmental uncertainty separately.
A timeout is not evidence that no remote change occurred.

A passed result proves desired API configuration, state and a fresh provider
no-op. It explicitly reports `kernel_verified: false`. Kernel enforcement,
management reachability and intentional household communications require separate
target verification. No temporary enable/disable watchdog or recovery behavior is
part of this capability.
