# Prepare a real deployment

The outcome of this guide is a consumer-owned set of qualified inputs and a
reviewable execution boundary. It bridges the [offline tutorial](first-configuration.md)
and the [deployment procedure](../operations/deployment.md). Public documentation
supplies reusable requirements; the consumer supplies actual allocations,
protected paths, approvals and operating commands.

## Select compatible source

Record the framework revision, library revision, example/source revision and
selected image/catalogue/tooling identities. Use reviewed immutable selections.
For homelab-stack, inspect the framework selection in its reusable phase workflow;
do not substitute a newer framework just because it is available. When evaluating
an update, compare the effective configuration at the intended tuple.

Choose the actual [adapter capability](../reference/support.md) and library
profile before allocating a guest. A profile can impose a narrower requirement
than the general [app property schema](../reference/app-properties.md). Some
adapters support owned continuation without fresh commissioning. Valid YAML
cannot supply a missing creation capability.

## Qualify platform and ownership

The application deployment platform is Debian 13 LXC on Proxmox. Supply the
host, template, storage capacity and provider/SSH permissions required by the
[context](../reference/contexts.md) and [guest](../reference/guests.md).
Host bootstrap and installer work have [separate contracts](../framework-reference.md).

For first installation, confirm the supported owner/backend is genuinely absent
and no conflicting service/data namespace exists. For continuation, preserve
current ordinary receipts, backend state and sealed app payloads. `retained`
does not adopt an external installation; a prior `fresh` installation keeps its
source for ordinary updates. Consult [lifecycle](../reference/lifecycle.md) for
identity and marker restrictions.

## Network and control access

Bind real [networks and NICs](../reference/networks.md), usable allocations,
bridge/VLAN availability and a reachable [control interface](../reference/guests.md#guest-control-interface).
Confirm exactly one ordinary route. If DHCP is selected, the environment must
provide the declared lease endpoint; compilation reserves nothing. Confirm
required DNS/provider/service flows under the actual [policy](../reference/policies.md).

Supply genuine SSH public keys, trusted CA and known-host inputs. Source
admission rejects known synthetic bindings, but a passed source check does not
establish lease identity, external address uniqueness, firewall reachability or
host trust. Preserve the specific native verification required by the selected
consumer procedure.

## Prepare material, storage and service prerequisites

[Secret sources](../reference/identity-and-secrets.md#secret-sources) describe
file/environment/generated metadata. Compilation does not open those private
sources. The consumer must place actual material at the declared boundary with
the required ownership and modes. Preserve existing account/key/data identities;
a renamed reference is not permission for rotation.

Select [storage pools, volumes and bindings](../reference/storage.md) consistent
with the adapter's owned paths and first-installation support. Supply required
existing database/account/configuration/device inputs. A software image alone
does not commission its service. Use the chosen library profile for exact roles,
versions, runtime reserves and health requirements.

## Prepare the protected workflow

Generate and review the [workflow graph](validate-and-generate.md) for the same
source tuple. The consumer owns runner labels, protected environment selection,
trigger, named secret forwarding at each reusable-workflow edge and authority
for the exact action. Preserve source/security/history/signature/review gates.
A skipped check is not evidence of acceptance.

The public repository intentionally provides no production consumer identity or
generic launch command. Use the consumer's reviewed procedure once its exact
inputs and trigger are concrete. No supported procedure may bypass an active
HOLD, missing ownership or the [saved-plan restrictions](../reference/lifecycle.md#infrastructure-plan-policy).

## Review readiness for the next stage

| Review | Evidence to retain |
| --- | --- |
| Source | Validated compatible tuple, effective defaults, resolved bindings and workflow graph |
| Target prerequisites | Actual capacity, trust, material, storage and network checks required by the chosen path |
| Change effect | Affected identities/phases, likely service interruption and qualified recovery readiness |
| Execution | Exact consumer procedure, protected inputs and authority for the selected operation |
| Acceptance | Named service checks and expected result to perform after the phases complete |

If any required prerequisite is unknown, source work can still be reviewed, but
do not label the installation prepared. Continue to [first installation](../operations/deployment.md#first-installation)
or [later deployments](../operations/verify-and-maintain.md#later-deployments),
then [verify the service](../operations/verify-and-maintain.md#service-verification).

[Start here](../start-here.md) · [Operations index](../operations/README.md)
