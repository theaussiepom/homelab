# Prepare a real deployment

Turn a compiled site into a reviewable installation proposal: a concrete consumer source directory, a compatible library/framework selection, qualified target inputs and named service checks. Start with the [stack design journey](https://github.com/theaussiepom/homelab-stack/blob/main/docs/start-here.md) if you are choosing real applications. The [framework walkthrough](first-configuration.md) teaches the field and inspection mechanics, but its synthetic image and library are not a deployment starting selection.

Public documentation supplies the contracts. You supply the actual Proxmox allocations, network facts, controller paths, protected material and approved operating procedure. The completed result here is readiness evidence for that exact proposal; [deployment](../operations/deployment.md) is the next stage.

## Select compatible source

Choose the actual [adapter capability](../reference/support.md) and library profile before allocating a guest. A profile can impose narrower requirements than the general [app property schema](../reference/app-properties.md). Some adapters support owned continuation without fresh commissioning; valid YAML cannot supply a missing creation capability. Check whether your intended result is a new service or continuation of a genuinely HomeLab-owned one.

Record the framework revision, library revision, example/source revision and selected image/catalogue/tooling identities. For homelab-stack, read the selected framework revision from its `.github/workflows/phase.yml` and use its [getting-started instructions](https://github.com/theaussiepom/homelab-stack/blob/main/docs/start-here.md) to obtain compatible source. Do not substitute a newer framework just because it is available. When evaluating an update, compare effective configuration at the intended tuple.

Keep the three source owners visible. For example, your local parent directory can contain these separately reviewed directories:

```text
homelab-work/
  homelab/                 selected framework checkout and requirements.lock.txt
  homelab-stack/           selected library checkout, stack.json and images.json
  my-site/
    site.yaml              your complete site root
    apps/                  optional complete typed app leaves
    guests/                optional complete typed guest leaves
```

The names above are an example layout, not required repository names. Create `my-site` and copy the complete selected library example and all of its site-relative dependencies as instructed by that library's guide. Preserve relative leaf and asset paths. The framework lesson's `base` and `recursive` entries belong to its own library; do not assume they exist in homelab-stack. Avoid copying a file whose surrounding definitions or assets you have not selected.

## Replace practice values with known facts

Work in your consumer's `site.yaml` and its referenced leaves. Each row identifies where the fact comes from and the field that consumes it; a reference is an ID you declare in the same site, not an automatic lookup of your environment. The exact `<context>`, `<guest>` and `<network>` keys are the IDs in your selected composition.

| Fact you need | Where to establish it | Authored location and effect |
| --- | --- | --- |
| Proxmox node and API address | Your Proxmox inventory and trusted management endpoint | [`contexts.<context>.node`](../reference/contexts.md#context-node), `api_endpoint: {external: <endpoint>}` and [`external_endpoints.<endpoint>`](../reference/networks.md#external-endpoints); HTTPS port 8006 |
| Existing Debian 13 LXC template identity | The chosen node's template storage inventory | [`guests.<guest>.template_file_id`](../reference/guests.md#guest-template-file-id); exact provider file ID, not a download URL |
| Root storage pool and capacity | The node's available storage and the library's guest/app requirements | [`storage.<pool>.pool`](../reference/storage.md#storage-pool), its `context`, then `guests.<guest>.root_storage: <pool>` |
| Unused VMID and stable hostname | Your allocation inventory across the API authority; existing state when continuing | [`guests.<guest>.identity`](../reference/guests.md#guest-identity); avoid protected IDs and preserve existing owned identities |
| Bridge, VLAN, subnet and gateway | Proxmox bridge configuration plus the network/router configuration serving it | [`networks.<network>`](../reference/networks.md#network-property-index); `vlan: null` is an explicit untagged choice |
| Guest address and virtual NIC MAC | Your address/MAC allocation record or declared DHCP reservation | [`guests.<guest>.interfaces.<nic>`](../reference/networks.md#nic-property-index); select one `control_interface` and exactly one ordinary default route |
| DNS used by the guest | Your intended existing resolver and its allowed network path | `external_endpoints.<dns>` and [`contexts.<context>.dns_servers`](../reference/contexts.md#context-dns-servers); this reference does not create the resolver |
| Memory, CPU, root capacity and timezone | Library template/runtime requirements plus actual node capacity | [`guests.<guest>.resources`](../reference/guests.md#resource-fields), context or guest `timezone`; override only deliberate differences |
| Genuine public key, CA and known-host input | Your reviewed controller access and host-trust procedure | [`contexts.<context>.ssh_public_keys`](../reference/contexts.md#context-ssh-public-keys) and [`trust`](../reference/contexts.md#context-trust); do not derive trust from an unverified example |
| Token/key source locations and controller state/backup paths | The protected runner/controller's provisioning and custody procedure | [`secret_sources`](../reference/identity-and-secrets.md#secret-sources), context `credentials` IDs and [`paths`](../reference/contexts.md#context-paths); metadata references, not inline private values |
| App data paths, accounts, devices and endpoints | The selected profile's required bindings and actual existing/commissioned prerequisites | [`apps.<app>`](../reference/apps.md), [`storage`](../reference/storage.md) and related typed declarations; the profile determines which rows are required |

Replace whole example endpoint values and their references consistently. A subnet change may require changes to guest addresses, gateway, DNS endpoints and selected policies. [Network/NIC diagnostics](../reference/networks.md#network-and-nic-diagnostics) catch declared inconsistencies; they cannot establish external uniqueness, VLAN availability or the intended DHCP lease. Keep any unknown fact explicitly unresolved in your review notes rather than turning a plausible value into a claim of readiness.

## Qualify platform and ownership

The application deployment platform is Debian 13 LXC on Proxmox. Supply the host, template, storage capacity and provider/SSH permissions required by the [context](../reference/contexts.md) and [guest](../reference/guests.md). Host bootstrap and installer work have [separate contracts](../framework-reference.md).

For first installation, confirm the supported owner/backend is genuinely absent and no conflicting service/data namespace exists. For continuation, preserve current ordinary receipts, backend state and sealed app payloads. `retained` does not adopt an external installation; a prior `fresh` installation keeps its source for ordinary updates. Consult [lifecycle](../reference/lifecycle.md) for identity and marker restrictions. A different VMID, hostname or storage pool is not an ordinary label edit.

## Network and control access

Bind real [networks and NICs](../reference/networks.md), usable allocations, bridge/VLAN availability and a reachable [control interface](../reference/guests.md#guest-control-interface). Confirm exactly one ordinary route. If DHCP is selected, the environment must provide the declared lease endpoint; compilation reserves nothing. Confirm required DNS/provider/service flows under the actual [policy](../reference/policies.md).

Supply genuine SSH public keys, trusted CA and known-host inputs. Source admission rejects known synthetic bindings, but a passed source check does not establish lease identity, external address uniqueness, firewall reachability or host trust. Preserve the specific native verification required by the selected consumer procedure.

## Prepare material, storage and service prerequisites

[Secret sources](../reference/identity-and-secrets.md#secret-sources) describe file/environment/generated metadata. Compilation does not open those private sources. The consumer must place actual material at the declared controller boundary with the required ownership and modes. A path available on your laptop is not necessarily available to the protected runner. Preserve existing account/key/data identities; a renamed reference is not permission for rotation.

Select [storage pools, volumes and bindings](../reference/storage.md) consistent with the adapter's owned paths and first-installation support. Supply required existing database/account/configuration/device inputs. A software image alone does not commission its service. Use the chosen library profile for exact roles, versions, runtime reserves and health requirements.

## Check the source you will review

With the example directory layout above, start inside `homelab-work/homelab` and activate the hash-locked environment for this selected framework, as in [the walkthrough setup](first-configuration.md#prepare-an-isolated-workspace). These commands use the existing sibling directories; change the two directory names if you chose different ones:

```sh
FRAMEWORK="$(pwd -P)"
LIBRARY="$(cd ../homelab-stack && pwd -P)"
SITE_ROOT="$(cd ../my-site && pwd -P)"
python "$FRAMEWORK/blueprints/compile.py" --stack "$LIBRARY" --site "$SITE_ROOT/site.yaml" --check
python "$FRAMEWORK/blueprints/compile.py" --stack "$LIBRARY" --site "$SITE_ROOT/site.yaml" --check --admit
```

The first command resolves and lowers all guests. The second adds source suitability checks, including known synthetic bindings and public-key suitability. Both are source-only and perform no native deployment. Admission may still refuse deliberately synthetic examples until you replace their required bindings with established real inputs. Do not weaken checks to pass an incomplete proposal.

Inspect each affected guest's packet using a new private output filename and the [walkthrough inspection pattern](first-configuration.md#validate-then-produce-a-packet), substituting your real guest/app IDs. Compare node, VMID, hostname, root storage, template, NICs, resources, app publications and phase order with the intended allocations and profile contract. A clean check without that comparison can miss a valid but unintended choice. [Validate and generate](validate-and-generate.md) explains plan and workflow inspection without launching it.

## Prepare the protected workflow

Generate and review the [workflow graph](validate-and-generate.md) for the same source tuple. The consumer owns runner labels, protected environment selection, trigger, named secret forwarding at each reusable-workflow edge and authority for the exact action. Preserve source/security/history/signature/review gates. A skipped check is not evidence of acceptance.

The public repository intentionally provides no production consumer identity or generic launch command. Use the consumer's reviewed procedure once its exact inputs and trigger are concrete. No supported procedure may bypass an active HOLD, missing ownership or the [saved-plan restrictions](../reference/lifecycle.md#infrastructure-plan-policy).

## Review readiness for the next stage

| Review | Evidence to retain |
| --- | --- |
| Source | Compatible immutable tuple, consumer source revision, successful check/admission, inspected effective values and workflow graph |
| Target prerequisites | Actual capacity, trust, material, storage and network checks required by the chosen path |
| Change effect | Affected identities/phases, likely service interruption and qualified recovery readiness |
| Execution | Exact consumer procedure, protected inputs and authority for the selected operation |
| Acceptance | Named service checks and expected result to perform after the phases complete |

If any required prerequisite is unknown, source work can still be reviewed, but do not label the installation prepared. Continue to [first installation](../operations/deployment.md#first-installation) or [later deployments](../operations/verify-and-maintain.md#later-deployments), then [verify the service](../operations/verify-and-maintain.md#service-verification).

[Start here](../start-here.md) · [Configuration walkthrough](first-configuration.md) · [Operations index](../operations/README.md)
