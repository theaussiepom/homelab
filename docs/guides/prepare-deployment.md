# Prepare a real deployment

Turn a compiled site into a reviewable installation proposal: a directory containing your configuration, compatible library and framework revisions, verified target inputs and named service checks. Start with the [stack design journey](https://github.com/theaussiepom/homelab-stack/blob/main/docs/start-here.md) if you are choosing real applications. The [framework walkthrough](first-configuration.md) teaches the configuration fields and inspection tools, but its synthetic image and library cannot serve as the starting point for a deployment.

Public documentation supplies the contracts. You supply the actual Proxmox allocations, network facts, controller paths, protected inputs and approved operating procedure. The completed result here is evidence that this exact proposal is ready for review; [deployment](../operations/deployment.md) is the next stage.

## Select compatible source

Choose the actual [adapter capability](../reference/support.md) and library profile before allocating a guest. A profile can impose narrower requirements than the general [app property schema](../reference/app-properties.md). Some adapters can update an existing HomeLab installation but cannot perform its initial setup. Valid YAML cannot add a creation capability that the adapter lacks. Check whether your intended result is a new service or an update to one already managed by HomeLab.

Record the framework revision, library revision, example or source revision, and the exact images, catalogue and tools selected. For homelab-stack, read the selected framework revision from its `.github/workflows/phase.yml` and use its [getting-started instructions](https://github.com/theaussiepom/homelab-stack/blob/main/docs/start-here.md) to obtain compatible source. Do not substitute a newer framework just because it is available. When evaluating an update, compare the effective configuration using the intended combination of revisions and artifact selections.

Keep framework, library and your own configuration in separate directories. For example, your local parent directory can contain these separately reviewed directories:

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

Work in your `site.yaml` and its referenced files. Each row identifies where the fact comes from and the field that consumes it; a reference is an ID you declare in the same site, not an automatic lookup of your environment. The exact `<context>`, `<guest>` and `<network>` keys are the IDs in your selected composition.

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
| Token/key source locations and controller state/backup paths | The procedure that provisions and protects the runner or controller | [`secret_sources`](../reference/identity-and-secrets.md#secret-sources), context `credentials` IDs and [`paths`](../reference/contexts.md#context-paths); metadata references, not inline private values |
| App data paths, accounts, devices and endpoints | The selected profile's required bindings and actual prerequisites already present or set up | [`apps.<app>`](../reference/apps.md), [`storage`](../reference/storage.md) and related typed declarations; the profile determines which rows are required |

Replace whole example endpoint values and their references consistently. A subnet change may require changes to guest addresses, gateway, DNS endpoints and selected policies. [Network/NIC diagnostics](../reference/networks.md#network-and-nic-diagnostics) catch declared inconsistencies; they cannot establish external uniqueness, VLAN availability or the intended DHCP lease. Keep any unknown fact explicitly unresolved in your review notes rather than turning a plausible value into a claim of readiness.

## Qualify platform and ownership

The application deployment platform is Debian 13 LXC on Proxmox. Supply the host, template, storage capacity and provider/SSH permissions required by the [context](../reference/contexts.md) and [guest](../reference/guests.md). Host bootstrap and installer work have [separate contracts](../framework-reference.md).

For first installation, confirm that the backend and ownership records do not already exist and that no service or data uses the paths and identities required by the new installation. For updates to an existing installation, preserve current operation receipts, backend state and app payloads sealed against changes. `retained` does not adopt an external installation; an existing `fresh` installation keeps that source for later updates. Consult [lifecycle](../reference/lifecycle.md) for identity and marker restrictions. A different VMID, hostname or storage pool is not an ordinary label edit.

## Network and control access

Declare real [networks and NICs](../reference/networks.md) with usable allocations, available bridges and VLANs, and a reachable [control interface](../reference/guests.md#guest-control-interface). Confirm exactly one ordinary route. If DHCP is selected, the environment must provide the declared lease endpoint; compilation reserves nothing. Confirm the required network access to DNS, providers and services under the actual [policy](../reference/policies.md).

Supply genuine SSH public keys, trusted CA and known-host inputs. Source admission rejects known synthetic bindings, but a passed source check does not establish lease identity, external address uniqueness, firewall reachability or host trust. Perform the checks on the actual target required by your selected deployment procedure.

## Prepare material, storage and service prerequisites

[Secret sources](../reference/identity-and-secrets.md#secret-sources) describe where a secret comes from: a file, an environment variable or a generator. Compilation does not open those private sources. You must place the actual values or files at the declared controller locations with the required ownership and permissions. A path available on your laptop is not necessarily available to the protected runner. Preserve existing account, key and data identities; a renamed reference is not permission for rotation.

Select [storage pools, volumes and bindings](../reference/storage.md) consistent with the adapter's owned paths and first-installation support. Supply the required existing databases, accounts, configuration and device inputs. A software image alone does not perform a service's initial setup. Use the chosen library profile for exact roles, versions, runtime reserves and health requirements.

### Set up backups before the first deployment

Follow [Set up backups](../backup/README.md) during initial preparation. It walks through generic PBS installation and storage, recovery-key creation and independent storage, creation of the PBS API token, and the exact GitHub Environment secret to add. You then return to the [backup configuration](../reference/backup.md) to bind the shared settings and enroll individual guests with `backup:`.

Complete that setup before enabling an operational job. Review its declared service pauses, database locks, transport policy and staging capacity. CD installs and maintains the declared backup configuration; the guide's [first backup, restore rehearsal and maintenance checklist](../backup/operations.md) establishes when it is ready to run unattended. No recovery private key or password-manager login is required by CD.

## Check the source you will review

With the example directory layout above, start inside `homelab-work/homelab` and activate the hash-locked environment for this selected framework, as in [the walkthrough setup](first-configuration.md#prepare-an-isolated-workspace). These commands use the existing sibling directories; change the two directory names if you chose different ones:

```sh
FRAMEWORK="$(pwd -P)"
LIBRARY="$(cd ../homelab-stack && pwd -P)"
SITE_ROOT="$(cd ../my-site && pwd -P)"
python "$FRAMEWORK/blueprints/compile.py" --stack "$LIBRARY" --site "$SITE_ROOT/site.yaml" --check
python "$FRAMEWORK/blueprints/compile.py" --stack "$LIBRARY" --site "$SITE_ROOT/site.yaml" --check --admit
```

The first command resolves every guest's references and generates its deployment inputs. The second also checks whether the source is suitable for deployment, including checks for known synthetic bindings and unsuitable public keys. Both commands inspect source only; neither deploys to a target. The suitability check may reject deliberately synthetic examples until you replace their required bindings with established real inputs. Do not weaken checks to pass an incomplete proposal.

Inspect each affected guest's packet using a new private output filename and the [walkthrough inspection pattern](first-configuration.md#validate-then-produce-a-packet), substituting your real guest/app IDs. Compare node, VMID, hostname, root storage, template, NICs, resources, app publications and phase order with the intended allocations and profile contract. A clean check without that comparison can miss a valid but unintended choice. [Validate and generate](validate-and-generate.md) explains plan and workflow inspection without launching it.

## Prepare the protected workflow

Generate and review the [workflow graph](validate-and-generate.md) for the same combination of source revisions. Your deployment repository supplies runner labels, the protected environment, the trigger, named secrets forwarded at each reusable-workflow call, and authority for the exact action. Preserve the required source, security, history, signature and review checks. A skipped check is not evidence of acceptance.

The public repository intentionally identifies no production deployment repository and provides no generic launch command. Use your reviewed deployment procedure once its exact inputs and trigger are defined. No supported procedure may bypass an active HOLD, missing ownership or the [saved-plan restrictions](../reference/lifecycle.md#infrastructure-plan-policy).

## Review readiness for the next stage

| Review | Evidence to retain |
| --- | --- |
| Source | Compatible fixed framework, library and artifact selections, your configuration revision, successful validation and deployment-suitability checks, inspected generated values and workflow graph |
| Target prerequisites | Actual capacity, trust, protected-input, storage and network checks required by the chosen path |
| Change effect | Affected identities/phases, likely service interruption and verified recovery prerequisites |
| Execution | Exact procedure from your deployment repository, protected inputs and authority for the selected operation |
| Acceptance | Named service checks and expected result to perform after the phases complete |

If any required prerequisite is unknown, source work can still be reviewed, but do not label the installation prepared. Continue to [first installation](../operations/deployment.md#first-installation) or [later deployments](../operations/verify-and-maintain.md#later-deployments), then [verify the service](../operations/verify-and-maintain.md#service-verification).

[Start here](../start-here.md) · [Configuration walkthrough](first-configuration.md) · [Operations index](../operations/README.md)
