# The configuration model

A site chooses reusable definitions and binds them to concrete resources. HomeLab checks these choices, resolves their relationships and produces a plan containing only the fields its contracts allow. It has no fixed inventory of guests and no implicit application bundle.

```mermaid
flowchart LR
  library[Library: profiles and defaults] --> plan[Resolved typed plan]
  site[Site: instances and bindings] --> plan
  plan --> packet[Guest packets]
  plan --> graph[Workflow dependencies]
  packet --> infra[OpenTofu infrastructure]
  infra --> preparation[Ansible preparation]
  preparation --> apps[Selected app phases]
  apps --> agent[Optional monitoring agent]
```

## Definitions and instances

A [guest template](reference/library.md) supplies complete defaults for resources, startup and security. A [profile](reference/supporting-types.md) selects an adapter and names its interface, storage, software, runtime and health roles. These are library choices. A [site guest](reference/guests.md) allocates identity, context, network interfaces (NICs) and storage; an [app](reference/apps.md) selects a profile, chooses its guest and binds those roles. Two app instances may share a guest only if their listeners, owned paths, service identities and budgets are compatible.

For example, the [offline resolver](examples/first-configuration/README.md) selects profile `recursive` on guest `resolver`. Its `local` role binds guest loopback, the address used to reach services within that guest; its `private` role selects an app network. Neither binding creates a public route. Follow the [app interface records](reference/apps.md#interface-roles) and [NIC address records](reference/networks.md#field-guest-nic-address) to see which address each scope can produce.

## Values, waits and permissions

| Relationship | What it provides | Owner |
| --- | --- | --- |
| Value reference | A declared address, port, protocol or other typed value | [Endpoints and connections](reference/connections.md) |
| Readiness | An explicit allowed dependency and order | [Connection readiness](reference/connections.md), [guest readiness](reference/guests.md#guest-readiness) |
| Access policy | Ordered rules allowing a required flow | [Network policies](reference/policies.md) |
| Publication | A declared DNS/HTTPS route and its ownership | [Exposures](reference/exposures.md) |

A value reference alone does not make deployment wait or grant network access. A loopback address reaches only the same guest; a connection between guests must use an address reachable from the other guest. The [relationship guide](guides/references-and-reuse.md) and [complete broker/browser example](examples/relationships/README.md) demonstrate these distinctions. Root [Zabbix selection](reference/zabbix.md) derives its specific monitoring access rules through an explicit feature; it is not a general exception for arbitrary references.

## Defaults and source reuse

Complete [typed source files](reference/sources.md) organize declarations; they do not merge fragments. For guest defaults, only resources, startup and security merge by direct field. Software and runtime lists append to the template selections. App properties combine selected profile defaults with explicit app keys using only the fields accepted by the adapter. Consult each owner before treating omission, null, an empty map or an empty list as interchangeable.

The [guest inheritance example](reference/guests.md#defaults-and-resolution) shows input and effective values. A library default change reaches inheriting instances, while an explicit guest override remains authoritative for that field.

## Resolution and execution

The compiler reads source snapshots within fixed limits, validates components, resolves names and bindings, and checks dependencies, resource budgets and traffic rules. It then converts the completed plan into deployment inputs, a step called **lowering**. Source pins identify the exact bytes it read. Runtime packets and receipts use JSON even when authored configuration is YAML.

Compilation checks private-source metadata without opening the declared files. The phase runner later selects only the inputs needed by its phase. OpenTofu owns infrastructure and state; Ansible owns guest configuration and services. Receipts from successful operations, payloads sealed against changes, and the backend identity establish whether HomeLab owns the installation. They do not provide a general import mechanism. See [lifecycle](reference/lifecycle.md) and [evidence](concepts/evidence.md).

## First installation and later deployments

When a guest or app does not yet exist and its adapter supports creation, `fresh` permits first installation. Keep that source for later updates; deployment checks the actual ownership records to distinguish creation from an update. `retained` requires an existing installation owned by HomeLab and rejects missing ownership. An adapter may support updates to an existing installation without supporting its initial setup. Check its [support limits](reference/support.md), then follow [preparation](guides/prepare-deployment.md) → [deployment](operations/deployment.md) → [service verification](operations/verify-and-maintain.md).

[Documentation index](README.md) · [Contract reference](reference/README.md)
